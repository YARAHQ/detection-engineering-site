#!/usr/bin/env python3
"""
YARA Rule Compile-Review Loop
Iteratively reviews and fixes YARA rules until they compile successfully.
Can integrate with LLM for automatic fixes.
"""

import sys
import subprocess
import re
import tempfile
import os
from pathlib import Path


class YARACompileLoop:
    def __init__(self, rule_file: str, max_iterations: int = 5):
        self.rule_file = Path(rule_file)
        self.max_iterations = max_iterations
        self.iteration = 0
        self.yara_path = self._find_yara()
        
    def _find_yara(self) -> str:
        """Find yara binary in PATH."""
        result = subprocess.run(
            ["which", "yara"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    
    def compile_rule(self) -> tuple[bool, str]:
        """Try to compile the YARA rule. Returns (success, error_message)."""
        if not self.yara_path:
            return False, "yara binary not found in PATH"
        
        result = subprocess.run(
            [self.yara_path, "-c", str(self.rule_file), "/dev/null"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            return True, ""
        
        # Parse errors
        errors = result.stderr.strip() or result.stdout.strip()
        return False, errors
    
    def analyze_errors(self, errors: str) -> list[dict]:
        """Analyze compilation errors and extract fixable issues."""
        issues = []
        
        # Pattern 1: Unreferenced strings
        unref_match = re.findall(
            r'unreferenced string "(\$[a-zA-Z0-9_]+)"',
            errors
        )
        for var in unref_match:
            issues.append({
                "type": "unreferenced_string",
                "variable": var,
                "message": f"String {var} defined but not used in condition",
                "fix": f"Add {var} to condition or remove the string"
            })
        
        # Pattern 2: Syntax errors
        syntax_match = re.search(
            r'syntax error.*line (\d+).*?unexpected (\S+)',
            errors,
            re.DOTALL
        )
        if syntax_match:
            line_no = syntax_match.group(1)
            unexpected = syntax_match.group(2)
            issues.append({
                "type": "syntax_error",
                "line": line_no,
                "unexpected": unexpected,
                "message": f"Syntax error on line {line_no}: unexpected {unexpected}",
                "fix": "Check syntax around that line"
            })
        
        # Pattern 3: Undefined strings
        undef_match = re.findall(
            r'undefined string "(\$[a-zA-Z0-9_]+)"',
            errors
        )
        for var in undef_match:
            issues.append({
                "type": "undefined_string",
                "variable": var,
                "message": f"String {var} referenced but not defined",
                "fix": f"Define {var} in strings section or remove from condition"
            })
        
        return issues
    
    def auto_fix(self, errors: str) -> bool:
        """Attempt automatic fixes for common issues."""
        issues = self.analyze_errors(errors)
        
        if not issues:
            return False
        
        # Read current rule
        with open(self.rule_file, 'r') as f:
            rule_content = f.read()
        
        fixes_applied = []
        
        for issue in issues:
            if issue["type"] == "unreferenced_string":
                # Option 1: Remove the unused string
                var = issue["variable"]
                pattern = rf'\s+{re.escape(var)}\s*=\s*"[^"]*"[^\n]*\n'
                if re.search(pattern, rule_content):
                    rule_content = re.sub(pattern, '\n', rule_content)
                    fixes_applied.append(f"Removed unused {var}")
                    continue
            
            elif issue["type"] == "undefined_string":
                # Can't auto-fix undefined strings
                pass
        
        # Write fixed rule
        if fixes_applied:
            with open(self.rule_file, 'w') as f:
                f.write(rule_content)
            print(f"✅ Auto-fixed: {', '.join(fixes_applied)}")
            return True
        
        return False
    
    def generate_llm_prompt(self, errors: str) -> str:
        """Generate a prompt for LLM to fix the rule."""
        with open(self.rule_file, 'r') as f:
            rule_content = f.read()
        
        issues = self.analyze_errors(errors)
        
        prompt = f"""You are an expert YARA rule author. Fix the compilation errors in this rule.

COMPILATION ERRORS:
{errors}

ISSUES IDENTIFIED:
"""
        for i, issue in enumerate(issues, 1):
            prompt += f"\n{i}. {issue['message']}"
            prompt += f"\n   Fix: {issue['fix']}"
        
        prompt += f"""

CURRENT RULE:
```yara
{rule_content}
```

TASK:
1. Fix ALL compilation errors
2. Ensure all defined strings are used in the condition
3. Maintain the rule's detection logic and purpose
4. Follow YARA best practices (naming, structure)
5. Return ONLY the complete fixed YARA rule

FIXED RULE:
```yara
"""
        return prompt
    
    def run(self) -> bool:
        """Run the compile-review loop."""
        print("=" * 65)
        print("  YARA RULE COMPILE-REVIEW LOOP")
        print("=" * 65)
        print()
        
        if not self.rule_file.exists():
            print(f"❌ Error: Rule file not found: {self.rule_file}")
            return False
        
        while self.iteration < self.max_iterations:
            self.iteration += 1
            print(f"\n{'─' * 65}")
            print(f"  ITERATION {self.iteration}/{self.max_iterations}")
            print(f"{'─' * 65}\n")
            
            # Try to compile
            success, errors = self.compile_rule()
            
            if success:
                print("✅ SUCCESS! Rule compiles without errors.")
                print()
                print("Final rule:")
                with open(self.rule_file, 'r') as f:
                    print(f.read())
                return True
            
            # Compilation failed
            print("❌ COMPILATION FAILED\n")
            print("Errors:")
            print(errors)
            print()
            
            # Try auto-fix first
            print("Attempting auto-fix...")
            if self.auto_fix(errors):
                print("Retrying with auto-fixes applied...\n")
                continue
            
            # Auto-fix didn't work - need LLM help
            print("Auto-fix failed. Generating LLM prompt...\n")
            
            prompt = self.generate_llm_prompt(errors)
            
            # Save prompt to temp file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.txt',
                delete=False,
                prefix='yara_fix_prompt_'
            ) as f:
                f.write(prompt)
                prompt_file = f.name
            
            print(f"📄 Prompt saved to: {prompt_file}")
            print()
            print("To fix with LLM:")
            print(f"  1. Read the prompt: cat {prompt_file}")
            print("  2. Send to your LLM (Claude, GPT, etc.)")
            print(f"  3. Save the fixed rule to: {self.rule_file}")
            print("  4. Press Enter to retry compilation...")
            print()
            input()
        
        print()
        print(f"⚠️  Max iterations ({self.max_iterations}) reached.")
        print("Manual intervention required.")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: yara-compile-loop.py <rule-file.yar> [max-iterations]")
        print()
        print("Example:")
        print("  yara-compile-loop.py my_rule.yar")
        print("  yara-compile-loop.py my_rule.yar 10")
        sys.exit(1)
    
    rule_file = sys.argv[1]
    max_iter = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    
    loop = YARACompileLoop(rule_file, max_iter)
    success = loop.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

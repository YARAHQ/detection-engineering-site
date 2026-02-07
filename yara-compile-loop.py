#!/usr/bin/env python3
"""
YARA Rule Compile-Review Loop
Iteratively reviews and fixes YARA rules until they compile successfully.
Includes VT Intelligence content search for false positive validation.
"""

import sys
import subprocess
import re
import tempfile
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Tuple


class VTValidator:
    """VirusTotal Intelligence content search for string validation."""
    
    def __init__(self):
        self.api_key = self._get_api_key()
        
    def _get_api_key(self) -> Optional[str]:
        """Get VT API key from standard locations."""
        # Try environment variable
        if 'VT_API_KEY' in os.environ:
            return os.environ['VT_API_KEY']
        
        # Try file
        key_file = Path.home() / '.virustotal' / 'apikey'
        if key_file.exists():
            return key_file.read_text().strip()
        
        # Try OpenClaw credentials
        creds_file = Path.home() / '.openclaw' / 'credentials' / 'virustotal-api-key.json'
        if creds_file.exists():
            import json
            data = json.loads(creds_file.read_text())
            return data.get('api_key') or data.get('token')
        
        return None
    
    def search_content(self, query: str, limit: int = 10) -> Dict:
        """Search for content in VT Intelligence."""
        if not self.api_key:
            return {"error": "VT API key not configured"}
        
        import urllib.request
        import urllib.parse
        
        encoded_query = urllib.parse.quote(query)
        url = f"https://www.virustotal.com/api/v3/intelligence/search?query={encoded_query}&limit={limit}"
        
        req = urllib.request.Request(
            url,
            headers={'x-apikey': self.api_key}
        )
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def check_string_fp(self, string_value: str, min_hits: int = 100) -> Tuple[bool, Dict]:
        """
        Check if a string matches on too many legitimate files.
        Returns (is_suspicious, details).
        """
        # Clean the string for VT search
        # Remove fullword, ascii modifiers for search
        clean_str = re.sub(r'\s+fullword\s*$', '', string_value)
        clean_str = re.sub(r'\s+ascii\s*$', '', clean_str)
        clean_str = re.sub(r'\s+wide\s*$', '', clean_str)
        clean_str = clean_str.strip('"')
        
        # Skip if too short or common
        if len(clean_str) < 8:
            return False, {"reason": "too_short", "hits": 0}
        
        # Search in VT
        query = f'content:"{clean_str}"'
        result = self.search_content(query, limit=1)
        
        if 'error' in result:
            return False, {"error": result['error']}
        
        total_hits = result.get('meta', {}).get('total_hits', 0)
        
        # If hits > threshold, it might be too common
        if total_hits > min_hits:
            return True, {
                "reason": "too_common",
                "hits": total_hits,
                "threshold": min_hits,
                "suggestion": "Consider using more specific strings or adding context"
            }
        
        return False, {"hits": total_hits}


class YARACompileLoop:
    def __init__(self, rule_file: str, max_iterations: int = 5, vt_check: bool = False):
        self.rule_file = Path(rule_file)
        self.max_iterations = max_iterations
        self.iteration = 0
        self.yara_path = self._find_yara()
        self.vt_validator = VTValidator() if vt_check else None
        self.vt_check_enabled = vt_check
        
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
    
    def extract_strings(self) -> List[Dict]:
        """Extract string definitions from the YARA rule."""
        with open(self.rule_file, 'r') as f:
            content = f.read()
        
        strings = []
        # Pattern: $var = "value" [modifiers]
        pattern = r'(\$[a-zA-Z0-9_]+)\s*=\s*"([^"]+)"(?:\s+((?:fullword|ascii|wide|nocase|private)\s*)*)?'
        
        for match in re.finditer(pattern, content):
            var_name = match.group(1)
            value = match.group(2)
            modifiers = match.group(3) or ""
            
            strings.append({
                "variable": var_name,
                "value": value,
                "modifiers": modifiers.strip(),
                "full_string": match.group(0)
            })
        
        return strings
    
    def validate_strings_with_vt(self) -> List[Dict]:
        """Check strings against VT Intelligence for false positives."""
        if not self.vt_validator or not self.vt_validator.api_key:
            print("⚠️  VT API key not configured - skipping FP validation")
            return []
        
        print("🔍 Checking strings against VirusTotal Intelligence...")
        print("   (This may take a moment for each string)\n")
        
        strings = self.extract_strings()
        problematic = []
        
        for s in strings:
            # Skip short or common strings
            if len(s['value']) < 12:
                continue
            
            # Skip API-related strings
            if any(x in s['value'].lower() for x in [
                'api-ms-win', 'kernel32', 'ntdll', 'user32',
                'virtualprotect', 'virtualalloc', 'getprocaddress'
            ]):
                continue
            
            print(f"   Checking {s['variable']}: \"{s['value'][:50]}...\" ", end='', flush=True)
            
            is_suspicious, details = self.vt_validator.check_string_fp(
                s['full_string'],
                min_hits=500  # Threshold for "too common"
            )
            
            if is_suspicious:
                print(f"⚠️  {details['hits']} hits")
                problematic.append({
                    "string": s,
                    "details": details
                })
            elif 'error' in details:
                print(f"❌ Error: {details['error']}")
            else:
                print(f"✓ {details.get('hits', 0)} hits")
        
        print()
        return problematic
    
    def generate_llm_prompt(self, errors: str, vt_issues: List[Dict] = None) -> str:
        """Generate a prompt for LLM to fix the rule."""
        with open(self.rule_file, 'r') as f:
            rule_content = f.read()
        
        issues = self.analyze_errors(errors)
        
        prompt = f"""You are an expert YARA rule author. Fix the compilation errors and false positive issues in this rule.

COMPILATION ERRORS:
{errors}

ISSUES IDENTIFIED:
"""
        for i, issue in enumerate(issues, 1):
            prompt += f"\n{i}. {issue['message']}"
            prompt += f"\n   Fix: {issue['fix']}"
        
        # Add VT validation issues if any
        if vt_issues:
            prompt += "\n\nVIRUSTOTAL FALSE POSITIVE WARNINGS:\n"
            for issue in vt_issues:
                s = issue['string']
                d = issue['details']
                prompt += f"\n- {s['variable']}: \"{s['value'][:60]}...\""
                prompt += f"\n  Matches {d['hits']} files in VT (too common!)"
                prompt += f"\n  Suggestion: {d.get('suggestion', 'Use more specific strings')}"
        
        prompt += f"""

CURRENT RULE:
```yara
{rule_content}
```

TASK:
1. Fix ALL compilation errors
2. Ensure all defined strings are used in the condition"""
        
        if vt_issues:
            prompt += """
3. Address FALSE POSITIVE issues:
   - Replace overly common strings with more specific ones
   - Add context (combine multiple strings)
   - Use unique file paths, C2 domains, or malware-specific artifacts"""
        
        prompt += """
4. Maintain the rule's detection logic and purpose
5. Follow YARA best practices (naming, structure)
6. Return ONLY the complete fixed YARA rule

FIXED RULE:
```yara
"""
        return prompt
    
    def run(self) -> bool:
        """Run the compile-review loop."""
        print("=" * 65)
        print("  YARA RULE COMPILE-REVIEW LOOP")
        if self.vt_check_enabled:
            print("  (with VirusTotal FP validation)")
        print("=" * 65)
        print()
        
        if not self.rule_file.exists():
            print(f"❌ Error: Rule file not found: {self.rule_file}")
            return False
        
        # Initial VT validation if enabled
        vt_issues = []
        if self.vt_check_enabled:
            vt_issues = self.validate_strings_with_vt()
            if vt_issues:
                print("⚠️  VIRUSTOTAL WARNINGS:")
                for issue in vt_issues:
                    s = issue['string']
                    d = issue['details']
                    print(f"  - {s['variable']}: {d['hits']} hits in VT")
                print()
        
        while self.iteration < self.max_iterations:
            self.iteration += 1
            print(f"\n{'─' * 65}")
            print(f"  ITERATION {self.iteration}/{self.max_iterations}")
            print(f"{'─' * 65}\n")
            
            # Try to compile
            success, errors = self.compile_rule()
            
            if success and not vt_issues:
                print("✅ SUCCESS! Rule compiles without errors.")
                print()
                print("Final rule:")
                with open(self.rule_file, 'r') as f:
                    print(f.read())
                return True
            
            if success and vt_issues:
                print("✅ Rule compiles but has FP warnings from VT")
                # Continue to get fixes for FP issues
            
            # Compilation failed or FP issues
            if errors:
                print("❌ COMPILATION FAILED\n")
                print("Errors:")
                print(errors)
                print()
            
            # Try auto-fix first
            if errors:
                print("Attempting auto-fix...")
                if self.auto_fix(errors):
                    print("Retrying with auto-fixes applied...\n")
                    continue
            
            # Need LLM help
            if errors:
                print("Auto-fix failed. Generating LLM prompt...\n")
            elif vt_issues:
                print("VT validation found potential false positives. Generating prompt...\n")
            
            prompt = self.generate_llm_prompt(errors or "", vt_issues)
            
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
            
            # Clear VT issues after attempting fix
            vt_issues = []
        
        print()
        print(f"⚠️  Max iterations ({self.max_iterations}) reached.")
        print("Manual intervention required.")
        return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='YARA Rule Compile-Review Loop with optional VT FP validation'
    )
    parser.add_argument('rule_file', help='YARA rule file to validate')
    parser.add_argument(
        '--max-iter', '-m',
        type=int,
        default=5,
        help='Maximum iterations (default: 5)'
    )
    parser.add_argument(
        '--vt-check', '-v',
        action='store_true',
        help='Enable VirusTotal content search for FP validation'
    )
    
    args = parser.parse_args()
    
    loop = YARACompileLoop(args.rule_file, args.max_iter, args.vt_check)
    success = loop.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

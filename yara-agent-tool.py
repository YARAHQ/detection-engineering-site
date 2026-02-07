#!/usr/bin/env python3
"""
YARA Rule Validation Agent Tool
Designed for LLM agent integration with JSON output for automated decision-making.

Usage by agent:
  result = json.loads(subprocess.run(['python3', 'yara-agent-tool.py', '-j', rule.yar'], capture_output=True).stdout)
  if result['compiles'] and result['issues']:
      # Agent decides to fix issues
      fixed_rule = agent_fix(result['issues'], result['rule_content'])
"""

import sys
import subprocess
import re
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any


class YARAValidationTool:
    """Tool for validating YARA rules - designed for LLM agent integration."""
    
    def __init__(self, rule_file: str, vt_check: bool = False):
        self.rule_file = Path(rule_file)
        self.vt_check = vt_check
        self.vt_api_key = self._get_vt_key()
        
    def _get_vt_key(self) -> Optional[str]:
        """Get VT API key."""
        if 'VT_API_KEY' in os.environ:
            return os.environ['VT_API_KEY']
        key_file = Path.home() / '.virustotal' / 'apikey'
        if key_file.exists():
            return key_file.read_text().strip()
        return None
    
    def compile_rule(self) -> Dict[str, Any]:
        """Compile the rule and return structured result."""
        result = subprocess.run(
            ['yara', '-c', str(self.rule_file), '/dev/null'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            return {
                'compiles': True,
                'errors': []
            }
        
        errors = result.stderr.strip() or result.stdout.strip()
        return {
            'compiles': False,
            'errors': self._parse_errors(errors)
        }
    
    def _parse_errors(self, error_text: str) -> List[Dict]:
        """Parse YARA errors into structured format."""
        errors = []
        
        # Unreferenced string
        for match in re.finditer(r'unreferenced string "(\$[a-zA-Z0-9_]+)"', error_text):
            errors.append({
                'type': 'unreferenced_string',
                'variable': match.group(1),
                'severity': 'error',
                'auto_fixable': True,
                'fix_action': 'remove_string',
                'message': f'{match.group(1)} defined but not used in condition'
            })
        
        # Undefined string (handles both $var and $var* patterns)
        for match in re.finditer(r'undefined string "(\$[a-zA-Z0-9_\*]+)"', error_text):
            var = match.group(1).rstrip('*')
            errors.append({
                'type': 'undefined_string',
                'variable': var,
                'severity': 'error',
                'auto_fixable': False,
                'message': f'{var} referenced but not defined'
            })
        
        # Syntax error
        syntax_match = re.search(r'syntax error.*?line (\d+)', error_text)
        if syntax_match:
            errors.append({
                'type': 'syntax_error',
                'line': int(syntax_match.group(1)),
                'severity': 'error',
                'auto_fixable': False,
                'message': f'Syntax error on line {syntax_match.group(1)}'
            })
        
        return errors
    
    def extract_rule_info(self) -> Dict[str, Any]:
        """Extract rule structure for analysis."""
        with open(self.rule_file, 'r') as f:
            content = f.read()
        
        # Extract rule name
        rule_name = re.search(r'rule\s+(\w+)', content)
        
        # Extract strings
        strings = []
        str_pattern = r'(\$[a-zA-Z0-9_]+)\s*=\s*("[^"]+"|\{[^}]+\})'
        for match in re.finditer(str_pattern, content):
            strings.append({
                'variable': match.group(1),
                'value': match.group(2),
                'type': 'text' if match.group(2).startswith('"') else 'bytes'
            })
        
        # Extract condition
        condition_match = re.search(r'condition:\s*(.+?)(?=\nrule|\Z)', content, re.DOTALL)
        condition = condition_match.group(1).strip() if condition_match else ""
        
        # Check which strings are used in condition
        for s in strings:
            var_base = s['variable'].rstrip('0123456789')
            # Check if used: $var, $var*, or $var1
            if re.search(rf'\{re.escape(s["variable"])}\b|\{re.escape(var_base)}\*', condition):
                s['used_in_condition'] = True
            else:
                s['used_in_condition'] = False
        
        return {
            'rule_name': rule_name.group(1) if rule_name else 'unknown',
            'strings': strings,
            'condition': condition,
            'content': content
        }
    
    def check_string_stability(self, string_value: str, min_hits: int = 500) -> Optional[Dict]:
        """Check if a string is stable (low FP rate) via VT."""
        if not self.vt_api_key or not self.vt_check:
            return None
        
        # Clean string for search
        clean = string_value.strip('"').replace('\\', '')
        if len(clean) < 12:
            return None
        
        # Skip common APIs
        common_apis = ['kernel32', 'ntdll', 'user32', 'virtualprotect', 'virtualalloc',
                      'getprocaddress', 'loadlibrary', 'api-ms-win']
        if any(api in clean.lower() for api in common_apis):
            return None
        
        try:
            import urllib.request
            import urllib.parse
            
            query = urllib.parse.quote(f'content:"{clean}"')
            url = f"https://www.virustotal.com/api/v3/intelligence/search?query={query}&limit=1"
            
            req = urllib.request.Request(url, headers={'x-apikey': self.vt_api_key})
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                hits = data.get('meta', {}).get('total_hits', 0)
                
                if hits > min_hits:
                    return {
                        'string': clean[:50],
                        'hits': hits,
                        'stable': False,
                        'recommendation': 'Too common - use more specific string or add context'
                    }
                return {'string': clean[:50], 'hits': hits, 'stable': True}
        except Exception:
            return None
    
    def check_combination_stability(self, strings: List[str], min_required: int = 2) -> Optional[Dict]:
        """Check if a COMBINATION of strings is stable (more accurate than individual checks)."""
        if not self.vt_api_key or not self.vt_check:
            return None
        
        # Clean strings
        clean_strings = []
        for s in strings:
            clean = s.strip('"').replace('\\', '')
            if len(clean) >= 12:
                clean_strings.append(clean)
        
        if len(clean_strings) < min_required:
            return None
        
        # Skip if all are common APIs
        common_apis = ['kernel32', 'ntdll', 'user32', 'virtualprotect', 'virtualalloc',
                      'getprocaddress', 'loadlibrary', 'api-ms-win']
        if all(any(api in s.lower() for api in common_apis) for s in clean_strings):
            return None
        
        try:
            import urllib.request
            import urllib.parse
            
            # Build AND query: string1 AND string2 AND ...
            query_parts = [f'content:"{s}"' for s in clean_strings[:3]]  # Limit to 3 for API
            query = urllib.parse.quote(' AND '.join(query_parts))
            url = f"https://www.virustotal.com/api/v3/intelligence/search?query={query}&limit=1"
            
            req = urllib.request.Request(url, headers={'x-apikey': self.vt_api_key})
            
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                hits = data.get('meta', {}).get('total_hits', 0)
                
                return {
                    'strings': [s[:40] for s in clean_strings[:3]],
                    'hits': hits,
                    'stable': hits < 100,  # Combination is stable if < 100 hits
                    'recommendation': f'Combination has {hits} hits' + (' (specific)' if hits < 100 else ' (may need more context)')
                }
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_condition_risk(self, info: Dict) -> List[Dict]:
        """Analyze condition for risky patterns."""
        risks = []
        condition = info['condition']
        
        # Check for any of ($op*) with single opcode
        op_strings = [s for s in info['strings'] if s['variable'].startswith('$op')]
        if 'any of ($op*)' in condition and len(op_strings) == 1:
            risks.append({
                'type': 'weak_opcode_condition',
                'severity': 'warning',
                'message': 'any of ($op*) with single opcode - may match too broadly',
                'recommendation': 'Add more opcode patterns or use specific $op1'
            })
        
        # Check for all of ($op*) with single opcode
        if 'all of ($op*)' in condition and len(op_strings) == 1:
            risks.append({
                'type': 'single_opcode',
                'severity': 'info',
                'message': 'all of ($op*) with single opcode - use $op1 instead',
                'recommendation': 'Replace with just $op1 for clarity'
            })
        
        # Check for weak filesize
        filesize_match = re.search(r'filesize\s*<\s*(\d+)(KB|MB)?', condition)
        if filesize_match:
            size = int(filesize_match.group(1))
            unit = filesize_match.group(2) or 'bytes'
            if unit == 'KB' and size < 10:
                risks.append({
                    'type': 'suspicious_filesize',
                    'severity': 'warning',
                    'message': f'Filesize {size}KB is very small',
                    'recommendation': 'Verify actual sample size and update condition'
                })
        
        return risks
    
    def generate_fix_plan(self, result: Dict) -> Dict[str, Any]:
        """Generate a fix plan for agent to execute."""
        plan = {
            'actions': [],
            'explanation': []
        }
        
        # Auto-fixable errors
        for error in result.get('errors', []):
            if error.get('auto_fixable'):
                plan['actions'].append({
                    'action': error['fix_action'],
                    'target': error['variable'],
                    'reason': error['message']
                })
        
        # Stability issues
        for issue in result.get('stability_issues', []):
            if not issue.get('stable'):
                plan['actions'].append({
                    'action': 'review_string',
                    'target': issue['string'],
                    'reason': f"{issue['hits']} VT hits - {issue['recommendation']}"
                })
        
        # Condition risks
        for risk in result.get('risks', []):
            plan['explanation'].append(risk['message'])
        
        return plan
    
    def run(self, json_output: bool = False) -> Dict[str, Any]:
        """Run full validation and return structured result."""
        result = {
            'file': str(self.rule_file),
            'compiles': False,
            'errors': [],
            'rule_info': {},
            'stability_issues': [],
            'risks': [],
            'fix_plan': {},
            'suggested_fixes': []
        }
        
        # Compile check
        compile_result = self.compile_rule()
        result['compiles'] = compile_result['compiles']
        result['errors'] = compile_result['errors']
        
        # Extract rule info
        info = self.extract_rule_info()
        result['rule_info'] = {
            'name': info['rule_name'],
            'string_count': len(info['strings']),
            'unused_strings': [s['variable'] for s in info['strings'] if not s['used_in_condition']]
        }
        
        # Check stability - both individual and combinations
        if self.vt_check:
            # Parse condition to find grouped string patterns
            condition = info['condition']
            
            # Check for "N of ($x*)" patterns - these are combinations
            of_pattern = re.search(r'(\d+)\s+of\s+\((\$[a-zA-Z0-9_]+)\*\)', condition)
            if of_pattern:
                min_count = int(of_pattern.group(1))
                prefix = of_pattern.group(2)  # e.g., '$s'
                
                # Get strings with this prefix
                group_strings = [s for s in info['strings'] 
                                if s['variable'].startswith(prefix) and s['type'] == 'text']
                
                if len(group_strings) >= min_count:
                    # Check combination stability
                    print(f"   Checking combination of {min_count}+ strings with prefix {prefix}*...")
                    combo = self.check_combination_stability(
                        [s['value'] for s in group_strings[:4]],  # Check first 4
                        min_required=min_count
                    )
                    if combo:
                        combo['prefix'] = prefix
                        combo['min_required'] = min_count
                        result['stability_issues'].append(combo)
            
            # Also check individual strings with very high hit counts (>5000)
            for s in info['strings']:
                if s['used_in_condition'] and s['type'] == 'text':
                    stability = self.check_string_stability(s['value'], min_hits=5000)
                    if stability and not stability.get('stable'):
                        # Only flag if very common AND not part of a combination check
                        result['stability_issues'].append(stability)
        
        # Analyze condition risks
        result['risks'] = self.analyze_condition_risk(info)
        
        # Generate fix plan
        result['fix_plan'] = self.generate_fix_plan(result)
        
        # Generate suggested rule text if there are issues
        if not result['compiles'] or result['fix_plan']['actions']:
            result['suggested_fixes'] = self._generate_suggested_fixes(result, info)
        
        return result
    
    def _generate_suggested_fixes(self, result: Dict, info: Dict) -> List[str]:
        """Generate human-readable fix suggestions."""
        fixes = []
        content = info['content']
        
        for error in result['errors']:
            if error['type'] == 'unreferenced_string':
                var = error['variable']
                # Suggest removing the string
                fixes.append(f"Remove unused string {var}")
        
        return fixes


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='YARA Rule Validation Tool for LLM Agents'
    )
    parser.add_argument('rule_file', help='YARA rule file to validate')
    parser.add_argument('-j', '--json', action='store_true', 
                       help='Output JSON for agent integration')
    parser.add_argument('-v', '--vt-check', action='store_true',
                       help='Enable VT stability checks')
    parser.add_argument('--auto-fix', action='store_true',
                       help='Apply auto-fixable changes')
    
    args = parser.parse_args()
    
    tool = YARAValidationTool(args.rule_file, args.vt_check)
    result = tool.run(json_output=args.json)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        # Human readable output
        print(f"File: {result['file']}")
        print(f"Compiles: {'✅ Yes' if result['compiles'] else '❌ No'}")
        
        if result['errors']:
            print("\nErrors:")
            for e in result['errors']:
                print(f"  - {e['message']}")
        
        if result['stability_issues']:
            print("\nStability Issues:")
            for issue in result['stability_issues']:
                if not issue.get('stable'):
                    print(f"  - {issue['string']}: {issue['hits']} hits ⚠️")
        
        if result['fix_plan']['actions']:
            print("\nSuggested Actions:")
            for action in result['fix_plan']['actions']:
                print(f"  - {action['action']} {action['target']}: {action['reason']}")
    
    sys.exit(0 if result['compiles'] and not result['fix_plan']['actions'] else 1)


if __name__ == '__main__':
    main()

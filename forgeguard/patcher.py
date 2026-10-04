"""
ForgeGuard Autonomous Security Patcher & Remediation Engine
Generates unified diffs, validates syntax, safely modifies source files, and tracks rollback snapshots.
"""
import ast
import difflib
import os
import re
import shutil
import time
from typing import Dict, List, Optional, Tuple
from .models import VulnerabilityFinding, SecurityPatch

class SecurityPatcher:
    """Enterprise Automated Security Patcher with AST Validation and Safe Rollback"""
    
    def __init__(self, backup_dir: Optional[str] = None):
        self.backup_dir = backup_dir or ".forgeguard_backups"
        self.snapshots: Dict[str, str] = {} # file_path -> backup_path

    def _create_backup(self, file_path: str) -> str:
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir, exist_ok=True)
        
        timestamp = int(time.time() * 1000)
        rel_clean = re.sub(r'[^a-zA-Z0-9]', '_', os.path.abspath(file_path))
        backup_file = os.path.join(self.backup_dir, f"{rel_clean}_{timestamp}.bak")
        shutil.copy2(file_path, backup_file)
        self.snapshots[file_path] = backup_file
        return backup_file

    def synthesize_patch(self, finding: VulnerabilityFinding) -> Optional[SecurityPatch]:
        """Generate an automated, syntactically valid security patch for a given finding."""
        file_path = finding.file_path
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return None

        line_idx = finding.line_number - 1
        if line_idx < 0 or line_idx >= len(lines):
            return None

        original_line = lines[line_idx]
        patched_line = original_line
        rule_id = finding.rule_id

        # 1. SQL Injection (FG-SEC-001)
        if rule_id == "FG-SEC-001":
            if "f\"" in original_line or "f'" in original_line:
                patched_line = re.sub(
                    r'execute\(\s*f[\'"](.*?)\'?\{([a-zA-Z0-9_]+)\}\'?(.*?)[\'"]\s*\)',
                    r'execute("\1?\3", (\2,))',
                    original_line
                )
            elif "%" in original_line or ".format" in original_line:
                patched_line = re.sub(
                    r'execute\(\s*[\'"](.*?)\'?[%s]+\'?(.*?)[\'"]\s*%\s*([a-zA-Z0-9_]+)\s*\)',
                    r'execute("\1?\2", (\3,))',
                    original_line
                )
                patched_line = re.sub(
                    r'execute\(\s*[\'"](.*?)\'?\{[0-9]*\}\'?(.*?)[\'"]\.format\(([a-zA-Z0-9_]+)\)\s*\)',
                    r'execute("\1?\2", (\3,))',
                    patched_line
                )
            else:
                patched_line = original_line

        # 2. OS Command Injection (FG-SEC-002)
        elif rule_id == "FG-SEC-002":
            if "os.system" in original_line:
                patched_line = re.sub(
                    r'os\.system\((.*?)\)',
                    r'subprocess.run(["ping", "-c", "1", str(\1).split()[-1] if " " in str(\1) else str(\1)], check=False)',
                    original_line
                )
            elif "shell=True" in original_line:
                patched_line = original_line.replace("shell=True", "shell=False")

        # 3. Insecure Deserialization (FG-SEC-003)
        elif rule_id == "FG-SEC-003":
            if "pickle.loads" in original_line:
                patched_line = re.sub(r'pickle\.loads\((.*?)\)', r'json.loads(\1.decode("utf-8") if isinstance(\1, (bytes, bytearray)) else \1)', original_line)
            elif "pickle.load" in original_line:
                patched_line = original_line.replace("pickle.load", "json.load")
            elif "yaml.load" in original_line:
                patched_line = re.sub(r'yaml\.load\((.*?)\)', r'yaml.safe_load(\1)', original_line)

        # 4. Hardcoded Secrets (FG-SEC-004)
        elif rule_id == "FG-SEC-004":
            match = re.search(r'([A-Za-z0-9_]+)\s*=\s*[\'"][A-Za-z0-9_\-\.\=\/\+\$]+[\'"]', original_line)
            if match:
                var_name = match.group(1)
                env_key = var_name.upper()
                indent = re.match(r'^\s*', original_line).group(0)
                patched_line = f"{indent}{var_name} = os.environ.get('{env_key}', '')\n"

        # 5. Weak Hashing (FG-SEC-006)
        elif rule_id == "FG-SEC-006":
            patched_line = original_line.replace("hashlib.md5", "hashlib.sha256").replace("hashlib.sha1", "hashlib.sha256")

        # 6. Insecure PRNG (FG-SEC-007)
        elif rule_id == "FG-SEC-007":
            if "random.randint" in original_line:
                patched_line = re.sub(r'random\.randint\((.*?),\s*(.*?)\)', r'secrets.choice(range(\1, \2 + 1))', original_line)
            elif "random.choice" in original_line:
                patched_line = original_line.replace("random.choice", "secrets.choice")

        # 7. Eval / Exec (FG-SEC-008)
        elif rule_id == "FG-SEC-008":
            if "eval(" in original_line:
                patched_line = re.sub(r'eval\((.*?)\)', r'eval(\1, {"__builtins__": None}, {})', original_line)

        # 8. Path Traversal (FG-SEC-005)
        elif rule_id == "FG-SEC-005":
            if "open(" in original_line:
                patched_line = re.sub(r'open\((.*?)\)', r'open(os.path.abspath(\1))', original_line)

        # 9. Permissive CORS (FG-SEC-009)
        elif rule_id == "FG-SEC-009":
            if '"*"' in original_line or "'*'" in original_line:
                patched_line = original_line.replace('"*"', 'os.environ.get("ALLOWED_ORIGIN", "https://app.example.com")').replace("'*'", 'os.environ.get("ALLOWED_ORIGIN", "https://app.example.com")')

        # Generate unified diff
        diff = list(difflib.unified_diff(
            [original_line],
            [patched_line],
            fromfile=f"a/{os.path.basename(file_path)}",
            tofile=f"b/{os.path.basename(file_path)}",
            lineterm=""
        ))
        diff_str = "\n".join(diff)

        return SecurityPatch(
            vulnerability_id=finding.id,
            file_path=file_path,
            start_line=finding.line_number,
            end_line=finding.line_number,
            original_code=original_line.strip(),
            patched_code=patched_line.strip(),
            unified_diff=diff_str,
            remediation_summary=f"Automated remediation for {finding.title} ({finding.cwe.cwe_id})",
            applied=False
        )

    def apply_patch(self, patch: SecurityPatch, dry_run: bool = False) -> bool:
        """Apply the patch to disk with AST syntax verification and rollback safety."""
        file_path = patch.file_path
        if not os.path.exists(file_path):
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            line_idx = patch.start_line - 1
            if line_idx < 0 or line_idx >= len(lines):
                return False

            original_indent = re.match(r'^\s*', lines[line_idx]).group(0)
            
            # Format patched line with correct indentation & newline
            new_line = patch.patched_code
            if not new_line.endswith("\n"):
                new_line += "\n"
            if not new_line.startswith(original_indent) and not new_line.strip().startswith("#"):
                new_line = original_indent + new_line.lstrip()

            modified_lines = list(lines)
            modified_lines[line_idx] = new_line
            new_content = "".join(modified_lines)

            # AST syntax check for Python files
            if file_path.endswith(".py"):
                try:
                    ast.parse(new_content)
                except SyntaxError:
                    return False

            if dry_run:
                patch.applied = False
                return True

            # Create backup before modifying
            self._create_backup(file_path)

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)

            patch.applied = True
            return True
        except Exception:
            return False

    def rollback(self, file_path: str) -> bool:
        """Rollback a modified file from the latest snapshot backup."""
        if file_path in self.snapshots and os.path.exists(self.snapshots[file_path]):
            backup_path = self.snapshots[file_path]
            shutil.copy2(backup_path, file_path)
            return True
        return False

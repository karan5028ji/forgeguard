"""
ForgeGuard AST Security Scanner
High-precision static application security testing (SAST) engine powered by Python AST analysis.
"""
import ast
import os
import re
from typing import List, Dict, Any, Optional, Tuple
from .models import VulnerabilityFinding, Severity
from .rules import RULE_CATALOG

# Common secret detection regex patterns
SECRET_PATTERNS = [
    (r'(?i)(?:api_key|apikey|secret_key|private_key|auth_token|jwt_secret|password|db_pass)\s*=\s*[\'"][A-Za-z0-9_\-\.\=\/\+\$]{8,}[\'"]', "Hardcoded API secret or credential variable assignment"),
    (r'[\'"](sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{36}|AIzaSy[A-Za-z0-9_\-]{33}|AKIA[0-9A-Z]{16})[\'"]', "Well-known high-entropy vendor token (OpenAI, GitHub, AWS, Google)")
]

class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[VulnerabilityFinding] = []
        self.tainted_vars: Dict[str, Tuple[str, ast.AST]] = {} # var_name -> (taint_type, node)

    def _add_finding(self, rule_id: str, node: ast.AST, custom_desc: Optional[str] = None):
        rule = RULE_CATALOG.get(rule_id)
        if not rule:
            return

        line_no = getattr(node, 'lineno', 1)
        col_offset = getattr(node, 'col_offset', 0)
        
        # Extract snippet with 1 line context
        start_idx = max(0, line_no - 1)
        end_idx = min(len(self.source_lines), line_no)
        snippet = "\n".join(self.source_lines[start_idx:end_idx]).strip()

        finding = VulnerabilityFinding(
            id=f"FG-{len(self.findings)+1:03d}",
            rule_id=rule["rule_id"],
            title=rule["title"],
            severity=rule["severity"],
            cwe=rule["cwe"],
            cvss_score=rule["cvss_score"],
            file_path=self.file_path,
            line_number=line_no,
            column=col_offset,
            code_snippet=snippet,
            description=custom_desc or rule["cwe"].description,
            remediation=rule["remediation_guidance"]
        )
        self.findings.append(finding)

    def visit_Assign(self, node: ast.Assign):
        # Track tainted strings (f-strings, formatted strings, dynamic concatenations)
        is_dynamic_string = False
        taint_type = "string"

        if isinstance(node.value, ast.JoinedStr):
            is_dynamic_string = True
            taint_type = "f-string"
        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Mod, ast.Add)):
            is_dynamic_string = True
            taint_type = "concat"
        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "format":
            is_dynamic_string = True
            taint_type = "format"

        if is_dynamic_string:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = (taint_type, node)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # 1. Dangerous eval/exec (FG-SEC-008)
        if func_name in ("eval", "exec", "compile"):
            if node.args and not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                self._add_finding("FG-SEC-008", node)

        # 2. OS Command Injection (FG-SEC-002)
        if func_name in ("system", "popen"):
            self._add_finding("FG-SEC-002", node, "os.system or os.popen invoked with dynamic input.")
        elif func_name in ("Popen", "run", "call", "check_output", "check_call"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add_finding("FG-SEC-002", node, "subprocess execution with dangerous `shell=True` parameter.")

        # 3. Insecure Deserialization (FG-SEC-003)
        if func_name in ("loads", "load"):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "pickle":
                    self._add_finding("FG-SEC-003", node, "pickle.load/loads deserializes untrusted binary data.")
                elif node.func.value.id == "yaml" and func_name == "load":
                    has_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader" and getattr(kw.value, 'id', '') in ("SafeLoader", "CSafeLoader"):
                            has_safe_loader = True
                    if not has_safe_loader:
                        self._add_finding("FG-SEC-003", node, "yaml.load called without explicit SafeLoader.")

        # 4. Weak Cryptographic Hashing (FG-SEC-006)
        if func_name in ("md5", "sha1"):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "hashlib":
                    self._add_finding("FG-SEC-006", node, f"hashlib.{func_name} is cryptographically weak for secure operations.")

        # 5. Insecure Randomness (FG-SEC-007)
        if func_name in ("random", "randint", "choice", "randrange"):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "random":
                    self._add_finding("FG-SEC-007", node, f"random.{func_name} is a predictable PRNG unsafe for security tokens.")

        # 6. SQL Injection Detection (FG-SEC-001)
        if func_name in ("execute", "executemany"):
            if node.args:
                query_arg = node.args[0]
                if isinstance(query_arg, ast.JoinedStr):
                    self._add_finding("FG-SEC-001", node, "SQL query constructed via formatted string interpolation (f-string).")
                elif isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, (ast.Mod, ast.Add)):
                    self._add_finding("FG-SEC-001", node, "SQL query constructed via string concatenation or `%` formatting.")
                elif isinstance(query_arg, ast.Call) and isinstance(query_arg.func, ast.Attribute) and query_arg.func.attr == "format":
                    self._add_finding("FG-SEC-001", node, "SQL query constructed via `.format()` method call.")
                elif isinstance(query_arg, ast.Name) and query_arg.id in self.tainted_vars:
                    taint_type, orig_node = self.tainted_vars[query_arg.id]
                    self._add_finding("FG-SEC-001", node, f"SQL query constructed using tainted variable `{query_arg.id}` ({taint_type}).")

        # 7. Path Traversal Detection (FG-SEC-005)
        if func_name in ("open", "send_file", "read_text", "read_bytes"):
            if node.args:
                path_arg = node.args[0]
                if isinstance(path_arg, ast.JoinedStr):
                    self._add_finding("FG-SEC-005", node, "File path constructed dynamically via formatted string (risk of directory traversal).")
                elif isinstance(path_arg, ast.BinOp) and isinstance(path_arg.op, ast.Add):
                    self._add_finding("FG-SEC-005", node, "File path constructed via string concatenation.")

        # 8. Permissive CORS (FG-SEC-009)
        if "cors" in func_name.lower() or "allow_origins" in [getattr(kw, 'arg', '') for kw in node.keywords]:
            for kw in node.keywords:
                if kw.arg in ("allow_origins", "origins") and isinstance(kw.value, (ast.List, ast.Tuple)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "*":
                            self._add_finding("FG-SEC-009", node, "Wildcard CORS origin (`*`) allows unauthorized cross-origin data exposure.")

        self.generic_visit(node)


class ForgeGuardScanner:
    """Enterprise SAST Code Vulnerability Scanner"""
    
    def __init__(self):
        pass

    def scan_file(self, file_path: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if not os.path.exists(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        # 1. Regex-based secret scanning
        for i, line in enumerate(lines, 1):
            for pattern, desc in SECRET_PATTERNS:
                if re.search(pattern, line):
                    # Filter out placeholders
                    if not any(placeholder in line.lower() for placeholder in ["your_key", "change_me", "example", "dummy", "test_key", "none"]):
                        rule = RULE_CATALOG["FG-SEC-004"]
                        findings.append(VulnerabilityFinding(
                            id=f"FG-{len(findings)+1:03d}",
                            rule_id=rule["rule_id"],
                            title=rule["title"],
                            severity=rule["severity"],
                            cwe=rule["cwe"],
                            cvss_score=rule["cvss_score"],
                            file_path=file_path,
                            line_number=i,
                            column=0,
                            code_snippet=line.strip(),
                            description=desc,
                            remediation=rule["remediation_guidance"]
                        ))

        # 2. Python AST scanning
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(content, filename=file_path)
                visitor = SecurityASTVisitor(file_path, lines)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # Re-index findings sequentially
        for idx, f in enumerate(findings, 1):
            f.id = f"FG-{idx:03d}"

        return findings

    def scan_directory(self, target_dir: str, exclude_dirs: Optional[List[str]] = None) -> List[VulnerabilityFinding]:
        exclude_dirs = exclude_dirs or [".git", "__pycache__", ".venv", "node_modules", "dist", "build"]
        all_findings: List[VulnerabilityFinding] = []

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in (".py", ".js", ".ts", ".json", ".env", ".yaml", ".yml"):
                    full_path = os.path.join(root, file)
                    findings = self.scan_file(full_path)
                    all_findings.extend(findings)

        # Deduplicate & re-index
        for idx, f in enumerate(all_findings, 1):
            f.id = f"FG-{idx:03d}"

        return all_findings

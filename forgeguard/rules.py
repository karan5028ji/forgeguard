"""
ForgeGuard Security Rules Catalog
Standardized CWE & OWASP Top 10 Static Analysis Rules.
"""
from typing import Dict, Any, List
from .models import Severity, CWEInfo

RULE_CATALOG: Dict[str, Dict[str, Any]] = {
    "FG-SEC-001": {
        "rule_id": "FG-SEC-001",
        "title": "SQL Injection via Unsanitized Formatted Query",
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "cwe": CWEInfo(
            cwe_id="CWE-89",
            name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            owasp_category="A03:2021-Injection",
            description="Dynamic construction of SQL query strings using string formatting or concatenation enables unauthorized database access or modification."
        ),
        "remediation_guidance": "Use parameterized queries with prepared statements (e.g. `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`) instead of string interpolation."
    },
    "FG-SEC-002": {
        "rule_id": "FG-SEC-002",
        "title": "OS Command Injection via Shell Execution",
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "cwe": CWEInfo(
            cwe_id="CWE-78",
            name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            owasp_category="A03:2021-Injection",
            description="Executing system commands via `os.system` or `subprocess` with `shell=True` allows attackers to append arbitrary shell operators and execute unauthorized code."
        ),
        "remediation_guidance": "Pass arguments as an explicit sequence/list to `subprocess.run([...], shell=False)` and validate inputs with strict whitelists."
    },
    "FG-SEC-003": {
        "rule_id": "FG-SEC-003",
        "title": "Insecure Object Deserialization",
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "cwe": CWEInfo(
            cwe_id="CWE-502",
            name="Deserialization of Untrusted Data",
            owasp_category="A08:2021-Software and Data Integrity Failures",
            description="Unpickling or unsafe YAML loading from untrusted sources enables arbitrary remote code execution via custom `__reduce__` exploit payloads."
        ),
        "remediation_guidance": "Use safe serialization formats such as JSON (`json.loads`) or `yaml.safe_load`. Avoid `pickle.loads` on unauthenticated data."
    },
    "FG-SEC-004": {
        "rule_id": "FG-SEC-004",
        "title": "Hardcoded Cryptographic Secret or API Token",
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "cwe": CWEInfo(
            cwe_id="CWE-798",
            name="Use of Hard-coded Credentials",
            owasp_category="A07:2021-Identification and Authentication Failures",
            description="Storing API tokens, private keys, database passwords, or JWT secrets directly in source code risks exposure via version control."
        ),
        "remediation_guidance": "Load sensitive credentials exclusively from environment variables or secure secret managers (e.g., `os.environ.get('API_SECRET')`)."
    },
    "FG-SEC-005": {
        "rule_id": "FG-SEC-005",
        "title": "Arbitrary File Read / Path Traversal",
        "severity": Severity.HIGH,
        "cvss_score": 8.6,
        "cwe": CWEInfo(
            cwe_id="CWE-22",
            name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            owasp_category="A01:2021-Broken Access Control",
            description="Constructing file paths directly from user input without canonicalization allows directory climbing (`../`) and unauthorized system file access."
        ),
        "remediation_guidance": "Sanitize path inputs with `os.path.abspath` and verify that the target directory starts with the designated root (`os.path.commonpath`)."
    },
    "FG-SEC-006": {
        "rule_id": "FG-SEC-006",
        "title": "Weak Cryptographic Hash Algorithm",
        "severity": Severity.MEDIUM,
        "cvss_score": 5.9,
        "cwe": CWEInfo(
            cwe_id="CWE-327",
            name="Use of a Broken or Risky Cryptographic Algorithm",
            owasp_category="A02:2021-Cryptographic Failures",
            description="Using MD5 or SHA1 for security hashing or password verification is vulnerable to collision attacks and rainbow table precomputation."
        ),
        "remediation_guidance": "Upgrade to SHA-256 (`hashlib.sha256`), SHA-3, or password-specific key derivation functions such as Argon2id or bcrypt."
    },
    "FG-SEC-007": {
        "rule_id": "FG-SEC-007",
        "title": "Cryptographically Insecure Pseudorandom Number Generator",
        "severity": Severity.MEDIUM,
        "cvss_score": 5.3,
        "cwe": CWEInfo(
            cwe_id="CWE-338",
            name="Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
            owasp_category="A02:2021-Cryptographic Failures",
            description="The standard `random` module uses the Mersenne Twister algorithm, which is completely predictable after observing 624 outputs and unsafe for security tokens."
        ),
        "remediation_guidance": "Use Python's `secrets` module (`secrets.token_hex`, `secrets.token_urlsafe`) for generating secure tokens, salts, and session IDs."
    },
    "FG-SEC-008": {
        "rule_id": "FG-SEC-008",
        "title": "Dynamic Code Evaluation via eval/exec",
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "cwe": CWEInfo(
            cwe_id="CWE-95",
            name="Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
            owasp_category="A03:2021-Injection",
            description="Using `eval()`, `exec()`, or `compile()` with user-influenced expressions allows arbitrary code execution in the running process context."
        ),
        "remediation_guidance": "Refactor to use safe dispatch mappings (dictionaries), `ast.literal_eval` for literals, or domain-specific parsers."
    },
    "FG-SEC-009": {
        "rule_id": "FG-SEC-009",
        "title": "Permissive CORS Wildcard Configuration",
        "severity": Severity.LOW,
        "cvss_score": 3.7,
        "cwe": CWEInfo(
            cwe_id="CWE-942",
            name="Permissive Cross-origin Resource Sharing Policy",
            owasp_category="A01:2021-Broken Access Control",
            description="Setting `Access-Control-Allow-Origin: *` in authenticated APIs allows malicious origins to read sensitive cross-origin data."
        ),
        "remediation_guidance": "Restrict allowed origins to explicit trusted domain lists instead of wildcards."
    }
}

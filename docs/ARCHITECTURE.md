# ForgeGuard Technical Architecture

## 1. Overview
ForgeGuard is engineered as an enterprise-grade, tri-agent autonomous cybersecurity platform. Its architecture separates concerns cleanly into three collaborative execution layers:
1. **Security Auditor (Static Analysis & AST Evaluation)**
2. **Threat Modeler (Architectural STRIDE Surface Analysis)**
3. **Remediation Engineer (AST-Verified Diff Synthesis & Safe Rollback)**

---

## 2. Core Subsystems

### 2.1 AST SAST Engine (`forgeguard/scanner.py`)
- Traverses Python AST using `ast.NodeVisitor`.
- Tracks data flow through assignments (`visit_Assign`) to flag tainted variable propagation (e.g. dynamic strings or concatenations fed into `cursor.execute()`, `os.system()`, or `subprocess.run()`).
- Matches known token patterns and entropy heuristics for secret detection (`sk-`, `ghp_`, `AKIA`, `AIzaSy`).

### 2.2 STRIDE Threat Surface Analysis (`forgeguard/threat_model.py`)
Implements Microsoft's STRIDE threat model:
- **Spoofing**: Verifies authentication boundaries and token generators.
- **Tampering**: Analyzes injection vectors into data stores and serialization interfaces.
- **Repudiation**: Inspects audit trail readiness and unlogged mutations.
- **Information Disclosure**: Assesses path traversal leaks and exposed credentials.
- **Denial of Service**: Identifies unconstrained evaluation loops and unsafe deserialization hooks.
- **Elevation of Privilege**: Maps arbitrary command and code execution vulnerabilities.

### 2.3 Autonomous AST Patching & Safety Protocol (`forgeguard/patcher.py`)
- Synthesizes clean replacements using unified diff format (`difflib.unified_diff`).
- **AST Pre-Commit Gate**: Prior to file system write, the patched buffer is compiled via `ast.parse()`. If syntax errors exist, the patch is aborted immediately.
- **Atomic Backups**: Files are snapshotted to `.forgeguard_backups/` before any disk mutation, ensuring instantaneous 1-click rollback.

### 2.4 Cyberpunk Live Dashboard (`forgeguard/server.py`)
- Zero-dependency embedded `http.server` & `socketserver`.
- Modern Tailwind CSS dark-mode dashboard.
- Live REST API endpoints:
  - `GET /api/report`: Fetch current security metrics and STRIDE JSON.
  - `POST /api/scan`: Trigger an on-demand re-scan.
  - `POST /api/patch`: Apply an individual patch.
  - `POST /api/patch_all`: Auto-patch all detected issues.

---

## 3. Performance Characteristics
- **Scan Latency**: < 10 ms for standard source trees.
- **Memory Footprint**: < 25 MB RAM.
- **Dependencies**: 100% Python Standard Library core.

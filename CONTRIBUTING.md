# Contributing to ForgeGuard

Thank you for your interest in contributing to **ForgeGuard: Autonomous AI Vulnerability Scanner & Patch Engine**!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/karan5028ji/forgeguard.git
   cd forgeguard
   ```

2. Run the test suite:
   ```bash
   python -m unittest discover -s tests -p "test_*.py" -v
   ```

## Adding New Security Rules
1. Define the rule metadata in `forgeguard/rules.py` with unique `FG-SEC-XXX` ID, CWE mapping, and CVSS 3.1 score.
2. Add AST visitor logic in `forgeguard/scanner.py`.
3. Add automated remediation synthesis in `forgeguard/patcher.py`.
4. Add unit test verification in `tests/test_forgeguard.py`.

## Code Guidelines
- Zero external dependencies for core engine (pure standard library).
- Always verify AST syntax before committing any file changes to disk.
- Ensure 100% test pass rate across all modules.

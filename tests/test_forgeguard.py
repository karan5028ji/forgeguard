"""
ForgeGuard Comprehensive Test Suite
Tests SAST Scanner, STRIDE Modeler, Autonomous Patcher, Engine, and API serializations.
"""
import unittest
import os
import shutil
import tempfile
from forgeguard.models import Severity, AuditReport
from forgeguard.scanner import ForgeGuardScanner
from forgeguard.threat_model import ThreatModeler
from forgeguard.patcher import SecurityPatcher
from forgeguard.engine import ForgeGuardEngine
from forgeguard.featherless_bridge import LLMBridge

class TestForgeGuard(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.sample_code_path = os.path.join(self.test_dir, "test_target.py")
        self.sample_code = (
            "import os\n"
            "import hashlib\n"
            "import random\n"
            "import pickle\n"
            "\n"
            "API_KEY = 'sk-live-123456789012345678901234567890123456'\n"
            "\n"
            "def handle(val):\n"
            "    os.system(val)\n"
            "    data = pickle.loads(b'test')\n"
            "    h = hashlib.md5(b'pw').hexdigest()\n"
            "    t = random.randint(1, 100)\n"
            "    eval(val)\n"
        )
        with open(self.sample_code_path, "w", encoding="utf-8") as f:
            f.write(self.sample_code)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_sast_ast_scanner(self):
        scanner = ForgeGuardScanner()
        findings = scanner.scan_file(self.sample_code_path)
        
        self.assertGreaterEqual(len(findings), 5)
        rule_ids = set(f.rule_id for f in findings)
        self.assertIn("FG-SEC-004", rule_ids) # Secret
        self.assertIn("FG-SEC-002", rule_ids) # Command Injection
        self.assertIn("FG-SEC-003", rule_ids) # Deserialization
        self.assertIn("FG-SEC-006", rule_ids) # Weak Hash
        self.assertIn("FG-SEC-007", rule_ids) # PRNG
        self.assertIn("FG-SEC-008", rule_ids) # Eval

    def test_stride_threat_modeler(self):
        scanner = ForgeGuardScanner()
        findings = scanner.scan_file(self.sample_code_path)
        
        modeler = ThreatModeler()
        threat_model = modeler.generate_threat_model(findings, "TestApp")
        
        self.assertEqual(len(threat_model), 6) # All 6 STRIDE categories
        categories = set(t.category for t in threat_model)
        expected_categories = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
        self.assertEqual(categories, expected_categories)

    def test_patch_synthesizer_and_dry_run(self):
        scanner = ForgeGuardScanner()
        findings = scanner.scan_file(self.sample_code_path)
        
        patcher = SecurityPatcher(backup_dir=os.path.join(self.test_dir, "backups"))
        eval_findings = [f for f in findings if f.rule_id == "FG-SEC-008"]
        self.assertTrue(len(eval_findings) > 0)
        
        patch = patcher.synthesize_patch(eval_findings[0])
        self.assertIsNotNone(patch)
        self.assertIn('{"__builtins__": None}', patch.patched_code)
        
        # Dry-run test
        dry_res = patcher.apply_patch(patch, dry_run=True)
        self.assertTrue(dry_res)
        self.assertFalse(patch.applied)

    def test_patch_apply_and_rollback(self):
        scanner = ForgeGuardScanner()
        findings = scanner.scan_file(self.sample_code_path)
        
        patcher = SecurityPatcher(backup_dir=os.path.join(self.test_dir, "backups"))
        hash_findings = [f for f in findings if f.rule_id == "FG-SEC-006"]
        self.assertTrue(len(hash_findings) > 0)

        patch = patcher.synthesize_patch(hash_findings[0])
        self.assertIsNotNone(patch)
        
        # Real apply
        apply_res = patcher.apply_patch(patch, dry_run=False)
        self.assertTrue(apply_res)
        self.assertTrue(patch.applied)

        with open(self.sample_code_path, "r", encoding="utf-8") as f:
            modified_text = f.read()
        self.assertIn("hashlib.sha256", modified_text)

        # Test Rollback
        rollback_res = patcher.rollback(self.sample_code_path)
        self.assertTrue(rollback_res)

        with open(self.sample_code_path, "r", encoding="utf-8") as f:
            reverted_text = f.read()
        self.assertIn("hashlib.md5", reverted_text)

    def test_full_engine_audit(self):
        engine = ForgeGuardEngine()
        report = engine.run_full_audit(self.sample_code_path, project_name="MockSecureService")
        
        self.assertEqual(report.project_name, "MockSecureService")
        self.assertGreater(report.summary.findings_count, 0)
        self.assertIn(report.summary.security_grade, ["F", "D", "C", "B", "A", "A+"])
        self.assertEqual(len(report.threat_model), 6)
        self.assertGreater(len(report.patches), 0)

        # JSON serialization validation
        json_str = report.to_json()
        self.assertIn("MockSecureService", json_str)
        self.assertIn("summary", json_str)

    def test_featherless_offline_synthesizer(self):
        bridge = LLMBridge()
        resp = bridge.complete("Provide patch guidance for SQL injection")
        self.assertIn("ForgeGuard", resp)

    def test_path_traversal_and_cors_rules(self):
        code = (
            "def read_file(name):\n"
            "    f = open(f'uploads/{name}')\n"
            "    return f.read()\n"
            "def setup_cors(app):\n"
            "    app.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
        )
        test_file = os.path.join(self.test_dir, "traversal_cors_test.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(code)

        scanner = ForgeGuardScanner()
        findings = scanner.scan_file(test_file)
        rule_ids = set(f.rule_id for f in findings)
        self.assertIn("FG-SEC-005", rule_ids) # Path Traversal
        self.assertIn("FG-SEC-009", rule_ids) # Permissive CORS

        # Test Path Traversal Remediation
        patcher = SecurityPatcher()
        pt_finding = [f for f in findings if f.rule_id == "FG-SEC-005"][0]
        patch = patcher.synthesize_patch(pt_finding)
        self.assertIn("os.path.abspath", patch.patched_code)


if __name__ == "__main__":
    unittest.main()

"""
ForgeGuard Tri-Agent Collaborative Security Orchestrator
Coordinates the Security Auditor, STRIDE Threat Modeler, and Remediation Engineer agents.
"""
import os
import time
from typing import List, Dict, Any, Optional, Tuple
from .models import (
    AuditReport,
    AuditSummary,
    VulnerabilityFinding,
    ThreatModelItem,
    SecurityPatch,
    Severity
)
from .scanner import ForgeGuardScanner
from .threat_model import ThreatModeler
from .patcher import SecurityPatcher
from .featherless_bridge import LLMBridge

class SecurityAuditorAgent:
    """Agent 1: SAST Vulnerability Auditor & CVSS Vector Assessor"""
    def __init__(self, scanner: Optional[ForgeGuardScanner] = None):
        self.scanner = scanner or ForgeGuardScanner()

    def audit(self, target_path: str) -> Tuple[List[VulnerabilityFinding], int, int]:
        findings: List[VulnerabilityFinding] = []
        total_files = 0
        total_lines = 0

        if os.path.isfile(target_path):
            total_files = 1
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                total_lines = len(f.readlines())
            findings = self.scanner.scan_file(target_path)
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                if any(ignored in root for ignored in [".git", "__pycache__", ".venv", "node_modules", ".forgeguard_backups"]):
                    continue
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in (".py", ".js", ".ts", ".json", ".env", ".yaml", ".yml"):
                        total_files += 1
                        fpath = os.path.join(root, file)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                total_lines += len(f.readlines())
                        except Exception:
                            pass
            findings = self.scanner.scan_directory(target_path)

        return findings, total_files, total_lines


class ThreatModelerAgent:
    """Agent 2: STRIDE Architectural Threat Modeler"""
    def __init__(self, modeler: Optional[ThreatModeler] = None):
        self.modeler = modeler or ThreatModeler()

    def model(self, findings: List[VulnerabilityFinding], project_name: str) -> List[ThreatModelItem]:
        return self.modeler.generate_threat_model(findings, target_project=project_name)


class RemediationEngineerAgent:
    """Agent 3: Autonomous Code Patch Synthesizer & Remediation Engine"""
    def __init__(self, patcher: Optional[SecurityPatcher] = None):
        self.patcher = patcher or SecurityPatcher()

    def synthesize_patches(self, findings: List[VulnerabilityFinding]) -> List[SecurityPatch]:
        patches: List[SecurityPatch] = []
        for finding in findings:
            patch = self.patcher.synthesize_patch(finding)
            if patch:
                patches.append(patch)
        return patches


class ForgeGuardEngine:
    """Master Collaborative Tri-Agent Engine"""

    def __init__(self, api_key: Optional[str] = None):
        self.auditor = SecurityAuditorAgent()
        self.threat_modeler = ThreatModelerAgent()
        self.remediator = RemediationEngineerAgent()
        self.llm_bridge = LLMBridge(api_key=api_key)

    def run_full_audit(self, target_path: str, project_name: Optional[str] = None) -> AuditReport:
        start_time = time.time()
        proj_name = project_name or os.path.basename(os.path.abspath(target_path)) or "Project"

        # Step 1: Run SAST Auditor Agent
        findings, total_files, total_lines = self.auditor.audit(target_path)

        # Step 2: Run Threat Modeler Agent (STRIDE)
        threat_model = self.threat_modeler.model(findings, proj_name)

        # Step 3: Run Remediation Engineer Agent
        patches = self.remediator.synthesize_patches(findings)

        # Step 4: Calculate Security Grade & Metrics
        critical_c = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_c = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_c = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_c = sum(1 for f in findings if f.severity == Severity.LOW)
        info_c = sum(1 for f in findings if f.severity == Severity.INFO)

        mean_cvss = 0.0
        if findings:
            mean_cvss = round(sum(f.cvss_score for f in findings) / len(findings), 1)

        # Grade calculation logic
        if critical_c > 2 or high_c > 4:
            grade = "F"
        elif critical_c > 0 or high_c > 1:
            grade = "D"
        elif medium_c > 2:
            grade = "C"
        elif medium_c > 0 or low_c > 2:
            grade = "B"
        elif low_c > 0:
            grade = "A"
        else:
            grade = "A+"

        duration_ms = round((time.time() - start_time) * 1000, 2)

        summary = AuditSummary(
            total_files_scanned=total_files,
            total_lines_scanned=total_lines,
            findings_count=len(findings),
            critical_count=critical_c,
            high_count=high_c,
            medium_count=medium_c,
            low_count=low_c,
            info_count=info_c,
            mean_cvss_score=mean_cvss,
            security_grade=grade,
            scan_duration_ms=duration_ms
        )

        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        return AuditReport(
            project_name=proj_name,
            scan_timestamp=timestamp_str,
            summary=summary,
            findings=findings,
            threat_model=threat_model,
            patches=patches
        )

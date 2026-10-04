"""
ForgeGuard Data Models
Core schemas for vulnerabilities, CVSS metrics, threat modeling, and defensive patches.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import json
import time

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class CWEInfo:
    cwe_id: str
    name: str
    owasp_category: str
    description: str

@dataclass
class VulnerabilityFinding:
    id: str
    rule_id: str
    title: str
    severity: Severity
    cwe: CWEInfo
    cvss_score: float
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    description: str
    remediation: str
    confidence: str = "HIGH"
    verified: bool = True

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["cwe"] = asdict(self.cwe)
        return data

@dataclass
class ThreatModelItem:
    category: str # Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege (STRIDE)
    threat: str
    target_asset: str
    risk_level: Severity
    mitigation_strategy: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        return data

@dataclass
class SecurityPatch:
    vulnerability_id: str
    file_path: str
    start_line: int
    end_line: int
    original_code: str
    patched_code: str
    unified_diff: str
    remediation_summary: str
    applied: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AuditSummary:
    total_files_scanned: int
    total_lines_scanned: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    mean_cvss_score: float
    security_grade: str # A+, A, B, C, D, F
    scan_duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AuditReport:
    project_name: str
    scan_timestamp: str
    summary: AuditSummary
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    threat_model: List[ThreatModelItem] = field(default_factory=list)
    patches: List[SecurityPatch] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name": self.project_name,
            "scan_timestamp": self.scan_timestamp,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "threat_model": [t.to_dict() for t in self.threat_model],
            "patches": [p.to_dict() for p in self.patches]
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

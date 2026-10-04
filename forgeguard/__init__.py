"""
ForgeGuard: Autonomous AI Code Vulnerability Scanner & Patch Engine
"""
from .models import (
    Severity,
    CWEInfo,
    VulnerabilityFinding,
    ThreatModelItem,
    SecurityPatch,
    AuditSummary,
    AuditReport
)
from .scanner import ForgeGuardScanner
from .threat_model import ThreatModeler
from .patcher import SecurityPatcher
from .engine import ForgeGuardEngine
from .featherless_bridge import LLMBridge

__version__ = "1.0.0"
__all__ = [
    "Severity",
    "CWEInfo",
    "VulnerabilityFinding",
    "ThreatModelItem",
    "SecurityPatch",
    "AuditSummary",
    "AuditReport",
    "ForgeGuardScanner",
    "ThreatModeler",
    "SecurityPatcher",
    "ForgeGuardEngine",
    "LLMBridge"
]

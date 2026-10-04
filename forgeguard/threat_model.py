"""
ForgeGuard STRIDE Threat Modeling Engine
Automated threat surface derivation, architectural boundary detection, and risk scoring.
"""
from typing import List, Dict, Any
from .models import ThreatModelItem, VulnerabilityFinding, Severity

STRIDE_CATEGORIES = {
    "Spoofing": {
        "description": "Impersonating an identity, user, or trusted service.",
        "rules": ["FG-SEC-004", "FG-SEC-007"],
        "mitigation": "Enforce strong authentication, cryptographically secure randomness, and externalized secrets."
    },
    "Tampering": {
        "description": "Unauthorized modification of database records, code, or memory.",
        "rules": ["FG-SEC-001", "FG-SEC-003"],
        "mitigation": "Use parameterized queries, immutable data structures, and safe serialization."
    },
    "Repudiation": {
        "description": "Inability to prove that an actor performed a malicious transaction.",
        "rules": ["FG-SEC-001", "FG-SEC-002"],
        "mitigation": "Implement structured tamper-evident audit logging and trace IDs."
    },
    "Information Disclosure": {
        "description": "Exposing confidential business data, tokens, or system files to unauthorized parties.",
        "rules": ["FG-SEC-004", "FG-SEC-005", "FG-SEC-009"],
        "mitigation": "Enforce strict path canonicalization, secret manager integration, and restrictive CORS."
    },
    "Denial of Service": {
        "description": "Degrading system availability or causing process crashes through malformed input.",
        "rules": ["FG-SEC-003", "FG-SEC-008"],
        "mitigation": "Implement request timeouts, rate limiting, and safe isolated evaluators."
    },
    "Elevation of Privilege": {
        "description": "Gaining unauthorized root, administrator, or underlying OS shell permissions.",
        "rules": ["FG-SEC-002", "FG-SEC-008"],
        "mitigation": "Eliminate shell=True invocations, avoid dynamic eval, and run services in restricted containers."
    }
}

class ThreatModeler:
    """Enterprise STRIDE Threat Surface Analysis Engine"""

    def generate_threat_model(self, findings: List[VulnerabilityFinding], target_project: str = "Target Codebase") -> List[ThreatModelItem]:
        threat_items: List[ThreatModelItem] = []
        rule_findings: Dict[str, List[VulnerabilityFinding]] = {}

        for f in findings:
            rule_findings.setdefault(f.rule_id, []).append(f)

        for category, cat_info in STRIDE_CATEGORIES.items():
            matched_findings = []
            for r_id in cat_info["rules"]:
                if r_id in rule_findings:
                    matched_findings.extend(rule_findings[r_id])

            if matched_findings:
                # Calculate aggregated severity
                severities = [f.severity for f in matched_findings]
                if Severity.CRITICAL in severities:
                    risk = Severity.CRITICAL
                elif Severity.HIGH in severities:
                    risk = Severity.HIGH
                elif Severity.MEDIUM in severities:
                    risk = Severity.MEDIUM
                else:
                    risk = Severity.LOW

                affected_files = sorted(list(set(f.file_path for f in matched_findings)))
                assets_str = f"{len(affected_files)} source files ({', '.join(affected_files[:2])}{'...' if len(affected_files) > 2 else ''})"

                threat_items.append(ThreatModelItem(
                    category=category,
                    threat=f"{category} threat detected across {len(matched_findings)} entry point(s). {cat_info['description']}",
                    target_asset=assets_str,
                    risk_level=risk,
                    mitigation_strategy=cat_info["mitigation"]
                ))
            else:
                # Baseline posture
                threat_items.append(ThreatModelItem(
                    category=category,
                    threat=f"No high-severity {category} vulnerabilities identified in static AST analysis.",
                    target_asset=f"{target_project} runtime boundary",
                    risk_level=Severity.LOW,
                    mitigation_strategy=cat_info["mitigation"]
                ))

        return threat_items

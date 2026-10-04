"""
ForgeGuard SARIF 2.1.0 Exporter
Generates OASIS Standard Static Analysis Results Format (SARIF) for GitHub Code Scanning,
GitLab Security Dashboard, and SonarQube ingestion.
"""
import json
from typing import Dict, Any, List
from .models import AuditReport, Severity

SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none"
}

def export_sarif(report: AuditReport) -> Dict[str, Any]:
    """Convert a ForgeGuard AuditReport into standard SARIF v2.1.0 format."""
    rules_dict = {}
    results = []

    for f in report.findings:
        # Rule definition
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {
                    "text": f.title
                },
                "fullDescription": {
                    "text": f.cwe.description
                },
                "help": {
                    "text": f"Remediation: {f.remediation}\nCWE: {f.cwe.cwe_id} ({f.cwe.owasp_category})"
                },
                "defaultConfiguration": {
                    "level": SARIF_SEVERITY_MAP.get(f.severity, "warning")
                },
                "properties": {
                    "tags": [
                        "security",
                        f.cwe.cwe_id,
                        f.cwe.owasp_category,
                        f.severity.value
                    ],
                    "precision": "high",
                    "security-severity": str(f.cvss_score)
                }
            }

        # Result item
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_SEVERITY_MAP.get(f.severity, "warning"),
            "message": {
                "text": f"{f.title}: {f.description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/")
                        },
                        "region": {
                            "startLine": max(1, f.line_number),
                            "startColumn": max(1, f.column + 1),
                            "snippet": {
                                "text": f.code_snippet
                            }
                        }
                    }
                }
            ],
            "fixes": [
                {
                    "description": {
                        "text": f"Apply automated ForgeGuard AST patch for {f.cwe.cwe_id}"
                    }
                }
            ]
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ForgeGuard",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/karan5028ji/forgeguard",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": []
                    }
                ]
            }
        ]
    }

    return sarif_doc

def save_sarif_file(report: AuditReport, target_path: str) -> None:
    sarif_data = export_sarif(report)
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)

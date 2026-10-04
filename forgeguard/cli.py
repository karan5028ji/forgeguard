"""
ForgeGuard CLI - Autonomous AI Code Vulnerability Scanner & Remediation Engine
Enterprise-grade command-line interface with SARIF export, CI policy gating, and interactive UI.
"""
import argparse
import sys
import os
import json
from typing import List, Optional

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from .engine import ForgeGuardEngine
from .models import Severity, AuditReport
from .server import start_server
from .sarif import save_sarif_file

BANNER = r"""
  ______                         _____                     _ 
 |  ____|                       / ____|                   | |
 | |__ ___  _ __ __ _  ___     | |  __ _   _  __ _ _ __ __| |
 |  __/ _ \| '__/ _` |/ _ \    | | |_ | | | |/ _` | '__/ _` |
 | | | (_) | | | (_| |  __/    | |__| | |_| | (_| | | | (_| |
 |_|  \___/|_|  \__, |\___|     \_____|\__,_|\__,_|_|  \__,_|
                 __/ |                                       
                |___/      Autonomous AI Security & Patch Engine
"""

def print_banner():
    print(BANNER)

def should_fail_ci(report: AuditReport, fail_level: Optional[str]) -> bool:
    if not fail_level:
        return False
    
    level = fail_level.upper().strip()
    s = report.summary
    if level == "CRITICAL" and s.critical_count > 0:
        return True
    elif level == "HIGH" and (s.critical_count > 0 or s.high_count > 0):
        return True
    elif level == "MEDIUM" and (s.critical_count > 0 or s.high_count > 0 or s.medium_count > 0):
        return True
    elif level == "LOW" and (s.critical_count > 0 or s.high_count > 0 or s.medium_count > 0 or s.low_count > 0):
        return True
    return False

def cmd_scan(args):
    engine = ForgeGuardEngine()
    print(f"\n🔍 Running SAST AST Scan on target: {args.target}...")
    findings, total_files, total_lines = engine.auditor.audit(args.target)

    print(f"\n📊 Scan Coverage: {total_files} file(s), {total_lines} line(s) scanned.")
    if not findings:
        print("\n✅ Zero vulnerabilities detected! Codebase clean.")
        return 0

    print(f"\n🚨 Detected {len(findings)} Vulnerability Finding(s):")
    print("-" * 80)
    for f in findings:
        print(f"[{f.id}] {f.severity.value} (CVSS {f.cvss_score}) - {f.title}")
        print(f"  Location: {f.file_path}:{f.line_number}")
        print(f"  Rule:     {f.cwe.cwe_id} ({f.cwe.owasp_category})")
        print(f"  Snippet:  {f.code_snippet}")
        print(f"  Fix:      {f.remediation}")
        print("-" * 80)

    if args.fail_on:
        crit_match = any(f.severity == Severity.CRITICAL for f in findings)
        high_match = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        if args.fail_on.upper() == "CRITICAL" and crit_match:
            print("\n❌ CI/CD Policy Gate Failed: Critical vulnerabilities detected.")
            return 1
        elif args.fail_on.upper() == "HIGH" and high_match:
            print("\n❌ CI/CD Policy Gate Failed: High or Critical vulnerabilities detected.")
            return 1

    return 0

def cmd_audit(args):
    engine = ForgeGuardEngine()
    print(f"\n🛡️ Running Tri-Agent Collaborative Security Audit on: {args.target}...")
    report = engine.run_full_audit(args.target)

    s = report.summary
    print("\n" + "=" * 60)
    print("           FORGEGUARD EXECUTIVE AUDIT SUMMARY")
    print("=" * 60)
    print(f" Project Target:      {report.project_name}")
    print(f" Security Grade:      {s.security_grade}")
    print(f" Mean CVSS 3.1 Score: {s.mean_cvss_score} / 10.0")
    print(f" Total Findings:      {s.findings_count} (Crit: {s.critical_count}, High: {s.high_count}, Med: {s.medium_count}, Low: {s.low_count})")
    print(f" AST Scan Speed:      {s.scan_duration_ms} ms across {s.total_files_scanned} files ({s.total_lines_scanned} lines)")
    print("=" * 60)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        print(f"\n💾 Full JSON report saved to: {args.json_out}")

    if args.sarif_out:
        save_sarif_file(report, args.sarif_out)
        print(f"📄 Standard OASIS SARIF v2.1.0 saved to: {args.sarif_out}")

    if should_fail_ci(report, args.fail_on):
        print(f"\n❌ CI/CD Policy Gate Failed: Findings exceed '--fail-on {args.fail_on}' threshold.")
        return 1

    return 0

def cmd_patch(args):
    engine = ForgeGuardEngine()
    print(f"\n🛠️ Generating and applying automated security patches for: {args.target}...")
    report = engine.run_full_audit(args.target)

    if not report.patches:
        print("\n✅ No patches required.")
        return 0

    sorted_patches = sorted(report.patches, key=lambda p: (p.file_path, -p.start_line))

    applied_count = 0
    for patch in sorted_patches:
        print(f"\n[Patch {patch.vulnerability_id}] {patch.file_path}:{patch.start_line}")
        print(f"  Summary: {patch.remediation_summary}")
        success = engine.remediator.patcher.apply_patch(patch, dry_run=args.dry_run)
        if success:
            applied_count += 1
            status = "DRY-RUN OK" if args.dry_run else "APPLIED"
            print(f"  Status:  ✅ {status}")
        else:
            print(f"  Status:  ❌ FAILED (AST verification or syntax error)")

    print(f"\n✨ Completed: {applied_count}/{len(report.patches)} patches successfully processed.")
    return 0

def cmd_serve(args):
    print_banner()
    start_server(target_path=args.target, port=args.port)
    return 0

def main():
    parser = argparse.ArgumentParser(description="ForgeGuard - Autonomous AI Code Vulnerability Scanner & Patch Engine")
    subparsers = parser.add_subparsers(dest="command", help="ForgeGuard Subcommands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Run SAST AST vulnerability scan")
    p_scan.add_argument("target", nargs="?", default=".", help="Target file or directory")
    p_scan.add_argument("--fail-on", dest="fail_on", choices=["critical", "high", "medium", "low"], help="Exit code 1 if threshold reached")

    # audit
    p_audit = subparsers.add_parser("audit", help="Run full Tri-Agent audit with STRIDE model")
    p_audit.add_argument("target", nargs="?", default=".", help="Target file or directory")
    p_audit.add_argument("--json", dest="json_out", help="Output path for JSON report")
    p_audit.add_argument("--sarif", dest="sarif_out", help="Output path for OASIS SARIF v2.1.0 report")
    p_audit.add_argument("--fail-on", dest="fail_on", choices=["critical", "high", "medium", "low"], help="Exit code 1 if threshold reached")

    # patch
    p_patch = subparsers.add_parser("patch", help="Synthesize and apply automated security patches")
    p_patch.add_argument("target", nargs="?", default=".", help="Target file or directory")
    p_patch.add_argument("--dry-run", action="store_true", help="Simulate patch application without modifying disk")

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch interactive web security dashboard")
    p_serve.add_argument("target", nargs="?", default=".", help="Target project to monitor")
    p_serve.add_argument("--port", type=int, default=8899, help="Dashboard port (default: 8899)")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "audit":
        sys.exit(cmd_audit(args))
    elif args.command == "patch":
        sys.exit(cmd_patch(args))
    elif args.command == "serve":
        sys.exit(cmd_serve(args))

if __name__ == "__main__":
    main()

import os
import sys
import html
import asyncio
import subprocess
from playwright.async_api import async_playwright

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "media_assets")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_cli_screens():
    # Run CLI scan
    result = subprocess.run(
        [sys.executable, "-m", "forgeguard.cli", "scan", "examples/vulnerable_app"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    cli_scan_text = result.stdout
    
    # Run CLI patch preview
    result_patch = subprocess.run(
        [sys.executable, "-m", "forgeguard.cli", "patch", "examples/vulnerable_app", "--preview"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    cli_patch_text = result_patch.stdout

    return cli_scan_text, cli_patch_text

async def capture_all_assets():
    cli_scan_text, cli_patch_text = generate_cli_screens()
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            device_scale_factor=2
        )
        page = await context.new_page()
        
        # 1. Capture Dashboard Main / Overview
        print("[1/8] Capturing Dashboard Main Overview...")
        await page.goto("http://localhost:8899", wait_until="networkidle")
        await page.wait_for_timeout(1500)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "01_dashboard_overview.png"), full_page=False)

        # 2. Capture Findings with Secret Masked
        print("[2/8] Capturing Vulnerability Findings...")
        await page.click("#tab-btn-findings")
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "02_vulnerability_findings.png"))

        # 3. Capture STRIDE Threat Matrix Tab
        print("[3/8] Capturing STRIDE Threat Matrix...")
        await page.click("#tab-btn-stride")
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "03_stride_matrix.png"))

        # 4. Capture Diffs Tab
        print("[4/8] Capturing Autonomous Unified Diffs...")
        await page.click("#tab-btn-diffs")
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "04_unified_diffs.png"))

        # 5. Capture Live Sandbox Tab
        print("[5/8] Capturing Live Interactive Sandbox...")
        await page.click("#tab-btn-sandbox")
        await page.wait_for_timeout(500)
        await page.click("button:has-text('Load Sample Vulnerable Code')")
        await page.wait_for_timeout(500)
        await page.click("button:has-text('Run In-Browser Audit')")
        await page.wait_for_timeout(1500)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "05_interactive_sandbox.png"))

        # 6. Capture Privacy Policy Modal
        print("[6/8] Capturing Privacy Policy & Zero-Retention Modal...")
        await page.click("#tab-btn-findings")
        await page.wait_for_timeout(500)
        await page.evaluate("openPrivacyModal()")
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "06_privacy_modal.png"))
        await page.evaluate("closePrivacyModal()")
        await page.wait_for_timeout(400)

        # 7. Render Terminal HTML snapshot for CLI Scan
        print("[7/8] Generating CLI Terminal Scan Snapshot...")
        escaped_scan = html.escape(cli_scan_text)
        terminal_html = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        </head>
        <body class="bg-[#050811] text-white p-12 flex items-center justify-center min-h-screen font-mono">
            <div class="w-full max-w-5xl bg-[#090d1a] border border-cyan-500/30 rounded-2xl shadow-2xl overflow-hidden">
                <div class="bg-[#0f172a] px-5 py-3 border-b border-slate-800 flex items-center justify-between">
                    <div class="flex items-center gap-2">
                        <span class="w-3.5 h-3.5 rounded-full bg-rose-500 inline-block"></span>
                        <span class="w-3.5 h-3.5 rounded-full bg-amber-500 inline-block"></span>
                        <span class="w-3.5 h-3.5 rounded-full bg-emerald-500 inline-block"></span>
                        <span class="ml-3 text-xs text-slate-400 font-semibold">forgeguard@sec-ops: ~ $ forgeguard scan examples/vulnerable_app</span>
                    </div>
                    <span class="text-[11px] text-cyan-400 font-bold tracking-widest uppercase">AST Engine v1.0</span>
                </div>
                <div class="p-6 text-xs text-slate-200 leading-relaxed font-mono whitespace-pre overflow-x-auto bg-[#070b16]">{escaped_scan}</div>
            </div>
        </body>
        </html>"""
        
        await page.set_content(terminal_html)
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "07_cli_terminal_scan.png"))

        # 8. Render Terminal HTML snapshot for CLI Auto-Patch
        print("[8/8] Generating CLI Patch Terminal Snapshot...")
        escaped_patch = html.escape(cli_patch_text)
        terminal_patch_html = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        </head>
        <body class="bg-[#050811] text-white p-12 flex items-center justify-center min-h-screen font-mono">
            <div class="w-full max-w-5xl bg-[#090d1a] border border-emerald-500/30 rounded-2xl shadow-2xl overflow-hidden">
                <div class="bg-[#0f172a] px-5 py-3 border-b border-slate-800 flex items-center justify-between">
                    <div class="flex items-center gap-2">
                        <span class="w-3.5 h-3.5 rounded-full bg-rose-500 inline-block"></span>
                        <span class="w-3.5 h-3.5 rounded-full bg-amber-500 inline-block"></span>
                        <span class="w-3.5 h-3.5 rounded-full bg-emerald-500 inline-block"></span>
                        <span class="ml-3 text-xs text-slate-400 font-semibold">forgeguard@sec-ops: ~ $ forgeguard patch examples/vulnerable_app --preview</span>
                    </div>
                    <span class="text-[11px] text-emerald-400 font-bold tracking-widest uppercase">Autonomous Synthesizer</span>
                </div>
                <div class="p-6 text-xs text-slate-200 leading-relaxed font-mono whitespace-pre overflow-x-auto bg-[#070b16]">{escaped_patch}</div>
            </div>
        </body>
        </html>"""
        await page.set_content(terminal_patch_html)
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "08_cli_terminal_patch.png"))

        await browser.close()
        print("✅ All UI & CLI screenshots captured in high resolution!")

if __name__ == "__main__":
    asyncio.run(capture_all_assets())

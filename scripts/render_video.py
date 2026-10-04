import os
import sys
import html
import asyncio
import subprocess

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import edge_tts
import imageio_ffmpeg
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEDIA_DIR = os.path.join(BASE_DIR, "media_assets")
VIDEO_DIR = os.path.join(BASE_DIR, "demo_video")
os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(VIDEO_DIR, exist_ok=True)

FFMPEG_EXE = imageio_ffmpeg.get_ffmpeg_exe()

SCENES = [
    {
        "id": "scene_01",
        "title": "ForgeGuard: Autonomous AI Security & Patch Engine",
        "subtitle": "ForgeGuard: Autonomous AI Vulnerability Auditor & Patch Engine",
        "narration": "Welcome to ForgeGuard. An autonomous, local-first AI security auditor and patch engine designed to eliminate vulnerability alert fatigue.",
        "image_name": "01_hero_intro.png",
        "badge": "FORGEGUARD v1.0 • ARCHITECTURE OVERVIEW"
    },
    {
        "id": "scene_02",
        "title": "Sub-50ms Deterministic AST Taint Analysis",
        "subtitle": "Instant AST Static Taint-Flow Analysis Under 50ms",
        "narration": "In under fifty milliseconds, ForgeGuard's deterministic AST analyzer performs static taint-flow tracking across Python codebases, discovering OWASP Top 10 vulnerabilities and hardcoded secrets.",
        "image_name": "07_cli_terminal_scan.png",
        "badge": "STATIC AST SCANNER • TAINT FLOW GRAPH"
    },
    {
        "id": "scene_03",
        "title": "Real-Time SOC Security Posture & Compliance",
        "subtitle": "Enterprise SOC Dashboard: CVSS 3.1 & Compliance Gauges",
        "narration": "The Cyber SOC Dashboard provides real-time security grading, mean CVSS scoring, and instant compliance health ratings across SOC 2 Type II, ISO 27001, and PCI-DSS.",
        "image_name": "01_dashboard_overview.png",
        "badge": "ENTERPRISE SOC DASHBOARD • COMPLIANCE MATRIX"
    },
    {
        "id": "scene_04",
        "title": "Deep Vulnerability Taint Inspection & Safe Masking",
        "subtitle": "Deep Taint Sinks & Safe Secrets Masking",
        "narration": "Security engineers can inspect exact vulnerability taint trajectories, complete with automated secret masking to safeguard credentials on shared dashboards.",
        "image_name": "02_vulnerability_findings.png",
        "badge": "VULNERABILITY AUDITOR • CREDENTIAL MASKING"
    },
    {
        "id": "scene_05",
        "title": "Autonomous 6-Axis STRIDE Threat Surface Modeling",
        "subtitle": "Automated 6-Axis STRIDE Threat Surface Matrix",
        "narration": "ForgeGuard autonomously synthesizes a 6-axis STRIDE threat surface model, mapping systemic attack vectors across Spoofing, Tampering, and Privilege Escalation.",
        "image_name": "03_stride_matrix.png",
        "badge": "STRIDE THREAT MODEL • ATTACK SURFACE RADAR"
    },
    {
        "id": "scene_06",
        "title": "Autonomous Unified Diff Patching with AST Verification",
        "subtitle": "Autonomous AST-Verified Unified Diff Remediation",
        "narration": "Rather than dumping noisy alerts, ForgeGuard synthesizes ready-to-merge unified diffs, safeguarded by pre-commit AST syntax checks and atomic backups.",
        "image_name": "04_unified_diffs.png",
        "badge": "AUTONOMOUS RECTIFIER • AST SYNTAX SAFETY"
    },
    {
        "id": "scene_07",
        "title": "Interactive Live Sandbox & Zero-Retention Privacy",
        "subtitle": "Live In-Browser AST Sandbox & Zero-Retention Privacy",
        "narration": "Developers can test arbitrary Python code in the live sandbox, backed by our 100% local-first, zero-data-retention privacy architecture.",
        "image_name": "05_interactive_sandbox.png",
        "badge": "LIVE SANDBOX • ZERO-DATA RETENTION PRIVACY"
    },
    {
        "id": "scene_08",
        "title": "Automated CLI Remediation & CI/CD Ready",
        "subtitle": "OASIS Standard SARIF v2.1.0 & CI/CD Pipeline Ready",
        "narration": "With OASIS SARIF v2.1.0 export and GitHub Code Scanning integration, ForgeGuard turns static analysis into instant, verifiable remediation.",
        "image_name": "08_cli_terminal_patch.png",
        "badge": "DEVSECOPS CI/CD • GITHUB ACTIONS SARIF"
    }
]

def generate_cli_screens():
    result = subprocess.run(
        [sys.executable, "-m", "forgeguard.cli", "scan", "examples/vulnerable_app"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        cwd=BASE_DIR
    )
    cli_scan_text = result.stdout
    
    result_patch = subprocess.run(
        [sys.executable, "-m", "forgeguard.cli", "patch", "examples/vulnerable_app", "--preview"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        cwd=BASE_DIR
    )
    cli_patch_text = result_patch.stdout

    return cli_scan_text, cli_patch_text

async def capture_screenshots_async():
    from playwright.async_api import async_playwright
    cli_scan_text, cli_patch_text = generate_cli_screens()
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            device_scale_factor=2
        )
        page = await context.new_page()

        # Hero Intro Slide
        print("📸 Capturing Hero Intro...")
        hero_html = """<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        </head>
        <body class="bg-[#050811] text-white flex items-center justify-center min-h-screen p-12 font-sans">
            <div class="max-w-5xl w-full text-center space-y-8 p-12 rounded-3xl bg-gradient-to-b from-[#0e1628] to-[#070b14] border border-cyan-500/30 shadow-[0_0_80px_rgba(6,182,212,0.15)]">
                <div class="inline-flex items-center gap-3 px-4 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-bold tracking-widest uppercase">
                    <i class="fa-solid fa-shield-halved"></i> ForgeHacks 2026 AI + Cybersecurity Track
                </div>
                <h1 class="text-6xl font-black tracking-tight text-white leading-tight">
                    Forge<span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-indigo-400 to-rose-400">Guard</span>
                </h1>
                <p class="text-xl text-slate-300 max-w-3xl mx-auto font-light leading-relaxed">
                    Autonomous AI Vulnerability Auditor, STRIDE Threat Surface Modeler & AST-Verified Patch Engine
                </p>
                <div class="grid grid-cols-3 gap-6 pt-6 max-w-3xl mx-auto text-left">
                    <div class="p-4 rounded-2xl bg-[#090e1c] border border-slate-800">
                        <div class="text-cyan-400 text-lg mb-1"><i class="fa-solid fa-bolt"></i></div>
                        <div class="font-bold text-white text-sm">Deterministic AST</div>
                        <div class="text-xs text-slate-400">Sub-50ms static taint tracking</div>
                    </div>
                    <div class="p-4 rounded-2xl bg-[#090e1c] border border-slate-800">
                        <div class="text-indigo-400 text-lg mb-1"><i class="fa-solid fa-shield-virus"></i></div>
                        <div class="font-bold text-white text-sm">STRIDE 6-Axis</div>
                        <div class="text-xs text-slate-400">Systemic threat surface modeling</div>
                    </div>
                    <div class="p-4 rounded-2xl bg-[#090e1c] border border-slate-800">
                        <div class="text-emerald-400 text-lg mb-1"><i class="fa-solid fa-code-merge"></i></div>
                        <div class="font-bold text-white text-sm">Autonomous Diffs</div>
                        <div class="text-xs text-slate-400">AST pre-commit verified patches</div>
                    </div>
                </div>
            </div>
        </body>
        </html>"""
        await page.set_content(hero_html)
        await page.wait_for_timeout(600)
        await page.screenshot(path=os.path.join(MEDIA_DIR, "01_hero_intro.png"))

        # Dashboard Overview
        print("📸 Capturing Dashboard Overview...")
        await page.goto("http://localhost:8899", wait_until="networkidle")
        await page.wait_for_timeout(1500)
        await page.screenshot(path=os.path.join(MEDIA_DIR, "01_dashboard_overview.png"))

        # Findings
        print("📸 Capturing Findings Tab...")
        await page.click("#tab-btn-findings")
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(MEDIA_DIR, "02_vulnerability_findings.png"))

        # STRIDE Matrix
        print("📸 Capturing STRIDE Matrix Tab...")
        await page.click("#tab-btn-stride")
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(MEDIA_DIR, "03_stride_matrix.png"))

        # Diffs
        print("📸 Capturing Unified Diffs Tab...")
        await page.click("#tab-btn-diffs")
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(MEDIA_DIR, "04_unified_diffs.png"))

        # Interactive Sandbox
        print("📸 Capturing Live Sandbox Tab...")
        await page.click("#tab-btn-sandbox")
        await page.wait_for_timeout(500)
        await page.evaluate("loadSampleSandboxCode()")
        await page.wait_for_timeout(500)
        await page.evaluate("runSandboxAudit()")
        await page.wait_for_timeout(1500)
        await page.screenshot(path=os.path.join(MEDIA_DIR, "05_interactive_sandbox.png"))

        # Privacy Modal
        print("📸 Capturing Privacy Modal...")
        await page.click("#tab-btn-findings")
        await page.wait_for_timeout(500)
        await page.evaluate("openPrivacyModal()")
        await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(MEDIA_DIR, "06_privacy_modal.png"))
        await page.evaluate("closePrivacyModal()")
        await page.wait_for_timeout(400)

        # CLI Terminal Scan
        print("📸 Capturing Terminal Scan Snapshot...")
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
        await page.screenshot(path=os.path.join(MEDIA_DIR, "07_cli_terminal_scan.png"))

        # CLI Terminal Patch
        print("📸 Capturing Terminal Patch Snapshot...")
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
        await page.screenshot(path=os.path.join(MEDIA_DIR, "08_cli_terminal_patch.png"))

        await browser.close()
        print("✅ All screenshots captured!")

async def generate_voiceovers():
    print("🎙️ Generating AI Voiceovers with edge-tts (en-US-ChristopherNeural)...")
    voice = "en-US-ChristopherNeural"
    for sc in SCENES:
        audio_path = os.path.join(MEDIA_DIR, f"{sc['id']}.mp3")
        communicate = edge_tts.Communicate(sc["narration"], voice, rate="+4%")
        await communicate.save(audio_path)
        print(f"  Generated {sc['id']}.mp3")

def get_audio_duration(audio_path):
    cmd = [
        FFMPEG_EXE, "-i", audio_path,
        "-show_entries", "format=duration",
        "-v", "quiet",
        "-of", "csv=p=0"
    ]
    res = subprocess.run([FFMPEG_EXE, "-i", audio_path], capture_output=True, text=True, errors="replace")
    # Parse duration from ffmpeg stderr
    for line in res.stderr.split("\n"):
        if "Duration:" in line:
            time_str = line.split("Duration:")[1].split(",")[0].strip()
            h, m, s = time_str.split(":")
            return float(h)*3600 + float(m)*60 + float(s)
    return 6.0

def create_video_segment(scene_data, output_mp4, width=1920, height=1080, fps=30):
    img_path = os.path.join(MEDIA_DIR, scene_data["image_name"])
    audio_path = os.path.join(MEDIA_DIR, f"{scene_data['id']}.mp3")
    
    duration = get_audio_duration(audio_path) + 0.5  # slight tail padding
    total_frames = int(duration * fps)

    # Load base image with PIL
    base_img = Image.open(img_path).convert("RGBA")
    
    # Scale & fit image nicely inside 1920x1080 canvas
    canvas = Image.new("RGBA", (width, height), (7, 11, 20, 255))
    
    # Resize preserving aspect ratio
    img_w, img_h = base_img.size
    ratio = min((width - 80) / img_w, (height - 180) / img_h)
    new_w, new_h = int(img_w * ratio), int(img_h * ratio)
    resized_img = base_img.resize((new_w, new_h), Image.Resampling.LANCZOS)
    
    offset_x = (width - new_w) // 2
    offset_y = 70 + (height - 180 - new_h) // 2
    canvas.paste(resized_img, (offset_x, offset_y), resized_img)

    # Draw Top Header Bar on Canvas
    draw = ImageDraw.Draw(canvas)
    
    # Header bar background
    draw.rectangle([(0, 0), (width, 58)], fill=(11, 16, 28, 240))
    draw.line([(0, 58), (width, 58)], fill=(30, 41, 59, 255), width=2)
    
    # Header badge
    draw.rectangle([(40, 12), (320, 46)], fill=(6, 182, 212, 35), outline=(6, 182, 212, 180), width=1)
    
    # Fonts
    try:
        font_header = ImageFont.truetype("arialbd.ttf", 16)
        font_title = ImageFont.truetype("arialbd.ttf", 18)
        font_sub = ImageFont.truetype("arialbd.ttf", 26)
    except:
        font_header = ImageFont.load_default()
        font_title = ImageFont.load_default()
        font_sub = ImageFont.load_default()

    draw.text((55, 20), scene_data["badge"], fill=(6, 182, 212, 255), font=font_header)
    draw.text((350, 18), scene_data["title"], fill=(241, 245, 249, 255), font=font_title)

    # Bottom Subtitle Badge
    sub_text = scene_data["subtitle"]
    sub_bg_x1, sub_bg_y1 = 120, height - 95
    sub_bg_x2, sub_bg_y2 = width - 120, height - 25
    draw.rounded_rectangle([(sub_bg_x1, sub_bg_y1), (sub_bg_x2, sub_bg_y2)], radius=16, fill=(10, 15, 26, 235), outline=(6, 182, 212, 160), width=2)
    
    # Center subtitle text
    bbox = draw.textbbox((0, 0), sub_text, font=font_sub)
    text_w = bbox[2] - bbox[0]
    text_x = (width - text_w) // 2
    draw.text((text_x, height - 72), sub_text, fill=(255, 255, 255, 255), font=font_sub)

    # Convert to RGB numpy array for OpenCV
    frame_rgb = np.array(canvas.convert("RGB"))
    frame_bgr = cv2.cvtColor(frame_rgb, cv2.COLOR_RGB2BGR)

    # Write video segment using OpenCV VideoWriter
    temp_silent_mp4 = os.path.join(VIDEO_DIR, f"temp_{scene_data['id']}_silent.mp4")
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    writer = cv2.VideoWriter(temp_silent_mp4, fourcc, fps, (width, height))
    
    for f_idx in range(total_frames):
        writer.write(frame_bgr)
    writer.release()

    # Mux Audio and Video using ffmpeg
    cmd = [
        FFMPEG_EXE, "-y",
        "-i", temp_silent_mp4,
        "-i", audio_path,
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        output_mp4
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(temp_silent_mp4):
        os.remove(temp_silent_mp4)

def assemble_full_video():
    print("🎬 Assembling Final Demo Video...")
    segment_files = []
    for sc in SCENES:
        seg_output = os.path.join(VIDEO_DIR, f"{sc['id']}.mp4")
        print(f"  Rendering Segment: {sc['id']}...")
        create_video_segment(sc, seg_output)
        segment_files.append(seg_output)

    # Create concat list for ffmpeg
    concat_txt = os.path.join(VIDEO_DIR, "concat_list.txt")
    with open(concat_txt, "w", encoding="utf-8") as f:
        for seg in segment_files:
            f.write(f"file '{os.path.basename(seg)}'\n")

    final_output = os.path.join(VIDEO_DIR, "ForgeGuard_Demo_Walkthrough.mp4")
    
    cmd = [
        FFMPEG_EXE, "-y",
        "-f", "concat",
        "-safe", "0",
        "-i", concat_txt,
        "-c", "copy",
        final_output
    ]
    subprocess.run(cmd, check=True, cwd=VIDEO_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Clean up segment mp4 files and concat list
    for seg in segment_files:
        if os.path.exists(seg):
            os.remove(seg)
    if os.path.exists(concat_txt):
        os.remove(concat_txt)

    print(f"\n🎉 ForgeGuard Master Demo Video Successfully Rendered at:\n{final_output}")
    return final_output

async def main():
    await capture_screenshots_async()
    await generate_voiceovers()
    assemble_full_video()

if __name__ == "__main__":
    asyncio.run(main())

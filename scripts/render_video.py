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
        "subtitle": "Eliminating AppSec Alert Fatigue with Autonomous Remediation",
        "narration": "Welcome to ForgeGuard, an autonomous, local-first AI security auditor and automated patch engine. Traditional application security tools flood backlogs with thousands of noisy warnings, causing severe alert fatigue. Meanwhile, generic LLMs hallucinate broken fixes or leak sensitive code to third-party clouds. ForgeGuard was built from the ground up to solve this fundamental problem.",
        "image_name": "01_hero_intro.png",
        "badge": "FORGEHACKS 2026 • AI + CYBERSECURITY TRACK"
    },
    {
        "id": "scene_02",
        "title": "Tri-Agent Collaborative Architecture",
        "subtitle": "Security Auditor, Threat Modeler & Remediation Engineer",
        "narration": "ForgeGuard uses a specialized tri-agent collaborative engine. The Security Auditor maps source trees with AST taint flow analysis. The Threat Modeler projects vulnerabilities onto the six STRIDE dimensions. And the Remediator autonomously synthesizes verified unified diffs. Grounded in deterministic syntax trees, ForgeGuard eliminates false positives without brittle wrappers.",
        "image_name": "01_hero_intro.png",
        "badge": "TRI-AGENT CORE • DETERMINISTIC ENGINE"
    },
    {
        "id": "scene_03",
        "title": "Sub-50ms Deterministic AST Taint Analysis",
        "subtitle": "Instant Static Taint-Flow Graph Analysis Under 50ms",
        "narration": "At the command line, ForgeGuard completes static audits in under fifty milliseconds. Unlike slow cloud scanners, our recursive AST visitor tracks tainted inputs across nine critical OWASP Top 10 and CWE classes, including SQL Injection, Command Injection, Insecure Deserialization, Path Traversal, and MD5 hashing.",
        "image_name": "07_cli_terminal_scan.png",
        "badge": "STATIC AST SCANNER • TAINT FLOW GRAPH"
    },
    {
        "id": "scene_04",
        "title": "Enterprise SOC Security Posture & Compliance Health",
        "subtitle": "Real-Time CVSS 3.1 Scoring & SOC 2, ISO 27001 Health",
        "narration": "The real-time Cyber SOC Dashboard provides engineering leaders with instant visibility. ForgeGuard calculates dynamic security grades from A-plus to F, mean CVSS 3.1 severity scores, and automated compliance health gauges mapped to SOC 2 Type II, ISO 27001, and PCI-DSS standards.",
        "image_name": "01_dashboard_overview.png",
        "badge": "ENTERPRISE SOC DASHBOARD • COMPLIANCE MATRIX"
    },
    {
        "id": "scene_05",
        "title": "Vulnerability Deep-Dive & Safe Secret Masking",
        "subtitle": "Exact Taint Trajectories & Executive Secret Masking",
        "narration": "Security engineers can drill directly into individual findings to inspect exact file paths, line numbers, and taint trajectories. To prevent credential leaks during reviews, ForgeGuard automatically detects and masks exposed API keys and JWT tokens, with a granular toggle to reveal secrets only when authorized.",
        "image_name": "02_vulnerability_findings.png",
        "badge": "VULNERABILITY AUDITOR • CREDENTIAL MASKING"
    },
    {
        "id": "scene_06",
        "title": "Automated 6-Axis STRIDE Threat Surface Modeling",
        "subtitle": "Systemic Attack Vector Radar & Blast Radius Telemetry",
        "narration": "Moving beyond basic static analysis, ForgeGuard autonomously synthesizes a six-axis STRIDE threat model. By categorizing weaknesses across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Privilege Elevation, it reveals systemic architectural risks and attack blast radii.",
        "image_name": "03_stride_matrix.png",
        "badge": "STRIDE THREAT MODEL • ATTACK SURFACE RADAR"
    },
    {
        "id": "scene_07",
        "title": "Autonomous Unified Diff Patching with AST Verification",
        "subtitle": "Zero Broken Builds with Pre-Commit Syntax Validation",
        "narration": "Instead of dumping raw alerts, ForgeGuard synthesizes ready-to-merge unified diffs using secure coding patterns like parameterized queries. Crucially, every patch undergoes an in-memory AST syntax compilation check before writing to disk, backed by atomic local backups to guarantee zero broken builds.",
        "image_name": "04_unified_diffs.png",
        "badge": "AUTONOMOUS RECTIFIER • AST SYNTAX SAFETY"
    },
    {
        "id": "scene_08",
        "title": "Interactive Live Sandbox & Zero-Retention Privacy",
        "subtitle": "100% Local-First Runtime & Enterprise GDPR Compliance",
        "narration": "Developers can also prototype and audit arbitrary Python code inside the live in-browser sandbox, instantly visualizing syntax trees and synthesized patches. Best of all, with our strict one hundred percent local-first, zero-retention policy, your proprietary source code never leaves your machine.",
        "image_name": "05_interactive_sandbox.png",
        "badge": "LIVE SANDBOX • ZERO-DATA RETENTION PRIVACY"
    },
    {
        "id": "scene_09",
        "title": "DevSecOps CI/CD Automation & SARIF Export",
        "subtitle": "OASIS Standard SARIF v2.1.0 & Pre-Commit Git Hooks",
        "narration": "In continuous integration environments, ForgeGuard seamlessly integrates into existing DevSecOps pipelines. The CLI features automated patching, fail-on threshold policies, pre-commit git hooks, and native export to the OASIS standard SARIF version 2.1.0 format, plugging directly into GitHub Code Scanning.",
        "image_name": "08_cli_terminal_patch.png",
        "badge": "DEVSECOPS CI/CD • GITHUB ACTIONS SARIF"
    },
    {
        "id": "scene_10",
        "title": "The Future of Autonomous Application Security",
        "subtitle": "From Vulnerability Alert Fatigue to Instant Verified Fixes",
        "narration": "In conclusion, ForgeGuard bridges the gap between deterministic static analysis and intelligent automated remediation. With multi-language ASTs and IDE extensions on our roadmap, ForgeGuard empowers teams to ship secure software with confidence. Thank you for watching our ForgeHacks 2026 presentation.",
        "image_name": "01_hero_intro.png",
        "badge": "FORGEGUARD • FUTURE ROADMAP"
    }
]

def get_audio_duration(audio_path):
    res = subprocess.run([FFMPEG_EXE, "-i", audio_path], capture_output=True, text=True, errors="replace")
    for line in res.stderr.split("\n"):
        if "Duration:" in line:
            time_str = line.split("Duration:")[1].split(",")[0].strip()
            h, m, s = time_str.split(":")
            return float(h)*3600 + float(m)*60 + float(s)
    return 16.0

async def generate_voiceovers():
    print("Generating AI Voiceovers with edge-tts (en-US-ChristopherNeural)...", flush=True)
    voice = "en-US-ChristopherNeural"
    total_duration = 0.0
    for sc in SCENES:
        audio_path = os.path.join(MEDIA_DIR, f"{sc['id']}.mp3")
        communicate = edge_tts.Communicate(sc["narration"], voice, rate="+6%")
        await communicate.save(audio_path)
        dur = get_audio_duration(audio_path)
        total_duration += dur
        print(f"  Generated {sc['id']}.mp3 ({dur:.1f}s)", flush=True)
    print(f"\n>>> Total Audio Duration: {total_duration:.1f}s (~{total_duration/60:.2f} mins) <<<", flush=True)

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
    draw.rectangle([(40, 12), (380, 46)], fill=(6, 182, 212, 35), outline=(6, 182, 212, 180), width=1)
    
    # Fonts
    try:
        font_header = ImageFont.truetype("arialbd.ttf", 15)
        font_title = ImageFont.truetype("arialbd.ttf", 18)
        font_sub = ImageFont.truetype("arialbd.ttf", 24)
    except:
        font_header = ImageFont.load_default()
        font_title = ImageFont.load_default()
        font_sub = ImageFont.load_default()

    draw.text((55, 20), scene_data["badge"], fill=(6, 182, 212, 255), font=font_header)
    draw.text((410, 18), scene_data["title"], fill=(241, 245, 249, 255), font=font_title)

    # Bottom Subtitle Badge
    sub_text = scene_data["subtitle"]
    sub_bg_x1, sub_bg_y1 = 100, height - 95
    sub_bg_x2, sub_bg_y2 = width - 100, height - 25
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
    print("Assembling Final Demo Video...", flush=True)
    segment_files = []
    for sc in SCENES:
        seg_output = os.path.join(VIDEO_DIR, f"{sc['id']}.mp4")
        print(f"  Rendering Segment: {sc['id']}...", flush=True)
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

    total_dur = get_audio_duration(final_output)
    print(f"\nForgeGuard Master Demo Video Successfully Rendered!", flush=True)
    print(f"File: {final_output}", flush=True)
    print(f"Total Video Duration: {total_dur:.1f} seconds ({total_dur/60:.2f} minutes)", flush=True)
    return final_output

async def main():
    print("Starting video rendering process...", flush=True)
    await generate_voiceovers()
    assemble_full_video()

if __name__ == "__main__":
    asyncio.run(main())

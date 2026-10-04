"""
ForgeGuard Live SOC Security Dashboard & Remediation Server
Enterprise-grade embedded HTTP server delivering real-time SAST reports, STRIDE radar metrics,
side-by-side AST diff studio, interactive live code sandbox, and 1-click autonomous patching.
"""
import http.server
import socketserver
import json
import os
import tempfile
import urllib.parse
from typing import Optional
from .engine import ForgeGuardEngine
from .models import AuditReport
from .sarif import export_sarif

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForgeGuard Enterprise SOC Security Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2338bdf8'%3E%3Cpath d='M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z'/%3E%3C/svg%3E">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        cyber: {
                            bg: '#070a13',
                            card: '#0d1322',
                            cardHover: '#131b2e',
                            border: '#1e293b',
                            accent: '#38bdf8',
                            danger: '#f43f5e',
                            warning: '#fbbf24',
                            success: '#10b981',
                            purple: '#a855f7'
                        }
                    }
                }
            }
        }
    </script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #070a13; color: #f1f5f9; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .diff-added { background-color: rgba(16, 185, 129, 0.12); color: #34d399; border-left: 3px solid #10b981; }
        .diff-removed { background-color: rgba(244, 63, 94, 0.12); color: #fb7185; border-left: 3px solid #f43f5e; }
        .glow-cyan { box-shadow: 0 0 20px rgba(56, 189, 248, 0.25); }
        .glass-panel { background: rgba(13, 19, 34, 0.85); backdrop-filter: blur(12px); border: 1px solid #1e293b; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #070a13; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #334155; }
    </style>
</head>
<body class="min-h-screen flex flex-col antialiased selection:bg-cyan-500 selection:text-white">

    <!-- Top Navigation -->
    <header class="border-b border-cyber-border bg-[#0d1322]/90 backdrop-blur sticky top-0 z-50 px-6 py-3.5 flex items-center justify-between">
        <div class="flex items-center space-x-4">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-indigo-600 to-purple-600 flex items-center justify-center glow-cyan">
                <i class="fa-solid fa-shield-halved text-white text-xl"></i>
            </div>
            <div>
                <div class="flex items-center gap-2">
                    <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                        FORGEGUARD <span class="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-mono font-semibold">ENTERPRISE SOC</span>
                    </h1>
                    <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> SYSTEM ONLINE
                    </span>
                </div>
                <p class="text-xs text-slate-400">Autonomous AI Vulnerability Auditor, STRIDE Threat Modeler & AST-Verified Patch Engine</p>
            </div>
        </div>

        <div class="flex items-center space-x-3">
            <button onclick="downloadSarif()" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition border border-slate-700 flex items-center gap-2">
                <i class="fa-solid fa-file-export text-cyan-400"></i> Export SARIF 2.1.0
            </button>
            <button onclick="triggerRescan()" id="btn-rescan" class="px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition shadow-lg shadow-indigo-600/20 flex items-center gap-2">
                <i class="fa-solid fa-arrows-rotate"></i> Re-Scan AST
            </button>
            <button onclick="applyAllPatches()" id="btn-patchall" class="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition shadow-lg shadow-emerald-600/20 flex items-center gap-2">
                <i class="fa-solid fa-wand-magic-sparkles"></i> Auto-Patch All
            </button>
        </div>
    </header>

    <!-- Tri-Agent Live Telemetry HUD Bar -->
    <div class="bg-[#0a0f1d] border-b border-cyber-border px-6 py-2 flex flex-wrap items-center justify-between text-xs text-slate-400">
        <div class="flex items-center space-x-6 font-mono">
            <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
                <span class="text-slate-300 font-semibold">Agent 1: Security Auditor</span>
                <span class="text-cyan-400">[AST & Taint Flow]</span>
            </div>
            <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-purple-400"></span>
                <span class="text-slate-300 font-semibold">Agent 2: Threat Modeler</span>
                <span class="text-purple-400">[STRIDE Matrix]</span>
            </div>
            <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                <span class="text-slate-300 font-semibold">Agent 3: Remediation Engineer</span>
                <span class="text-emerald-400">[AST Safety Gate]</span>
            </div>
        </div>
        <div class="flex items-center gap-4 font-mono text-[11px] text-slate-500">
            <span>Inference: <strong class="text-slate-300">Featherless.ai (Llama-3.1-8B)</strong></span>
            <span>Target: <strong class="text-slate-300" id="hud-target">...</strong></span>
        </div>
    </div>

    <!-- Target Path Quick Bar & Quick Switcher -->
    <div class="bg-[#080d1a] border-b border-cyber-border px-6 py-2.5 flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2 flex-1 max-w-2xl">
            <span class="text-xs font-mono text-slate-400 font-semibold">Target Path:</span>
            <div class="relative flex-1">
                <input type="text" id="custom-target-path" placeholder="Enter file or folder path (e.g., examples/production_fintech_service)" class="w-full px-3 py-1 bg-[#050811] text-xs font-mono text-cyan-300 rounded border border-slate-800 focus:outline-none focus:border-cyan-500">
            </div>
            <button onclick="scanCustomPath()" class="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded transition flex items-center gap-1.5 shadow-sm">
                <i class="fa-solid fa-magnifying-glass-arrow-right"></i> Scan Path
            </button>
        </div>

        <div class="flex items-center gap-2 text-xs font-mono">
            <span class="text-slate-500">Quick Switch:</span>
            <button onclick="switchTarget('examples/vulnerable_app')" class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">Vulnerable App</button>
            <button onclick="switchTarget('examples/production_fintech_service')" class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">Fintech Wallet</button>
            <button onclick="switchTarget('.')" class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700">Entire Project</button>
        </div>
    </div>

    <!-- Main Container -->
    <main class="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">

        <!-- Executive KPI Overview Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <!-- Security Posture Grade -->
            <div class="glass-panel rounded-2xl p-5 relative overflow-hidden flex flex-col justify-between">
                <div class="flex items-center justify-between">
                    <span class="text-xs uppercase tracking-wider text-slate-400 font-bold">Security Posture</span>
                    <i class="fa-solid fa-shield-virus text-xl text-rose-500"></i>
                </div>
                <div class="my-3 flex items-baseline gap-3">
                    <span id="kpi-grade" class="text-5xl font-black text-rose-400 tracking-tight">--</span>
                    <span id="kpi-grade-desc" class="text-xs text-rose-400/80 font-medium">Critical Action Required</span>
                </div>
                <div class="text-[11px] text-slate-500 font-mono" id="kpi-project-name">Project: ...</div>
            </div>

            <!-- Mean CVSS Score Gauge -->
            <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between">
                <div class="flex items-center justify-between">
                    <span class="text-xs uppercase tracking-wider text-slate-400 font-bold">Mean CVSS 3.1 Score</span>
                    <i class="fa-solid fa-gauge-high text-xl text-amber-400"></i>
                </div>
                <div class="my-3 flex items-baseline gap-2">
                    <span id="kpi-cvss" class="text-5xl font-black text-amber-400 tracking-tight">0.0</span>
                    <span class="text-xs text-slate-400 font-semibold">/ 10.0</span>
                </div>
                <div class="text-[11px] text-slate-400 flex items-center gap-1.5">
                    <span class="w-2 h-2 rounded-full bg-amber-400"></span> Severity: <strong id="kpi-cvss-level">Critical</strong>
                </div>
            </div>

            <!-- Total Findings & Breakdown -->
            <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between">
                <div class="flex items-center justify-between">
                    <span class="text-xs uppercase tracking-wider text-slate-400 font-bold">Total Vulnerabilities</span>
                    <i class="fa-solid fa-bug text-xl text-cyan-400"></i>
                </div>
                <div class="my-3 flex items-baseline gap-3">
                    <span id="kpi-total-findings" class="text-5xl font-black text-white tracking-tight">0</span>
                    <div class="flex gap-2 font-mono text-xs">
                        <span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 font-bold" id="kpi-crit-count">0 C</span>
                        <span class="px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/30 font-bold" id="kpi-high-count">0 H</span>
                        <span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 font-bold" id="kpi-med-count">0 M</span>
                    </div>
                </div>
                <div class="text-[11px] text-slate-400">OWASP Top 10 & CWE mapped</div>
            </div>

            <!-- AST Scan Velocity -->
            <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between">
                <div class="flex items-center justify-between">
                    <span class="text-xs uppercase tracking-wider text-slate-400 font-bold">AST Scan Velocity</span>
                    <i class="fa-solid fa-bolt text-xl text-indigo-400"></i>
                </div>
                <div class="my-3 flex items-baseline gap-2">
                    <span id="kpi-speed" class="text-4xl font-extrabold text-indigo-300 font-mono tracking-tight">0.0</span>
                    <span class="text-xs text-indigo-400 font-semibold font-mono">ms</span>
                </div>
                <div class="text-[11px] text-slate-400 font-mono flex justify-between">
                    <span id="kpi-files">0 files</span>
                    <span id="kpi-lines">0 lines</span>
                </div>
            </div>
        </div>

        <!-- Visual Analytics Grid (Donut Chart + STRIDE Radar) -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <!-- Severity Donut Chart -->
            <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between">
                <div class="text-xs uppercase tracking-wider text-slate-400 font-bold mb-2 flex items-center justify-between">
                    <span>Severity Distribution</span>
                    <i class="fa-solid fa-chart-pie text-slate-500"></i>
                </div>
                <div class="h-44 relative flex items-center justify-center">
                    <canvas id="chart-severity"></canvas>
                </div>
            </div>

            <!-- STRIDE Threat Surface Radar -->
            <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between">
                <div class="text-xs uppercase tracking-wider text-slate-400 font-bold mb-2 flex items-center justify-between">
                    <span>STRIDE Threat Radar</span>
                    <i class="fa-solid fa-circle-nodes text-purple-400"></i>
                </div>
                <div class="h-44 relative flex items-center justify-center">
                    <canvas id="chart-stride"></canvas>
                </div>
            </div>

            <!-- Compliance Framework Readiness -->
            <div class="glass-panel rounded-2xl p-5 flex flex-col justify-between space-y-3">
                <div class="text-xs uppercase tracking-wider text-slate-400 font-bold flex items-center justify-between">
                    <span>Compliance Health</span>
                    <i class="fa-solid fa-certificate text-emerald-400"></i>
                </div>
                <div class="space-y-2.5">
                    <div>
                        <div class="flex justify-between text-xs mb-1">
                            <span class="font-medium text-slate-300">SOC 2 Type II</span>
                            <span class="font-mono text-cyan-400 font-bold" id="comp-soc2">--</span>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-1.5">
                            <div class="bg-cyan-400 h-1.5 rounded-full transition-all duration-500" id="comp-soc2-bar" style="width: 0%"></div>
                        </div>
                    </div>
                    <div>
                        <div class="flex justify-between text-xs mb-1">
                            <span class="font-medium text-slate-300">ISO/IEC 27001</span>
                            <span class="font-mono text-purple-400 font-bold" id="comp-iso">--</span>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-1.5">
                            <div class="bg-purple-400 h-1.5 rounded-full transition-all duration-500" id="comp-iso-bar" style="width: 0%"></div>
                        </div>
                    </div>
                    <div>
                        <div class="flex justify-between text-xs mb-1">
                            <span class="font-medium text-slate-300">PCI-DSS 4.0</span>
                            <span class="font-mono text-emerald-400 font-bold" id="comp-pci">--</span>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-1.5">
                            <div class="bg-emerald-400 h-1.5 rounded-full transition-all duration-500" id="comp-pci-bar" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="text-[10px] text-slate-500">Autonomous remediation increases compliance score in real time.</div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <div class="flex border-b border-cyber-border space-x-6 text-sm font-semibold">
            <button onclick="switchTab('findings')" id="tab-btn-findings" class="pb-3 border-b-2 border-cyan-400 text-cyan-400 flex items-center gap-2 transition">
                <i class="fa-solid fa-triangle-exclamation"></i> Vulnerabilities (<span id="tab-count-findings">0</span>)
            </button>
            <button onclick="switchTab('stride')" id="tab-btn-stride" class="pb-3 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition">
                <i class="fa-solid fa-network-wired"></i> STRIDE Threat Matrix
            </button>
            <button onclick="switchTab('diffs')" id="tab-btn-diffs" class="pb-3 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition">
                <i class="fa-solid fa-code-compare"></i> AST Diff Studio (<span id="tab-count-diffs">0</span>)
            </button>
            <button onclick="switchTab('sandbox')" id="tab-btn-sandbox" class="pb-3 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition">
                <i class="fa-solid fa-terminal"></i> ⚡ Live Code Sandbox
            </button>
            <button onclick="switchTab('raw')" id="tab-btn-raw" class="pb-3 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition">
                <i class="fa-solid fa-file-code"></i> Raw JSON Report
            </button>
        </div>

        <!-- Tab 1: Vulnerability Findings -->
        <div id="tab-findings" class="space-y-4">
            <!-- Search & Filter Controls -->
            <div class="flex flex-wrap items-center justify-between gap-3 bg-cyber-card p-3 rounded-xl border border-cyber-border">
                <div class="relative flex-1 min-w-[240px]">
                    <i class="fa-solid fa-magnifying-glass absolute left-3 top-2.5 text-slate-500 text-xs"></i>
                    <input type="text" id="finding-search" oninput="filterFindings()" placeholder="Filter by rule, CWE, file or snippet..." class="w-full pl-9 pr-3 py-1.5 bg-[#050811] text-xs text-slate-200 rounded-lg border border-slate-800 focus:outline-none focus:border-cyan-500">
                </div>
                <div class="flex gap-2 text-xs">
                    <button onclick="setFilterSev('ALL')" class="px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-semibold hover:bg-slate-700" id="btn-sev-ALL">All</button>
                    <button onclick="setFilterSev('CRITICAL')" class="px-2.5 py-1 rounded bg-rose-500/10 text-rose-400 font-semibold border border-rose-500/30 hover:bg-rose-500/20" id="btn-sev-CRITICAL">Critical</button>
                    <button onclick="setFilterSev('HIGH')" class="px-2.5 py-1 rounded bg-orange-500/10 text-orange-400 font-semibold border border-orange-500/30 hover:bg-orange-500/20" id="btn-sev-HIGH">High</button>
                    <button onclick="setFilterSev('MEDIUM')" class="px-2.5 py-1 rounded bg-amber-500/10 text-amber-400 font-semibold border border-amber-500/30 hover:bg-amber-500/20" id="btn-sev-MEDIUM">Medium</button>
                </div>
            </div>

            <!-- Findings List -->
            <div id="findings-container" class="space-y-3"></div>
        </div>

        <!-- Tab 2: STRIDE Threat Matrix -->
        <div id="tab-stride" class="hidden space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4" id="stride-container"></div>
        </div>

        <!-- Tab 3: AST Diff Studio -->
        <div id="tab-diffs" class="hidden space-y-4">
            <div id="diffs-container" class="space-y-4"></div>
        </div>

        <!-- Tab 4: Live Code Sandbox & Patcher -->
        <div id="tab-sandbox" class="hidden space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <!-- Code Input -->
                <div class="glass-panel rounded-2xl p-5 space-y-3">
                    <div class="flex items-center justify-between">
                        <span class="text-xs uppercase font-mono font-bold text-cyan-400"><i class="fa-solid fa-code"></i> In-Browser Source Code Input</span>
                        <button onclick="loadSampleSandboxCode()" class="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700">
                            Load Sample Exploit
                        </button>
                    </div>
                    <textarea id="sandbox-code-input" rows="14" class="w-full bg-[#050811] p-3 rounded-xl font-mono text-xs text-slate-200 border border-slate-800 focus:outline-none focus:border-cyan-500 leading-relaxed" placeholder="# Paste Python code here to test AST auditing & auto-patching..."></textarea>
                    <button onclick="runSandboxAudit()" id="btn-run-sandbox" class="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20">
                        <i class="fa-solid fa-wand-magic-sparkles"></i> Analyze AST & Synthesize Live Patch
                    </button>
                </div>

                <!-- Live Results & Diff View -->
                <div class="glass-panel rounded-2xl p-5 space-y-3">
                    <div class="flex items-center justify-between">
                        <span class="text-xs uppercase font-mono font-bold text-emerald-400"><i class="fa-solid fa-shield-check"></i> AST-Synthesized Remediation</span>
                        <span id="sandbox-status" class="text-xs font-mono text-slate-400">Ready</span>
                    </div>
                    <div id="sandbox-results" class="bg-[#050811] p-3 rounded-xl font-mono text-xs text-slate-300 border border-slate-800 min-h-[340px] overflow-y-auto space-y-2">
                        <div class="text-slate-500 text-center py-24">Paste code on the left and click "Analyze AST & Synthesize Live Patch"</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab 5: Raw JSON Report -->
        <div id="tab-raw" class="hidden">
            <div class="glass-panel rounded-2xl p-5">
                <div class="flex justify-between items-center mb-3">
                    <span class="text-xs uppercase font-mono text-slate-400">audit_report.json</span>
                    <button onclick="copyRawJson()" class="px-3 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 flex items-center gap-1.5">
                        <i class="fa-regular fa-copy"></i> Copy JSON
                    </button>
                </div>
                <pre id="raw-json-view" class="bg-[#050811] p-4 rounded-xl overflow-x-auto text-xs font-mono text-emerald-400 leading-relaxed max-h-[600px] border border-slate-800/80"></pre>
            </div>
        </div>

    </main>

    <!-- Footer with Privacy & Local-First Guarantee -->
    <footer class="border-t border-cyber-border bg-[#0a0f1d] px-6 py-4 mt-8">
        <div class="max-w-7xl mx-auto flex flex-wrap items-center justify-between text-xs text-slate-500 gap-3">
            <div class="flex items-center gap-2">
                <i class="fa-solid fa-lock text-cyan-400"></i>
                <span><strong>Zero-Data-Retention Commitment:</strong> 100% Local-First AST Execution. Code is never uploaded, tracked, or used for AI model training.</span>
            </div>
            <div class="flex items-center gap-4 font-mono text-[11px]">
                <button onclick="openPrivacyModal()" class="text-slate-400 hover:text-cyan-400 transition underline">Privacy Policy</button>
                <span>•</span>
                <button onclick="openTermsModal()" class="text-slate-400 hover:text-cyan-400 transition underline">Terms & Conditions</button>
                <span>•</span>
                <span>ForgeGuard v1.0 Enterprise</span>
            </div>
        </div>
    </footer>

    <!-- Privacy Policy Modal -->
    <div id="privacy-modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 hidden items-center justify-center p-4">
        <div class="glass-panel max-w-2xl w-full rounded-2xl p-6 border border-slate-700 space-y-4 shadow-2xl">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <div class="flex items-center gap-2 text-white font-bold text-base">
                    <i class="fa-solid fa-shield-halved text-cyan-400"></i> ForgeGuard Zero-Data-Retention & Privacy Commitment
                </div>
                <button onclick="closePrivacyModal()" class="text-slate-400 hover:text-white text-lg"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div class="text-xs text-slate-300 space-y-3 leading-relaxed max-h-[400px] overflow-y-auto pr-2">
                <p><strong>1. Local-First Processing:</strong> All static AST analysis, taint tracking, and patch synthesis execute 100% locally on your machine. Your source code never leaves your runtime boundary.</p>
                <p><strong>2. Zero Code Retention & Zero Model Training:</strong> We do not store, index, or retain customer source code. Proprietary code is never used for training foundation models.</p>
                <p><strong>3. Opt-In Ephemeral Inference:</strong> Optional cloud LLM bridges (Featherless.ai) are strictly opt-in via user API key, encrypted via HTTPS, and discarded immediately post-response.</p>
                <p><strong>4. Local Backup Isolation:</strong> Pre-remediation snapshots (.forgeguard_backups/) reside exclusively on your local disk.</p>
                <p><strong>5. Compliance Alignment:</strong> SOC 2 Type II (Confidentiality), ISO/IEC 27001, GDPR & CCPA privacy principles.</p>
            </div>
            <div class="border-t border-slate-800 pt-3 flex justify-end">
                <button onclick="closePrivacyModal()" class="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold">Understood</button>
            </div>
        </div>
    </div>

    <!-- Terms & Conditions Modal -->
    <div id="terms-modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 hidden items-center justify-center p-4">
        <div class="glass-panel max-w-2xl w-full rounded-2xl p-6 border border-slate-700 space-y-4 shadow-2xl">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
                <div class="flex items-center gap-2 text-white font-bold text-base">
                    <i class="fa-solid fa-scale-balanced text-indigo-400"></i> ForgeGuard Terms & Conditions of Use
                </div>
                <button onclick="closeTermsModal()" class="text-slate-400 hover:text-white text-lg"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div class="text-xs text-slate-300 space-y-3 leading-relaxed max-h-[400px] overflow-y-auto pr-2">
                <p><strong>1. Defensive & Authorized Use:</strong> ForgeGuard is designed strictly for defensive security auditing and authorized code remediation. Users must have explicit authorization for scanned systems.</p>
                <p><strong>2. AST Pre-Commit Safety:</strong> ForgeGuard incorporates automated AST syntax checks and snapshot backups (.forgeguard_backups/) before disk commits. Users are advised to run automated CI/CD test suites before production deployment.</p>
                <p><strong>3. Disclaimer of Warranties:</strong> Provided "AS-IS" under the MIT License without warranties of merchantability or fitness for a specific deployment.</p>
                <p><strong>4. Open Source License:</strong> Core components are free and open-source under MIT.</p>
            </div>
            <div class="border-t border-slate-800 pt-3 flex justify-end">
                <button onclick="closeTermsModal()" class="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold">I Agree</button>
            </div>
        </div>
    </div>

    <!-- Global Toast Notification -->
    <div id="toast" class="fixed bottom-5 right-5 bg-slate-900 border border-cyan-500/50 text-white px-4 py-3 rounded-xl shadow-2xl text-xs hidden flex items-center gap-2.5 z-50 transition-all duration-300">
        <i class="fa-solid fa-circle-check text-cyan-400 text-sm"></i>
        <span id="toast-msg">Operation completed</span>
    </div>

    <!-- Frontend Script Logic -->
    <script>
        let currentReport = null;
        let selectedSevFilter = 'ALL';
        let chartSeverityInst = null;
        let chartStrideInst = null;

        function openPrivacyModal() {
            const m = document.getElementById('privacy-modal');
            m.classList.remove('hidden');
            m.classList.add('flex');
        }
        function closePrivacyModal() {
            const m = document.getElementById('privacy-modal');
            m.classList.add('hidden');
            m.classList.remove('flex');
        }
        function openTermsModal() {
            const m = document.getElementById('terms-modal');
            m.classList.remove('hidden');
            m.classList.add('flex');
        }
        function closeTermsModal() {
            const m = document.getElementById('terms-modal');
            m.classList.add('hidden');
            m.classList.remove('flex');
        }

        function showToast(msg) {
            const toast = document.getElementById('toast');
            document.getElementById('toast-msg').innerText = msg;
            toast.classList.remove('hidden');
            setTimeout(() => { toast.classList.add('hidden'); }, 3500);
        }

        function switchTab(tabName) {
            ['findings', 'stride', 'diffs', 'sandbox', 'raw'].forEach(t => {
                const el = document.getElementById('tab-' + t);
                const btn = document.getElementById('tab-btn-' + t);
                if (el) el.classList.add('hidden');
                if (btn) btn.className = "pb-3 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition";
            });
            const targetEl = document.getElementById('tab-' + tabName);
            const targetBtn = document.getElementById('tab-btn-' + tabName);
            if (targetEl) targetEl.classList.remove('hidden');
            if (targetBtn) targetBtn.className = "pb-3 border-b-2 border-cyan-400 text-cyan-400 flex items-center gap-2 transition";
        }

        function getSeverityBadge(sev) {
            const map = {
                'CRITICAL': 'bg-rose-500/15 text-rose-400 border-rose-500/40',
                'HIGH': 'bg-orange-500/15 text-orange-400 border-orange-500/40',
                'MEDIUM': 'bg-amber-500/15 text-amber-400 border-amber-500/40',
                'LOW': 'bg-blue-500/15 text-blue-400 border-blue-500/40',
                'INFO': 'bg-slate-500/15 text-slate-400 border-slate-500/40'
            };
            return `<span class="px-2.5 py-0.5 rounded text-[11px] font-bold font-mono border ${map[sev] || map['INFO']}">${sev}</span>`;
        }

        function setFilterSev(sev) {
            selectedSevFilter = sev;
            filterFindings();
        }

        function filterFindings() {
            if (!currentReport) return;
            const query = document.getElementById('finding-search').value.toLowerCase();
            const filtered = currentReport.findings.filter(f => {
                const matchSev = (selectedSevFilter === 'ALL' || f.severity === selectedSevFilter);
                const matchQuery = (
                    f.title.toLowerCase().includes(query) ||
                    f.rule_id.toLowerCase().includes(query) ||
                    f.cwe.cwe_id.toLowerCase().includes(query) ||
                    f.file_path.toLowerCase().includes(query) ||
                    f.code_snippet.toLowerCase().includes(query)
                );
                return matchSev && matchQuery;
            });
            renderFindingsList(filtered);
        }

        async function loadReport() {
            try {
                const res = await fetch('/api/report');
                const data = await res.json();
                currentReport = data;
                renderDashboard(data);
            } catch (err) {
                console.error("Failed to load report", err);
            }
        }

        function renderDashboard(data) {
            const s = data.summary;
            document.getElementById('hud-target').innerText = data.project_name;
            document.getElementById('custom-target-path').value = data.project_name;
            document.getElementById('kpi-grade').innerText = s.security_grade;
            document.getElementById('kpi-grade-desc').innerText = s.security_grade === 'A+' ? 'Zero Critical Risks' : s.security_grade === 'F' ? 'Critical Action Required' : 'Remediation Advised';
            document.getElementById('kpi-grade').className = s.security_grade === 'A+' || s.security_grade === 'A' ? "text-5xl font-black text-emerald-400 tracking-tight" : "text-5xl font-black text-rose-400 tracking-tight";
            document.getElementById('kpi-project-name').innerText = "Project: " + data.project_name;
            document.getElementById('kpi-cvss').innerText = s.mean_cvss_score.toFixed(1);
            document.getElementById('kpi-cvss-level').innerText = s.mean_cvss_score >= 9.0 ? 'Critical' : s.mean_cvss_score >= 7.0 ? 'High' : s.mean_cvss_score >= 4.0 ? 'Medium' : 'Low';
            document.getElementById('kpi-total-findings').innerText = s.findings_count;
            document.getElementById('kpi-crit-count').innerText = s.critical_count + ' C';
            document.getElementById('kpi-high-count').innerText = s.high_count + ' H';
            document.getElementById('kpi-med-count').innerText = s.medium_count + ' M';
            document.getElementById('kpi-speed').innerText = s.scan_duration_ms.toFixed(1);
            document.getElementById('kpi-files').innerText = s.total_files_scanned + ' files';
            document.getElementById('kpi-lines').innerText = s.total_lines_scanned + ' lines';

            document.getElementById('tab-count-findings').innerText = data.findings.length;
            document.getElementById('tab-count-diffs').innerText = data.patches.length;
            document.getElementById('raw-json-view').innerText = JSON.stringify(data, null, 2);

            // Calculate Compliance Health Scores
            const totalF = data.findings.length;
            const soc2Score = totalF === 0 ? 100 : Math.max(15, 100 - (s.critical_count * 30 + s.high_count * 15 + s.medium_count * 5));
            const isoScore = totalF === 0 ? 100 : Math.max(20, 100 - (s.critical_count * 25 + s.high_count * 15 + s.medium_count * 5));
            const pciScore = totalF === 0 ? 100 : Math.max(10, 100 - (s.critical_count * 35 + s.high_count * 20));

            document.getElementById('comp-soc2').innerText = soc2Score + '%';
            document.getElementById('comp-soc2-bar').style.width = soc2Score + '%';
            document.getElementById('comp-iso').innerText = isoScore + '%';
            document.getElementById('comp-iso-bar').style.width = isoScore + '%';
            document.getElementById('comp-pci').innerText = pciScore + '%';
            document.getElementById('comp-pci-bar').style.width = pciScore + '%';

            renderCharts(s, data.threat_model);
            filterFindings();
            renderStrideMatrix(data.threat_model);
            renderDiffsList(data.patches);
        }

        function renderCharts(s, threatModel) {
            const ctxSev = document.getElementById('chart-severity').getContext('2d');
            if (chartSeverityInst) chartSeverityInst.destroy();
            chartSeverityInst = new Chart(ctxSev, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [s.critical_count, s.high_count, s.medium_count, s.low_count],
                        backgroundColor: ['#f43f5e', '#fb923c', '#fbbf24', '#38bdf8'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { boxWidth: 10, color: '#94a3b8', font: { size: 10 } } }
                    },
                    cutout: '70%'
                }
            });

            const ctxStride = document.getElementById('chart-stride').getContext('2d');
            if (chartStrideInst) chartStrideInst.destroy();
            const strideScores = threatModel.map(t => t.risk_level === 'CRITICAL' ? 10 : t.risk_level === 'HIGH' ? 7.5 : t.risk_level === 'MEDIUM' ? 5 : 2);
            chartStrideInst = new Chart(ctxStride, {
                type: 'radar',
                data: {
                    labels: ['Spoofing', 'Tampering', 'Repudiation', 'Info Leak', 'DoS', 'Privilege'],
                    datasets: [{
                        label: 'Risk Vector',
                        data: strideScores,
                        backgroundColor: 'rgba(168, 85, 247, 0.25)',
                        borderColor: '#a855f7',
                        pointBackgroundColor: '#c084fc',
                        pointBorderColor: '#fff',
                        borderWidth: 1.5
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        r: {
                            angleLines: { color: '#1e293b' },
                            grid: { color: '#1e293b' },
                            pointLabels: { color: '#94a3b8', font: { size: 9 } },
                            ticks: { display: false, max: 10 }
                        }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        let revealedSecrets = {};
        let currentFilteredFindings = null;

        function maskSecretString(str) {
            return str.replace(/([\'"][A-Za-z0-9_\-\.\=\/\+\$]{3})([A-Za-z0-9_\-\.\=\/\+\$]{8,})([A-Za-z0-9_\-\.\=\/\+\$]{3}[\'"])/g, '$1••••••••••••••••$3');
        }

        function toggleSecretReveal(findingId) {
            revealedSecrets[findingId] = !revealedSecrets[findingId];
            renderFindingsList(currentFilteredFindings || currentReport.findings);
        }

        function renderFindingsList(findings) {
            currentFilteredFindings = findings;
            const container = document.getElementById('findings-container');
            container.innerHTML = '';
            if (findings.length === 0) {
                container.innerHTML = '<div class="p-12 text-center text-slate-500 bg-cyber-card rounded-xl border border-cyber-border"><i class="fa-solid fa-circle-check text-emerald-400 text-3xl mb-2"></i><p>Zero matching vulnerabilities! System is secure.</p></div>';
                return;
            }

            findings.forEach(f => {
                const card = document.createElement('div');
                card.className = "bg-cyber-card hover:bg-cyber-cardHover border border-cyber-border hover:border-slate-700 rounded-xl p-4 transition duration-200";
                
                const isSecret = f.rule_id === 'FG-SEC-004' || f.title.toLowerCase().includes('secret') || f.title.toLowerCase().includes('token');
                const isRevealed = Boolean(revealedSecrets[f.id]);
                const displaySnippet = (isSecret && !isRevealed) ? maskSecretString(f.code_snippet) : f.code_snippet;
                
                const secretToggleBtn = isSecret ? `
                    <button onclick="toggleSecretReveal('${f.id}')" class="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-slate-300 border border-slate-700 font-mono transition flex items-center gap-1">
                        <i class="fa-solid ${isRevealed ? 'fa-eye-slash' : 'fa-eye'}"></i> ${isRevealed ? 'Mask Secret' : 'Reveal Secret'}
                    </button>
                ` : '';

                card.innerHTML = `
                    <div class="flex items-center justify-between mb-2">
                        <div class="flex items-center gap-3">
                            ${getSeverityBadge(f.severity)}
                            <span class="font-bold text-slate-100 text-sm">${f.title}</span>
                            <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono border border-slate-700">${f.cwe.cwe_id}</span>
                        </div>
                        <span class="text-xs font-mono font-bold text-amber-400">CVSS ${f.cvss_score}</span>
                    </div>
                    <p class="text-xs text-slate-300 mb-3">${f.description}</p>
                    <div class="bg-[#050811] rounded-lg p-3 font-mono text-xs text-slate-300 mb-3 border border-slate-800">
                        <div class="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                            <span class="flex items-center gap-1.5"><i class="fa-regular fa-file"></i> ${f.file_path}:${f.line_number}</span>
                            ${secretToggleBtn}
                        </div>
                        <code class="text-rose-300 font-semibold">${displaySnippet}</code>
                    </div>
                    <div class="text-xs text-cyan-400/90 bg-cyan-950/20 border border-cyan-900/40 p-2.5 rounded-lg flex items-start gap-2">
                        <i class="fa-solid fa-lightbulb mt-0.5 text-cyan-400"></i>
                        <div><strong>Remediation:</strong> ${f.remediation}</div>
                    </div>
                `;
                container.appendChild(card);
            });
        }

        function renderStrideMatrix(threatModel) {
            const container = document.getElementById('stride-container');
            container.innerHTML = '';
            threatModel.forEach(t => {
                const card = document.createElement('div');
                card.className = "bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-2.5";
                card.innerHTML = `
                    <div class="flex items-center justify-between">
                        <div class="font-bold text-slate-100 flex items-center gap-2 text-sm">
                            <i class="fa-solid fa-shield-virus text-indigo-400"></i> ${t.category}
                        </div>
                        ${getSeverityBadge(t.risk_level)}
                    </div>
                    <p class="text-xs text-slate-300">${t.threat}</p>
                    <div class="text-xs font-mono text-slate-400"><span class="text-slate-500">Blast Radius:</span> ${t.target_asset}</div>
                    <div class="text-xs text-emerald-400/90 bg-emerald-950/20 border border-emerald-900/40 p-2.5 rounded-lg">
                        <strong>Architectural Mitigation:</strong> ${t.mitigation_strategy}
                    </div>
                `;
                container.appendChild(card);
            });
        }

        function renderDiffsList(patches) {
            const container = document.getElementById('diffs-container');
            container.innerHTML = '';
            if (patches.length === 0) {
                container.innerHTML = '<div class="p-12 text-center text-slate-500 bg-cyber-card rounded-xl border border-cyber-border">No automated patches generated.</div>';
                return;
            }

            patches.forEach((p) => {
                const card = document.createElement('div');
                card.className = "bg-cyber-card border border-cyber-border rounded-xl p-4 space-y-3";
                const displayOrig = p.remediation_summary.toLowerCase().includes('secret') ? maskSecretString(p.original_code) : p.original_code;
                
                card.innerHTML = `
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-2">
                            <span class="text-xs px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-mono font-semibold">${p.vulnerability_id}</span>
                            <span class="text-xs text-slate-400 font-mono">${p.file_path}:${p.start_line}</span>
                        </div>
                        <button onclick="applyPatch('${p.vulnerability_id}')" class="px-3 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold transition flex items-center gap-1.5 shadow-md shadow-emerald-600/20">
                            <i class="fa-solid fa-check"></i> Apply Patch
                        </button>
                    </div>
                    <div class="space-y-1.5 font-mono text-xs">
                        <div class="diff-removed p-2.5 rounded-lg"><span class="text-rose-500 font-bold mr-2">-</span>${displayOrig}</div>
                        <div class="diff-added p-2.5 rounded-lg"><span class="text-emerald-500 font-bold mr-2">+</span>${p.patched_code}</div>
                    </div>
                `;
                container.appendChild(card);
            });
        }

        async function triggerRescan() {
            showToast("Initiating live AST & STRIDE rescan...");
            await fetch('/api/scan', { method: 'POST' });
            await loadReport();
            showToast("Scan completed successfully!");
        }

        async function scanCustomPath() {
            const path = document.getElementById('custom-target-path').value.trim();
            if (!path) return;
            showToast("Switching target to: " + path);
            await fetch('/api/scan_target', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_path: path })
            });
            await loadReport();
            showToast("Target scanned successfully!");
        }

        async function switchTarget(path) {
            document.getElementById('custom-target-path').value = path;
            await scanCustomPath();
        }

        async function applyPatch(vulnId) {
            showToast("Applying patch for " + vulnId + " with AST pre-commit check...");
            const res = await fetch('/api/patch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ vulnerability_id: vulnId })
            });
            const d = await res.json();
            if (d.success) {
                showToast("Patch applied successfully!");
                await loadReport();
            } else {
                showToast("Patch verification failed: " + (d.error || 'Syntax guard error'));
            }
        }

        async function applyAllPatches() {
            showToast("Auto-patching all detected vulnerabilities...");
            const res = await fetch('/api/patch_all', { method: 'POST' });
            const d = await res.json();
            showToast(`Applied ${d.applied_count || 0} patches safely!`);
            await loadReport();
        }

        function loadSampleSandboxCode() {
            document.getElementById('sandbox-code-input').value = `import os
import sqlite3
import hashlib
import random
import pickle

API_KEY = "sk-live-098234098234098234098234098234098234"

def query_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchall()

def execute_cmd(host):
    os.system(f"ping -c 1 {host}")

def deserialize_blob(data):
    return pickle.loads(data)

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def get_otp():
    return random.randint(100000, 999999)

def calc_price(expr):
    return eval(expr)`;
            showToast("Loaded sample vulnerable Python code.");
        }

        async function runSandboxAudit() {
            const code = document.getElementById('sandbox-code-input').value;
            if (!code.trim()) {
                showToast("Please enter Python code first!");
                return;
            }

            document.getElementById('sandbox-status').innerText = "Analyzing AST...";
            const res = await fetch('/api/sandbox', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: code })
            });
            const d = await res.json();

            document.getElementById('sandbox-status').innerText = `${d.findings.length} findings, ${d.patches.length} patches`;

            const resultsContainer = document.getElementById('sandbox-results');
            resultsContainer.innerHTML = '';

            if (d.findings.length === 0) {
                resultsContainer.innerHTML = '<div class="text-emerald-400 py-12 text-center font-bold"><i class="fa-solid fa-circle-check text-2xl mb-2"></i><br/>Code is 100% clean. Zero vulnerabilities detected!</div>';
                return;
            }

            resultsContainer.innerHTML += `<div class="text-xs text-slate-400 font-bold mb-2 uppercase tracking-wide">AST Findings (${d.findings.length}):</div>`;
            d.findings.forEach(f => {
                resultsContainer.innerHTML += `
                    <div class="p-2.5 rounded bg-cyber-card border border-slate-800 space-y-1">
                        <div class="flex justify-between items-center">
                            <span class="font-bold text-slate-200 text-xs">${f.title}</span>
                            ${getSeverityBadge(f.severity)}
                        </div>
                        <div class="text-[11px] text-slate-400 font-mono">Line ${f.line_number}: <code class="text-rose-400">${f.code_snippet}</code></div>
                        <div class="text-[11px] text-cyan-400">Fix: ${f.remediation}</div>
                    </div>
                `;
            });

            if (d.patches.length > 0) {
                resultsContainer.innerHTML += `<div class="text-xs text-slate-400 font-bold mt-4 mb-2 uppercase tracking-wide">Synthesized Diffs (${d.patches.length}):</div>`;
                d.patches.forEach(p => {
                    resultsContainer.innerHTML += `
                        <div class="p-2 rounded bg-cyber-card border border-slate-800 space-y-1 font-mono text-[11px]">
                            <div class="diff-removed p-1.5 rounded"><span class="text-rose-500 font-bold mr-1">-</span>${p.original_code}</div>
                            <div class="diff-added p-1.5 rounded"><span class="text-emerald-500 font-bold mr-1">+</span>${p.patched_code}</div>
                        </div>
                    `;
                });
            }
            showToast("Sandbox analysis completed!");
        }

        function downloadSarif() {
            window.open('/api/sarif', '_blank');
        }

        function copyRawJson() {
            if (currentReport) {
                navigator.clipboard.writeText(JSON.stringify(currentReport, null, 2));
                showToast("Report JSON copied to clipboard!");
            }
        }

        window.addEventListener('DOMContentLoaded', loadReport);
    </script>
</body>
</html>
"""

class ForgeGuardRequestHandler(http.server.BaseHTTPRequestHandler):
    engine: ForgeGuardEngine = None
    target_path: str = "."
    latest_report: Optional[AuditReport] = None

    def _set_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif parsed.path == "/api/report":
            if not ForgeGuardRequestHandler.latest_report:
                ForgeGuardRequestHandler.latest_report = ForgeGuardRequestHandler.engine.run_full_audit(ForgeGuardRequestHandler.target_path)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(ForgeGuardRequestHandler.latest_report.to_json().encode("utf-8"))
        elif parsed.path == "/api/sarif":
            if not ForgeGuardRequestHandler.latest_report:
                ForgeGuardRequestHandler.latest_report = ForgeGuardRequestHandler.engine.run_full_audit(ForgeGuardRequestHandler.target_path)
            
            sarif_doc = export_sarif(ForgeGuardRequestHandler.latest_report)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=forgeguard_report.sarif")
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps(sarif_doc, indent=2).encode("utf-8"))
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._set_security_headers()
            self.end_headers()
            not_found_html = """<!DOCTYPE html><html lang="en" class="dark"><head><meta charset="UTF-8"><title>404 - Endpoint Not Found | ForgeGuard</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-[#070a13] text-white min-h-screen flex items-center justify-center font-mono p-6"><div class="text-center max-w-md space-y-4 p-8 bg-[#0d1322] rounded-2xl border border-slate-800"><div class="text-5xl text-rose-500 font-bold">404</div><h1 class="text-lg font-bold">Endpoint Not Found</h1><p class="text-xs text-slate-400">The requested resource does not exist in the ForgeGuard API boundary.</p><a href="/" class="inline-block px-4 py-2 text-xs bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition">Back to SOC Dashboard</a></div></body></html>"""
            self.wfile.write(not_found_html.encode("utf-8"))

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
            ForgeGuardRequestHandler.latest_report = ForgeGuardRequestHandler.engine.run_full_audit(ForgeGuardRequestHandler.target_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "findings": len(ForgeGuardRequestHandler.latest_report.findings)}).encode("utf-8"))
        elif parsed.path == "/api/scan_target":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))
            new_target = payload.get("target_path", ".")
            if os.path.exists(new_target):
                ForgeGuardRequestHandler.target_path = new_target
            ForgeGuardRequestHandler.latest_report = ForgeGuardRequestHandler.engine.run_full_audit(ForgeGuardRequestHandler.target_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "target": ForgeGuardRequestHandler.target_path}).encode("utf-8"))
        elif parsed.path == "/api/sandbox":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))
            code = payload.get("code", "")
            
            # Temporary file audit
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
                tf.write(code)
                temp_name = tf.name

            try:
                report = ForgeGuardRequestHandler.engine.run_full_audit(temp_name, project_name="In-Browser Sandbox")
                response_data = report.to_dict()
            finally:
                if os.path.exists(temp_name):
                    os.remove(temp_name)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
        elif parsed.path == "/api/patch":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))
            vuln_id = payload.get("vulnerability_id")
            
            success = False
            if ForgeGuardRequestHandler.latest_report:
                for patch in ForgeGuardRequestHandler.latest_report.patches:
                    if patch.vulnerability_id == vuln_id:
                        success = ForgeGuardRequestHandler.engine.remediator.patcher.apply_patch(patch)
                        break

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": success}).encode("utf-8"))
        elif parsed.path == "/api/patch_all":
            applied_count = 0
            if ForgeGuardRequestHandler.latest_report:
                sorted_patches = sorted(ForgeGuardRequestHandler.latest_report.patches, key=lambda p: (p.file_path, -p.start_line))
                for patch in sorted_patches:
                    if ForgeGuardRequestHandler.engine.remediator.patcher.apply_patch(patch):
                        applied_count += 1

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "applied_count": applied_count}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def start_server(target_path: str = ".", port: int = 8899) -> None:
    ForgeGuardRequestHandler.engine = ForgeGuardEngine()
    ForgeGuardRequestHandler.target_path = target_path
    ForgeGuardRequestHandler.latest_report = ForgeGuardRequestHandler.engine.run_full_audit(target_path)

    with socketserver.TCPServer(("", port), ForgeGuardRequestHandler) as httpd:
        print(f"\n⚡ ForgeGuard Security Dashboard running at http://localhost:{port}")
        print("Press Ctrl+C to stop the dashboard server.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down ForgeGuard server...")

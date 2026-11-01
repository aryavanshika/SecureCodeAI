"""
=============================================================================
SECURECODE AI - Enterprise Dark Cybersecurity SaaS Platform
=============================================================================
High-Contrast Dark Theme Specification:
- Main Background: #080D18
- Sidebar Background: #0B1220
- Card Background: #111C2E
- Secondary Card: #17243A
- Primary Text: #F8FAFC
- Secondary Text: #B8C5D9
- Primary Accent: #3186FF
- Secondary Accent: #8B5CF6
- Success: #22C55E
- Critical: #EF4444
- High: #F97316
- Medium: #EAB308
- Low: #38BDF8
- Borders: #26364D
=============================================================================
"""

import os
import io
import time
import json
import datetime
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Core Engine and Adapter
import backend_adapter
from mock_scanner import get_demo_snippet, normalize_language
import autofix
import patch_verifier
import project_scanner
import attack_simulator
import risk_analyzer
import secret_detector
import dependency_scanner
from utils.report_generator import (
    generate_json_report,
    generate_csv_report,
    generate_text_summary,
    generate_markdown_report
)

# ---------------------------------------------------------------------------
# 1. Page Configuration & Custom CSS Injection
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SecureCode AI | Enterprise Code Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject custom CSS for dark cybersecurity theme & contrast fixes
css_path = os.path.join(os.path.dirname(__file__), "assets", "style.css")
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# 2. Session State Initialization
# ---------------------------------------------------------------------------
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None
if "current_code" not in st.session_state:
    st.session_state.current_code = get_demo_snippet("python")
if "selected_language" not in st.session_state:
    st.session_state.selected_language = "python"
if "current_filename" not in st.session_state:
    st.session_state.current_filename = "app_vulnerable.py"
if "project_scan_result" not in st.session_state:
    st.session_state.project_scan_result = None
if "last_patch_verification" not in st.session_state:
    st.session_state.last_patch_verification = None
if "active_nav" not in st.session_state:
    st.session_state.active_nav = "📊 Dashboard"

# Pre-populate initial scan so Dashboard has data on first launch
if not st.session_state.scan_history and st.session_state.current_analysis is None:
    init_analysis = backend_adapter.analyze_code(st.session_state.current_code, "python")
    st.session_state.current_analysis = init_analysis
    st.session_state.scan_history.append({
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filename": st.session_state.current_filename,
        "language": "PYTHON",
        "score": init_analysis["summary"]["health_score"],
        "total_vulns": init_analysis["summary"]["total_vulnerabilities"],
        "critical": init_analysis["summary"]["critical"],
        "high": init_analysis["summary"]["high"],
        "medium": init_analysis["summary"]["medium"],
        "low": init_analysis["summary"]["low"],
        "fixed": init_analysis["summary"]["total_vulnerabilities"]
    })


# ---------------------------------------------------------------------------
# UI Component Helpers (High-Contrast Dark SaaS)
# ---------------------------------------------------------------------------

def render_top_header():
    """Renders the top header bar with branding, engine info, and system status."""
    health = backend_adapter.check_backend_health()
    if health["connected"]:
        status_badge = """
        <span class="system-status-badge">
            <span class="live-dot"></span> FastAPI Backend Online (Port 8000) • Engines Ready
        </span>
        """
        engine_label = "FastAPI REST Backend (Bandit + AST + SAST)"
    else:
        status_badge = """
        <span class="system-status-badge" style="background: rgba(234, 179, 8, 0.12) !important; color: #EAB308 !important; border-color: rgba(234, 179, 8, 0.35) !important;">
            <span class="live-dot" style="background-color: #EAB308; box-shadow: 0 0 8px #EAB308;"></span> Direct Python Mode • Local SAST Active
        </span>
        """
        engine_label = "Direct Python Engine (Bandit + AST + SAST)"

    st.markdown(f"""
    <div class="cyber-top-header">
        <div>
            <h1 class="cyber-title">
                🛡️ <span class="gradient-text">SecureCode AI</span>
            </h1>
            <div class="cyber-subtitle">
                <span style="color: #3186FF; font-weight: 700;">Intelligent Code Security, Detection & Auto-Remediation</span>
                <span>•</span>
                <span>Active Engine: <strong style="color: #8B5CF6;">{engine_label}</strong></span>
            </div>
        </div>
        <div>
            {status_badge}
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_overview_metric_cards_6(score: int, total_vulns: int, critical_vulns: int, high_vulns: int, fixed_vulns: int, files_scanned: int):
    """
    Renders the six required Dashboard Overview metric cards:
    1. Security Score
    2. Total Vulnerabilities
    3. Critical Issues
    4. High Issues
    5. Fixed Issues
    6. Files Scanned
    """
    score_border = "border-accent-green text-fixed" if score >= 80 else "border-accent-amber text-medium" if score >= 50 else "border-accent-red text-critical"
    crit_color = "text-critical" if critical_vulns > 0 else "text-fixed"
    high_color = "text-high" if high_vulns > 0 else "text-fixed"

    st.markdown(f"""
    <div class="metric-grid-6">
        <!-- 1. Security Score -->
        <div class="cyber-card {score_border}">
            <div class="card-top">
                <span>Security Score</span>
                <span style="font-size: 1.15rem;">🛡️</span>
            </div>
            <div class="card-value {score_border.split()[1]}">{score} <span style="font-size: 0.9rem; color: #B8C5D9;">/ 100</span></div>
            <div class="card-desc">Estimated security health index</div>
        </div>

        <!-- 2. Total Vulnerabilities -->
        <div class="cyber-card border-accent-purple">
            <div class="card-top">
                <span>Total Vulnerabilities</span>
                <span style="font-size: 1.15rem;">⚠️</span>
            </div>
            <div class="card-value text-total">{total_vulns}</div>
            <div class="card-desc">Identified security flaws</div>
        </div>

        <!-- 3. Critical Issues -->
        <div class="cyber-card border-accent-red">
            <div class="card-top">
                <span>Critical Issues</span>
                <span style="font-size: 1.15rem;">🚨</span>
            </div>
            <div class="card-value {crit_color}">{critical_vulns}</div>
            <div class="card-desc">Require immediate hotfix</div>
        </div>

        <!-- 4. High Issues -->
        <div class="cyber-card border-accent-orange">
            <div class="card-top">
                <span>High Issues</span>
                <span style="font-size: 1.15rem;">🟠</span>
            </div>
            <div class="card-value {high_color}">{high_vulns}</div>
            <div class="card-desc">Remediate prior to release</div>
        </div>

        <!-- 5. Fixed Issues -->
        <div class="cyber-card border-accent-green">
            <div class="card-top">
                <span>Fixed Issues</span>
                <span style="font-size: 1.15rem;">✨</span>
            </div>
            <div class="card-value text-fixed">{fixed_vulns}</div>
            <div class="card-desc">Automated patches synthesized</div>
        </div>

        <!-- 6. Files Scanned -->
        <div class="cyber-card border-accent-cyan">
            <div class="card-top">
                <span>Files Scanned</span>
                <span style="font-size: 1.15rem;">📁</span>
            </div>
            <div class="card-value text-low">{files_scanned}</div>
            <div class="card-desc">Source files inspected</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_circular_score(score: int, total_issues: int) -> str:
    """Renders a circular radial SVG progress meter with high contrast."""
    circumference = 408.4  # 2 * pi * 65
    offset = circumference - (score / 100.0) * circumference

    if score >= 80:
        stroke_color = "#22C55E"
        status_label = "SECURE / LOW RISK"
        glow_color = "rgba(34, 197, 94, 0.45)"
    elif score >= 50:
        stroke_color = "#EAB308"
        status_label = "MODERATE RISK"
        glow_color = "rgba(234, 179, 8, 0.45)"
    else:
        stroke_color = "#EF4444"
        status_label = "CRITICAL RISK"
        glow_color = "rgba(239, 68, 68, 0.45)"

    return f"""
    <div class="radial-wrapper">
        <div style="font-size: 0.8rem; font-weight: 700; color: #B8C5D9; text-transform: uppercase; letter-spacing: 0.5px;">Posture Rating</div>
        <div class="radial-svg-box">
            <svg class="radial-svg-element" width="170" height="170">
                <circle class="radial-track" cx="85" cy="85" r="65"></circle>
                <circle class="radial-indicator" cx="85" cy="85" r="65" 
                    stroke="{stroke_color}" 
                    stroke-dasharray="{circumference}" 
                    stroke-dashoffset="{offset}"
                    style="filter: drop-shadow(0 0 10px {glow_color});">
                </circle>
            </svg>
            <div class="radial-inner-content">
                <div class="radial-score-large" style="color: {stroke_color};">{score}</div>
                <div class="radial-score-muted">out of 100</div>
            </div>
        </div>
        <div style="font-size: 0.85rem; font-weight: 800; color: {stroke_color}; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px;">
            {status_label}
        </div>
        <div style="font-size: 0.78rem; color: #B8C5D9; margin-top: 3px;">
            {total_issues} flaw(s) flagged for remediation
        </div>
    </div>
    """


def render_plotly_severity_chart(critical: int, high: int, medium: int, low: int):
    """
    Renders an Enterprise Dark Plotly bar chart with #111C2E background,
    distinguishable severity colors, and high-contrast white text labels.
    """
    categories = ["Critical", "High", "Medium", "Low"]
    counts = [critical, high, medium, low]
    colors = ["#EF4444", "#F97316", "#EAB308", "#38BDF8"]

    fig = go.Figure(data=[
        go.Bar(
            x=categories,
            y=counts,
            marker=dict(
                color=colors,
                line=dict(color="#26364D", width=1.5)
            ),
            text=counts,
            textposition="auto",
            textfont=dict(color="#F8FAFC", size=13, family="JetBrains Mono"),
            hoverinfo="x+y"
        )
    ])

    fig.update_layout(
        paper_bgcolor="#111C2E",
        plot_bgcolor="#111C2E",
        margin=dict(l=35, r=20, t=30, b=35),
        height=230,
        xaxis=dict(
            showgrid=False,
            tickfont=dict(color="#F8FAFC", size=12, family="Plus Jakarta Sans"),
            linecolor="#26364D",
            linewidth=1.5
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="#17243A",
            gridwidth=1,
            tickfont=dict(color="#B8C5D9", size=11, family="JetBrains Mono"),
            linecolor="#26364D",
            zerolinecolor="#26364D"
        ),
        font=dict(family="Plus Jakarta Sans", color="#F8FAFC")
    )
    return fig


def render_scan_activity_table(history: list):
    """
    Renders a high-contrast, fully dark HTML table for Recent Scan Activity
    with #111C2E card background, #17243A headers, and crisp readable text.
    """
    if not history:
        st.info("No scan history logged yet.")
        return

    html_rows = []
    for item in history:
        score = item.get("score", 100)
        score_badge = f'<span style="background: rgba(34, 197, 94, 0.2); color: #22C55E; border: 1px solid #22C55E; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-family: monospace;">{score}</span>' if score >= 80 else \
                      f'<span style="background: rgba(234, 179, 8, 0.2); color: #EAB308; border: 1px solid #EAB308; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-family: monospace;">{score}</span>' if score >= 50 else \
                      f'<span style="background: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid #EF4444; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-family: monospace;">{score}</span>'

        crit = item.get("critical", 0)
        crit_badge = f'<span style="color: #EF4444; font-weight: 700;">{crit}</span>' if crit > 0 else f'<span style="color: #B8C5D9;">0</span>'

        html_rows.append(f"""
        <tr>
            <td style="color: #B8C5D9; font-size: 0.8rem;">{item.get('timestamp', 'N/A')}</td>
            <td style="color: #F8FAFC; font-weight: 600; font-family: monospace;">{item.get('filename', 'Unknown')}</td>
            <td><span class="tag-cwe">{item.get('language', 'N/A')}</span></td>
            <td>{score_badge}</td>
            <td style="color: #F8FAFC; font-weight: 600;">{item.get('total_vulns', 0)}</td>
            <td>{crit_badge}</td>
            <td style="color: #22C55E; font-weight: 600;">{item.get('fixed', item.get('total_vulns', 0))}</td>
        </tr>
        """)

    table_html = f"""
    <div class="cyber-table-container">
        <table class="cyber-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Filename</th>
                    <th>Language</th>
                    <th>Score</th>
                    <th>Issues</th>
                    <th>Critical</th>
                    <th>Patched</th>
                </tr>
            </thead>
            <tbody>
                {''.join(html_rows)}
            </tbody>
        </table>
    </div>
    """
    st.markdown(table_html, unsafe_allow_html=True)


def render_findings_matrix(vulns: list):
    """Renders a high-contrast, fully dark HTML table for detected vulnerabilities."""
    if not vulns:
        return

    rows = []
    for v in vulns:
        sev = v.get("severity", "Low")
        sev_class = f"sev-{sev.lower()}"
        snippet = v.get("code_snippet", "").replace("<", "&lt;").replace(">", "&gt;")

        rows.append(f"""
        <tr>
            <td><span class="tag-line">Line {v.get('line_number', 0)}</span></td>
            <td><span class="sev-badge {sev_class}">{sev}</span></td>
            <td><span class="tag-cwe">{v.get('cwe', 'N/A')}</span></td>
            <td style="color: #F8FAFC; font-weight: 600;">{v.get('name', 'N/A')}</td>
            <td><code style="background: #080D18; color: #F8FAFC; padding: 2px 6px; border: 1px solid #26364D; border-radius: 4px; font-size: 0.8rem;">{snippet}</code></td>
        </tr>
        """)

    table_html = f"""
    <div class="cyber-table-container">
        <table class="cyber-table">
            <thead>
                <tr>
                    <th style="width: 10%;">Line #</th>
                    <th style="width: 12%;">Severity</th>
                    <th style="width: 15%;">CWE ID</th>
                    <th style="width: 25%;">Vulnerability</th>
                    <th style="width: 38%;">Affected Code</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    """
    st.markdown(table_html, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# 3. Sidebar (Dark Navy #0B1220, 9 Navigation Items & Status)
# ---------------------------------------------------------------------------
with st.sidebar:
    # SecureCode AI Logo and Branding
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 6px;">
        <span style="font-size: 2.2rem; filter: drop-shadow(0 0 12px rgba(49, 134, 255, 0.55));">🛡️</span>
        <div>
            <span style="font-size: 1.25rem; font-weight: 800; color: #F8FAFC; letter-spacing: -0.3px;">SECURECODE <span style="color: #3186FF;">AI</span></span><br/>
            <span style="font-size: 0.72rem; color: #8B5CF6; text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">SaaS Cyber Platform</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # 9 Required Navigation Views
    NAV_OPTIONS = [
        "📊 Dashboard",
        "🔍 New Code Scan",
        "📁 Project Scanner",
        "✨ AutoFix & Remediation",
        "🧪 Attack Simulation Lab",
        "📈 Security Analytics",
        "📜 Scan History",
        "📄 Reports & CI/CD",
        "ℹ️ About SecureCode AI"
    ]

    selected_nav = st.radio(
        "Navigation Menu",
        NAV_OPTIONS,
        index=NAV_OPTIONS.index(st.session_state.active_nav) if st.session_state.active_nav in NAV_OPTIONS else 0,
        label_visibility="collapsed"
    )
    st.session_state.active_nav = selected_nav

    st.markdown("---")

    # 1-Click Demo Snippets Loader
    st.caption("⚡ 1-CLICK DEMO SNIPPETS")
    c_btn1, c_btn2 = st.columns(2)
    with c_btn1:
        if st.button("🐍 Python", use_container_width=True):
            st.session_state.selected_language = "python"
            st.session_state.current_code = get_demo_snippet("python")
            st.session_state.current_filename = "vulnerable_api.py"
            st.session_state.current_analysis = None
            st.rerun()

        if st.button("☕ Java", use_container_width=True):
            st.session_state.selected_language = "java"
            st.session_state.current_code = get_demo_snippet("java")
            st.session_state.current_filename = "VulnerableController.java"
            st.session_state.current_analysis = None
            st.rerun()

    with c_btn2:
        if st.button("🟨 JavaScript", use_container_width=True):
            st.session_state.selected_language = "javascript"
            st.session_state.current_code = get_demo_snippet("javascript")
            st.session_state.current_filename = "insecure_server.js"
            st.session_state.current_analysis = None
            st.rerun()

        if st.button("⚙️ C++", use_container_width=True):
            st.session_state.selected_language = "cpp"
            st.session_state.current_code = get_demo_snippet("cpp")
            st.session_state.current_filename = "memory_buffer.cpp"
            st.session_state.current_analysis = None
            st.rerun()

    st.markdown("---")

    # Detection Engine Status Indicator
    engine_meta = backend_adapter.get_active_engine_info()
    health_info = backend_adapter.check_backend_health()
    status_dot_color = "#22C55E" if health_info["connected"] else "#EAB308"
    status_text = "FastAPI Backend: Online" if health_info["connected"] else "Direct Python Engine"

    st.markdown(f"""
    <div style="background: #111C2E; border: 1px solid #26364D; border-radius: 8px; padding: 10px 14px;">
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: {status_dot_color}; box-shadow: 0 0 8px {status_dot_color};"></span>
            <span style="color: #F8FAFC; font-size: 0.8rem; font-weight: 700;">{status_text}</span>
        </div>
        <div style="color: #B8C5D9; font-size: 0.72rem; margin-top: 4px;">
            {engine_meta['engine_name']}
        </div>
    </div>
    """, unsafe_allow_html=True)

    if not health_info["connected"]:
        st.caption("💡 Run FastAPI: `python -m uvicorn backend.main:app --reload --port 8000`")

    # Teammate Backend Integration Expander
    with st.expander("🤝 Teammate Backend Contract"):
        st.info(
            "Backend Adapter is decoupled! Place your AI/model logic in `backend/ai_engine.py` "
            "implementing `analyze_code(code, lang)`. The frontend automatically hooks into it "
            "with zero changes needed!"
        )

    # Version Footer
    st.markdown("""
    <div style="padding-top: 14px; color: #B8C5D9; font-size: 0.72rem; text-align: center;">
        SecureCode AI v2.5 • Enterprise Cyber SaaS<br/>
        Deterministic SAST & Patch Verification
    </div>
    """, unsafe_allow_html=True)


# Compute Cumulative Metrics for 6 Overview Cards
history = st.session_state.scan_history
total_scans = len(history)
total_vulns = sum(item.get("total_vulns", 0) for item in history)
total_critical = sum(item.get("critical", 0) for item in history)
total_high = sum(item.get("high", 0) for item in history)
total_fixed = sum(item.get("fixed", item.get("total_vulns", 0)) for item in history)
unique_files = len(set(item.get("filename", "") for item in history)) if history else 0
if st.session_state.project_scan_result:
    proj_files = st.session_state.project_scan_result.get("summary", {}).get("total_files_scanned", 0)
    files_scanned_count = max(unique_files, proj_files)
else:
    files_scanned_count = max(unique_files, 1 if st.session_state.current_analysis else 0)

avg_score = round(sum(item.get("score", 100) for item in history) / total_scans, 1) if total_scans > 0 else 100


# ===========================================================================
# VIEW 1: DASHBOARD
# ===========================================================================
if selected_nav == "📊 Dashboard":
    render_top_header()

    # 6 Overview Metric Cards
    render_overview_metric_cards_6(
        score=int(avg_score),
        total_vulns=total_vulns,
        critical_vulns=total_critical,
        high_vulns=total_high,
        fixed_vulns=total_fixed,
        files_scanned=files_scanned_count
    )

    st.write("")

    # Dashboard Body: Posture Radial + Severity Bar Chart
    dash_col1, dash_col2 = st.columns([5, 3])

    with dash_col1:
        st.markdown("### 📈 Threat & Severity Distribution")

        if st.session_state.current_analysis:
            cur_sum = st.session_state.current_analysis.get("summary", {})
            chart_fig = render_plotly_severity_chart(
                critical=cur_sum.get("critical", 0),
                high=cur_sum.get("high", 0),
                medium=cur_sum.get("medium", 0),
                low=cur_sum.get("low", 0)
            )
            st.plotly_chart(chart_fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("Run an audit to view live severity charts.")

        st.markdown("### 🕒 Recent Scan Activity")
        render_scan_activity_table(history)

    with dash_col2:
        st.markdown("### 🛡️ Active Security Rating")
        cur_score = st.session_state.current_analysis.get("summary", {}).get("health_score", 100) if st.session_state.current_analysis else 100
        cur_issues = st.session_state.current_analysis.get("summary", {}).get("total_vulnerabilities", 0) if st.session_state.current_analysis else 0
        st.markdown(render_circular_score(cur_score, cur_issues), unsafe_allow_html=True)

        st.write("")
        st.markdown("""
        <div class="cyber-card" style="text-align: center;">
            <h4 style="color: #F8FAFC; margin: 0 0 6px 0;">Multi-Module Defense</h4>
            <p style="color: #B8C5D9; font-size: 0.85rem; margin-bottom: 12px;">
                Scan single files, entire multi-file project archives, or explore the Attack Simulation Lab.
            </p>
        </div>
        """, unsafe_allow_html=True)

        qc1, qc2 = st.columns(2)
        with qc1:
            if st.button("🔍 New Scan", type="primary", use_container_width=True):
                st.session_state.active_nav = "🔍 New Code Scan"
                st.rerun()
        with qc2:
            if st.button("📁 ZIP Audit", use_container_width=True):
                st.session_state.active_nav = "📁 Project Scanner"
                st.rerun()


# ===========================================================================
# VIEW 2: NEW CODE SCAN (Single File SAST Scanner)
# ===========================================================================
elif selected_nav == "🔍 New Code Scan":
    render_top_header()

    cur_score = st.session_state.current_analysis.get("summary", {}).get("health_score", 100) if st.session_state.current_analysis else 100
    cur_vulns = st.session_state.current_analysis.get("summary", {}).get("total_vulnerabilities", 0) if st.session_state.current_analysis else 0
    cur_crit = st.session_state.current_analysis.get("summary", {}).get("critical", 0) if st.session_state.current_analysis else 0
    cur_high = st.session_state.current_analysis.get("summary", {}).get("high", 0) if st.session_state.current_analysis else 0
    cur_fixed = cur_vulns

    # 6 Metric Cards
    render_overview_metric_cards_6(cur_score, cur_vulns, cur_crit, cur_high, cur_fixed, files_scanned_count)

    st.write("")
    st.markdown("### 📥 Code Scanner & Target Configuration")

    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 2, 2])

    with ctrl_col1:
        lang_map = {
            "Python (.py)": "python",
            "JavaScript (.js)": "javascript",
            "Java (.java)": "java",
            "C / C++ (.cpp, .c)": "cpp"
        }
        current_idx = list(lang_map.values()).index(st.session_state.selected_language) if st.session_state.selected_language in lang_map.values() else 0
        chosen_label = st.selectbox(
            "Target Programming Language",
            options=list(lang_map.keys()),
            index=current_idx
        )
        st.session_state.selected_language = lang_map[chosen_label]

    with ctrl_col2:
        code_lines = len(st.session_state.current_code.splitlines()) if st.session_state.current_code else 0
        code_bytes = len(st.session_state.current_code.encode("utf-8")) if st.session_state.current_code else 0
        st.markdown(f"""
        <div style="background: #111C2E; border: 1px solid #26364D; border-radius: 8px; padding: 10px 14px; margin-top: 24px;">
            <span style="color: #B8C5D9; font-size: 0.72rem; text-transform: uppercase; font-weight: 700;">Target File:</span>
            <span style="color: #3186FF; font-family: monospace; font-weight: 600;">{st.session_state.current_filename}</span><br/>
            <span style="color: #B8C5D9; font-size: 0.76rem;">{code_lines} lines • {code_bytes} bytes</span>
        </div>
        """, unsafe_allow_html=True)

    with ctrl_col3:
        st.markdown("""
        <div style="background: #17243A; border: 1px solid #26364D; border-radius: 8px; padding: 10px 14px; margin-top: 24px;">
            <span style="color: #8B5CF6; font-size: 0.72rem; text-transform: uppercase; font-weight: 700;">Detection Mode:</span><br/>
            <span style="color: #F8FAFC; font-size: 0.85rem; font-weight: 600;">Adapter Fallback / Live Switch</span>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # Dual Code Input: Drag & Drop File Upload vs Live Code Editor
    tab_upload, tab_editor = st.tabs([
        "📁 Drag & Drop Source File",
        "✍️ Code Editor"
    ])

    with tab_upload:
        uploaded_file = st.file_uploader(
            "Upload source code file (.py, .js, .java, .cpp, .c, .h)",
            type=["py", "js", "java", "cpp", "c", "h", "hpp", "txt"],
            help="Upload source files up to 5MB."
        )
        if uploaded_file is not None:
            raw_bytes = uploaded_file.read()
            try:
                file_str = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                file_str = raw_bytes.decode("latin-1")

            st.session_state.current_code = file_str
            st.session_state.current_filename = uploaded_file.name

            ext = uploaded_file.name.split(".")[-1].lower()
            if ext in ["py"]:
                st.session_state.selected_language = "python"
            elif ext in ["js", "jsx", "ts"]:
                st.session_state.selected_language = "javascript"
            elif ext in ["java"]:
                st.session_state.selected_language = "java"
            elif ext in ["cpp", "c", "h", "hpp"]:
                st.session_state.selected_language = "cpp"

            st.success(f"Loaded **{uploaded_file.name}** ({len(file_str.splitlines())} lines)")

    with tab_editor:
        user_code = st.text_area(
            "Source Code Buffer:",
            value=st.session_state.current_code,
            height=280,
            key="cyber_code_editor"
        )
        st.session_state.current_code = user_code

    st.write("")

    # Prominent Scan Code Button
    scan_clicked = st.button(
        "🔍 Scan Code & Run SAST Audit",
        type="primary",
        use_container_width=True
    )

    if scan_clicked:
        if not st.session_state.current_code.strip():
            st.warning("⚠️ Source code buffer is empty. Please upload a file or write code.")
        else:
            progress_bar = st.progress(0, text="Initiating AST parser and security checks...")
            time.sleep(0.15)
            progress_bar.progress(30, text="Scanning token streams for SQLi, XSS, and command injection...")
            time.sleep(0.15)
            progress_bar.progress(70, text="Evaluating hardcoded secrets, unsafe buffers, and debug flags...")
            time.sleep(0.15)
            progress_bar.progress(90, text="Synthesizing automated remediation diff...")

            analysis_result = backend_adapter.analyze_code(
                code=st.session_state.current_code,
                language=st.session_state.selected_language
            )

            progress_bar.progress(100, text="Audit completed!")
            time.sleep(0.15)
            progress_bar.empty()

            st.session_state.current_analysis = analysis_result

            # Append to Scan History
            hist_entry = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "filename": st.session_state.current_filename,
                "language": st.session_state.selected_language.upper(),
                "score": analysis_result["summary"]["health_score"],
                "total_vulns": analysis_result["summary"]["total_vulnerabilities"],
                "critical": analysis_result["summary"]["critical"],
                "high": analysis_result["summary"]["high"],
                "medium": analysis_result["summary"]["medium"],
                "low": analysis_result["summary"]["low"],
                "fixed": analysis_result["summary"]["total_vulnerabilities"]
            }
            st.session_state.scan_history.insert(0, hist_entry)
            st.toast("Security analysis completed successfully!", icon="✅")

    # Vulnerability Results
    if st.session_state.current_analysis:
        res = st.session_state.current_analysis
        summary = res.get("summary", {})
        vulns = res.get("vulnerabilities", [])
        patched_code = res.get("patched_code", "")

        st.markdown("---")
        st.markdown("### 📊 Vulnerability Results & Severity Summary")

        gauge_col, cards_col = st.columns([2, 3])

        with gauge_col:
            health_score = summary.get("health_score", 100)
            total_issues = summary.get("total_vulnerabilities", 0)
            st.markdown(render_circular_score(health_score, total_issues), unsafe_allow_html=True)

        with cards_col:
            st.markdown("""
            <div style="font-size: 0.82rem; font-weight: 700; color: #B8C5D9; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px;">
                Severity Breakdown Cards
            </div>
            """, unsafe_allow_html=True)

            sc1, sc2 = st.columns(2)
            with sc1:
                st.markdown(f"""
                <div class="cyber-card border-accent-red" style="margin-bottom: 12px;">
                    <div class="card-top">
                        <span>Critical Severity</span>
                        <span>🔴</span>
                    </div>
                    <div class="card-value text-critical">{summary.get('critical', 0)}</div>
                    <div class="card-desc">Immediate action required</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="cyber-card border-accent-amber">
                    <div class="card-top">
                        <span>Medium Severity</span>
                        <span>🟡</span>
                    </div>
                    <div class="card-value text-medium">{summary.get('medium', 0)}</div>
                    <div class="card-desc">Scheduled cycle remediation</div>
                </div>
                """, unsafe_allow_html=True)

            with sc2:
                st.markdown(f"""
                <div class="cyber-card border-accent-orange" style="margin-bottom: 12px;">
                    <div class="card-top">
                        <span>High Severity</span>
                        <span>🟠</span>
                    </div>
                    <div class="card-value text-high">{summary.get('high', 0)}</div>
                    <div class="card-desc">Fix prior to release</div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="cyber-card border-accent-cyan">
                    <div class="card-top">
                        <span>Low / Hardening</span>
                        <span>🔵</span>
                    </div>
                    <div class="card-value text-low">{summary.get('low', 0)}</div>
                    <div class="card-desc">Security best practice</div>
                </div>
                """, unsafe_allow_html=True)

        st.write("")
        st.markdown("#### 📋 Vulnerability Findings Matrix")

        if not vulns:
            st.success("🎉 **Clean Bill of Health!** No security vulnerabilities detected in the scanned code.")
        else:
            render_findings_matrix(vulns)

            st.write("")
            st.markdown("#### 📖 Detailed Findings & Remediation Advice")

            for v in vulns:
                sev = v["severity"]
                badge_class = f"sev-{sev.lower()}"
                exp_title = f"Line {v['line_number']} [{sev.upper()}]: {v['name']} ({v['cwe']})"

                with st.expander(exp_title, expanded=(sev == "Critical")):
                    st.markdown(f"""
                    <div style="margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                        <span class="sev-badge {badge_class}">{sev}</span>
                        <span class="tag-line">Line {v['line_number']}</span>
                        <span class="tag-cwe">{v['cwe']}</span>
                    </div>
                    """, unsafe_allow_html=True)

                    st.markdown("**🚨 Vulnerability Explanation:**")
                    st.write(v["description"])

                    st.markdown("**📌 Affected Code Snippet:**")
                    st.code(v["code_snippet"], language=st.session_state.selected_language)

                    st.markdown("**🛡️ Recommended Solution:**")
                    st.info(v["recommendation"])

                    st.markdown("**✅ Suggested Secure Code:**")
                    st.code(v["suggested_fix"], language=st.session_state.selected_language)

                    # Quick navigation button to AutoFix Studio
                    if st.button(f"✨ Open in AutoFix Studio ({v['cwe']})", key=f"btn_autofix_{v['cwe']}_{v['line_number']}"):
                        st.session_state.active_nav = "✨ AutoFix & Remediation"
                        st.rerun()

            st.markdown("---")
            st.markdown("### 🔄 Quick Code Comparison: Original vs. Secured Patch")
            col_orig, col_fixed = st.columns(2)

            with col_orig:
                st.markdown("""
                <div style="border-left: 4px solid #EF4444; padding-left: 8px; margin-bottom: 6px;">
                    <span style="font-weight: 700; color: #EF4444;">🔴 Original Vulnerable Code</span>
                </div>
                """, unsafe_allow_html=True)
                st.code(st.session_state.current_code, language=st.session_state.selected_language, line_numbers=True)

            with col_fixed:
                st.markdown("""
                <div style="border-left: 4px solid #22C55E; padding-left: 8px; margin-bottom: 6px;">
                    <span style="font-weight: 700; color: #22C55E;">🟢 Synthesized Secured Code</span>
                </div>
                """, unsafe_allow_html=True)
                st.code(patched_code, language=st.session_state.selected_language, line_numbers=True)

            st.download_button(
                label="💾 Download Secured Source File",
                data=patched_code,
                file_name=f"secure_patched_{st.session_state.current_filename}",
                mime="text/plain"
            )


# ===========================================================================
# VIEW 3: PROJECT SCANNER (Multi-File ZIP Archive Audit)
# ===========================================================================
elif selected_nav == "📁 Project Scanner":
    render_top_header()

    st.markdown("### 📁 Multi-File Project Scanner (ZIP Archive)")
    st.markdown("""
    Upload an entire software project repository packaged as a `.zip` archive.
    SecureCode AI will extract supported source files (`.py`, `.js`, `.java`, `.cpp`, `.c`)
    and perform a comprehensive security audit across all repository files.
    """)

    # Zip Slip & Sandbox Defense Notice
    st.markdown("""
    <div style="background: #111C2E; border: 1px solid #26364D; border-left: 4px solid #3186FF; border-radius: 8px; padding: 12px 16px; margin-bottom: 18px;">
        <span style="color: #3186FF; font-weight: 700;">🛡️ Built-in Extraction Defenses:</span>
        <span style="color: #B8C5D9; font-size: 0.85rem;">
            Enforces strict Zip Slip path traversal defense (directory breakout rejection),
            30MB uncompressed limit, 2MB single-file limit, and maximum 50 source files.
            Uploaded code is inspected strictly statically and never executed.
        </span>
    </div>
    """, unsafe_allow_html=True)

    uploaded_zip = st.file_uploader(
        "Upload Project ZIP Archive (.zip)",
        type=["zip"],
        help="Upload multi-file project archives up to 30MB."
    )

    if uploaded_zip is not None:
        zip_bytes = uploaded_zip.read()
        btn_scan_zip = st.button("🚀 Analyze Complete Project ZIP", type="primary", use_container_width=True)

        if btn_scan_zip:
            with st.spinner("Extracting archive safely and auditing all project files..."):
                try:
                    proj_res = project_scanner.scan_zip_project(zip_bytes, project_name=uploaded_zip.name)
                    st.session_state.project_scan_result = proj_res
                    st.toast("Project scan completed successfully!", icon="✅")
                except project_scanner.ProjectScannerError as pe:
                    st.error(f"❌ Security Warning: {str(pe)}")
                except Exception as ex:
                    st.error(f"❌ Scan failed: {str(ex)}")

    if st.session_state.project_scan_result:
        proj = st.session_state.project_scan_result
        psum = proj.get("summary", {})
        pfiles = proj.get("files", [])

        st.markdown("---")
        st.markdown(f"### 📊 Project Audit Summary: `{psum.get('project_name', 'Project')}`")

        # Project Score + Metric Cards
        p_score = psum.get("overall_security_score", 100)
        p_total_flaws = psum.get("total_flaws", 0)
        p_files_count = psum.get("total_files_scanned", 0)
        p_vuln_files = psum.get("files_with_vulnerabilities", 0)
        p_clean_files = psum.get("clean_files", 0)

        p_col1, p_col2 = st.columns([2, 4])
        with p_col1:
            st.markdown(render_circular_score(p_score, p_total_flaws), unsafe_allow_html=True)

        with p_col2:
            st.markdown(f"""
            <div class="metric-grid-4" style="margin-top: 10px;">
                <div class="cyber-card border-accent-cyan">
                    <div class="card-top"><span>Files Scanned</span><span>📁</span></div>
                    <div class="card-value text-low">{p_files_count}</div>
                    <div class="card-desc">Source files inspected</div>
                </div>
                <div class="cyber-card border-accent-green">
                    <div class="card-top"><span>Clean Files</span><span>✅</span></div>
                    <div class="card-value text-fixed">{p_clean_files}</div>
                    <div class="card-desc">Zero vulnerabilities</div>
                </div>
                <div class="cyber-card border-accent-orange">
                    <div class="card-top"><span>Vulnerable Files</span><span>⚠️</span></div>
                    <div class="card-value text-high">{p_vuln_files}</div>
                    <div class="card-desc">Contain active flaws</div>
                </div>
                <div class="cyber-card border-accent-red">
                    <div class="card-top"><span>Total Flaws</span><span>🚨</span></div>
                    <div class="card-value text-critical">{p_total_flaws}</div>
                    <div class="card-desc">Remediation required</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.write("")
        st.markdown("#### 📂 Per-File Breakdown & Audit Findings")

        for f_idx, f_entry in enumerate(pfiles):
            f_name = f_entry["filename"]
            f_score = f_entry["score"]
            f_vulns = f_entry["vulnerabilities"]
            f_count = len(f_vulns)
            f_badge = "🟢 CLEAN" if f_count == 0 else f"🔴 {f_count} ISSUE(S)"

            with st.expander(f"{f_badge} — {f_name} (Score: {f_score}/100, {f_entry['language'].upper()})", expanded=(f_count > 0 and f_idx == 0)):
                if not f_vulns:
                    st.success(f"No security vulnerabilities detected in `{f_name}`.")
                else:
                    render_findings_matrix(f_vulns)

        # Export Project Reports
        st.markdown("---")
        st.markdown("#### 📥 Export Consolidated Project Reports")
        pe_col1, pe_col2 = st.columns(2)

        with pe_col1:
            csv_data = project_scanner.generate_project_csv_report(proj)
            st.download_button(
                "⬇️ Download Project CSV Report",
                data=csv_data,
                file_name=f"project_audit_{psum.get('project_name', 'archive')}.csv",
                mime="text/csv",
                use_container_width=True
            )

        with pe_col2:
            json_data = json.dumps(proj, indent=2)
            st.download_button(
                "⬇️ Download Project JSON Report",
                data=json_data,
                file_name=f"project_audit_{psum.get('project_name', 'archive')}.json",
                mime="application/json",
                use_container_width=True
            )


# ===========================================================================
# VIEW 4: AUTOFIX & REMEDIATION (Diff, Rationale & Empirical Verification)
# ===========================================================================
elif selected_nav == "✨ AutoFix & Remediation":
    render_top_header()

    st.markdown("### ✨ AutoFix & Remediation Studio")
    st.markdown("""
    Automatically synthesize context-aware, secure remediation patches.
    **Key Differentiator:** SecureCode AI does not guess whether a patch is safe — 
    it empirically **rescans** the remediated code with the security engine to verify resolution.
    """)

    cur_analysis = st.session_state.current_analysis
    if not cur_analysis or not cur_analysis.get("vulnerabilities"):
        st.info("ℹ️ No active vulnerabilities detected in the current code buffer. Scan code in **New Code Scan** to generate patches.")
        target_code = st.session_state.current_code
        patched_code = target_code
        active_vulns = []
    else:
        target_code = st.session_state.current_code
        active_vulns = cur_analysis.get("vulnerabilities", [])
        patched_code = cur_analysis.get("patched_code", target_code)

    st.write("")

    # Patch Scope Selector
    scope_options = ["Remediate All Vulnerabilities (Full Patch)"] + [
        f"Line {v['line_number']} [{v['severity']}]: {v['name']} ({v['cwe']})"
        for v in active_vulns
    ]

    selected_scope = st.selectbox("Select Remediation Target:", scope_options)

    if selected_scope == "Remediate All Vulnerabilities (Full Patch)":
        target_cwe = None
        working_patch = patched_code
        patch_info = {
            "cwe": "Multi-Vulnerability",
            "rationale": "Applies bottom-up remediation transforms resolving all detected SQLi, XSS, credential leaks, and unsafe buffers."
        }
    else:
        # Extract selected vulnerability
        v_idx = scope_options.index(selected_scope) - 1
        sel_vuln = active_vulns[v_idx]
        target_cwe = sel_vuln.get("cwe")
        patch_info = autofix.generate_patch_for_vulnerability(target_code, sel_vuln, language=st.session_state.selected_language)
        working_patch = patch_info.get("modified_code", patched_code)

    # 1. Plain-English Safety Rationale
    cwe_for_rationale = target_cwe or (active_vulns[0].get("cwe") if active_vulns else "CWE-89")
    rationale_text = autofix.REMEDIATION_RATIONALES.get(
        cwe_for_rationale,
        "Remediates vulnerable logic using hardened standard library constructs, parameterized queries, and safe buffer bounds."
    )

    st.markdown(f"""
    <div style="background: #111C2E; border: 1px solid #26364D; border-left: 4px solid #22C55E; border-radius: 8px; padding: 14px 18px; margin: 12px 0 18px 0;">
        <span style="color: #22C55E; font-weight: 700; font-size: 0.95rem;">🛡️ Remediation Safety Rationale ({cwe_for_rationale}):</span>
        <div style="color: #F8FAFC; font-size: 0.88rem; margin-top: 6px; line-height: 1.5;">
            {rationale_text}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 2. Side-by-Side Diff Visualizer
    col_v1, col_v2 = st.columns(2)
    with col_v1:
        st.markdown("""
        <div style="border-left: 4px solid #EF4444; padding-left: 8px; margin-bottom: 6px;">
            <span style="font-weight: 700; color: #EF4444;">🔴 Original Vulnerable Source</span>
        </div>
        """, unsafe_allow_html=True)
        st.code(target_code, language=st.session_state.selected_language, line_numbers=True)

    with col_v2:
        st.markdown("""
        <div style="border-left: 4px solid #22C55E; padding-left: 8px; margin-bottom: 6px;">
            <span style="font-weight: 700; color: #22C55E;">🟢 Proposed Secured Patch</span>
        </div>
        """, unsafe_allow_html=True)
        st.code(working_patch, language=st.session_state.selected_language, line_numbers=True)

    # Unified Diff expander
    with st.expander("🔍 View Unified Diff (+ / - Line Comparison)"):
        diff_text = autofix.get_unified_diff(target_code, working_patch, filename=st.session_state.current_filename)
        st.code(diff_text, language="diff")

    st.markdown("---")

    # 3. Empirical Patch Verification Action
    st.markdown("### 🔬 Empirical Patch Verification (Rescan Validation)")
    st.caption("Click below to trigger a live re-audit on the patched code. SecureCode AI evaluates whether the flaw is genuinely resolved without introducing new flaws.")

    btn_verify = st.button("🧪 Verify Patch with SAST Rescan", type="primary", use_container_width=True)

    if btn_verify:
        with st.spinner("Rescanning patched source code through SAST engine..."):
            verification_result = patch_verifier.verify_patch(
                original_analysis=cur_analysis or {"vulnerabilities": []},
                patched_code=working_patch,
                target_vuln_cwe=target_cwe,
                language=st.session_state.selected_language
            )
            st.session_state.last_patch_verification = verification_result

    if st.session_state.last_patch_verification:
        v_res = st.session_state.last_patch_verification
        v_status = v_res.get("status")
        v_msg = v_res.get("message")
        v_prev = v_res.get("previous_count", 0)
        v_new = v_res.get("new_count", 0)
        v_score_prev = v_res.get("previous_score", 0)
        v_score_new = v_res.get("new_score", 100)
        v_delta = v_res.get("score_delta", 0)

        # Status badge colors
        if v_status == patch_verifier.STATUS_RESOLVED:
            v_badge_color = "#22C55E"
            v_bg = "rgba(34, 197, 94, 0.15)"
            v_icon = "✅"
        elif v_status == patch_verifier.STATUS_STILL_DETECTED:
            v_badge_color = "#EF4444"
            v_bg = "rgba(239, 68, 68, 0.15)"
            v_icon = "❌"
        elif v_status == patch_verifier.STATUS_NEW_FINDINGS:
            v_badge_color = "#F97316"
            v_bg = "rgba(249, 115, 22, 0.15)"
            v_icon = "⚠️"
        else:
            v_badge_color = "#38BDF8"
            v_bg = "rgba(56, 189, 248, 0.15)"
            v_icon = "ℹ️"

        st.markdown(f"""
        <div style="background: #111C2E; border: 1px solid #26364D; border-left: 5px solid {v_badge_color}; border-radius: 8px; padding: 16px 20px; margin: 16px 0;">
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <div>
                    <span style="font-size: 1.15rem; font-weight: 800; color: {v_badge_color};">
                        {v_icon} Verification Status: {v_status}
                    </span>
                    <div style="color: #F8FAFC; font-size: 0.9rem; margin-top: 6px;">
                        {v_msg}
                    </div>
                </div>
                <div style="text-align: right;">
                    <span style="color: #B8C5D9; font-size: 0.8rem; text-transform: uppercase;">Score Delta:</span><br/>
                    <span style="font-size: 1.5rem; font-weight: 800; color: #22C55E; font-family: monospace;">
                        {v_score_prev} ➔ {v_score_new} (+{v_delta})
                    </span>
                </div>
            </div>
            <div style="display: flex; gap: 24px; margin-top: 12px; border-top: 1px solid #17243A; padding-top: 10px;">
                <span style="color: #B8C5D9; font-size: 0.82rem;">Flaws Before: <strong style="color: #EF4444;">{v_prev}</strong></span>
                <span style="color: #B8C5D9; font-size: 0.82rem;">Flaws After: <strong style="color: #22C55E;">{v_new}</strong></span>
                <span style="color: #B8C5D9; font-size: 0.82rem;">Resolved CWEs: <strong style="color: #22C55E;">{', '.join(v_res.get('resolved_cwes', [])) or 'None'}</strong></span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Download Remediated Code
    st.download_button(
        "💾 Download Verified Secure Code",
        data=working_patch,
        file_name=f"secured_{st.session_state.current_filename}",
        mime="text/plain",
        use_container_width=True
    )


# ===========================================================================
# VIEW 5: ATTACK SIMULATION LAB (Educational Conceptual Visualizer)
# ===========================================================================
elif selected_nav == "🧪 Attack Simulation Lab":
    render_top_header()

    st.markdown("### 🧪 Attack Simulation Lab (Educational Playground)")
    st.markdown("""
    Explore interactive conceptual attack simulations to understand how security vulnerabilities execute in memory
    and how secure code paradigms neutralize exploit payloads.
    """)

    # Safety Disclaimer
    st.markdown("""
    <div style="background: #111C2E; border: 1px solid #26364D; border-left: 4px solid #EAB308; border-radius: 8px; padding: 12px 16px; margin-bottom: 18px;">
        <span style="color: #EAB308; font-weight: 700;">⚠️ Safe Educational Demonstration:</span>
        <span style="color: #B8C5D9; font-size: 0.85rem;">
            All simulations are 100% static and purely conceptual demonstrations.
            No live database connections, remote servers, or operating system shells are executed.
        </span>
    </div>
    """, unsafe_allow_html=True)

    sims = attack_simulator.get_available_simulations()
    sim_keys = list(sims.keys())
    sim_labels = [f"{sims[k]['title']} ({sims[k]['cwe']})" for k in sim_keys]

    selected_label = st.selectbox("Select Attack Simulation Vector:", sim_labels)
    chosen_key = sim_keys[sim_labels.index(selected_label)]
    sim_data = sims[chosen_key]

    st.write("")

    sim_col1, sim_col2 = st.columns([3, 2])
    with sim_col1:
        st.markdown(f"#### 🎯 Attack Vector: {sim_data['title']}")
        st.write(sim_data["explanation"])
        st.markdown(f"**Exploit Impact:** `{sim_data['impact']}`")

    with sim_col2:
        custom_input = st.text_input(
            "Test Payload String:",
            value=sim_data["sample_input"],
            help="Simulated payload passed into vulnerable vs secure handlers."
        )

    st.write("")

    # Side-by-Side Code Implementation
    sc_c1, sc_c2 = st.columns(2)
    with sc_c1:
        st.markdown("""
        <div style="border-left: 4px solid #EF4444; padding-left: 8px; margin-bottom: 6px;">
            <span style="font-weight: 700; color: #EF4444;">🔴 Vulnerable Implementation</span>
        </div>
        """, unsafe_allow_html=True)
        st.code(sim_data["vulnerable_code"], language="python" if "def " in sim_data["vulnerable_code"] else "javascript")

    with sc_c2:
        st.markdown("""
        <div style="border-left: 4px solid #22C55E; padding-left: 8px; margin-bottom: 6px;">
            <span style="font-weight: 700; color: #22C55E;">🟢 Remediated Implementation</span>
        </div>
        """, unsafe_allow_html=True)
        st.code(sim_data["secure_code"], language="python" if "def " in sim_data["secure_code"] else "javascript")

    st.write("")
    btn_sim = st.button("🚀 Run Conceptual Attack Simulation", type="primary", use_container_width=True)

    if btn_sim:
        sim_run = attack_simulator.simulate_attack(chosen_key, custom_input)

        st.markdown("---")
        st.markdown("### 👁️ Simulated Execution Results")

        res_c1, res_c2 = st.columns(2)

        with res_c1:
            st.markdown(f"""
            <div class="cyber-card border-accent-red">
                <div class="card-top">
                    <span>Vulnerable Code Output</span>
                    <span>🚨</span>
                </div>
                <div style="font-size: 1.15rem; font-weight: 800; color: #EF4444; margin-bottom: 8px;">
                    {sim_run['vulnerable_output']['status']}
                </div>
                <div style="color: #B8C5D9; font-size: 0.85rem; margin-bottom: 8px;">
                    <strong>Behavior:</strong> {sim_run['vulnerable_output']['simulated_db_action' if 'simulated_db_action' in sim_run['vulnerable_output'] else 'simulated_browser_action' if 'simulated_browser_action' in sim_run['vulnerable_output'] else 'simulated_os_action']}
                </div>
                <div style="background: #080D18; border: 1px solid #26364D; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 0.8rem; color: #EF4444;">
                    {sim_run['vulnerable_output']['interpolated_query' if 'interpolated_query' in sim_run['vulnerable_output'] else 'parsed_dom' if 'parsed_dom' in sim_run['vulnerable_output'] else 'interpolated_command']}
                </div>
                <div style="color: #F8FAFC; font-size: 0.82rem; margin-top: 8px;">
                    {sim_run['vulnerable_output']['verdict']}
                </div>
            </div>
            """, unsafe_allow_html=True)

        with res_c2:
            st.markdown(f"""
            <div class="cyber-card border-accent-green">
                <div class="card-top">
                    <span>Remediated Code Output</span>
                    <span>✅</span>
                </div>
                <div style="font-size: 1.15rem; font-weight: 800; color: #22C55E; margin-bottom: 8px;">
                    {sim_run['secure_output']['status']}
                </div>
                <div style="color: #B8C5D9; font-size: 0.85rem; margin-bottom: 8px;">
                    <strong>Behavior:</strong> {sim_run['secure_output']['simulated_db_action' if 'simulated_db_action' in sim_run['secure_output'] else 'simulated_browser_action' if 'simulated_browser_action' in sim_run['secure_output'] else 'simulated_os_action']}
                </div>
                <div style="background: #080D18; border: 1px solid #26364D; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 0.8rem; color: #22C55E;">
                    {sim_run['secure_output']['parameter_binding' if 'parameter_binding' in sim_run['secure_output'] else 'parsed_dom' if 'parsed_dom' in sim_run['secure_output'] else 'execution_array']}
                </div>
                <div style="color: #F8FAFC; font-size: 0.82rem; margin-top: 8px;">
                    {sim_run['secure_output']['verdict']}
                </div>
            </div>
            """, unsafe_allow_html=True)


# ===========================================================================
# VIEW 6: SECURITY RISK ANALYTICS, SECRETS & DEPENDENCIES
# ===========================================================================
elif selected_nav == "📈 Security Analytics":
    render_top_header()

    st.markdown("### 📈 Security Risk Analytics & Deep Inspection")
    st.markdown("""
    Comprehensive risk scoring models, highest-priority threat spotlighting, secret token scanning,
    and dependency vulnerability analysis cross-referenced against the OSV advisory catalog.
    """)

    cur_vulns = st.session_state.current_analysis.get("vulnerabilities", []) if st.session_state.current_analysis else []
    risk_data = risk_analyzer.analyze_project_risk(cur_vulns)

    # 1. Composite Risk Model
    rk_col1, rk_col2 = st.columns([2, 4])

    with rk_col1:
        st.markdown(f"""
        <div class="radial-wrapper">
            <div style="font-size: 0.8rem; font-weight: 700; color: #B8C5D9; text-transform: uppercase;">Composite Threat Index</div>
            <div class="radial-score-large" style="color: {risk_data['risk_color']}; font-size: 3.2rem; margin: 16px 0;">
                {risk_data['overall_risk_score']}
            </div>
            <div style="font-size: 0.95rem; font-weight: 800; color: {risk_data['risk_color']}; text-transform: uppercase;">
                {risk_data['risk_tier']}
            </div>
            <div style="font-size: 0.78rem; color: #B8C5D9; margin-top: 6px;">
                Calculated via CVSS Multipliers
            </div>
        </div>
        """, unsafe_allow_html=True)

    with rk_col2:
        top_flaw = risk_data.get("highest_priority_vuln")
        top_flaw_title = f"{top_flaw['name']} ({top_flaw['cwe']})" if top_flaw else "None Identified"
        top_flaw_desc = top_flaw['description'] if top_flaw else "No critical or high-risk vulnerabilities flagged in buffer."

        st.markdown(f"""
        <div class="cyber-card border-accent-red" style="margin-bottom: 14px;">
            <div class="card-top">
                <span>Highest Priority Vulnerability Spotlight</span>
                <span>🚨</span>
            </div>
            <div style="font-size: 1.15rem; font-weight: 800; color: #EF4444; margin-bottom: 6px;">
                {top_flaw_title}
            </div>
            <div style="color: #F8FAFC; font-size: 0.86rem; line-height: 1.5;">
                {top_flaw_desc}
            </div>
        </div>

        <div class="cyber-card border-accent-purple">
            <div class="card-top">
                <span>Active Threat Factors</span>
                <span>⚡</span>
            </div>
            <ul style="color: #B8C5D9; font-size: 0.85rem; margin: 4px 0 0 16px; padding: 0;">
                {''.join(f"<li>{factor}</li>" for factor in risk_data.get('risk_factors', []))}
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # Prioritized Remediation Roadmap
    if risk_data.get("remediation_order"):
        st.markdown("#### 🎯 Prioritized Remediation Roadmap Queue")
        q_rows = []
        for q in risk_data["remediation_order"]:
            sev_class = f"sev-{q['severity'].lower()}"
            q_rows.append(f"""
            <tr>
                <td style="font-weight: 700; color: #3186FF;">#{q['priority']}</td>
                <td><span class="sev-badge {sev_class}">{q['severity']}</span></td>
                <td><span class="tag-cwe">{q['cwe']}</span></td>
                <td style="color: #F8FAFC; font-weight: 600;">{q['name']}</td>
                <td style="color: #B8C5D9; font-size: 0.82rem;">{q['action']}</td>
            </tr>
            """)

        queue_html = f"""
        <div class="cyber-table-container">
            <table class="cyber-table">
                <thead>
                    <tr>
                        <th style="width: 8%;">Rank</th>
                        <th style="width: 12%;">Severity</th>
                        <th style="width: 14%;">CWE</th>
                        <th style="width: 26%;">Vulnerability</th>
                        <th style="width: 40%;">Recommended Action</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(q_rows)}
                </tbody>
            </table>
        </div>
        """
        st.markdown(queue_html, unsafe_allow_html=True)

    st.markdown("---")

    # Deep Inspection Tabs: Secrets Detector & Dependency Scanner
    tab_secrets, tab_deps = st.tabs([
        "🔑 Secret & Credential Detector",
        "📦 Dependency Vulnerability Scanner"
    ])

    # Tab 1: Secret & Credential Detector
    with tab_secrets:
        st.markdown("#### 🔑 Hardcoded Secrets & Token Detector")
        st.caption("Scans source code for leaked OpenAI keys, AWS Access IDs, Google Cloud tokens, JWTs, and database credentials.")

        secret_input = st.text_area(
            "Code Buffer for Secret Inspection:",
            value=st.session_state.current_code,
            height=180,
            key="secret_scan_buffer"
        )

        if st.button("🔍 Scan for Leaked Credentials", type="primary"):
            findings = secret_detector.scan_for_secrets(secret_input)
            if not findings:
                st.success("✅ Clean: No exposed cryptographic keys, API tokens, or hardcoded passwords found.")
            else:
                st.warning(f"🚨 Detected **{len(findings)}** exposed secret(s) in code buffer!")
                sec_rows = []
                for s in findings:
                    sec_rows.append(f"""
                    <tr>
                        <td><span class="tag-line">Line {s['line_number']}</span></td>
                        <td><span class="sev-badge sev-critical">{s['severity']}</span></td>
                        <td style="color: #F8FAFC; font-weight: 600;">{s['type']}</td>
                        <td><code style="background: #080D18; color: #EF4444; padding: 2px 8px; border: 1px solid #EF4444; border-radius: 4px;">{s['masked_value']}</code></td>
                        <td style="color: #B8C5D9; font-size: 0.82rem;">{s['recommendation']}</td>
                    </tr>
                    """)

                sec_table = f"""
                <div class="cyber-table-container">
                    <table class="cyber-table">
                        <thead>
                            <tr>
                                <th>Line #</th>
                                <th>Severity</th>
                                <th>Token Type</th>
                                <th>Masked Value</th>
                                <th>Remediation Advice</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(sec_rows)}
                        </tbody>
                    </table>
                </div>
                """
                st.markdown(sec_table, unsafe_allow_html=True)

    # Tab 2: Dependency Vulnerability Scanner
    with tab_deps:
        st.markdown("#### 📦 Software Bill of Materials (SBOM) & Dependency Audit")
        st.caption("Audits manifest files (`requirements.txt`, `package.json`, `pom.xml`) against Google OSV CVE advisories.")

        sample_manifests = {
            "Python (requirements.txt with Log4Shell/Requests flaw)": (
                "requirements.txt",
                "requests==2.28.0\nflask==2.1.0\nurllib3==1.26.5\ndjango==4.1.0\npillow==9.0.0\npytest==7.4.0\n"
            ),
            "JavaScript (package.json with Lodash/Axios flaw)": (
                "package.json",
                '{\n  "name": "vulnerable-app",\n  "dependencies": {\n    "lodash": "4.17.15",\n    "axios": "0.21.1",\n    "express": "4.18.2"\n  }\n}'
            ),
            "Java (pom.xml with Log4j 2.14.1 Log4Shell)": (
                "pom.xml",
                '<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n      <artifactId>log4j-core</artifactId>\n      <version>2.14.1</version>\n    </dependency>\n  </dependencies>\n</project>'
            )
        }

        chosen_manifest_key = st.selectbox("Select Manifest Template or Provide Custom Input:", list(sample_manifests.keys()))
        default_filename, default_content = sample_manifests[chosen_manifest_key]

        manifest_text = st.text_area("Manifest Content:", value=default_content, height=180)

        if st.button("📦 Audit Dependencies against OSV Database", type="primary"):
            m_type = dependency_scanner.detect_manifest_type(default_filename)
            dep_res = dependency_scanner.scan_manifest_dependencies(manifest_text, m_type)

            st.write("")
            dep_sum = dep_res.get("summary", {})
            st.markdown(f"**Total Packages:** `{dep_sum.get('total_dependencies', 0)}` • **Vulnerable:** `<span style='color: #EF4444;'>{dep_sum.get('vulnerable_dependencies', 0)}</span>`", unsafe_allow_html=True)

            dep_flaws = dep_res.get("vulnerabilities", [])
            if not dep_flaws:
                st.success("✅ All declared dependencies are on clean or patched releases with zero active OSV advisories.")
            else:
                dep_rows = []
                for df in dep_flaws:
                    sev_class = f"sev-{df['severity'].lower()}"
                    dep_rows.append(f"""
                    <tr>
                        <td style="color: #F8FAFC; font-weight: 700; font-family: monospace;">{df['package']}</td>
                        <td><code style="background: #080D18; color: #EF4444; padding: 2px 6px; border-radius: 4px;">{df['installed_version']}</code></td>
                        <td><span class="sev-badge {sev_class}">{df['severity']}</span></td>
                        <td><span class="tag-cwe">{df['cve']}</span></td>
                        <td style="color: #B8C5D9; font-size: 0.82rem;">{df['advisory_title']}</td>
                        <td><code style="background: rgba(34, 197, 94, 0.2); color: #22C55E; border: 1px solid #22C55E; padding: 2px 6px; border-radius: 4px;">{df['fixed_version']}</code></td>
                    </tr>
                    """)

                dep_table = f"""
                <div class="cyber-table-container">
                    <table class="cyber-table">
                        <thead>
                            <tr>
                                <th>Package</th>
                                <th>Installed</th>
                                <th>Severity</th>
                                <th>CVE ID</th>
                                <th>Advisory Summary</th>
                                <th>Safe Upgrade Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(dep_rows)}
                        </tbody>
                    </table>
                </div>
                """
                st.markdown(dep_table, unsafe_allow_html=True)


# ===========================================================================
# VIEW 7: SCAN HISTORY & DEVELOPER SCORECARD
# ===========================================================================
elif selected_nav == "📜 Scan History":
    render_top_header()

    # 6 Metric Cards
    render_overview_metric_cards_6(int(avg_score), total_vulns, total_critical, total_high, total_fixed, files_scanned_count)

    st.write("")
    st.markdown("### 🏆 Developer Security Scorecard")
    st.caption("Tracks your posture trajectory across iterative code scans in this session.")

    history = st.session_state.scan_history

    if len(history) >= 2:
        latest = history[0]
        previous = history[1]
        score_diff = latest.get("score", 100) - previous.get("score", 100)
        vuln_diff = latest.get("total_vulns", 0) - previous.get("total_vulns", 0)

        diff_symbol = "+" if score_diff >= 0 else ""
        diff_color = "#22C55E" if score_diff >= 0 else "#EF4444"

        st.markdown(f"""
        <div class="cyber-card" style="margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    <span style="font-size: 1.15rem; font-weight: 800; color: #F8FAFC;">Scan Trajectory (Latest vs Previous)</span>
                    <div style="color: #B8C5D9; font-size: 0.85rem; margin-top: 4px;">
                        Comparing {latest['filename']} with {previous['filename']}
                    </div>
                </div>
                <div>
                    <span style="font-size: 1.6rem; font-weight: 800; color: {diff_color}; font-family: monospace;">
                        {diff_symbol}{score_diff} Score Points
                    </span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")
    st.markdown("### 📜 Scan & Audit History")

    if not history:
        st.info("No scan records found in this session. Head to **New Code Scan** to audit your code!")
    else:
        top_h1, top_h2 = st.columns([5, 1])
        with top_h1:
            st.caption(f"Showing **{len(history)}** historical audits logged in session memory:")
        with top_h2:
            if st.button("🗑️ Clear History", use_container_width=True):
                st.session_state.scan_history = []
                st.rerun()

        render_scan_activity_table(history)


# ===========================================================================
# VIEW 8: REPORTS & CI/CD PIPELINE INTEGRATION
# ===========================================================================
elif selected_nav == "📄 Reports & CI/CD":
    render_top_header()

    res = st.session_state.current_analysis
    if not res:
        st.warning("⚠️ No active scan report available. Run an audit in **New Code Scan** first!")
    else:
        summary = res.get("summary", {})
        health_score = summary.get("health_score", 100)
        total_vulns = summary.get("total_vulnerabilities", 0)
        crit_vulns = summary.get("critical", 0)
        high_vulns = summary.get("high", 0)
        fixed_vulns = total_vulns

        # 6 Metric Cards
        render_overview_metric_cards_6(health_score, total_vulns, crit_vulns, high_vulns, fixed_vulns, files_scanned_count)

        st.write("")
        st.markdown("### 📥 Compliance & Audit Reports")
        st.caption("Export audit findings in standard JSON, PDF, CSV, and Text summary formats.")

        # 4 Download Cards (JSON, PDF, CSV, TXT)
        rep_col1, rep_col2, rep_col3, rep_col4 = st.columns(4)

        # 1. JSON Report Card
        with rep_col1:
            st.markdown("""
            <div class="report-export-box">
                <div>
                    <div class="report-box-icon">📦</div>
                    <div class="report-box-title">JSON Report</div>
                    <div class="report-box-desc">Structured machine-readable data for CI/CD pipelines and SIEM.</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            json_str = backend_adapter.fetch_json_report(res)
            st.download_button(
                "⬇️ Download JSON",
                data=json_str,
                file_name=f"SecureCode_{st.session_state.current_filename}.json",
                mime="application/json",
                use_container_width=True
            )

        # 2. PDF Report Card (ReportLab)
        with rep_col2:
            st.markdown("""
            <div class="report-export-box">
                <div>
                    <div class="report-box-icon">📑</div>
                    <div class="report-box-title">PDF Report</div>
                    <div class="report-box-desc">Executive AppSec summary document with metrics and fix guidance.</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            pdf_bytes = backend_adapter.fetch_pdf_report(res)
            st.download_button(
                "⬇️ Download PDF",
                data=pdf_bytes,
                file_name=f"SecureCode_Report_{st.session_state.current_filename}.pdf",
                mime="application/pdf",
                use_container_width=True
            )

        # 3. CSV Matrix Card
        with rep_col3:
            st.markdown("""
            <div class="report-export-box">
                <div>
                    <div class="report-box-icon">📊</div>
                    <div class="report-box-title">CSV Matrix</div>
                    <div class="report-box-desc">Tabular dataset generated with line numbers, CWEs, and steps.</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            csv_str = generate_csv_report(res)
            st.download_button(
                "⬇️ Download CSV",
                data=csv_str,
                file_name=f"SecureCode_{st.session_state.current_filename}.csv",
                mime="text/csv",
                use_container_width=True
            )

        # 4. Text Summary Card
        with rep_col4:
            st.markdown("""
            <div class="report-export-box">
                <div>
                    <div class="report-box-icon">📝</div>
                    <div class="report-box-title">Text Summary</div>
                    <div class="report-box-desc">Human-readable ASCII executive security summary for handoffs.</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            txt_str = generate_text_summary(res, file_name=st.session_state.current_filename)
            st.download_button(
                "⬇️ Download TXT",
                data=txt_str,
                file_name=f"SecureCode_{st.session_state.current_filename}.txt",
                mime="text/plain",
                use_container_width=True
            )

        st.markdown("---")

        # CI/CD Integration Generator
        st.markdown("### ⚙️ CI/CD Integration (GitHub Actions Generator)")
        st.caption("Generate an automated pull-request security gate workflow file for your git repository.")

        ci_c1, ci_c2 = st.columns([2, 4])
        with ci_c1:
            fail_threshold = st.selectbox(
                "Build Failure Threshold:",
                ["Critical Issues Only", "Critical or High Issues", "Any Vulnerability"]
            )
            branch_target = st.text_input("Target Branch:", value="main")

        threshold_flag = "--fail-on-critical" if fail_threshold == "Critical Issues Only" else "--fail-on-high" if fail_threshold == "Critical or High Issues" else "--fail-on-any"

        github_action_yaml = f"""# .github/workflows/securecode.yml
name: SecureCode AI SAST Security Gate

on:
  push:
    branches: [ {branch_target} ]
  pull_request:
    branches: [ {branch_target} ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code Repository
        uses: actions/checkout@v4

      - name: Set up Python Environment
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install SecureCode AI CLI
        run: |
          pip install -r requirements.txt

      - name: Run Static Security Analysis
        run: |
          python -m tests.test_scanner {threshold_flag}

      - name: Archive Security Audit Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: securecode-audit-reports
          path: reports/
"""

        with ci_c2:
            st.code(github_action_yaml, language="yaml")
            st.download_button(
                "⬇️ Download `.github/workflows/securecode.yml`",
                data=github_action_yaml,
                file_name="securecode.yml",
                mime="text/yaml",
                use_container_width=True
            )

        st.markdown("---")
        st.markdown("### 👁️ Live Report Inspector")
        md_str = generate_markdown_report(res, file_name=st.session_state.current_filename)
        preview_tab1, preview_tab2, preview_tab3 = st.tabs(["📄 Formatted Markdown", "📝 Plain Text Summary", "📦 Raw JSON"])
        with preview_tab1:
            st.markdown(md_str)
        with preview_tab2:
            st.text(txt_str)
        with preview_tab3:
            st.json(res)


# ===========================================================================
# VIEW 9: ABOUT SECURECODE AI
# ===========================================================================
elif selected_nav == "ℹ️ About SecureCode AI":
    render_top_header()

    st.markdown("### 🛡️ About SecureCode AI")

    ab_c1, ab_c2 = st.columns([3, 2])
    with ab_c1:
        st.write(
            "**SecureCode AI** is an intelligent static application security testing (SAST), "
            "automated code remediation, and empirical patch verification platform. "
            "It gives developers and AppSec engineers immediate vulnerability visibility, "
            "actionable fix advice, side-by-side patch diffs, and empirical rescan verification."
        )

        st.markdown("#### 📐 System Architecture & Decoupled Pipeline")
        st.markdown("""
        ```
        +-------------------------------------------------------+
        |  Streamlit SaaS Frontend (app.py)                     |
        |  • Dark Navy Theme (#080D18) & High-Contrast Design   |
        |  • 9 Integrated Modules (Project Scanner, AutoFix)    |
        |  • SVG Radial Security Meter & Dark Plotly Charts     |
        |  • Multi-format Exporters (JSON, CSV, TXT, CI/CD)     |
        +-------------------------------------------------------+
                                   │
                                   ▼
        +-------------------------------------------------------+
        |  Backend Adapter (backend_adapter.py)                 |
        |  • Auto-detects live teammate backend                 |
        |  • Transparent fallback to local mock engine          |
        |  • Tags source engine on every finding                |
        +-------------------------------------------------------+
                │                                       │
                ▼                                       ▼
        +-----------------------+       +-----------------------+
        | Live AI Backend       |       | Rule-Based SAST       |
        | (backend/ai_engine.py)|       | (mock_scanner.py)     |
        | Teammate LLM Engine   |       | 9 CWE Categories      |
        +-----------------------+       +-----------------------+
        ```
        """)

        st.markdown("#### ⚖️ Transparency & Integrity Disclosure")
        st.warning(
            "**Transparency Notice:** When operating without an active AI model API key or teammate backend, "
            "SecureCode AI executes deterministic pattern matching rules and regex heuristics via `mock_scanner.py`. "
            "It does NOT claim pattern matching is AI. When teammate backend models are ready, they drop seamlessly "
            "into `backend_adapter.py` without frontend alterations."
        )

    with ab_c2:
        st.markdown("#### 🛠️ Technology Stack")
        st.markdown("""
        - **Frontend:** Streamlit, Custom High-Contrast CSS, Plotly
        - **Data Processing:** Pandas
        - **Theme Palette:**
          - Background: `#080D18`
          - Sidebar: `#0B1220`
          - Cards: `#111C2E`
          - Secondary Card: `#17243A`
          - Primary Accent: `#3186FF`
          - Secondary Accent: `#8B5CF6`
          - Success: `#22C55E`
          - Critical: `#EF4444`
          - High: `#F97316`
          - Medium: `#EAB308`
          - Low: `#38BDF8`
          - Borders: `#26364D`
        - **Supported Languages:** Python, JavaScript, Java, C/C++
        - **Standards Enforced:** OWASP Top 10, CWE-89, CWE-798, CWE-78, CWE-79, CWE-327, CWE-502, CWE-22, CWE-489, CWE-120
        - **OSV / CVE Catalogs:** Real vulnerability advisories for Log4j, Spring, Requests, Flask, Lodash
        """)

        st.markdown("#### 👥 Hackathon Team Division")
        st.markdown("""
        - **Frontend & Integration:** Dashboard UI/UX, SVG gauges, diff visualizer, empirical patch verifier, ZIP extractor.
        - **AI & Backend:** AST parsers, LLM prompt engineering, security model APIs.
        """)

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #B8C5D9; font-size: 0.8rem; padding: 4px 0;">
    🛡️ <strong>SecureCode AI</strong> — Intelligent Code Security, Vulnerability Detection & Auto-Remediation Platform | High-Contrast Dark Cybersecurity SaaS.
</div>
""", unsafe_allow_html=True)

"""
=============================================================================
SecureCode AI - Backend Integration Adapter (backend_adapter.py)
=============================================================================
PURPOSE:
Provides a resilient, transparent bridge connecting the Streamlit Frontend
to the FastAPI REST Backend (http://127.0.0.1:8000).

FEATURES:
- Real REST communication with the FastAPI server via requests.
- Automatic health check and engine capability detection.
- Graceful direct-engine execution if the FastAPI daemon is offline.
- Real analysis via Bandit, Python AST Analyzer, and Multi-Language SAST.
- Downloadable JSON and ReportLab PDF reports.
=============================================================================
"""

import os
import requests
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Direct imports as guaranteed fallback if FastAPI daemon is temporarily offline
from backend.scanner import scan_source_code, normalize_language_name
from backend.database import get_all_scans, get_stats, get_scan
from backend.fixer import generate_secure_patch
from backend.report_generator import generate_json_report, generate_pdf_report
from mock_scanner import get_demo_snippet

API_BASE_URL = os.getenv("SECURECODE_API_ENDPOINT", "http://127.0.0.1:8000")
API_TIMEOUT = 12  # seconds


def check_backend_health() -> Dict[str, Any]:
    """
    Checks if the FastAPI server is running and healthy at API_BASE_URL.
    """
    try:
        resp = requests.get(f"{API_BASE_URL}/health", timeout=1.5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "connected": True,
                "status": "online",
                "service": data.get("service", "SecureCode AI Backend"),
                "version": data.get("version", "1.0.0"),
                "engines": data.get("available_engines", []),
                "url": API_BASE_URL
            }
    except Exception:
        pass

    return {
        "connected": False,
        "status": "offline",
        "service": "Direct Python In-Process Engine",
        "version": "1.0.0",
        "engines": [
            "Bandit Python SAST Engine",
            "Python AST Security Analyzer",
            "Multi-Language Static Rules Engine"
        ],
        "url": API_BASE_URL,
        "notice": f"FastAPI daemon is not reachable at {API_BASE_URL}. Running via direct Python engine."
    }


def get_active_engine_info() -> Dict[str, Any]:
    """Returns metadata describing the currently active engine."""
    health = check_backend_health()
    if health["connected"]:
        return {
            "engine_name": "FastAPI REST Backend (Bandit + AST + Heuristics)",
            "is_mock": False,
            "mode": f"FastAPI REST API ({health['url']})",
            "status": "ONLINE",
            "notice": f"Connected to live FastAPI backend at {health['url']}. Executing Bandit, AST & SAST engines."
        }
    else:
        return {
            "engine_name": "Direct Python Security Engine (Bandit + AST + SAST)",
            "is_mock": False,
            "mode": "Direct Python Execution (FastAPI Offline)",
            "status": "LOCAL",
            "notice": f"FastAPI backend offline at {API_BASE_URL}. Executing real analysis via direct Python engine."
        }


def analyze_code(
    code: str,
    language: str = "python",
    file_name: str = "source_file.py"
) -> Dict[str, Any]:
    """
    Analyzes code by querying the FastAPI backend at /scan/text.
    Falls back to direct scanner execution if FastAPI is offline.
    """
    # 1. Attempt FastAPI REST call
    try:
        resp = requests.post(
            f"{API_BASE_URL}/scan/text",
            json={
                "code": code,
                "language": language,
                "filename": file_name
            },
            timeout=API_TIMEOUT
        )
        if resp.status_code == 200:
            result = resp.json()
            result["metadata"]["backend_mode"] = "FastAPI REST API (http://127.0.0.1:8000)"
            result["metadata"]["is_mock"] = False
            return result
    except Exception:
        pass

    # 2. Fallback to direct Python scanner execution
    result = scan_source_code(code=code, language=language, file_name=file_name)
    result["metadata"]["backend_mode"] = "Direct Python Engine (FastAPI offline)"
    result["metadata"]["is_mock"] = False
    return result


def fetch_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches scan history from FastAPI or direct SQLite database."""
    try:
        resp = requests.get(f"{API_BASE_URL}/history?limit={limit}", timeout=2.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    return get_all_scans(limit=limit)


def fetch_stats() -> Dict[str, Any]:
    """Fetches dashboard metrics from FastAPI or direct SQLite database."""
    try:
        resp = requests.get(f"{API_BASE_URL}/stats", timeout=2.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    return get_stats()


def fetch_pdf_report(scan_result: Dict[str, Any]) -> bytes:
    """Retrieves PDF report from FastAPI or direct ReportLab generator."""
    scan_id = scan_result.get("scan_id")
    if scan_id:
        try:
            resp = requests.get(f"{API_BASE_URL}/report/{scan_id}?format=pdf", timeout=5.0)
            if resp.status_code == 200 and resp.content.startswith(b"%PDF-"):
                return resp.content
        except Exception:
            pass

    return generate_pdf_report(scan_result)


def fetch_json_report(scan_result: Dict[str, Any]) -> str:
    """Retrieves JSON report string."""
    scan_id = scan_result.get("scan_id")
    if scan_id:
        try:
            resp = requests.get(f"{API_BASE_URL}/report/{scan_id}?format=json", timeout=3.0)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass

    return generate_json_report(scan_result)


def suggest_fix(code: str, language: str = "python", target_cwe: Optional[str] = None) -> Dict[str, Any]:
    """Generates remediation patch from FastAPI or direct fixer."""
    try:
        resp = requests.post(
            f"{API_BASE_URL}/fix/suggest",
            json={"code": code, "language": language, "target_cwe": target_cwe},
            timeout=5.0
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    return generate_secure_patch(code, language=language, target_cwe=target_cwe)


# Re-exports for backwards compatibility
normalize_language = normalize_language_name

"""
=============================================================================
SecureCode AI - Multi-File Project ZIP Scanner (project_scanner.py)
=============================================================================
PURPOSE:
Safely unpacks and audits multi-file software projects uploaded as ZIP archives.

SECURITY DEFENSES:
- Zip Slip Defense: Validates canonical paths against base extraction directory.
  Rejects members containing '..' or leading slashes.
- Denial of Service (Zip Bomb) Defense:
  * Maximum total uncompressed size limit: 30 MB
  * Maximum individual file size limit: 2 MB
  * Maximum source file count: 50 files
- Safe Sandbox: Operates entirely inside temporary directories that are wiped
  on completion. Never executes uploaded code.
=============================================================================
"""

import os
import zipfile
import tempfile
import io
import pandas as pd
from typing import Dict, Any, List, Optional
import backend_adapter

# Configuration Limits
MAX_TOTAL_UNCOMPRESSED_BYTES = 30 * 1024 * 1024  # 30 MB
MAX_SINGLE_FILE_BYTES = 2 * 1024 * 1024          # 2 MB
MAX_SOURCE_FILES = 50

# Supported Source File Extensions
SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".cpp": "cpp",
    ".c": "cpp",
    ".h": "cpp",
    ".hpp": "cpp"
}


class ProjectScannerError(Exception):
    """Custom exception raised for invalid or hazardous ZIP archives."""
    pass


def scan_zip_project(zip_bytes: bytes, project_name: str = "project.zip") -> Dict[str, Any]:
    """
    Safely inspects and audits a ZIP project archive.

    Args:
        zip_bytes (bytes): Raw bytes of the uploaded ZIP file.
        project_name (str): Display name of the archive.

    Returns:
        dict: Consolidated multi-file audit report including file-wise findings,
              project-wide security score, and aggregated metrics.
    """
    if not zip_bytes or len(zip_bytes) == 0:
        raise ProjectScannerError("Uploaded ZIP file is empty.")

    try:
        zip_file = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise ProjectScannerError("Invalid ZIP file format. Archive cannot be read.")

    # 1. Pre-extraction safety validation
    total_uncompressed_size = 0
    valid_members = []

    for member in zip_file.infolist():
        # Reject directories
        if member.is_dir():
            continue

        # Prevent Zip Slip / Path Traversal
        filename = member.filename.replace("\\", "/")
        if ".." in filename.split("/") or filename.startswith("/"):
            raise ProjectScannerError(f"Security hazard detected: Zip Slip path traversal attempt in '{member.filename}'.")

        # Check supported file type
        ext = os.path.splitext(filename)[1].lower()
        if ext in SUPPORTED_EXTENSIONS:
            if member.file_size > MAX_SINGLE_FILE_BYTES:
                continue  # Skip oversized individual file
            total_uncompressed_size += member.file_size
            valid_members.append((member, ext))

    if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise ProjectScannerError(f"Archive exceeds maximum allowed uncompressed capacity (30MB limit).")

    if len(valid_members) > MAX_SOURCE_FILES:
        valid_members = valid_members[:MAX_SOURCE_FILES]

    if not valid_members:
        raise ProjectScannerError("No supported source code files (.py, .js, .java, .cpp) were found in the archive.")

    # 2. Extract and scan inside isolated temporary directory
    file_results: List[Dict[str, Any]] = []
    all_vulns: List[Dict[str, Any]] = []
    total_lines = 0

    with tempfile.TemporaryDirectory() as temp_dir:
        for member, ext in valid_members:
            # Extract safely
            target_path = os.path.abspath(os.path.join(temp_dir, member.filename))
            # Verify target path is strictly within temp_dir
            if not target_path.startswith(os.path.abspath(temp_dir)):
                raise ProjectScannerError(f"Extraction path escape detected in '{member.filename}'.")

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with open(target_path, "wb") as f_out:
                f_out.write(zip_file.read(member.filename))

            # Read content as text
            try:
                with open(target_path, "r", encoding="utf-8", errors="replace") as f_in:
                    content = f_in.read()
            except Exception:
                continue

            lang = SUPPORTED_EXTENSIONS.get(ext, "python")
            file_analysis = backend_adapter.analyze_code(content, language=lang)

            lines_in_file = len(content.splitlines())
            total_lines += lines_in_file

            # Tag each vulnerability with its file origin
            for v in file_analysis.get("vulnerabilities", []):
                v_copy = dict(v)
                v_copy["filename"] = member.filename
                v_copy["language"] = lang
                all_vulns.append(v_copy)

            file_results.append({
                "filename": member.filename,
                "language": lang,
                "lines": lines_in_file,
                "score": file_analysis.get("summary", {}).get("health_score", 100),
                "total_vulns": len(file_analysis.get("vulnerabilities", [])),
                "critical": file_analysis.get("summary", {}).get("critical", 0),
                "high": file_analysis.get("summary", {}).get("high", 0),
                "medium": file_analysis.get("summary", {}).get("medium", 0),
                "low": file_analysis.get("summary", {}).get("low", 0),
                "vulnerabilities": file_analysis.get("vulnerabilities", []),
                "patched_code": file_analysis.get("patched_code", "")
            })

    # 3. Aggregate project-wide metrics
    total_critical = sum(f["critical"] for f in file_results)
    total_high = sum(f["high"] for f in file_results)
    total_medium = sum(f["medium"] for f in file_results)
    total_low = sum(f["low"] for f in file_results)
    total_vulns_count = len(all_vulns)

    # Project-wide health score calculation
    deductions = (total_critical * 30) + (total_high * 20) + (total_medium * 10) + (total_low * 5)
    project_score = max(0, min(100, 100 - deductions))

    return {
        "project_name": project_name,
        "files_scanned": len(file_results),
        "total_lines": total_lines,
        "project_score": project_score,
        "summary": {
            "health_score": project_score,
            "total_vulnerabilities": total_vulns_count,
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
            "fixed": total_vulns_count
        },
        "file_results": file_results,
        "all_vulnerabilities": all_vulns
    }


def generate_consolidated_csv(project_report: Dict[str, Any]) -> str:
    """Generates a project-wide consolidated CSV string via Pandas."""
    vulns = project_report.get("all_vulnerabilities", [])
    if not vulns:
        df = pd.DataFrame([{
            "Project": project_report.get("project_name", "Project"),
            "Filename": "N/A",
            "Line": 0,
            "Severity": "Clean",
            "CWE": "N/A",
            "Vulnerability": "No vulnerabilities detected in project files."
        }])
    else:
        rows = []
        for v in vulns:
            rows.append({
                "Filename": v.get("filename", "N/A"),
                "Line": v.get("line_number", 0),
                "Severity": v.get("severity", "Low"),
                "CWE": v.get("cwe", "N/A"),
                "Vulnerability": v.get("name", "Issue"),
                "Snippet": v.get("code_snippet", ""),
                "Recommendation": v.get("recommendation", "")
            })
        df = pd.DataFrame(rows)

    return df.to_csv(index=False)

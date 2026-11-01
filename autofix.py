"""
=============================================================================
SecureCode AI - AutoFix & Patch Engine (autofix.py)
=============================================================================
PURPOSE:
Generates context-aware, secure remediation patches and provides plain-English
explanations of why the corrected code is safer.

EDUCATIONAL TRANSPARENCY:
If the live backend is unavailable, patches are generated via deterministic
remediation templates and clearly labeled as:
'Educational Sample Patch (Rule-Based Synthesis)'
=============================================================================
"""

import re
import difflib
from typing import Dict, Any, List, Optional
import backend_adapter


REMEDIATION_RATIONALES = {
    "CWE-89": (
        "Why this is safer: Parameterized queries decouple SQL command logic from data input. "
        "User characters (such as quotes or semicolons) are treated strictly as literal field data "
        "by the database driver, making SQL syntax hijacking mathematically impossible."
    ),
    "CWE-798": (
        "Why this is safer: Loading secrets at runtime from environment variables (os.getenv) "
        "ensures that sensitive tokens, keys, and passwords never persist in git version control, "
        "preventing unauthorized extraction if code repositories or backups are exposed."
    ),
    "CWE-78": (
        "Why this is safer: Invoking subprocesses with structured argument arrays (shell=False) "
        "directly spawns the operating system executable without invoking a shell interpreter "
        "(sh or cmd.exe). Shell metacharacters (;, &&, |) cannot be injected to chain commands."
    ),
    "CWE-79": (
        "Why this is safer: Assigning to element.textContent (or utilizing auto-escaped templates) "
        "forces the browser to parse input purely as plain text rather than executable markup, "
        "preventing malicious script execution and cookie theft in client sessions."
    ),
    "CWE-327": (
        "Why this is safer: Modern cryptographic algorithms like SHA-256 have large 256-bit hash spaces "
        "and strong collision resistance. Unlike MD5 and SHA-1, there are no known practical collision "
        "attacks capable of generating forged hashes."
    ),
    "CWE-502": (
        "Why this is safer: Standard JSON (json.loads) or yaml.safe_load restricts serialization "
        "strictly to primitive data types (strings, lists, numbers). It prohibits arbitrary Python "
        "or Java object instantiation that attackers abuse for Remote Code Execution."
    ),
    "CWE-22": (
        "Why this is safer: Passing user-supplied filenames through os.path.basename() strips all "
        "relative directory traversal sequences (such as '../../etc/'). Validating against an allowed "
        "base directory confines file access to authorized sandboxes."
    ),
    "CWE-489": (
        "Why this is safer: Disabling debug mode in production prevents interactive debuggers "
        "(like Werkzeug) from providing a browser console to execute arbitrary code, and silences "
        "verbose stack traces that expose database credentials and server layouts."
    ),
    "CWE-120": (
        "Why this is safer: Bounded memory functions (such as strncpy and snprintf) require an explicit "
        "destination buffer capacity argument, preventing writes from overflowing buffer memory boundaries "
        "and corrupting the call stack."
    )
}


def generate_patch_for_vulnerability(
    code: str,
    vuln: Dict[str, Any],
    language: str = "python"
) -> Dict[str, Any]:
    """
    Generates a secure patch specifically targeting an individual vulnerability.

    Returns:
        dict: Patch details including modified code, affected line, and safety rationale.
    """
    lines = code.split("\n")
    target_line_idx = vuln.get("line_number", 1) - 1
    cwe = vuln.get("cwe", "CWE-Unknown")
    vuln_name = vuln.get("name", "Vulnerability")

    original_line = lines[target_line_idx] if 0 <= target_line_idx < len(lines) else ""
    indent = len(original_line) - len(original_line.lstrip()) if original_line else 0
    indent_str = original_line[:indent] if original_line else ""

    fix_pattern = vuln.get("_fix_rule")
    replaced = False
    new_line = original_line

    if fix_pattern and original_line:
        search_re, replace_re = fix_pattern
        new_line, count = re.subn(search_re, replace_re, original_line)
        if count > 0:
            lines[target_line_idx] = new_line
            replaced = True

    if not replaced:
        suggested = vuln.get("suggested_fix", "# Secure coding practice")
        lines[target_line_idx] = (
            f"{indent_str}# [SECURECODE AI AUTO-REMEDIATION: {vuln_name} ({cwe})]\n"
            f"{indent_str}{suggested}"
        )
        new_line = lines[target_line_idx]

    patched_full_code = "\n".join(lines)
    rationale = REMEDIATION_RATIONALES.get(
        cwe,
        "Why this is safer: Replaces an insecure pattern with validated, defensive programming constructs."
    )

    return {
        "vulnerability_id": vuln.get("id"),
        "cwe": cwe,
        "vuln_name": vuln_name,
        "line_number": target_line_idx + 1,
        "original_line": original_line,
        "replacement_line": new_line,
        "original_code": code,
        "patched_code": patched_full_code,
        "rationale": rationale,
        "is_educational_sample": True,
        "source": "Rule-Based Remediation Synthesizer (Educational Sample)"
    }


def generate_full_project_patch(code: str, vulnerabilities: List[Dict[str, Any]]) -> str:
    """Applies all available fixes in reverse order to produce the complete patched code."""
    lines = code.split("\n")
    sorted_vulns = sorted(vulnerabilities, key=lambda v: v.get("line_number", 0), reverse=True)

    for v in sorted_vulns:
        line_idx = v.get("line_number", 1) - 1
        if 0 <= line_idx < len(lines):
            original = lines[line_idx]
            indent = len(original) - len(original.lstrip())
            indent_str = original[:indent]

            fix_pattern = v.get("_fix_rule")
            replaced = False

            if fix_pattern:
                search_re, replace_re = fix_pattern
                new_line, count = re.subn(search_re, replace_re, original)
                if count > 0:
                    lines[line_idx] = new_line
                    replaced = True

            if not replaced:
                suggested = v.get("suggested_fix", "# Secure remediation")
                lines[line_idx] = (
                    f"{indent_str}# [SECURECODE AI FIX: {v.get('name', 'Issue')} ({v.get('cwe', '')})]\n"
                    f"{indent_str}{suggested}"
                )

    return "\n".join(lines)


def get_diff_highlights(original_code: str, patched_code: str) -> List[str]:
    """Computes a unified text diff between original and patched code."""
    orig_lines = original_code.splitlines(keepends=True)
    patch_lines = patched_code.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        orig_lines,
        patch_lines,
        fromfile="Original Code (Vulnerable)",
        tofile="Patched Code (Remediated)",
        n=2
    ))
    return diff

"""
=============================================================================
SecureCode AI - Patch Verification Engine (patch_verifier.py)
=============================================================================
PURPOSE:
Verifies remediation patches by rescanning patched code using the configured
engine (backend_adapter.analyze_code).

VERIFICATION CRITERIA (No assumptions; empirical rescanning only):
- 'Resolved by scanner rule': Target flaw no longer triggers detection.
- 'Still detected': Flaw pattern persists in rescanned code.
- 'New findings introduced': Patch created secondary security warnings.
- 'Verification unavailable': Scanner execution failed or returned empty.
=============================================================================
"""

from typing import Dict, Any, List, Optional
import backend_adapter

STATUS_RESOLVED = "Resolved by scanner rule"
STATUS_STILL_DETECTED = "Still detected"
STATUS_NEW_FINDINGS = "New findings introduced"
STATUS_UNAVAILABLE = "Verification unavailable"


def verify_patch(
    original_analysis: Dict[str, Any],
    patched_code: str,
    target_vuln_cwe: Optional[str] = None,
    language: str = "python"
) -> Dict[str, Any]:
    """
    Empirically verifies a patch by executing a fresh scan on the patched code
    and evaluating the differential delta.

    Args:
        original_analysis (dict): Previous scan results before patching.
        patched_code (str): The code containing proposed fixes.
        target_vuln_cwe (str, optional): The specific CWE ID targeted for resolution.
        language (str): Target programming language.

    Returns:
        dict: Complete verification metrics and comparative breakdown.
    """
    if not patched_code or not patched_code.strip():
        return {
            "status": STATUS_UNAVAILABLE,
            "message": "Patched code is empty. Verification could not proceed.",
            "is_verified": False,
            "previous_count": 0,
            "new_count": 0,
            "resolved_cwes": [],
            "introduced_cwes": [],
            "new_analysis": None
        }

    # 1. Rescan patched code using backend adapter
    try:
        new_analysis = backend_adapter.analyze_code(patched_code, language=language)
    except Exception as e:
        return {
            "status": STATUS_UNAVAILABLE,
            "message": f"Rescan execution failed: {str(e)}",
            "is_verified": False,
            "previous_count": len(original_analysis.get("vulnerabilities", [])),
            "new_count": 0,
            "resolved_cwes": [],
            "introduced_cwes": [],
            "new_analysis": None
        }

    prev_vulns = original_analysis.get("vulnerabilities", [])
    new_vulns = new_analysis.get("vulnerabilities", [])

    prev_cwes = [v.get("cwe") for v in prev_vulns]
    new_cwes = [v.get("cwe") for v in new_vulns]

    # Calculate differential deltas
    resolved_cwes = [cwe for cwe in prev_cwes if cwe not in new_cwes]
    introduced_cwes = [cwe for cwe in new_cwes if cwe not in prev_cwes]

    previous_count = len(prev_vulns)
    new_count = len(new_vulns)

    # 2. Determine verification outcome
    if target_vuln_cwe:
        # Verifying single targeted vulnerability
        if target_vuln_cwe in new_cwes:
            status = STATUS_STILL_DETECTED
            is_verified = False
            msg = f"The target vulnerability ({target_vuln_cwe}) is still detected by the scanner."
        elif introduced_cwes:
            status = STATUS_NEW_FINDINGS
            is_verified = False
            msg = f"Target {target_vuln_cwe} was resolved, but new potential findings were introduced: {', '.join(introduced_cwes)}."
        else:
            status = STATUS_RESOLVED
            is_verified = True
            msg = f"Target vulnerability {target_vuln_cwe} has been successfully resolved without introducing new flaws."
    else:
        # Verifying full project remediation
        if new_count == 0 and previous_count > 0:
            status = STATUS_RESOLVED
            is_verified = True
            msg = f"All {previous_count} vulnerability patterns have been completely neutralized."
        elif new_count < previous_count:
            if introduced_cwes:
                status = STATUS_NEW_FINDINGS
                is_verified = False
                msg = f"Remediated {len(resolved_cwes)} issues, but introduced {len(introduced_cwes)} new finding(s)."
            else:
                status = STATUS_RESOLVED
                is_verified = True
                msg = f"Successfully reduced vulnerability count from {previous_count} to {new_count}."
        elif new_count == previous_count:
            status = STATUS_STILL_DETECTED
            is_verified = False
            msg = "Vulnerability count unchanged. The patch did not satisfy scanner rules."
        else:
            status = STATUS_NEW_FINDINGS
            is_verified = False
            msg = f"Warning: The patched code triggered {new_count - previous_count} additional security alerts."

    score_before = original_analysis.get("summary", {}).get("health_score", 0)
    score_after = new_analysis.get("summary", {}).get("health_score", 100)
    score_delta = score_after - score_before

    return {
        "status": status,
        "message": msg,
        "is_verified": is_verified,
        "previous_count": previous_count,
        "new_count": new_count,
        "score_before": score_before,
        "score_after": score_after,
        "score_delta": score_delta,
        "resolved_cwes": list(set(resolved_cwes)),
        "introduced_cwes": list(set(introduced_cwes)),
        "new_analysis": new_analysis
    }

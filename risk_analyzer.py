"""
=============================================================================
SecureCode AI - Security Risk Analytics Engine (risk_analyzer.py)
=============================================================================
PURPOSE:
Evaluates composite security risk across scanned files, identifies the single
highest-priority threat, and produces an actionable, prioritized remediation order.

METHODOLOGY (Transparent, Non-ML Scoring Model):
Calculates risk using a deterministic formula aligned with CVSS and OWASP
risk rating methodologies:
- Severity Weights: Critical = 25 pts, High = 15 pts, Medium = 8 pts, Low = 3 pts
- Exploitability Factor: +20% if Remote Code Execution or XSS patterns exist
- Sensitive Data Factor: +25% if Credential Leak or SQLi patterns exist
- Composite Project Risk: Clamped between 0 and 100
=============================================================================
"""

from typing import Dict, Any, List

CWE_WEIGHTS = {
    "CWE-78": {"exploitability": 10.0, "impact": 10.0, "category": "Remote Code Execution"},
    "CWE-89": {"exploitability": 9.5, "impact": 9.5, "category": "Data Breach / SQL Injection"},
    "CWE-798": {"exploitability": 9.0, "impact": 9.0, "category": "Credential Exposure"},
    "CWE-120": {"exploitability": 8.5, "impact": 9.5, "category": "Memory Corruption"},
    "CWE-502": {"exploitability": 8.0, "impact": 9.0, "category": "Insecure Deserialization"},
    "CWE-79": {"exploitability": 8.0, "impact": 7.0, "category": "Client-Side Scripting"},
    "CWE-22": {"exploitability": 7.5, "impact": 7.5, "category": "Path Traversal"},
    "CWE-327": {"exploitability": 5.0, "impact": 6.0, "category": "Weak Cryptography"},
    "CWE-489": {"exploitability": 6.0, "impact": 5.0, "category": "Information Disclosure"}
}


def analyze_project_risk(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes a comprehensive risk rating and prioritized remediation roadmap.

    Args:
        vulnerabilities (list): List of detected vulnerability findings.

    Returns:
        dict: Overall risk score, risk tier, highest priority vulnerability,
              and ordered remediation queue.
    """
    if not vulnerabilities:
        return {
            "overall_risk_score": 0,
            "risk_tier": "LOW RISK",
            "risk_color": "#22C55E",
            "highest_priority_vuln": None,
            "remediation_order": [],
            "risk_factors": ["No active security flaws identified."],
            "formula_explanation": "Zero vulnerabilities detected. Baseline risk score is 0."
        }

    critical_count = sum(1 for v in vulnerabilities if v.get("severity") == "Critical")
    high_count = sum(1 for v in vulnerabilities if v.get("severity") == "High")
    medium_count = sum(1 for v in vulnerabilities if v.get("severity") == "Medium")
    low_count = sum(1 for v in vulnerabilities if v.get("severity") == "Low")

    base_score = (critical_count * 25) + (high_count * 15) + (medium_count * 8) + (low_count * 3)

    # Contextual Multipliers
    has_rce = any(v.get("cwe") in ["CWE-78", "CWE-120", "CWE-502"] for v in vulnerabilities)
    has_data_leak = any(v.get("cwe") in ["CWE-89", "CWE-798"] for v in vulnerabilities)

    multiplier = 1.0
    risk_factors = []

    if has_rce:
        multiplier += 0.20
        risk_factors.append("Remote Code Execution / Memory Corruption vector present (+20% risk)")
    if has_data_leak:
        multiplier += 0.25
        risk_factors.append("Direct database access or credential exposure vector present (+25% risk)")

    final_score = int(min(100, round(base_score * multiplier)))

    if final_score >= 75:
        risk_tier = "CRITICAL RISK"
        risk_color = "#EF4444"
    elif final_score >= 50:
        risk_tier = "HIGH RISK"
        risk_color = "#F97316"
    elif final_score >= 25:
        risk_tier = "ELEVATED RISK"
        risk_color = "#EAB308"
    else:
        risk_tier = "LOW RISK"
        risk_color = "#38BDF8"

    # Prioritize findings for the remediation queue
    prioritized_list = []
    for v in vulnerabilities:
        cwe = v.get("cwe", "CWE-Unknown")
        weights = CWE_WEIGHTS.get(cwe, {"exploitability": 5.0, "impact": 5.0, "category": "General"})
        composite_weight = weights["exploitability"] * 0.4 + weights["impact"] * 0.6
        prioritized_list.append({
            "vuln": v,
            "weight": composite_weight,
            "category": weights["category"],
            "urgency": "Immediate" if v.get("severity") == "Critical" else "High" if v.get("severity") == "High" else "Scheduled"
        })

    # Sort descending by priority weight
    prioritized_list.sort(key=lambda x: x["weight"], reverse=True)

    highest_priority = prioritized_list[0]["vuln"] if prioritized_list else None

    # Build actionable remediation roadmap
    remediation_order = []
    for idx, item in enumerate(prioritized_list, start=1):
        v = item["vuln"]
        remediation_order.append({
            "priority_rank": idx,
            "id": v.get("id"),
            "name": v.get("name"),
            "cwe": v.get("cwe"),
            "severity": v.get("severity"),
            "line_number": v.get("line_number"),
            "filename": v.get("filename", "Current Buffer"),
            "category": item["category"],
            "urgency": item["urgency"],
            "action": v.get("recommendation")
        })

    formula_explanation = (
        f"Score calculated via: Base ({critical_count} Crit × 25 + {high_count} High × 15 + "
        f"{medium_count} Med × 8 + {low_count} Low × 3) × {multiplier:.2f} multiplier = {final_score}/100."
    )

    return {
        "overall_risk_score": final_score,
        "risk_tier": risk_tier,
        "risk_color": risk_color,
        "highest_priority_vuln": highest_priority,
        "remediation_order": remediation_order,
        "risk_factors": risk_factors,
        "formula_explanation": formula_explanation
    }

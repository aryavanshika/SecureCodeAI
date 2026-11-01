"""
=============================================================================
SecureCode AI - Secret & Credential Detector (secret_detector.py)
=============================================================================
PURPOSE:
Specialized scanner for detecting leaked cryptographic tokens, API keys,
passwords, and private key blocks in source code.

PRIVACY & SAFETY:
- All detected secret values are strictly MASKED in memory and the UI.
- Full secret values are never saved to reports, logs, or state.
=============================================================================
"""

import re
from typing import Dict, Any, List

SECRET_PATTERNS = [
    {
        "type": "OpenAI / Stripe Style API Key",
        "pattern": r"\b(sk-[A-Za-z0-9_\-]{20,})\b",
        "severity": "Critical"
    },
    {
        "type": "AWS Access Key ID",
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
        "severity": "Critical"
    },
    {
        "type": "Google Cloud API Key",
        "pattern": r"\b(AIza[0-9A-Za-z_\-]{35})\b",
        "severity": "Critical"
    },
    {
        "type": "JSON Web Token (JWT)",
        "pattern": r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+)\b",
        "severity": "High"
    },
    {
        "type": "Private Cryptographic Key",
        "pattern": r"(-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----)",
        "severity": "Critical"
    },
    {
        "type": "Hardcoded Password / Credential",
        "pattern": r"\b(password|passwd|pwd|db_password)\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
        "severity": "Critical"
    },
    {
        "type": "Generic Secret Token",
        "pattern": r"\b(api_key|apikey|secret_key|auth_token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.\/+=@!#$%^&*]{8,})['\"]",
        "severity": "Critical"
    }
]

EXACT_DUMMY_STRINGS = {
    "your_key", "your_secret", "changeme", "placeholder", "todo", "example",
    "insert_here", "dummy", "xxxx", "test_key", "none", "null", "password", "secret"
}


def mask_secret(secret_str: str) -> str:
    """Masks secret to prevent credential exposure in UI or exports."""
    if not secret_str:
        return "********"
    clean = secret_str.strip()
    if len(clean) <= 6:
        return "********"
    if len(clean) <= 12:
        return f"{clean[:2]}****{clean[-2:]}"
    return f"{clean[:4]}{'*' * (len(clean) - 8)}{clean[-4:]}"


def scan_for_secrets(code: str, filename: str = "Source_Buffer") -> List[Dict[str, Any]]:
    """
    Scans code for hardcoded secrets and returns masked findings.

    Args:
        code (str): Source code string to scan.
        filename (str): Source filename for tracking.

    Returns:
        list: Masked secret findings with line numbers and recommendations.
    """
    if not code:
        return []

    lines = code.split("\n")
    secrets_found: List[Dict[str, Any]] = []

    for line_idx, raw_line in enumerate(lines, start=1):
        clean_line = raw_line.strip()
        # Skip commented out code lines
        if clean_line.startswith(("#", "//", "/*", "*")):
            continue

        # Skip explicit environment variable retrievals
        lowered = clean_line.lower()
        if any(env_token in lowered for env_token in ["os.getenv", "os.environ", "process.env", "system.getenv", "getenv"]):
            continue

        for rule in SECRET_PATTERNS:
            match = re.search(rule["pattern"], raw_line, re.IGNORECASE)
            if match:
                raw_secret = match.group(0)
                if len(match.groups()) >= 2 and match.group(2):
                    raw_secret = match.group(2)

                secret_stripped = raw_secret.strip("\"'").lower()
                if secret_stripped in EXACT_DUMMY_STRINGS or secret_stripped.startswith("your_"):
                    continue

                masked_val = mask_secret(raw_secret)
                secrets_found.append({
                    "type": rule["type"],
                    "severity": rule["severity"],
                    "filename": filename,
                    "line_number": line_idx,
                    "masked_secret": masked_val,
                    "code_context": raw_line.strip().replace(raw_secret, masked_val),
                    "recommendation": (
                        "Immediately revoke this credential. Move the secret to an environment variable "
                        "loaded at runtime via os.getenv() or a secret management vault."
                    )
                })
                break

    return secrets_found

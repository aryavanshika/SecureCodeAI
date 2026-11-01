"""
=============================================================================
SecureCode AI - Educational Attack Simulation Lab (attack_simulator.py)
=============================================================================
PURPOSE:
Provides interactive, purely conceptual visual simulations of common software
vulnerabilities to demonstrate how exploits function and how secure code neutralizes them.

SAFETY GUARANTEE:
- All simulations are STATIC & PURELY CONCEPTUAL mock visualizations.
- Never executes real shell commands, database connections, or network payloads.
- Strictly harmless illustrative strings (e.g., `' OR '1'='1`, `alert('Demo')`, `; whoami`).
- Explicitly labeled as an educational laboratory.
=============================================================================
"""

from typing import Dict, Any, List

SIMULATIONS = {
    "sqli": {
        "id": "SIM-SQLI",
        "title": "SQL Injection (SQLi) — Authentication Bypass",
        "cwe": "CWE-89",
        "concept": "Taint Flow into Dynamic SQL Query Construction",
        "sample_input": "' OR '1'='1' --",
        "vulnerable_code": """# VULNERABLE CODE: Direct string formatting into SQL query
def login_user(username, password):
    query = f"SELECT * FROM users WHERE user = '{username}' AND pass = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()""",
        "secure_code": """# SECURE CODE: Parameterized query decouples logic from data
def login_user(username, password):
    query = "SELECT * FROM users WHERE user = %s AND pass = %s"
    cursor.execute(query, (username, password))
    return cursor.fetchone()""",
        "explanation": (
            "In vulnerable code, user input is concatenated directly into the query string. "
            "When an attacker enters `' OR '1'='1' --`, the quotes break out of the string literal, "
            "and the `'1'='1'` condition makes the entire WHERE clause evaluate to TRUE for every database row. "
            "The `--` comment operator instructs the database engine to discard the remaining password check entirely."
        ),
        "impact": "Bypasses authentication as administrator, exposes all confidential database records, or allows table dropping via stacked queries.",
        "fix_explanation": (
            "In secure code, parameterized queries (prepared statements) transmit the SQL statement and parameters "
            "in two distinct network packets. The database parser compiles the SQL structure first, and treats "
            "the user input strictly as literal string values. The input cannot modify query logic."
        ),
        "vulnerable_sim_output": {
            "interpolated_query": "SELECT * FROM users WHERE user = '' OR '1'='1' --' AND pass = '***'",
            "simulated_db_action": "WHERE clause evaluates to TRUE unconditionally. Authentication bypassed.",
            "simulated_records_returned": 1420,
            "status": "🔴 EXPLOIT SUCCESSFUL (Simulated)",
            "verdict": "Vulnerable code executed arbitrary attacker SQL logic."
        },
        "secure_sim_output": {
            "parameter_binding": "user = \"' OR '1'='1' --\" (treated as literal text)",
            "simulated_db_action": "Searched for a user literally named \"' OR '1'='1' --\". No match found.",
            "simulated_records_returned": 0,
            "status": "🟢 ATTACK NEUTRALIZED",
            "verdict": "Parameterized engine neutralized payload. Zero unauthorized records returned."
        }
    },

    "xss": {
        "id": "SIM-XSS",
        "title": "Cross-Site Scripting (XSS) — DOM Injection",
        "cwe": "CWE-79",
        "concept": "Unsanitized Markup Rendering in Client Browser Context",
        "sample_input": "<script>alert('Session Stolen: ' + document.cookie)</script>",
        "vulnerable_code": """// VULNERABLE CODE: Directly inserting untrusted text into innerHTML
function displaySearchQuery(query) {
    const container = document.getElementById("search-results");
    container.innerHTML = "<h3>Results for: " + query + "</h3>";
}""",
        "secure_code": """// SECURE CODE: Using textContent for safe text node rendering
function displaySearchQuery(query) {
    const container = document.getElementById("search-results");
    const heading = document.createElement("h3");
    heading.textContent = "Results for: " + query; // Auto-escaped
    container.replaceChildren(heading);
}""",
        "explanation": (
            "When untrusted input is assigned to `element.innerHTML`, the browser's HTML parser "
            "interprets `<script>` or `<img onerror=...>` tags as executable code. "
            "The attacker's JavaScript runs with full permissions of the logged-in user."
        ),
        "impact": "Session token theft (document.cookie), keystroke logging, CSRF token forgery, and silent account takeover.",
        "fix_explanation": (
            "Assigning input to `element.textContent` bypasses the HTML parser entirely and creates a raw text node. "
            "Characters like `<` and `>` are rendered visually on screen as literal glyphs without executing."
        ),
        "vulnerable_sim_output": {
            "parsed_dom": "<h3>Results for: <script>alert('Session Stolen: ' + document.cookie)</script></h3>",
            "simulated_browser_action": "Browser executes inline script in victim's session context.",
            "simulated_exfiltration": "Session cookie JWT token transmitted to remote server.",
            "status": "🔴 EXPLOIT SUCCESSFUL (Simulated)",
            "verdict": "Browser executed injected script. Session token compromised."
        },
        "secure_sim_output": {
            "parsed_dom": "<h3>Results for: &lt;script&gt;alert('Session Stolen: ' + document.cookie)&lt;/script&gt;</h3>",
            "simulated_browser_action": "Browser renders string as safe text glyphs. Script engine idle.",
            "simulated_exfiltration": "None. Cookies protected.",
            "status": "🟢 ATTACK NEUTRALIZED",
            "verdict": "textContent rendered markup as literal text. Zero script execution."
        }
    },

    "cmdi": {
        "id": "SIM-CMDI",
        "title": "OS Command Injection — Shell Metacharacter Chaining",
        "cwe": "CWE-78",
        "concept": "Shell Interpreter Execution of Unchecked System Commands",
        "sample_input": "127.0.0.1; cat /etc/passwd",
        "vulnerable_code": """# VULNERABLE CODE: Invoking system shell with unvalidated input
import os

def ping_host(target_ip):
    # Shell executes concatenated string
    os.system("ping -c 1 " + target_ip)""",
        "secure_code": """# SECURE CODE: Structured argument list without shell interpreter
import subprocess

def ping_host(target_ip):
    # shell=False prevents shell operator interpretation
    subprocess.run(["ping", "-c", "1", target_ip], shell=False, check=True)""",
        "explanation": (
            "When `os.system` or `shell=True` is used, the string is passed to an OS shell (`/bin/sh` or `cmd.exe`). "
            "Shell command terminators like `;`, `&&`, or `|` instruct the shell to start executing a second, independent command "
            "(`cat /etc/passwd`) immediately after the first command completes."
        ),
        "impact": "Full operating system compromise, arbitrary remote code execution (RCE), host file exfiltration, and lateral server movement.",
        "fix_explanation": (
            "Passing an argument list (`['ping', '-c', '1', target_ip]`) with `shell=False` invokes the OS kernel "
            "`execve` system call directly. The entire string `127.0.0.1; cat /etc/passwd` is passed as a single literal argument "
            "to the `ping` utility, which rejects it as an invalid hostname rather than executing it as a second command."
        ),
        "vulnerable_sim_output": {
            "shell_command_executed": "ping -c 1 127.0.0.1; cat /etc/passwd",
            "simulated_host_action": "Shell executes ping, then executes cat /etc/passwd.",
            "simulated_output_preview": "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:...",
            "status": "🔴 EXPLOIT SUCCESSFUL (Simulated)",
            "verdict": "Arbitrary command chained and executed on host system."
        },
        "secure_sim_output": {
            "kernel_exec_call": "execve('/bin/ping', ['ping', '-c', '1', '127.0.0.1; cat /etc/passwd'])",
            "simulated_host_action": "ping utility fails with error: 'unknown host: 127.0.0.1; cat /etc/passwd'.",
            "simulated_output_preview": "ping: cannot resolve 127.0.0.1; cat /etc/passwd: Unknown host",
            "status": "🟢 ATTACK NEUTRALIZED",
            "verdict": "Direct execve invocation prevented shell chaining. Attack neutralized."
        }
    }
}


def get_simulation(sim_key: str) -> Dict[str, Any]:
    """Retrieves simulation metadata for the given vulnerability key."""
    return SIMULATIONS.get(sim_key, SIMULATIONS["sqli"])

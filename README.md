# 🛡️ SECURECODE AI — Enterprise Cybersecurity SaaS Platform
### Intelligent Code Security, Vulnerability Detection, Auto-Remediation & Patch Verification

A comprehensive, enterprise-grade cybersecurity static application security testing (SAST), automated code remediation, and empirical patch verification platform built with **Python**, **Streamlit**, **Pandas**, and **Plotly**.

---

## 🎨 Enterprise Design System & Exact Color Palette

The interface adheres to an ultra-modern, high-contrast dark cybersecurity SaaS theme:

- **Main Background**: `#080D18` (Deep navy / obsidian)
- **Sidebar Background**: `#0B1220` (Dark navy container)
- **Card Background**: `#111C2E` (Frosted dark navy cards)
- **Secondary Card Background**: `#17243A` (Sub-container headers and toolbars)
- **Primary Text**: `#F8FAFC` (Crisp, high-contrast white)
- **Secondary Text**: `#B8C5D9` (High-contrast muted slate)
- **Primary Accent**: `#3186FF` (Electric cybersecurity blue)
- **Secondary Accent**: `#8B5CF6` (Neon purple)
- **Success / Secure**: `#22C55E` (Emerald green)
- **Critical Severity**: `#EF4444` (Crimson red)
- **High Severity**: `#F97316` (Vibrant orange)
- **Medium Severity**: `#EAB308` (Amber gold)
- **Low Severity / Hardening**: `#38BDF8` (Sky cyan)
- **Borders & Dividers**: `#26364D` (Subtle boundary borders)

---

## 🚀 How to Launch the Application

From the project root (`c:\Users\VICTUS\Downloads\securecode`):

```powershell
# Using Anaconda Python:
& "C:\Users\VICTUS\anaconda3\python.exe" -m streamlit run app.py

# Or if streamlit is on your system PATH:
streamlit run app.py
```

The application opens automatically in your browser at:
👉 **`http://localhost:8501`**

---

## 🧪 How to Run the Automated Test Suite

Run all 40 unit tests across the 4 specialized test suites:

```powershell
& "C:\Users\VICTUS\anaconda3\python.exe" -m unittest discover -s tests -p "test_*.py"
```

All 40 tests execute in <0.1 seconds with **0 failures and 0 errors**:
- `tests/test_scanner.py`: 29 tests for all 9 CWE detection rules & false-positive filters.
- `tests/test_project_scanner.py`: ZIP unpacking, multi-language aggregation & Zip Slip defense.
- `tests/test_patch_verifier.py`: AutoFix synthesis & empirical rescan verification statuses.
- `tests/test_modules.py`: Composite risk score, secret value masking, OSV dependency scanner & attack simulator.

---

## 🧭 Architecture & 9 Core Integrated Modules

SecureCode AI is organized into 9 dedicated views accessible via the sidebar:

### 1. 📊 Dashboard
- **6 Overview Metric Cards**:
  1. *Security Score* (0-100 with dynamic health color)
  2. *Total Vulnerabilities*
  3. *Critical Issues*
  4. *High Issues*
  5. *Fixed Issues* (Automated patches synthesized)
  6. *Files Scanned*
- **Threat & Severity Distribution**: Enterprise dark Plotly bar chart (`#111C2E` background, high-contrast labels).
- **Active Posture Rating**: Circular radial SVG progress meter with glow and risk tier.
- **Recent Scan Activity Table**: Custom dark cybersecurity table with score pills and severity badges.

### 2. 🔍 New Code Scan (Single-File SAST Engine)
- Multi-language support: **Python**, **JavaScript**, **Java**, and **C/C++**.
- Dual input modes: Drag & Drop source file uploader vs live code editor.
- AST and token stream analysis detecting:
  1. SQL Injection (`CWE-89`)
  2. Hardcoded Credentials (`CWE-798`)
  3. Command Injection (`CWE-78`)
  4. Cross-Site Scripting (`CWE-79`)
  5. Weak Cryptographic Hashing (`CWE-327`)
  6. Insecure Deserialization (`CWE-502`)
  7. Path Traversal (`CWE-22`)
  8. Debug Mode Exposure (`CWE-489`)
  9. Unsafe Memory Buffer Operations (`CWE-120`)
- Findings matrix and detailed expander cards with 1-click routing to the AutoFix Studio.

### 3. 📁 Multi-File Project Scanner (ZIP Archive)
- Audit entire codebases uploaded as `.zip` archives.
- **Zip Slip Defense**: Validates canonical paths against base extraction directories, rejecting path traversal attempts.
- **Denial-of-Service Defense**: Enforces 30MB uncompressed limit, 2MB single-file limit, and maximum 50 source files.
- Per-file findings accordion and consolidated CSV / JSON project report downloads.

### 4. ✨ AutoFix & Remediation Studio (The Core Differentiator)
- Context-aware automated patch synthesis for individual flaws or the entire source file.
- Plain-English **Remediation Safety Rationales** explaining why the secure fix is robust.
- Side-by-side **Before (Vulnerable) vs After (Patched)** code comparison and unified diff inspector.
- **Empirical Patch Verification (Rescan)**:
  - Rescans the patched code using the SAST engine.
  - Returns empirical status badges:
    - 🟢 `Resolved by scanner rule`
    - 🔴 `Still detected`
    - 🟠 `New findings introduced`
    - ⚪ `Verification unavailable`
  - Calculates live **Score Delta** (e.g. Previous: 30 ➔ New: 100, +70 pts).

### 5. 🧪 Attack Simulation Lab (Educational Playground)
- 100% safe, purely conceptual simulations of real-world exploits:
  1. *SQL Injection (CWE-89)* — Authentication Bypass & WHERE clause hijacking
  2. *Cross-Site Scripting (CWE-79)* — DOM textContent vs innerHTML injection
  3. *Command Injection (CWE-78)* — Shell metacharacter chaining vs structured argument arrays
- Interactive payload customization with side-by-side execution comparison:
  - 🔴 Vulnerable execution behavior (simulated database hijack or DOM execution)
  - 🟢 Remediated execution behavior (neutralized parameter binding)

### 6. 📈 Security Analytics, Secrets & Dependencies
- **Composite Risk Rating (0-100)**: Transparent, deterministic formula combining CVSS base weights, remote code execution multipliers (+20%), and sensitive data exposure multipliers (+25%).
- **Highest-Priority Vulnerability Spotlight**: Highlights the single most dangerous flaw.
- **Prioritized Remediation Roadmap Queue**: Step-by-step ordered table ranking fixes by impact.
- **🔑 Secret & Credential Detector**:
  - Scans for OpenAI/Stripe keys, AWS Access IDs, GCP tokens, JWTs, and passwords.
  - **Strict Value Masking**: Secret values are masked in memory and the UI (`sk-proj-a1b2...c3d4`).
- **📦 Dependency Vulnerability Scanner (SBOM)**:
  - Parses `requirements.txt`, `package.json`, and `pom.xml`.
  - Matches declared packages against real CVE advisories from the Google Open Source Vulnerability (OSV) catalog (Log4Shell, Spring4Shell, Lodash prototype pollution, Requests header leak).

### 7. 📜 Scan History & Developer Scorecard
- Developer Security Scorecard comparing latest scan against previous scans.
- Tracks score deltas, resolved flaws, and recurring flaws.
- Chronological scan log with 1-click history clearing.

### 8. 📄 Reports & CI/CD Pipeline Integration
- Compliance export cards for **JSON**, **CSV** (via Pandas), and **Plain-Text** summaries. (Strictly no PDF).
- **GitHub Actions CI/CD Generator**:
  - Configurable build gate thresholds: Fail on Critical, Fail on High+, or Fail on Any Flaw.
  - Exportable `.github/workflows/securecode.yml` workflow file.

### 9. ℹ️ About SecureCode AI
- Architectural decoupling specification.
- Transparency disclosure: Rule-based SAST heuristics are clearly labeled as deterministic fallback.
- Teammate Backend Contract: instructions for connecting live AI/LLM models via `backend_adapter.py`.

---

## 📁 Repository Structure

```
securecode/
│
├── .streamlit/
│   └── config.toml                 # Dark theme configuration (base = "dark", #080D18)
│
├── assets/
│   └── style.css                   # Enterprise dark cybersecurity stylesheet
│
├── app.py                          # Streamlit application (9 integrated modules)
├── backend_adapter.py              # Decoupled engine adapter (Live AI vs Rule Fallback)
├── mock_scanner.py                 # 9-rule multi-language deterministic SAST engine
├── autofix.py                      # Context-aware patch synthesis & safety rationales
├── patch_verifier.py               # Empirical rescan verification engine
├── project_scanner.py              # ZIP archive extractor with Zip Slip defense
├── attack_simulator.py             # Conceptual educational attack simulation lab
├── risk_analyzer.py                # Composite CVSS risk scoring model & remediation roadmap
├── secret_detector.py              # Leaked secret scanner with strict value masking
├── dependency_scanner.py           # Manifest parser with Google OSV CVE catalog
│
├── utils/
│   ├── __init__.py
│   └── report_generator.py         # Exporters for JSON, CSV (Pandas), TXT, and Markdown
│
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py             # 29 unit tests for SAST detection rules
│   ├── test_project_scanner.py     # Tests for ZIP unpacking & Zip Slip protection
│   ├── test_patch_verifier.py      # Tests for empirical patch rescan statuses
│   └── test_modules.py             # Tests for risk model, secrets, dependencies, simulator
│
├── requirements.txt                # Project dependencies (streamlit, pandas, plotly)
└── README.md                       # Comprehensive platform documentation
```

---

## 🤝 Teammate Backend Integration Contract

Teammates building an AI or LLM backend can seamlessly integrate their code:

1. Create a Python module at `backend/ai_engine.py`.
2. Implement a single function:
   ```python
   def analyze_code(code: str, language: str) -> dict:
       # Return dictionary matching standard schema:
       # { "vulnerabilities": [...], "summary": {...}, "patched_code": "..." }
   ```
3. `backend_adapter.py` will automatically detect `backend.ai_engine`, route traffic to it, and update the UI status indicator to **"Engine: Live Teammate AI"** with **zero frontend code changes required**!

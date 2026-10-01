# 🚀 TriageMind — Complete User & Quickstart Guide

> **AI-Powered Web Vulnerability Scanner & Triage Pipeline**  
> *Filière 4CIRM — EMSI Casablanca — Educational Security Research*

Welcome to **TriageMind**! This guide covers everything you need to set up, run, and interpret security assessments using TriageMind, whether you are running from source or from a distributed release package.

---

## 📋 Table of Contents
1. [Prerequisites & System Requirements](#1-prerequisites--system-requirements)
2. [Getting a Free Google Gemini API Key](#2-getting-a-free-google-gemini-api-key)
3. [Installation & Setup](#3-installation--setup)
4. [How to Run a Security Scan](#4-how-to-run-a-security-scan)
5. [Scan Walkthrough (Step-by-Step)](#5-scan-walkthrough-step-by-step)
6. [Advanced Usage & Scanning Scenarios](#6-advanced-usage--scanning-scenarios)
7. [Understanding Your Reports & Output Files](#7-understanding-your-reports--output-files)
8. [Troubleshooting & Common Questions](#8-troubleshooting--common-questions)

---

## 1. Prerequisites & System Requirements

Before you begin, ensure your machine meets these basic requirements:

| Component | Requirement | Notes |
|---|---|---|
| **Operating System** | Windows 10/11, macOS, or Linux | Scripts (`.bat`) are optimized for Windows |
| **Python** | Version **3.10** or higher | Make sure to check *"Add Python to PATH"* during installation |
| **Internet Connection** | Active connection | Required for Google Gemini API and NVD/EPSS/KEV threat lookups |
| **Gemini API Key** | Free tier API key | Takes 30 seconds to generate from Google AI Studio |

---

## 2. Getting a Free Google Gemini API Key

TriageMind uses Google Gemini to evaluate scanner findings and eliminate false positives.

1. Open your browser and go to **[Google AI Studio](https://aistudio.google.com/app/apikey)**.
2. Sign in with your Google account.
3. Click the blue **"Create API key"** button.
4. Select or create a Google Cloud project (free tier is default).
5. Copy your generated API key (it starts with `AIzaSy...`).
6. *Keep this key handy* — you will paste it when TriageMind starts, or set it as an environment variable (`set GEMINI_API_KEY=your_key_here`).

---

## 3. Installation & Setup

### Method A — ⚡ Automatic 1-Click Setup (Recommended on Windows)
Simply double-click:
```bat
setup.bat
```
This automated script will:
- Verify Python is properly installed and added to PATH.
- Install all required Python packages from `requirements.txt`.
- Download the headless Chromium browser (~150MB) used by Playwright for crawling.

---

### Method B — 💻 Manual Setup (Command Prompt / Terminal)
Open a terminal in the TriageMind directory and run:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Install Playwright Chromium browser
playwright install chromium
```

---

## 4. How to Run a Security Scan

### Option 1 — Double-Click
Double-click `run.bat` to launch TriageMind directly in a clean terminal window.

### Option 2 — Command Line
Open your terminal in the project folder and run:
```bash
python main.py
```

### Option 3 — Standalone Executable (If built)
Double-click `TriageMind.exe` in the distribution folder.

---

## 5. Scan Walkthrough (Step-by-Step)

When TriageMind launches, it guides you through an interactive console flow:

```
┌────────────────────────────────────────────────────────────┐
│                    TRIAGEMIND PIPELINE                     │
│         Unified Web Vulnerability Assessment v1.0          │
└────────────────────────────────────────────────────────────┘
```

### Step 1: API Key Entry
If `GEMINI_API_KEY` is not set in your environment, TriageMind will prompt:
```
Enter your Google Gemini API Key (hidden / paste):
```
Paste your key and press **Enter**.

### Step 2: Target Selection
Enter the full URL of the web application you wish to test:
```
Enter Target URL to Scan (e.g., http://localhost:3000): http://testphp.vulnweb.com
```

### Step 3: Automated Pipeline Execution
TriageMind will automatically execute all 4 phases with live visual feedback:
* **Phase 1 — Crawling & Security Probing:** Headless Chromium discovers links, renders JavaScript SPAs, and tests for vulnerabilities.
* **Phase 2 — Multi-Source Intelligence:** Findings are cross-referenced with NVD CVSS scores, FIRST.org EPSS exploitation probability, and CISA KEV exploitation catalogs.
* **Phase 3 — AI Triage & False Positive Suppression:** Google Gemini reviews all HTTP evidence and filters out false positives.
* **Phase 4 — Document Compilation:** Reports are rendered in Markdown, HTML, and high-resolution PDF.

### Step 4: Exporting the PDF Report
At the end of the scan, a native Windows **Save As** file dialog will open automatically:
1. Choose where you want to save the final PDF report (e.g., your Desktop or Documents folder).
2. Click **Save**.
3. Open your PDF report to review the executive summary and technical vulnerability cards.

---

## 6. Advanced Usage & Scanning Scenarios

You can run `python main.py` with custom flags for specific assessment requirements:

### 1. Authenticated Scanning (e.g., DVWA / Protected Dashboards)
To log in automatically before scanning:
```bash
python main.py --target http://localhost/dvwa/login.php --auth-login-url http://localhost/dvwa/login.php --auth-username admin --auth-password password --active
```
*TriageMind will locate the login form, authenticate, store the session cookies, and scan protected internal pages.*

### 2. Live Browser Visual Mode (Headed Crawl)
To watch the Chromium browser interact with the page in real-time (great for demos and debugging):
```bash
python main.py --target http://localhost:3000 --headed
```

### 3. Deep Assessment for Large Applications
For larger websites with deep link hierarchies:
```bash
python main.py --target http://example.com --max-depth 5 --crawl-duration 300 --active
```

---

## 7. Understanding Your Reports & Output Files

Every completed scan produces structured output files in your project directory:

| Output File | Format | Purpose |
|---|---|---|
| **`*_TriageMind_Report.pdf`** | PDF | **Primary deliverable.** Executive summary, CVSS metrics, MITRE ATT&CK mappings, and remediation cards. |
| **`*_TriageMind_Report.html`** | HTML | Standalone interactive web report with severity styling. |
| **`*_vulnerability_report.md`** | Markdown | Raw AI triage output formatted in GitHub Flavored Markdown. |
| **`enriched_results.json`** | JSON | Findings with CVSS v3.1, EPSS %, and CISA KEV threat metadata attached. |
| **`results.json`** | JSON | Raw telemetry captured directly by the crawler and active check engine. |
| **`scan_meta.json`** | JSON | Performance statistics (crawl time, pages visited, interaction counts). |

---

## 8. Troubleshooting & Common Questions

#### Q: `playwright install` fails with a network or permissions error
> **Fix:** Run Command Prompt as Administrator, execute `pip install --upgrade playwright`, and then run `playwright install chromium`.

#### Q: Gemini API returns a 503 or quota rate-limit error
> **Fix:** TriageMind automatically falls back across multiple models (`gemini-3.6-flash`, `gemini-3.5-flash`, `gemini-3.1-flash-lite`, `gemini-2.0-flash`). If all fail, check your quota on Google AI Studio or create a fresh API key.

#### Q: The scanner says "0 findings found"
> **Fix:** Check that your target URL is reachable and includes the protocol (`http://` or `https://`). For dynamic single-page applications, add `--headed` to verify if the crawler is waiting long enough for pages to render.

#### Q: Is my Gemini API key stored permanently?
> **Fix:** No. TriageMind only uses your API key in memory during the execution of Phase 3 and never logs or writes your key to disk.

---

*TriageMind — Automated Penetration Testing & AI Triage | Filière 4CIRM EMSI Casablanca*

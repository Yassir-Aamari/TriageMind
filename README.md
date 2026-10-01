# ▣ TRIAGEMIND — Unified Security Pipeline
> AI-Powered Web Vulnerability Scanner & Triage Pipeline
> Version 1.0.0 | Filière 4CIRM — EMSI Casablanca

---

## WHAT IS TRIAGEMIND?
TriageMind is an automated web vulnerability scanner that combines browser-based crawling, passive and active security checks, multi-source threat intelligence enrichment, and Google Gemini AI-assisted triage to produce professional penetration test reports.

---

## SYSTEM REQUIREMENTS
Before running TriageMind, make sure your system has:

| Requirement | Minimum Version | How to check |
|-------------|----------------|--------------|
| Python | 3.10 or higher | `python --version` |
| pip | Latest | `pip --version` |
| Node.js | Not required | — |
| Internet connection | Required | For Gemini API and NVD/EPSS/KEV lookups |
| Google Gemini API Key | Free tier | https://aistudio.google.com/app/apikey |

---

## INSTALLATION (First time only — takes 2-5 minutes)

### Step 1 — Install Python dependencies
Open a terminal or command prompt in this folder and run:
```bash
pip install -r requirements.txt
```

### Step 2 — Install Playwright browsers
```bash
playwright install chromium
```
This downloads the headless Chromium browser used for crawling. It is approximately 150MB.

### Step 3 — Get your Gemini API Key
1. Go to https://aistudio.google.com/app/apikey
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the key — you will paste it when TriageMind starts

---

## HOW TO RUN

### Option A — Run directly with Python
```bash
python main.py
```

### Option B — Run the executable (Windows)
```bash
TriageMind.exe
```

The program will guide you step by step:
1. Paste your Gemini API key when prompted
2. Enter the target website URL
3. Wait for the scan to complete (typically 5-10 minutes)
4. Save the PDF report when the dialog appears

---

## WHAT TRIAGEMIND DOES

```
Phase 1 — Crawling & Scanning
→ Playwright headless browser crawls the target
→ Passive checks: HTTP headers, cookies, information disclosure
→ Active checks: XSS, SQL Injection, Open Redirect, Sensitive Paths

Phase 2 — Vulnerability Enrichment
→ NVD API: CVSS v3.1 scores and CWE classifications
→ FIRST.org EPSS: Exploit probability scoring
→ CISA KEV: Known exploited vulnerability catalog check

Phase 3 — AI Triage
→ Google Gemini analyzes all findings
→ Suppresses false positives with evidence-based reasoning
→ Generates professional vulnerability report

Phase 4 — Report Generation
→ Converts findings to professional PDF
→ Includes executive summary, CVSS scores, attack chains
→ Compliance mapping (GDPR, ISO 27001, PCI-DSS, OWASP ASVS)
```

---

## OUTPUT FILES
After each scan, TriageMind produces:

| File | Description |
|------|-------------|
| `results.json` | Raw scanner findings |
| `enriched_results.json` | Findings enriched with CVSS/EPSS/KEV |
| `{target}_vulnerability_report.md` | AI-generated report in Markdown |
| `{target}_TriageMind_Report.html` | Report in HTML format |
| `{target}_TriageMind_Report.pdf` | Final professional PDF report |
| `scan_meta.json` | Scan metadata and statistics |

---

## ADVANCED OPTIONS
Run with additional flags for more control:

```bash
python main.py --headed              # Show browser window during crawl
python main.py --max-depth 5         # Crawl deeper (default: 3)
python main.py --crawl-duration 300  # Longer crawl time in seconds
python main.py --auth-login-url URL  # Authenticated scanning
python main.py --auth-username USER  # Login username
python main.py --auth-password PASS  # Login password
```

### Authenticated scanning example (DVWA):
```bash
python main.py --auth-login-url http://localhost/dvwa/login.php --auth-username admin --auth-password password
```

---

## TROUBLESHOOTING

| Problem | Solution |
|---------|----------|
| `playwright install` fails | Run `pip install playwright` first, then `playwright install chromium` |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again |
| Gemini API error 503 | Model is busy, TriageMind will automatically retry with a fallback model |
| PDF not generated | Make sure Playwright is installed: `playwright install chromium` |
| Scan finds nothing | Try with `--headed` to see what the browser sees |
| API key rejected | Make sure you copied the full key from Google AI Studio |

---

## REQUIREMENTS FILE
All Python dependencies are listed in `requirements.txt`. Key dependencies:

| Package | Purpose |
|---------|---------|
| playwright | Headless browser for crawling |
| google-genai | Gemini AI triage |
| rich | Terminal UI |
| jinja2 | HTML report templating |
| httpx | Async HTTP for enrichment APIs |
| markdown | Markdown to HTML conversion |

---

## IMPORTANT NOTES
- TriageMind is for **authorized security testing only**
- Only scan websites you own or have explicit written permission to test
- Results are AI-assisted and require human validation
- This tool is developed for educational purposes at EMSI Casablanca

---

*TriageMind Unified Security Pipeline v1.0 — EMSI Casablanca — Educational Security Research*

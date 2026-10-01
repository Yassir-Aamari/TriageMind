"""
pdf_generator.py
================
Phase 4: PDF Restitution.
Reads the Markdown vulnerability report, renders it into an executive HTML/CSS
template using Jinja2, then converts to PDF using Playwright headless Chromium.
Chromium is already installed by the scanner — zero additional dependencies.
Falls back to a standalone HTML file if Playwright PDF rendering fails.
"""

import argparse
import asyncio
import logging
import re
from datetime import date as _date
from pathlib import Path

import bleach
import markdown
from jinja2 import Environment, select_autoescape
from markupsafe import Markup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(module)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

_ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS).union({
    "div", "span", "p", "br", "hr", "h1", "h2", "h3", "h4",
    "table", "thead", "tbody", "tr", "th", "td", "pre", "code",
    "ul", "ol", "li", "strong", "em", "blockquote", "a",
})
_ALLOWED_ATTRIBUTES = {"*": ["class"], "a": ["href", "title"]}
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ target or site_name }} &#8212; Confidential Vulnerability Assessment Report</title>
    <style>
        /* Print color adjustment and page setup */
        * {
            box-sizing: border-box;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }

        @page {
            margin: 2.5cm 2cm 3cm 2cm;
            @top-left {
                content: "▣ TRIAGEMIN D";
                font-family: 'Courier New', monospace;
                font-size: 8pt;
                color: #888888;
                letter-spacing: 2px;
                border-bottom: 1px solid #dddddd;
                padding-bottom: 4px;
            }
            @top-right {
                content: "CONFIDENTIAL";
                font-size: 8pt;
                color: #cc0000;
                font-weight: bold;
                border-bottom: 1px solid #dddddd;
                padding-bottom: 4px;
            }
            @bottom-center {
                content: "TriageMind Security Report — CONFIDENTIAL     Page " counter(page) " of " counter(pages);
                font-size: 8pt;
                color: #888888;
                border-top: 1px solid #dddddd;
                padding-top: 4px;
            }
        }

        @page :first {
            @top-left { content: ""; border: none; }
            @top-right { content: ""; border: none; }
            @bottom-center { content: ""; border: none; }
        }

        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 11pt;
            color: #1a1a2e !important;
            background: white !important;
            line-height: 1.6;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
            margin: 0;
            padding: 0;
        }

        td, th {
            color: #1a1a2e !important;
        }

        p, li, span, div {
            color: inherit;
        }

        /* Cover page */
        .cover-page {
            background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3e 50%, #0d1b2a 100%);
            color: white;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            padding: 80px 40px;
            position: relative;
        }

        .page-break {
            page-break-after: always;
            break-after: page;
            height: 0;
            display: block;
        }

        .cover-triageming-brand {
            margin-bottom: 40px;
        }

        .cover-logo-ascii {
            font-family: 'Courier New', monospace;
            font-size: 18pt;
            font-weight: bold;
            color: #c8ff00;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        .cover-logo-sub {
            font-family: 'Courier New', monospace;
            font-size: 10pt;
            color: #888888;
            letter-spacing: 3px;
            margin-top: 6px;
        }

        .cover-classification {
            background: #ff4444;
            color: white;
            padding: 8px 24px;
            font-size: 12pt;
            font-weight: bold;
            letter-spacing: 4px;
            border-radius: 4px;
            margin-bottom: 30px;
            display: inline-block;
        }

        .cover-title {
            font-size: 24pt;
            font-weight: bold;
            color: #c8ff00;
            letter-spacing: 2px;
            margin-bottom: 16px;
            text-transform: uppercase;
            line-height: 1.2;
        }

        .cover-target {
            font-size: 15pt;
            color: #88ccff;
            margin-bottom: 30px;
            font-family: Consolas, monospace;
        }

        .cover-meta-table {
            width: 480px;
            margin: 30px auto;
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 8px;
            overflow: hidden;
        }

        .cover-meta-row {
            display: flex;
            padding: 12px 20px;
            background: rgba(255,255,255,0.03);
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }

        .cover-meta-row-alt {
            background: rgba(255,255,255,0.07);
        }

        .cover-meta-row:last-child {
            border-bottom: none;
        }

        .cover-meta-label {
            width: 160px;
            min-width: 160px;
            color: #888888;
            font-size: 9pt;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-align: right;
            padding-right: 20px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
        }

        .cover-meta-value {
            color: #cccccc;
            font-size: 10pt;
            display: flex;
            align-items: center;
        }

        .cover-footer {
            margin-top: 30px;
            font-size: 8.5pt;
            color: #778899;
            letter-spacing: 0.5px;
        }

        /* Page breaks */
        .page-break { page-break-after: always; }

        /* Report Body Layout */
        .report-content {
            padding: 40px 60px;
        }

        /* Headers */
        h1 { 
            font-size: 18pt; 
            color: #0a0a1a;
            border-bottom: 3px solid #c8ff00;
            padding-bottom: 8px;
            margin-top: 36px;
            margin-bottom: 16px;
        }

        h2 { 
            font-size: 13.5pt; 
            color: #1a1a3e;
            border-left: 4px solid #c8ff00;
            padding-left: 12px;
            margin-top: 28px;
            margin-bottom: 12px;
        }

        h3 { 
            font-size: 11.5pt; 
            color: #1a1a3e;
            margin-top: 20px;
            margin-bottom: 8px;
        }

        h4 { 
            font-size: 10pt; 
            color: #334155;
            margin-top: 14px;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        p {
            margin-bottom: 10px;
        }

        /* Finding blocks */
        h3[id^="finding"], h3:has(+ p strong) {
            background: #f0f4ff;
            border-left: 5px solid #1a1a3e;
            padding: 10px 14px;
            border-radius: 0 4px 4px 0;
            margin-top: 26px;
        }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 9.5pt;
            page-break-inside: avoid;
        }

        th {
            background: #1a1a3e;
            color: white !important;
            padding: 9px 12px;
            text-align: left;
            font-weight: 600;
            letter-spacing: 0.5px;
            border-top: 1px solid #1a1a3e;
        }

        td {
            padding: 8px 12px;
            border-bottom: 1px solid #e0e0e0;
            vertical-align: top;
        }

        tr:nth-child(even) td { background: #f8f9ff; }
        tr:hover td { background: #f0f4ff; }

        /* Code blocks */
        pre {
            background: #0a0a1a;
            color: #c8ff00;
            padding: 14px 16px;
            border-radius: 6px;
            font-size: 8.5pt;
            font-family: Consolas, 'Courier New', monospace;
            overflow-x: auto;
            border-left: 3px solid #c8ff00;
            margin: 12px 0;
            page-break-inside: avoid;
        }

        code {
            font-family: Consolas, 'Courier New', monospace;
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 9pt;
            color: #cc0000;
        }

        pre code {
            background: transparent;
            color: #c8ff00;
            padding: 0;
            font-size: 8.5pt;
        }

        /* Blockquotes for important notes */
        blockquote {
            background: #fff8e6;
            border-left: 4px solid #ffaa00;
            padding: 12px 16px;
            margin: 16px 0;
            font-style: normal;
            border-radius: 0 4px 4px 0;
        }

        ul, ol {
            padding-left: 22px;
            margin: 8px 0;
        }

        li {
            margin: 4px 0;
        }

        /* Stats boxes */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin: 24px 0;
        }

        .stat-box {
            background: #f0f4ff;
            border: 1px solid #d0d8ff;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }

        .stat-number {
            font-size: 24pt;
            font-weight: bold;
            color: #1a1a3e;
        }

        .stat-label {
            font-size: 9pt;
            color: #888888;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .footer {
            margin-top: 50px;
            border-top: 1px solid #e2e8f0;
            padding-top: 14px;
            text-align: center;
            font-size: 8pt;
            color: #64748b;
        }

        /* Print optimization */
        @media print {
            .cover-page { min-height: 100vh; }
            h2 { page-break-after: avoid; }
            h3 { page-break-after: avoid; }
            table { page-break-inside: avoid; }
            pre { page-break-inside: avoid; }
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('td').forEach(function(td) {
                var t = td.textContent.trim().toUpperCase();
                if (t === 'CRITICAL') {
                    td.style.cssText = 'color: #cc0000 !important; font-weight: bold; text-align: center;';
                } else if (t === 'HIGH') {
                    td.style.cssText = 'color: #cc6600 !important; font-weight: bold; text-align: center;';
                } else if (t === 'MEDIUM') {
                    td.style.cssText = 'color: #cc9900 !important; font-weight: bold; text-align: center;';
                } else if (t === 'LOW') {
                    td.style.cssText = 'color: #336600 !important; font-weight: bold; text-align: center;';
                } else if (t === 'INFORMATIONAL' || t === 'INFO') {
                    td.style.cssText = 'color: #0066cc !important; font-weight: bold; text-align: center;';
                } else if (t === 'CONFIRMED') {
                    td.style.cssText = 'color: #006600 !important; font-weight: bold;';
                } else if (t.includes('FALSE POSITIVE') || t.includes('SUPPRESSED')) {
                    td.style.cssText = 'color: #888888 !important; font-style: italic;';
                }
            });
        });
    </script>
</head>
<body>

<!-- Cover Page -->
<div class="cover-page">
    <div class="cover-triageming-brand">
        <div class="cover-logo-ascii">▣ TRIAGEMIN D</div>
        <div class="cover-logo-sub">Unified Security Pipeline v1.0</div>
    </div>
    <div class="cover-classification">CONFIDENTIAL</div>
    <div class="cover-title">VULNERABILITY ASSESSMENT REPORT</div>
    <div class="cover-target">{{ target or site_name }}</div>
    <div class="cover-meta-table">
        <div class="cover-meta-row">
            <div class="cover-meta-label">Assessment Date</div>
            <div class="cover-meta-value">{{ date or report_date }}</div>
        </div>
        <div class="cover-meta-row cover-meta-row-alt">
            <div class="cover-meta-label">Generated By</div>
            <div class="cover-meta-value">TriageMind Unified Security Pipeline v1.0</div>
        </div>
        <div class="cover-meta-row">
            <div class="cover-meta-label">Target Scope</div>
            <div class="cover-meta-value">{{ target or site_name }}</div>
        </div>
        <div class="cover-meta-row cover-meta-row-alt">
            <div class="cover-meta-label">Classification</div>
            <div class="cover-meta-value" style="color:#ff4444;font-weight:bold;">CONFIDENTIAL — Restricted to Authorised Personnel</div>
        </div>
        <div class="cover-meta-row">
            <div class="cover-meta-label">Methodology</div>
            <div class="cover-meta-value">OWASP WSTG v4.2 + PTES</div>
        </div>
        <div class="cover-meta-row cover-meta-row-alt">
            <div class="cover-meta-label">Assessment Type</div>
            <div class="cover-meta-value">Web Application Vulnerability Assessment</div>
        </div>
    </div>
    <div class="cover-footer">
        TriageMind Unified Security Pipeline &mdash; Fili&egrave;re 4CIRM &mdash; EMSI Casablanca
    </div>
</div>
<div class="page-break"></div>

<!-- Report Body -->
<div class="report-content">
    {{ report_html }}
</div>

<div class="footer">
    TriageMind Unified Security Pipeline &mdash; Generated {{ date or report_date }} &mdash; CONFIDENTIAL
</div>

</body>
</html>
"""


async def _playwright_to_pdf(html_abs: Path, pdf_path: Path) -> bool:
    """Use Playwright (already installed for scanning) to print HTML -> PDF."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning("Playwright not importable — PDF skipped.")
        return False
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(html_abs.as_uri(), wait_until="networkidle")
            await page.wait_for_timeout(600)   # let JS colour severity cells
            await page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                margin={"top": "2cm", "bottom": "2.2cm",
                        "left": "1.8cm", "right": "1.8cm"},
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=(
                    '<div style="font-size:8pt;color:#94a3b8;width:100%;'
                    'padding:0 1.8cm;display:flex;justify-content:space-between;">'
                    '<span>TriageMind Security Report \u2014 CONFIDENTIAL</span>'
                    '<span>Page <span class="pageNumber"></span>'
                    ' of <span class="totalPages"></span></span>'
                    '</div>'
                ),
            )
            await browser.close()
        logger.info("PDF compiled via Playwright Chromium: %s", pdf_path)
        return True
    except Exception as exc:
        logger.warning("Playwright PDF rendering failed: %s", exc)
        return False


def generate_pdf(
    input_md: str,
    output_pdf: str,
    output_html_fallback: str,
    site_name: str = "Target Application",
) -> None:
    input_path = Path(input_md)
    if not input_path.exists():
        logger.error("Input file %s not found.", input_md)
        raise FileNotFoundError(f"Input file not found: {input_md}")

    # 1. Read Markdown
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            md_text = f.read()
        logger.info("Loaded Markdown report from %s", input_md)
    except IOError as exc:
        raise RuntimeError(f"Failed to read {input_md}") from exc

    # Strip machine-readable TRIAGE_METRICS comment
    md_text = re.sub(
        r'<!--\s*TRIAGE_METRICS:[^>]*-->', '', md_text, flags=re.IGNORECASE
    ).lstrip()

    # 2. Convert Markdown -> HTML snippet
    try:
        html_snippet = markdown.markdown(md_text, extensions=['tables', 'fenced_code'])
        logger.info("Successfully parsed Markdown to HTML.")
    except Exception as exc:
        raise RuntimeError("Failed to convert Markdown to HTML") from exc

    # 3. Sanitise and wrap in Jinja2 template
    report_date = _date.today().strftime("%d %B %Y")
    try:
        sanitized_html = bleach.clean(
            html_snippet,
            tags=_ALLOWED_TAGS,
            attributes=_ALLOWED_ATTRIBUTES,
            protocols=["http", "https", "mailto"],
            strip=True,
        )
        template = Environment(autoescape=select_autoescape(["html", "xml"])).from_string(HTML_TEMPLATE)
        rendered_html = template.render(
            report_html=Markup(sanitized_html),
            site_name=site_name,
            report_date=report_date,
            target=site_name,
            date=report_date,
        )
        logger.info("Successfully rendered Jinja2 HTML wrapper.")
    except Exception as exc:
        raise RuntimeError("Failed to render HTML report") from exc

    # 4. Always write the HTML (used as Playwright input + standalone fallback)
    try:
        with open(output_html_fallback, "w", encoding="utf-8") as f:
            f.write(rendered_html)
        logger.info("HTML report written: %s", output_html_fallback)
    except IOError as exc:
        raise RuntimeError(f"Failed to write HTML to {output_html_fallback}") from exc

    # 5. Generate PDF via Playwright headless Chromium
    logger.info("Attempting PDF conversion via Playwright (headless Chromium)...")
    pdf_ok = asyncio.run(_playwright_to_pdf(Path(output_html_fallback).resolve(), Path(output_pdf)))

    if not pdf_ok:
        logger.warning(
            "\n*** PDF rendering failed — HTML report is available at: %s\n"
            "To convert manually: open the HTML in Chrome and use File -> Print -> Save as PDF.",
            output_html_fallback,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="TriageMind Phase 4: PDF Restitution")
    parser.add_argument("--input", default="vulnerability_report.md", help="Input Markdown file")
    parser.add_argument("--output", default="TriageMind_Security_Report.pdf", help="Output PDF file")
    parser.add_argument("--fallback", default="TriageMind_Security_Report.html", help="Fallback HTML file")
    
    args = parser.parse_args()
    
    logger.info("Starting Phase 4: PDF Restitution")
    generate_pdf(args.input, args.output, args.fallback)
    logger.info("Phase 4 complete.")

if __name__ == "__main__":
    main()

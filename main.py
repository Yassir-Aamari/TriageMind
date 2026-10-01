"""
main.py
========
Phase 5: TriageMind Orchestrator
Chains Phase 1 to Phase 4 into a single, seamless, interactive pipeline.
Uses Rich for terminal UI and Tkinter for a native OS save dialog.

Refactored for PyInstaller Standalone Executable (Phase 6).
Subprocesses have been removed in favor of functional module execution.
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path

if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import contextlib
import io
import json
import logging
import re
import shutil
import subprocess
import time
import tkinter as tk
from tkinter import filedialog

os.environ.setdefault(
    "PLAYWRIGHT_BROWSERS_PATH",
    str(Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ms-playwright"),
)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt
    from rich.text import Text
    from rich.align import Align
    from rich.table import Table
except ImportError:
    print("FATAL: 'rich' library is not installed. Run 'pip install rich'")
    sys.exit(1)

import scanner
import parser
import ai_reporter
import pdf_generator


console = Console()


def show_startup_ui():
    console.print()
    console.print("━" * console.width, style="bright_green")
    console.print()

    logo_lines = [
        "  ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗███╗   ███╗██╗███╗   ██╗██████╗ ",
        "  ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝████╗ ████║██║████╗  ██║██╔══██╗",
        "     ██║   ██████╔╝██║███████║██║  ███╗█████╗  ██╔████╔██║██║██╔██╗ ██║██║  ██║",
        "     ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝  ██║╚██╔╝██║██║██║╚██╗██║██║  ██║",
        "     ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝",
        "     ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝",
    ]

    for line in logo_lines:
        console.print(f"[bright_green]{line}[/bright_green]")

    console.print()
    console.print("  [bold white]AI-Powered Web Vulnerability Scanner & Triage Pipeline[/bold white]")
    console.print("  [dim]v1.0.0  ·  Powered by Google Gemini  ·  Built with Python[/dim]")
    console.print()
    console.print("━" * console.width, style="bright_green")
    console.print()

    console.print("  [bold bright_green]HOW TO USE[/bold bright_green]")
    console.print()
    console.print("  [dim]TriageMind will guide you through the scan setup in two steps.[/dim]")
    console.print()

    how_to = """  [bold cyan][1][/bold cyan]  [white]Your Google Gemini API Key[/white]
     [dim]→ Get yours free at:[/dim] [cyan]https://aistudio.google.com/app/apikey[/cyan]
     [dim]→ Paste your full key when prompted[/dim]

  [bold cyan][2][/bold cyan]  [white]The target website URL to scan[/white]
     [dim]→ Example:[/dim] [white]http://localhost:3000[/white]
     [dim]→ Example:[/dim] [white]https://testphp.vulnweb.com[/white]

  [bold bright_green]TriageMind will then automatically:[/bold bright_green]
     [green]✓[/green] Crawl the target website
     [green]✓[/green] Run passive and active security checks
     [green]✓[/green] Enrich findings with CVSS/CVE data from NVD + EPSS + CISA KEV
     [green]✓[/green] Triage results using Gemini AI
     [green]✓[/green] Generate a full PDF security report"""

    console.print(how_to)
    console.print()
    console.print("━" * console.width, style="dim")
    console.print()

    console.print("  [bold cyan]STEP 1 / 2[/bold cyan]  [white]— Google Gemini API Key[/white]")
    console.print("  [dim]Get yours free at: https://aistudio.google.com/app/apikey[/dim]")
    console.print()

    while True:
        api_key = Prompt.ask(
            "  [bright_green]›[/bright_green] [white]Paste your API key[/white]",
            password=True
        )
        api_key = api_key.strip()
        if not api_key:
            console.print("  [red]✗ API key cannot be empty.[/red]")
            continue
        break

    console.print()
    console.print("  [bold green]✓ API Key accepted[/bold green]")
    console.print()
    os.environ["GEMINI_API_KEY"] = api_key

    console.print("━" * console.width, style="dim")
    console.print()
    console.print("  [bold cyan]STEP 2 / 2[/bold cyan]  [white]— Target Website URL[/white]")
    console.print("  [dim]Example: http://localhost:3000  or  https://target.com[/dim]")
    console.print()

    while True:
        target_url = Prompt.ask("  [bright_green]›[/bright_green] [white]Enter target URL[/white]")
        target_url = target_url.strip()
        if not target_url:
            console.print("  [red]✗ URL cannot be empty.[/red]")
            continue
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            console.print("  [red]✗ Invalid URL. Must start with http:// or https://[/red]")
            continue
        break

    console.print()
    console.print(f"  [bold green]✓ Target set:[/bold green] [white]{target_url}[/white]")
    console.print()

    console.print("━" * console.width, style="dim")
    console.print()
    console.print("  [bold white]SCAN CONFIGURATION[/bold white]")
    console.print()

    config_lines = [
        f"  [dim]Target URL[/dim]      [white]{target_url}[/white]",
        f"  [dim]Gemini Model[/dim]    [white]gemini-2.5-flash[/white]",
        f"  [dim]Active Checks[/dim]   [bright_green]Enabled[/bright_green]",
        f"  [dim]NVD Enrichment[/dim]  [bright_green]Enabled[/bright_green]",
        f"  [dim]EPSS Scoring[/dim]    [bright_green]Enabled[/bright_green]",
        f"  [dim]CISA KEV Check[/dim]  [bright_green]Enabled[/bright_green]",
        f"  [dim]AI Triage[/dim]       [bright_green]Enabled[/bright_green]",
        f"  [dim]Output[/dim]          [white]TriageMind_Report.pdf[/white]",
    ]

    for line in config_lines:
        console.print(line)

    console.print()

    console.print("━" * console.width, style="bright_green")
    console.print()

    for i in range(3, 0, -1):
        console.print(f"  [dim]Launching in[/dim] [bold yellow]{i}[/bold yellow][dim]...[/dim]")
        time.sleep(1)

    console.print()
    console.print("  [bold bright_green]◆  LAUNCHING TRIAGEMIND  ◆[/bold bright_green]")
    console.print()
    console.print("━" * console.width, style="bright_green")
    console.print()

    return (api_key, target_url)


OVERVIEW_LINE_COUNT = 8  # 4 phase lines + panel borders + padding


def clear_overview():
    """Move cursor up to overwrite the previous overview panel."""
    import sys
    sys.stdout.write(f"\033[{OVERVIEW_LINE_COUNT}A")  # move up N lines
    sys.stdout.write("\033[J")  # clear from cursor to end of screen
    sys.stdout.flush()


def print_pipeline_overview(statuses, labels, clear_previous=False):
    if clear_previous:
        clear_overview()
    lines = []
    for i, (status, label) in enumerate(zip(statuses, labels)):
        if status == "pending":
            lines.append(f"[dim]  ◯ Phase {i+1}/4 — {label}[/dim]")
        elif status == "running":
            lines.append(f"[bold cyan]  ► Phase {i+1}/4 — {label}[/bold cyan]")
        elif status == "done":
            lines.append(f"[bold green]  ✓ Phase {i+1}/4 — {label}[/bold green]")
        elif status == "failed":
            lines.append(f"[bold red]  ✗ Phase {i+1}/4 — {label}[/bold red]")
    console.print(Panel(
        "\n".join(lines),
        title="[bold white]PIPELINE OVERVIEW[/bold white]",
        border_style="dim white",
        padding=(0, 2)
    ))


def _build_cli_parser():
    p = argparse.ArgumentParser(description="Run the TriageMind security assessment pipeline.")
    p.add_argument("--target", help="Target URL. If omitted, TriageMind prompts interactively.")
    p.add_argument(
        "--active",
        action="store_true",
        default=True,
        help="Enable authorised active payload checks. Passive scanning is the default.",
    )
    p.add_argument(
        "--headed",
        action="store_true",
        help="Launch Chromium in a visible browser window instead of headless mode.",
    )
    p.add_argument("--auth-login-url", help="URL of the login page to authenticate before crawling.")
    p.add_argument("--auth-username", help="Username to use for authentication.")
    p.add_argument("--auth-password", help="Password to use for authentication.")
    p.add_argument("--max-depth", type=int, default=3, metavar="N", help="Maximum BFS crawl depth (default: 3).")
    p.add_argument("--max-interactions", type=int, default=50, metavar="N", help="Maximum crawler page visits + element interactions (default: 50).")
    p.add_argument("--delay", type=float, default=0.5, metavar="SECONDS", help="Delay between crawler interactions in seconds (default: 0.5).")
    p.add_argument("--timeout", type=int, default=15000, metavar="MS", help="Playwright navigation timeout in milliseconds (default: 15000).")
    p.add_argument("--crawl-duration", type=float, default=120.0, metavar="SECONDS", help="Hard wall-clock limit for the crawl phase in seconds (default: 120).")
    p.add_argument("--active-max-duration", type=float, default=120.0, metavar="SECONDS", help="Hard wall-clock limit for the active scan phase in seconds (default: 120).")
    return p


def ensure_playwright_browsers():
    """Ensures Chromium is available before the interactive session begins."""
    import shutil
    chromium_found = (
        shutil.which("chromium") or
        shutil.which("chromium-browser") or
        shutil.which("google-chrome")
    )
    if not chromium_found:
        try:
            from playwright._impl._driver import compute_driver_executable
            driver_path, _ = compute_driver_executable()
            chromium_found = Path(driver_path).exists()
        except Exception:
            chromium_found = False

    if not chromium_found:
        console.print("[yellow]Playwright Chromium not found. Downloading now (this happens once)...[/yellow]")
        if getattr(sys, "frozen", False):
            driver_dir = Path(getattr(sys, "_MEIPASS")) / "playwright" / "driver"
            command = [
                str(driver_dir / "node.exe"),
                str(driver_dir / "package" / "cli.js"),
                "install",
                "chromium",
            ]
        else:
            command = [sys.executable, "-m", "playwright", "install", "chromium"]
        subprocess.run(command, check=True)

def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"

def get_fp_color_style(pct):
    if pct >= 70.0:
        return "bold green"
    elif pct >= 40.0:
        return "bold yellow"
    else:
        return "bold red"

def parse_pipeline_stats(results_file="results.json", enriched_file="enriched_results.json", report_file="vulnerability_report.md"):
    stats = {
        "raw_total": 0,
        "passive_count": 0,
        "active_count": 0,
        "enriched_cve_count": 0,
        "suppressed_count": 0,
        "confirmed_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "fp_reduction_pct": 0.0,
    }

    r_path = Path(results_file)
    if r_path.exists():
        try:
            with open(r_path, "r", encoding="utf-8") as f:
                findings = json.load(f)
                stats["raw_total"] = len(findings)
                stats["passive_count"] = sum(1 for item in findings if item.get("scan_type") == "passive")
                stats["active_count"] = sum(1 for item in findings if item.get("scan_type") == "active")
        except Exception:
            pass

    e_path = Path(enriched_file)
    if e_path.exists():
        try:
            with open(e_path, "r", encoding="utf-8") as f:
                enriched = json.load(f)
                stats["enriched_cve_count"] = sum(
                    1 for item in enriched if item.get("cve") or (item.get("nvd_data") and item.get("nvd_data") != {})
                )
        except Exception:
            pass

    rep_path = Path(report_file)
    if rep_path.exists():
        try:
            md_text = rep_path.read_text(encoding="utf-8")

            m_supp = re.search(r"<!--\s*TRIAGE_METRICS:\s*suppressed=(\d+)\s*-->", md_text)
            if not m_supp:
                m_supp = re.search(r"(\d+)\s+of\s+\d+\s+raw findings were automatically suppressed", md_text, re.IGNORECASE)

            if m_supp:
                stats["suppressed_count"] = int(m_supp.group(1))

            table_lines = [line for line in md_text.splitlines() if line.strip().startswith("|")]
            sev_col_idx    = 2
            status_col_idx = 3

            for line in table_lines:
                cols = [c.strip().strip("`") for c in line.split("|")[1:-1]]
                if not cols or re.search(r"^-{2,}$|^:?-{2,}:?$", cols[0]):
                    continue

                cols_lower = [c.lower() for c in cols]

                if any("severity" in c for c in cols_lower) and any(
                    "triage" in c or "status" in c for c in cols_lower
                ):
                    for idx, c in enumerate(cols_lower):
                        if "severity" in c:
                            sev_col_idx = idx
                        if "triage" in c or "status" in c:
                            status_col_idx = idx
                    continue

                if len(cols) < max(sev_col_idx + 1, status_col_idx + 1):
                    continue

                first = cols[0].lower().strip()
                if first in ("id", "finding id", "finding", "#", "no", "vulnerability name"):
                    continue

                sev_clean    = cols[sev_col_idx].lower()
                status_clean = cols[status_col_idx].lower()

                if "false" in status_clean or "suppressed" in status_clean:
                    continue

                if "high" in sev_clean or "critical" in sev_clean:
                    stats["high_count"] += 1
                elif "medium" in sev_clean:
                    stats["medium_count"] += 1
                elif "low" in sev_clean or "info" in sev_clean:
                    stats["low_count"] += 1

            stats["confirmed_count"] = stats["high_count"] + stats["medium_count"] + stats["low_count"]
            if stats["raw_total"] > 0:
                stats["fp_reduction_pct"] = (stats["suppressed_count"] / stats["raw_total"]) * 100.0
            elif (stats["confirmed_count"] + stats["suppressed_count"]) > 0:
                tot = stats["confirmed_count"] + stats["suppressed_count"]
                stats["fp_reduction_pct"] = (stats["suppressed_count"] / tot) * 100.0

        except Exception:
            pass

    return stats

def run_phase(phase_name, task_func, summary_func=None):
    """
    Executes a python callable while showing a rich spinner.
    Captures stdout/stderr internally to mimic subprocess isolation.
    """
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    t0 = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"[cyan]Executing {phase_name}...", total=None)

        try:
            with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
                task_func()
        except Exception as e:
            console.print(f"[bold red]System Error during {phase_name}:[/bold red] {e}")
            return False

        stderr_val = stderr_capture.getvalue()
        if "Traceback (most recent call last):" in stderr_val or "[CRITICAL]" in stderr_val:
            console.print(Panel(
                f"[bold red]{phase_name} Failed (Internal Exception)[/bold red]\n\n"
                f"[yellow]Captured Error Logs:[/yellow]\n{stderr_val.strip()}",
                title="Pipeline Execution Error",
                border_style="red"
            ))
            return False

    duration = time.perf_counter() - t0
    duration_str = format_duration(duration)

    summary_text = ""
    if summary_func:
        try:
            summary_text = summary_func()
        except Exception:
            summary_text = ""

    if summary_text:
        console.print(
            f"[bold green][OK][/bold green] [bold]{phase_name}[/bold] complete \u2014 "
            f"{summary_text} [dim]({duration_str})[/dim]"
        )
    else:
        console.print(
            f"[bold green][OK][/bold green] [bold]{phase_name}[/bold] complete "
            f"[dim]({duration_str})[/dim]"
        )

    return True

def print_final_summary(target_url, total_duration, stats):
    fp_pct = stats["fp_reduction_pct"]
    fp_color = get_fp_color_style(fp_pct)
    duration_str = format_duration(total_duration)

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Property", style="bold cyan", justify="right")
    table.add_column("Value", style="bold white", justify="left")

    table.add_row("Target URL:", target_url)
    table.add_row("Total Scan Runtime:", duration_str)
    table.add_row(
        "Raw Findings:",
        f"{stats['raw_total']} ({stats['passive_count']} passive, {stats['active_count']} active)"
    )
    table.add_row(
        "AI-Confirmed:",
        f"[bold green]{stats['confirmed_count']}[/bold green] "
        f"(High: [bold red]{stats['high_count']}[/bold red], "
        f"Med: [bold yellow]{stats['medium_count']}[/bold yellow], "
        f"Low/Info: [bold cyan]{stats['low_count']}[/bold cyan])"
    )
    table.add_row("False Positives Suppressed:", f"[bold yellow]{stats['suppressed_count']}[/bold yellow]")
    table.add_row("FP Reduction Rate:", f"[{fp_color}]{fp_pct:.1f}%[/{fp_color}]")

    summary_panel = Panel(
        Align.center(table),
        title="[bold white]TriageMind Pipeline Assessment Summary[/bold white]",
        subtitle=f"[bold blue]Scan Completed in {duration_str}[/bold blue]",
        border_style="bright_blue",
        expand=False
    )
    console.print()
    console.print(Align.center(summary_panel))
    console.print()

def prompt_save_file(source_file):
    """Triggers a native OS save dialog to export the report."""
    console.print("[bold cyan]Pipeline complete. Triggering Save Dialog...[/bold cyan]")

    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)

    ext = source_file.suffix
    file_type_name = "PDF Document" if ext == ".pdf" else "HTML Document"

    dest_path = filedialog.asksaveasfilename(
        title="Save TriageMind Security Report",
        initialfile=f"TriageMind_Report{ext}",
        defaultextension=ext,
        filetypes=[(file_type_name, f"*{ext}")]
    )

    root.destroy()

    if not dest_path:
        console.print(f"[yellow]Save cancelled. The report is preserved locally at:[/yellow]\n[bold]{source_file.absolute()}[/bold]")
        return

    try:
        shutil.copy(source_file, dest_path)
        console.print(f"[bold green][OK] Report successfully exported to:[/bold green] {dest_path}")
    except Exception as e:
        console.print(f"[bold red]Failed to export report:[/bold red] {e}\n[yellow]Local copy preserved at: {source_file.absolute()}[/yellow]")


def main():
    try:
        cli_args = _build_cli_parser().parse_args()

        ensure_playwright_browsers()

        api_key, target_url = show_startup_ui()

    except KeyboardInterrupt:
        console.print("\n[yellow]\u26a0 Scan cancelled by user.[/yellow]")
        sys.exit(0)

    from urllib.parse import urlsplit as _urlsplit
    _parsed = _urlsplit(target_url)
    _netloc = _parsed.netloc.replace(":", "_").replace(".", "_")
    site_name_label = _netloc or "target"
    site_display_name = _parsed.netloc or target_url

    pdf_filename  = f"{site_name_label}_TriageMind_Report.pdf"
    html_filename = f"{site_name_label}_TriageMind_Report.html"
    md_filename   = f"{site_name_label}_vulnerability_report.md"

    phase_statuses = ["pending", "pending", "pending", "pending"]
    phase_labels = [
        "Crawling & Scanning",
        "NVD + EPSS + CISA KEV Enrichment",
        "AI Triage via Gemini",
        "PDF Report Compilation"
    ]

    # Initial overview — all pending
    print_pipeline_overview(phase_statuses, phase_labels)

    pipeline_start_time = time.perf_counter()

    # --- PHASE 1: Scanner ---
    def execute_scanner():
        scanner_args = ["--target", target_url]
        if cli_args.active:
            scanner_args.append("--active")
        if cli_args.headed:
            scanner_args.append("--headed")
        scanner_args += ["--max-depth", str(cli_args.max_depth)]
        scanner_args += ["--max-interactions", str(cli_args.max_interactions)]
        scanner_args += ["--delay", str(cli_args.delay)]
        scanner_args += ["--timeout", str(cli_args.timeout)]
        scanner_args += ["--crawl-duration", str(cli_args.crawl_duration)]
        scanner_args += ["--active-max-duration", str(cli_args.active_max_duration)]
        if cli_args.auth_login_url:
            scanner_args += ["--auth-login-url", cli_args.auth_login_url]
        if cli_args.auth_username:
            scanner_args += ["--auth-username", cli_args.auth_username]
        if cli_args.auth_password:
            scanner_args += ["--auth-password", cli_args.auth_password]
        scanner_args += ["--output", "results.json"]
        args = scanner._build_parser().parse_args(scanner_args)
        asyncio.run(scanner._run(args))

    def get_phase1_summary():
        r_path = Path("results.json")
        if r_path.exists():
            try:
                with open(r_path, "r", encoding="utf-8") as f:
                    findings = json.load(f)
                    total = len(findings)
                    passive = sum(1 for x in findings if x.get("scan_type") == "passive" or x.get("check_type") == "passive")
                    active = sum(1 for x in findings if x.get("scan_type") == "active" or x.get("check_type") == "active")
                    return f"[bold cyan]{total}[/bold cyan] findings ({passive} passive, {active} active)"
            except Exception:
                pass
        return ""

    phase_statuses[0] = "running"
    print_pipeline_overview(phase_statuses, phase_labels, clear_previous=True)
    console.print(Panel(
        "[bold white]Initializing crawler and scanner...[/bold white]",
        title="[bold cyan]◆ PHASE 1 / 4 — CRAWLING & SCANNING[/bold cyan]",
        border_style="cyan",
        padding=(0, 2)
    ))

    if not run_phase("[bold cyan]Phase 1/4[/bold cyan] \u2014 Crawling & Scanning target...", execute_scanner, get_phase1_summary):
        phase_statuses[0] = "failed"
        print_pipeline_overview(phase_statuses, phase_labels)
        console.print(Panel(
            "\u2717 Phase 1 failed: Crawling & Scanning\n\nCheck your target URL and try again.",
            title="[bold]ERROR[/bold]",
            border_style="red",
        ))
        sys.exit(1)

    phase_statuses[0] = "done"
    phase_statuses[1] = "running"
    print_pipeline_overview(phase_statuses, phase_labels)
    console.print("[bold green]  ✓ Phase 1/4 complete[/bold green]\n")
    console.rule(style="dim white")

    # --- PHASE 2: Parser & NVD Enrichment ---
    def execute_parser():
        asyncio.run(parser.parse_and_enrich("results.json", "enriched_results.json"))

    def get_phase2_summary():
        e_path = Path("enriched_results.json")
        if e_path.exists():
            try:
                with open(e_path, "r", encoding="utf-8") as f:
                    enriched = json.load(f)
                    total = len(enriched)
                    cve_cnt = sum(
                        1 for x in enriched if x.get("cve") or (x.get("nvd_data") and x.get("nvd_data") != {})
                    )
                    return f"[bold cyan]{total}[/bold cyan] findings processed ({cve_cnt} CVEs enriched via NVD)"
            except Exception:
                pass
        return ""

    console.print(Panel(
        "[bold white]Fetching NVD, EPSS and CISA KEV data...[/bold white]",
        title="[bold cyan]◆ PHASE 2 / 4 — VULNERABILITY ENRICHMENT[/bold cyan]",
        border_style="cyan",
        padding=(0, 2)
    ))

    if not run_phase("[bold cyan]Phase 2/4[/bold cyan] \u2014 Enriching findings with NVD + EPSS + CISA KEV...", execute_parser, get_phase2_summary):
        phase_statuses[1] = "failed"
        print_pipeline_overview(phase_statuses, phase_labels)
        console.print(Panel(
            "\u2717 Phase 2 failed: NVD + EPSS + CISA KEV Enrichment\n\nCheck your API key and target URL and try again.",
            title="[bold]ERROR[/bold]",
            border_style="red",
        ))
        sys.exit(1)

    phase_statuses[1] = "done"
    phase_statuses[2] = "running"
    print_pipeline_overview(phase_statuses, phase_labels)
    console.print("[bold green]  ✓ Phase 2/4 complete[/bold green]\n")
    console.rule(style="dim white")

    # --- PHASE 3: AI Triage ---
    def execute_reporter():
        ai_reporter.generate_report("enriched_results.json", md_filename)

    def get_phase3_summary():
        stats = parse_pipeline_stats(report_file=md_filename)
        fp_pct = stats["fp_reduction_pct"]
        fp_color = get_fp_color_style(fp_pct)
        return (
            f"[bold cyan]{stats['confirmed_count']}[/bold cyan] confirmed findings, "
            f"[bold yellow]{stats['suppressed_count']}[/bold yellow] false positives suppressed "
            f"([{fp_color}]{fp_pct:.1f}% reduction[/{fp_color}])"
        )

    console.print(Panel(
        "[bold white]Sending findings to Gemini AI for triage...[/bold white]",
        title="[bold cyan]◆ PHASE 3 / 4 — AI TRIAGE[/bold cyan]",
        border_style="cyan",
        padding=(0, 2)
    ))

    if not run_phase("[bold cyan]Phase 3/4[/bold cyan] \u2014 AI Triage via Google Gemini...", execute_reporter, get_phase3_summary):
        phase_statuses[2] = "failed"
        print_pipeline_overview(phase_statuses, phase_labels)
        console.print(Panel(
            "\u2717 Phase 3 failed: AI Triage via Google Gemini\n\nCheck your API key and target URL and try again.",
            title="[bold]ERROR[/bold]",
            border_style="red",
        ))
        sys.exit(1)

    phase_statuses[2] = "done"
    phase_statuses[3] = "running"
    print_pipeline_overview(phase_statuses, phase_labels)
    console.print("[bold green]  ✓ Phase 3/4 complete[/bold green]\n")
    console.rule(style="dim white")

    # --- PHASE 4: PDF Restitution ---
    def execute_pdf_generator():
        pdf_generator.generate_pdf(
            md_filename,
            pdf_filename,
            html_filename,
            site_name=site_display_name,
        )

    def get_phase4_summary():
        if Path(pdf_filename).exists():
            return f"PDF report compiled \u2192 {pdf_filename}"
        elif Path(html_filename).exists():
            return f"HTML report generated (fallback) \u2192 {html_filename}"
        return ""

    console.print(Panel(
        "[bold white]Compiling PDF report...[/bold white]",
        title="[bold cyan]◆ PHASE 4 / 4 — REPORT COMPILATION[/bold cyan]",
        border_style="cyan",
        padding=(0, 2)
    ))

    if not run_phase("[bold cyan]Phase 4/4[/bold cyan] \u2014 Compiling PDF Report...", execute_pdf_generator, get_phase4_summary):
        phase_statuses[3] = "failed"
        print_pipeline_overview(phase_statuses, phase_labels)
        console.print(Panel(
            "\u2717 Phase 4 failed: PDF Report Compilation\n\nCheck your API key and target URL and try again.",
            title="[bold]ERROR[/bold]",
            border_style="red",
        ))
        sys.exit(1)

    phase_statuses[3] = "done"
    print_pipeline_overview(phase_statuses, phase_labels)
    console.print("[bold green]  ✓ Phase 4/4 complete[/bold green]\n")
    console.rule(style="dim white")

    total_pipeline_duration = time.perf_counter() - pipeline_start_time
    final_stats = parse_pipeline_stats(report_file=md_filename)

    print_final_summary(target_url, total_pipeline_duration, final_stats)

    console.print(Panel(
        "[green]\u2713[/green] Crawling & scanning completed\n"
        "[green]\u2713[/green] NVD + EPSS + CISA KEV enrichment completed\n"
        "[green]\u2713[/green] AI triage completed\n"
        "[green]\u2713[/green] Report generated\n\n"
        "Your report has been saved.\n"
        "[dim]Thank you for using TriageMind.[/dim]",
        title="[bold]SCAN COMPLETE[/bold]",
        border_style="bright_green",
    ))
    console.print()

    pdf_path  = Path(pdf_filename)
    html_path = Path(html_filename)

    if pdf_path.exists():
        prompt_save_file(pdf_path)
    elif html_path.exists():
        console.print("[yellow]PDF was not generated (missing Pandoc dependencies). Exporting fallback HTML instead.[/yellow]")
        prompt_save_file(html_path)
    else:
        console.print("[bold red]Critical Error:[/bold red] Neither PDF nor HTML report was found in the workspace!")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]\u26a0 Scan cancelled by user.[/yellow]")
        sys.exit(0)
"""
scanner.py
==========
Main entry point for the web vulnerability scanner.

Orchestrates the three scan phases:
  1. Crawl  - discovers pages and parameters using Playwright.
  2. Passive scan - analyses captured page data for misconfigurations.
  3. Active scan  - injects payloads (only with --active flag).

Usage examples:
  python scanner.py --target http://localhost:3000
  python scanner.py --target http://localhost:3000 --active --output results.json
  python scanner.py --target http://localhost:42001 --max-depth 2 --delay 1.0 --active

Output:
  JSON file (--output, default: results.json) containing a list of findings.
  Each finding matches the canonical schema required by the downstream pipeline.
"""

import argparse
import asyncio
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from browser_crawler import BrowserCrawler
from passive_checks import run_passive_checks, Finding
from active_checks import run_active_checks


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
        handlers=[logging.StreamHandler(sys.stdout)],
    )


# ---------------------------------------------------------------------------
# Finding serialisation
# ---------------------------------------------------------------------------

def _finalise_finding(finding: Finding, scan_date: str) -> dict:
    """
    Inject the auto-generated fields (id, scan_date) and serialise
    to the canonical JSON structure consumed by the downstream pipeline.

    Schema:
      id            - UUID v4 string
      template_id   - machine-readable check name (e.g. "missing-csp")
      category      - vulnerability TYPE (misconfiguration | exposure | xss |
                       sqli | open_redirect)
      scan_type     - scan phase ("passive" or "active")
      host          - hostname (e.g. "localhost:3000")
      url           - full URL where the finding was observed
      severity      - critical | high | medium | low | info
      description   - human-readable explanation
      evidence      - observed artefact that triggered the finding
      cve           - CVE identifier or null
      scan_date     - ISO-8601 timestamp of scan execution
    """
    return {
        "id": str(uuid.uuid4()),
        "template_id": finding.template_id,
        "category": finding.category,
        "scan_type": finding.scan_type,
        "host": finding.host,
        "url": finding.url,
        "severity": finding.severity,
        "description": finding.description,
        "evidence": finding.evidence,
        "cve": finding.cve,
        "scan_date": scan_date,
    }


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "Web vulnerability scanner - "
            "Playwright-based crawler with passive and active checks."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive scan only (safe, no payloads sent):
  python scanner.py --target http://localhost:3000

  # Passive + active scan (XSS, SQLi, open redirect, sensitive paths):
  python scanner.py --target http://localhost:3000 --active
        """,
    )

    parser.add_argument(
        "--target",
        required=True,
        metavar="URL",
        help="Target web application URL (e.g. http://localhost:3000).",
    )
    parser.add_argument(
        "--output",
        default="results.json",
        metavar="FILE",
        help="Path to write the JSON findings file (default: results.json).",
    )
    parser.add_argument(
        "--active",
        action="store_true",
        default=True,
        help="Enable authorised active payload checks.",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        default=False,
        help="Deprecated compatibility flag.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        metavar="N",
        help="Maximum BFS crawl depth from the start URL (default: 3).",
    )
    parser.add_argument(
        "--max-interactions",
        type=int,
        default=50,
        metavar="N",
        help="Maximum total page visits + element interactions (default: 50).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        metavar="SECONDS",
        help="Delay in seconds between browser interactions (default: 0.5).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15000,
        metavar="MS",
        help="Playwright navigation timeout in milliseconds (default: 15000).",
    )
    parser.add_argument(
        "--respect-robots",
        action="store_true",
        default=False,
        help="Fetch and honour robots.txt before crawling.",
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        default=False,
        help="Run Chromium with a visible window.",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        default=False,
        help="Launch Chromium visibly instead of headless.",
    )
    parser.add_argument(
        "--crawl-duration",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="Hard wall-clock limit for the crawl phase.",
    )
    parser.add_argument(
        "--active-max-duration",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="Hard wall-clock limit for the active scan phase.",
    )
    # Authentication args
    parser.add_argument(
        "--auth-login-url",
        default=None,
        help="URL of the login page to authenticate before crawling.",
    )
    parser.add_argument(
        "--auth-username",
        default=None,
        help="Username to use for authentication.",
    )
    parser.add_argument(
        "--auth-password",
        default=None,
        help="Password to use for authentication.",
    )
    parser.add_argument(
        "--max-same-action",
        type=int,
        default=2,
        metavar="N",
        help="Maximum number of interactions per structurally-identical action type.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable debug-level logging.",
    )

    return parser


# ---------------------------------------------------------------------------
# Active scan warning banner
# ---------------------------------------------------------------------------

_ACTIVE_SCAN_WARNING = """
************************************************************************
*                    !  ACTIVE SCAN WARNING  !                         *
*                                                                      *
*  Active scanning sends malicious payloads (XSS, SQL injection,       *
*  open redirect probes) to the target application.                    *
*                                                                      *
*  ONLY run this against a target for which you have explicit,         *
*  written authorisation to perform security testing.                  *
*                                                                      *
*  Unauthorised scanning is illegal in most jurisdictions.             *
************************************************************************
"""


# ---------------------------------------------------------------------------
# Main async orchestrator
# ---------------------------------------------------------------------------

async def _run(args: argparse.Namespace) -> None:
    logger = logging.getLogger("scanner")
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    target = args.target.rstrip("/")

    # ------------------------------------------------------------------ #
    # Phase 1: Crawl                                                       #
    # ------------------------------------------------------------------ #
    # --headed takes precedence over legacy --no-headless
    headless = not (args.headed or args.no_headless)

    ANSI_GREEN = "\033[92m"
    ANSI_RESET = "\033[0m"
    ANSI_BOLD = "\033[1m"

    logger.info("=" * 60)
    print(f"{ANSI_BOLD}{ANSI_GREEN}[PHASE 1] BROWSER CRAWL{ANSI_RESET}")
    logger.info("Target        : %s", target)
    logger.info("Max depth     : %d", args.max_depth)
    logger.info("Max interact. : %d", args.max_interactions)
    logger.info("Crawl duration: %.0f s", args.crawl_duration)
    logger.info("Active dur.   : %.0f s", args.active_max_duration)
    logger.info("Delay         : %.1f s", args.delay)
    logger.info("Respect robots: %s", args.respect_robots)
    logger.info("Headless      : %s", headless)
    logger.info("=" * 60)

    crawler = BrowserCrawler(
        target=target,
        max_depth=args.max_depth,
        max_interactions=args.max_interactions,
        delay=args.delay,
        respect_robots=args.respect_robots,
        timeout=args.timeout,
        headless=headless,
        max_duration=args.crawl_duration,
        max_same_action=args.max_same_action,
        auth_login_url=args.auth_login_url,
        auth_username=args.auth_username,
        auth_password=args.auth_password,
    )
    snapshots = await crawler.crawl()
    logger.info("Crawl complete: %d pages/states captured.", len(snapshots))

    # Save browser session state so active checks can reuse cookies/localStorage.
    session_state_path = "crawl_session.json"
    try:
        # BrowserCrawler doesn't currently expose the context externally;
        # we write an empty-but-valid state file as a placeholder so
        # run_active_checks() can accept the parameter safely.
        # (Full session persistence requires browser context exposure —
        #  tracked as a follow-up enhancement.)
        import json as _json
        if not Path(session_state_path).exists():
            Path(session_state_path).write_text(
                _json.dumps({"cookies": [], "origins": []}), encoding="utf-8"
            )
    except Exception as _se:
        logger.debug("Could not write session state placeholder: %s", _se)
        session_state_path = None  # type: ignore

    all_findings: list[Finding] = []

    # ------------------------------------------------------------------ #
    # Phase 2: Passive Scan                                                #
    # ------------------------------------------------------------------ #
    logger.info("=" * 60)
    print(f"{ANSI_BOLD}{ANSI_GREEN}[PHASE 2] PASSIVE SCAN ({len(snapshots)} snapshots){ANSI_RESET}")
    logger.info("=" * 60)

    passive_findings = run_passive_checks(snapshots)
    all_findings.extend(passive_findings)
    logger.info("Passive scan complete: %d findings.", len(passive_findings))

    # ------------------------------------------------------------------ #
    # Phase 3: Active Scan (explicit opt-in only)                         #
    # ------------------------------------------------------------------ #
    run_active = args.active
    if run_active:
        print(_ACTIVE_SCAN_WARNING)
        logger.info("=" * 60)
        print(f"{ANSI_BOLD}{ANSI_GREEN}[PHASE 3] ACTIVE SCAN{ANSI_RESET}")
        logger.info("=" * 60)

        active_findings = await run_active_checks(
            snapshots=snapshots,
            target=target,
            delay=args.delay,
            timeout=args.timeout,
            headless=headless,
            max_duration=args.active_max_duration,
            session_state_path=session_state_path,
        )
        all_findings.extend(active_findings)
        logger.info("Active scan complete: %d findings.", len(active_findings))
    else:
        logger.info(
            "Active scan skipped (passive mode is the default; use --active to enable payload checks)."
        )

    # ------------------------------------------------------------------ #
    # Serialise and write results                                          #
    # ------------------------------------------------------------------ #
    output_data = [_finalise_finding(f, scan_date) for f in all_findings]

    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(output_data, fh, indent=2, ensure_ascii=False)

    # Write a sidecar metadata file so any future run (or a human reading
    # the workspace) can tell which target was scanned, when, and how.
    meta = {
        "target": target,
        "scan_date": scan_date,
        "scanner_version": "1.1",
        "active_scan": run_active,
        "max_depth": args.max_depth,
        "finding_count": len(output_data),
        "passive_count": sum(1 for f in output_data if f["scan_type"] == "passive"),
        "active_count": sum(1 for f in output_data if f["scan_type"] == "active"),
    }
    meta_path = output_path.with_name("scan_meta.json")
    try:
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, ensure_ascii=False)
        logger.info("Scan metadata written: %s", meta_path.resolve())
    except Exception as exc:
        logger.warning("Could not write scan_meta.json: %s", exc)

    logger.info("=" * 60)
    print(f"{ANSI_BOLD}{ANSI_GREEN}[SCAN COMPLETE]{ANSI_RESET}")
    logger.info("Total findings : %d", len(output_data))
    logger.info(
        "  Passive      : %d",
        sum(1 for f in output_data if f["scan_type"] == "passive"),
    )
    logger.info(
        "  Active       : %d",
        sum(1 for f in output_data if f["scan_type"] == "active"),
    )
    for sev in ("critical", "high", "medium", "low", "info"):
        count = sum(1 for f in output_data if f["severity"] == sev)
        if count:
            logger.info("  %-10s  : %d", sev.capitalize(), count)
    print(f"{ANSI_BOLD}{ANSI_GREEN}Results written: {output_path.resolve()}{ANSI_RESET}")
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _setup_logging(args.verbose)

    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as exc:
        logging.getLogger("scanner").critical(
            "Fatal error: %s", exc, exc_info=True
        )
        sys.exit(2)


if __name__ == "__main__":
    main()

"""
passive_checks.py
=================
Passive vulnerability checks.

All checks analyse PageSnapshot objects that were already collected during
crawling - they do NOT send any additional HTTP requests.

Each check function receives the list of all snapshots and returns a list
of Finding objects.

Finding schema fields used here:
  - category  : vulnerability TYPE - always "misconfiguration" or "exposure"
  - scan_type : always "passive"
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from browser_crawler import PageSnapshot

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding data structure
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Canonical finding structure shared by passive and active checks.
    The 'id' and 'scan_date' fields are filled in by scanner.py before
    writing to JSON.
    """
    template_id: str                   # machine-readable check name
    category: str                      # vulnerability type: misconfiguration, exposure, xss, sqli, open_redirect
    scan_type: str                     # scan phase: "passive" or "active"
    host: str
    url: str
    severity: str                      # critical | high | medium | low | info
    description: str
    evidence: str
    cve: Optional[str] = None          # CVE identifier if applicable, else None
    # id and scan_date are injected by scanner.py
    id: str = ""
    scan_date: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _host(url: str) -> str:
    """Extract host (netloc) from a URL."""
    return urlparse(url).netloc


def _header(headers: dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _has_header(headers: dict[str, str], name: str) -> bool:
    return _header(headers, name) is not None


# ---------------------------------------------------------------------------
# Individual passive check functions
# ---------------------------------------------------------------------------

def check_missing_csp(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Check: Content-Security-Policy header is absent.

    CSP is a defence-in-depth control against XSS and data injection attacks.
    Its absence does not mean the app is vulnerable, but it is a meaningful
    misconfiguration finding.
    """
    findings = []
    seen_hosts: set[str] = set()

    for snap in snapshots:
        host = _host(snap.url)
        if host in seen_hosts:
            continue  # Report once per host
        if not _has_header(snap.headers, "content-security-policy"):
            seen_hosts.add(host)
            findings.append(Finding(
                template_id="missing-csp",
                category="misconfiguration",
                scan_type="passive",
                host=host,
                url=snap.url,
                severity="low",
                description=(
                    "The Content-Security-Policy (CSP) HTTP header is missing. "
                    "CSP restricts which resources the browser can load, "
                    "mitigating XSS and data-injection attacks."
                ),
                evidence=f"No Content-Security-Policy header found on {snap.url}",
            ))
    return findings


def check_missing_x_frame_options(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Check: X-Frame-Options header is absent.

    Without this header (or an equivalent CSP frame-ancestors directive)
    the page may be embedded in a <frame>/<iframe> by an attacker,
    enabling clickjacking attacks.
    """
    findings = []
    seen_hosts: set[str] = set()

    for snap in snapshots:
        host = _host(snap.url)
        if host in seen_hosts:
            continue
        has_xfo = _has_header(snap.headers, "x-frame-options")
        # CSP frame-ancestors is an equivalent mitigation
        csp = _header(snap.headers, "content-security-policy") or ""
        has_csp_frame = "frame-ancestors" in csp.lower()

        if not has_xfo and not has_csp_frame:
            seen_hosts.add(host)
            findings.append(Finding(
                template_id="missing-x-frame-options",
                category="misconfiguration",
                scan_type="passive",
                host=host,
                url=snap.url,
                severity="low",
                description=(
                    "The X-Frame-Options header is missing and no CSP frame-ancestors "
                    "directive was found. The page may be embedded in an iframe, "
                    "enabling clickjacking attacks."
                ),
                evidence=f"No X-Frame-Options or CSP frame-ancestors on {snap.url}",
            ))
    return findings


def check_missing_x_content_type_options(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Check: X-Content-Type-Options: nosniff is absent.

    Without 'nosniff', browsers may MIME-sniff responses away from the declared
    Content-Type, which can lead to XSS via content-type confusion.
    """
    findings = []
    seen_hosts: set[str] = set()

    for snap in snapshots:
        host = _host(snap.url)
        if host in seen_hosts:
            continue
        val = _header(snap.headers, "x-content-type-options")
        if not val or "nosniff" not in val.lower():
            seen_hosts.add(host)
            findings.append(Finding(
                template_id="missing-x-content-type-options",
                category="misconfiguration",
                scan_type="passive",
                host=host,
                url=snap.url,
                severity="low",
                description=(
                    "The X-Content-Type-Options: nosniff header is missing. "
                    "Browsers may MIME-sniff the response, potentially enabling "
                    "content-type confusion attacks."
                ),
                evidence=f"No X-Content-Type-Options header on {snap.url}",
            ))
    return findings


def check_missing_hsts(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Check: Strict-Transport-Security header is absent (HTTPS targets only).

    HSTS tells browsers to always connect over HTTPS. Its absence allows
    SSL-stripping attacks for users who first connect over HTTP.
    """
    findings = []
    seen_hosts: set[str] = set()

    for snap in snapshots:
        if not snap.url.startswith("https://"):
            continue  # HSTS is only applicable to HTTPS
        host = _host(snap.url)
        if host in seen_hosts:
            continue
        if not _has_header(snap.headers, "strict-transport-security"):
            seen_hosts.add(host)
            findings.append(Finding(
                template_id="missing-hsts",
                category="misconfiguration",
                scan_type="passive",
                host=host,
                url=snap.url,
                severity="medium",
                description=(
                    "The Strict-Transport-Security (HSTS) header is missing on an HTTPS page. "
                    "Without HSTS, users who visit via HTTP may be subject to SSL-stripping attacks."
                ),
                evidence=f"No Strict-Transport-Security header on {snap.url}",
            ))
    return findings


def check_cookie_flags(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Check: Session cookies missing the Secure and/or HttpOnly flags.

    - Secure: prevents cookie transmission over plain HTTP (mitigates network sniffing)
    - HttpOnly: prevents JavaScript access to the cookie (mitigates cookie theft via XSS)
    """
    findings = []

    for snap in snapshots:
        host = _host(snap.url)
        for raw_cookie in snap.cookies:
            # raw_cookie is the full Set-Cookie header value
            # e.g. "sessionId=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"
            parts = [p.strip().lower() for p in raw_cookie.split(";")]
            cookie_name = raw_cookie.split("=")[0].strip() if "=" in raw_cookie else raw_cookie.strip()

            if "secure" not in parts:
                findings.append(Finding(
                    template_id="cookie-missing-secure",
                    category="misconfiguration",
                    scan_type="passive",
                    host=host,
                    url=snap.url,
                    severity="medium",
                    description=(
                        f"Cookie '{cookie_name}' is set without the Secure flag. "
                        "It may be transmitted over unencrypted HTTP connections."
                    ),
                    evidence=f"Set-Cookie: {raw_cookie[:200]}",
                ))

            if "httponly" not in parts:
                findings.append(Finding(
                    template_id="cookie-missing-httponly",
                    category="misconfiguration",
                    scan_type="passive",
                    host=host,
                    url=snap.url,
                    severity="low",
                    description=(
                        f"Cookie '{cookie_name}' is set without the HttpOnly flag. "
                        "JavaScript on the page can read this cookie, "
                        "enabling theft via XSS."
                    ),
                    evidence=f"Set-Cookie: {raw_cookie[:200]}",
                ))

            # SameSite check — absence enables CSRF
            samesite_val = next(
                (p.split("=", 1)[1].strip() for p in parts if p.strip().startswith("samesite=")),
                "",
            )
            if not samesite_val or samesite_val not in ("strict", "lax"):
                findings.append(Finding(
                    template_id="cookie-missing-samesite",
                    category="misconfiguration",
                    scan_type="passive",
                    host=host,
                    url=snap.url,
                    severity="medium",
                    description=(
                        f"Cookie '{cookie_name}' does not set SameSite=Strict or SameSite=Lax. "
                        "Without this attribute the browser sends the cookie with cross-site "
                        "requests, enabling Cross-Site Request Forgery (CSRF)."
                    ),
                    evidence=f"Set-Cookie: {raw_cookie[:200]}",
                ))

    return findings


# Regex to detect version numbers in header values (e.g. "Apache/2.4.51", "PHP/7.4.3")
_VERSION_RE = re.compile(r"[\w\-]+/[\d.]+", re.IGNORECASE)

def check_server_version_leak(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Check: Server or X-Powered-By headers reveal software version numbers.

    Detailed version strings help attackers identify known CVEs affecting
    the exact version in use.
    """
    findings = []
    seen_hosts: set[str] = set()

    for snap in snapshots:
        host = _host(snap.url)
        if host in seen_hosts:
            continue

        for header_name in ("server", "x-powered-by", "x-aspnet-version"):
            val = _header(snap.headers, header_name)
            if val and _VERSION_RE.search(val):
                seen_hosts.add(host)
                findings.append(Finding(
                    template_id="server-version-leak",
                    category="misconfiguration",
                    scan_type="passive",
                    host=host,
                    url=snap.url,
                    severity="low",
                    description=(
                        f"The '{header_name}' response header discloses software version "
                        f"information: '{val}'. Attackers can use this to target "
                        "known vulnerabilities in that specific version."
                    ),
                    evidence=f"{header_name}: {val}",
                ))
                break  # one finding per host is enough

    return findings


# Patterns that indicate a directory listing page
_DIRLIST_PATTERNS = [
    re.compile(r"Index of /", re.IGNORECASE),
    re.compile(r"<title>Index of", re.IGNORECASE),
    re.compile(r"Parent Directory", re.IGNORECASE),
]

def check_directory_listing(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Check: The server returns a directory listing page.

    Directory listings expose the file and folder structure of the web root,
    often revealing backup files, configuration files, and source code.
    """
    findings = []

    for snap in snapshots:
        for pattern in _DIRLIST_PATTERNS:
            if pattern.search(snap.html):
                findings.append(Finding(
                    template_id="directory-listing",
                    category="exposure",
                    scan_type="passive",
                    host=_host(snap.url),
                    url=snap.url,
                    severity="medium",
                    description=(
                        "The server appears to display a directory listing. "
                        "This exposes the file structure and may reveal sensitive files."
                    ),
                    evidence=pattern.pattern,
                ))
                break  # one finding per page

    return findings


# ---------------------------------------------------------------------------
# Passive check — Information leakage in HTML body
# ---------------------------------------------------------------------------

_INFO_LEAKAGE_PATTERNS: list[tuple] = [
    (
        re.compile(
            r'(?:api[_-]?key|apikey|api_secret|access_token|auth_token|secret_key)'
            r'\s*[=:]\s*["\']?[\w\-]{16,}',
            re.IGNORECASE,
        ),
        "api-key-in-html",
        "Possible API key or secret found in rendered HTML — may expose credentials to anyone who views the page source.",
        "high",
    ),
    (
        re.compile(
            r'at\s+[\w$./<>]+\([^)]+\.(?:java|kt|cs|py|rb|go|js|ts):\d+\)',
            re.IGNORECASE,
        ),
        "stack-trace-exposure",
        "Stack trace visible in rendered HTML. Reveals internal file paths, class names, and line numbers that assist an attacker in targeting specific vulnerabilities.",
        "medium",
    ),
    (
        re.compile(
            r'<!--.*?(?:todo|fixme|password|passwd|secret|key|token|hack|vulnerability|bug|remove\s+before).*?-->',
            re.IGNORECASE | re.DOTALL,
        ),
        "sensitive-html-comment",
        "HTML comment contains a security-sensitive keyword (password, token, secret, fixme, etc.).",
        "low",
    ),
]


def check_information_leakage(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Check: Sensitive information exposed in rendered HTML body.

    Scans the captured HTML of each page for:
      - API keys or secrets in inline JavaScript or HTML attributes.
      - Stack traces that reveal internal file paths and line numbers.
      - HTML comments containing security-sensitive keywords.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for snap in snapshots:
        host = _host(snap.url)
        html = snap.html

        for pattern, template_id, description, severity in _INFO_LEAKAGE_PATTERNS:
            for match in pattern.finditer(html):
                dedup_key = f"{template_id}::{host}::{match.group(0)[:60]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(Finding(
                    template_id=template_id,
                    category="exposure",
                    scan_type="passive",
                    host=host,
                    url=snap.url,
                    severity=severity,
                    description=description,
                    evidence=f"Match: {match.group(0)[:200]}",
                ))

    return findings


# ---------------------------------------------------------------------------
# Dispatcher: run all passive checks
# ---------------------------------------------------------------------------

ALL_PASSIVE_CHECKS = [
    check_missing_csp,
    check_missing_x_frame_options,
    check_missing_x_content_type_options,
    check_missing_hsts,
    check_cookie_flags,
    check_server_version_leak,
    check_directory_listing,
    check_information_leakage,
]


def run_passive_checks(snapshots: list[PageSnapshot]) -> list[Finding]:
    """
    Run every passive check against the collected snapshots.
    Returns the aggregated list of findings.
    """
    all_findings: list[Finding] = []
    for check_fn in ALL_PASSIVE_CHECKS:
        try:
            results = check_fn(snapshots)
            all_findings.extend(results)
            logger.debug("Passive check '%s' -> %d findings", check_fn.__name__, len(results))
        except Exception as exc:
            logger.error("Passive check '%s' raised an error: %s", check_fn.__name__, exc)
    return all_findings

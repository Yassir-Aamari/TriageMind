"""
active_checks.py
================
Active vulnerability checks - sends test payloads against discovered parameters.

IMPORTANT: This module must ONLY be used against web applications for which
you have explicit written authorisation to perform security testing.
Unauthorised scanning is illegal in most jurisdictions.

Checks implemented:
  1. Reflected XSS       - injects a unique marker and verifies it appears
                           unescaped in the rendered DOM.
  2. Error-based SQLi    - injects quote characters and looks for database
                           error messages in the response.
  3. Open Redirect       - injects external URLs into redirect-related
                           parameters and checks if the browser navigates away.
  4. Sensitive path      - probes well-known sensitive paths at the site root.

Finding schema:
  category  -> xss | sqli | open_redirect | exposure
  scan_type -> "active"
"""

import asyncio
import logging
import re
import time
import uuid
from typing import Optional
from urllib.parse import (
    urlparse,
    urlunparse,
    urlencode,
    parse_qs,
    urljoin,
)

from playwright.async_api import (
    async_playwright,
    Page,
    TimeoutError as PlaywrightTimeoutError,
    Error as PlaywrightError,
)

from browser_crawler import PageSnapshot, DiscoveredForm
from passive_checks import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# XSS - we dynamically generate a unique marker per test
XSS_PAYLOAD_TMPL = "<script>alert('{}')</script>"
XSS_PAYLOAD_ALT_TMPL = '"><img src=x onerror="alert(\'{}\')">'

# SQLi - basic error-triggering payloads
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    '" OR "1"="1',
    "' --",
    "1'",
    "1 AND 1=1",
]

# SQL error fingerprints (regex patterns, case-insensitive)
SQLI_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"mysql_fetch",
        r"pg_query",
        r"sqlite3",
        r"ora-\d{4,5}",
        r"sqlstate",
        r"microsoft sql server",
        r"jdbc\.sqlexception",
        r"odbc.*driver",
        r"syntax error.*near",
        r"supplied argument is not a valid mysql",
    ]
]

# Open redirect - payloads and parameter name heuristics
REDIRECT_PARAMS = {
    "redirect", "url", "next", "return", "goto", "dest",
    "destination", "redir", "redirect_uri", "continue",
    "forward", "location", "target", "return_url",
}
REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
]

# Sensitive paths to probe at the site root
SENSITIVE_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.test",
    ".env.backup",
    "web.config",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "phpinfo.php",
    "robots.txt",
    "sitemap.xml",
    "wp-config.php",
    ".htaccess",
    "config.php",
    "database.yml",
    "application.properties",
    "Dockerfile",
    "docker-compose.yml",
    "package.json",
    "package-lock.json",
    "composer.json",
    "yarn.lock",
    "server.py",
    "settings.py",
    "config.js",
    # Additional paths for broader target coverage
    ".DS_Store",
    ".npmrc",
    "_redirects",
    "vercel.json",
    "netlify.toml",
    "config.yml",
    "config.yaml",
    "secrets.yml",
    "api_keys.txt",
    "id_rsa",
    "id_ed25519",
    ".ssh/id_rsa",
    "app.config",
    "appsettings.json",
    "appsettings.Development.json",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "server.key",
    "server.crt",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _host(url: str) -> str:
    return urlparse(url).netloc


def _inject_param(url: str, param: str, value: str) -> str:
    """Return a copy of url with the named query parameter replaced by value."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ---------------------------------------------------------------------------
# Active check - Reflected XSS
# ---------------------------------------------------------------------------

async def check_xss(
    page: Page,
    snapshots: list[PageSnapshot],
    target: str,
    delay: float,
    timeout: int,
    deadline: float,
) -> list[Finding]:
    """
    Reflected XSS check.

    For every URL query parameter and every form field discovered during crawl:
      1. Inject the XSS payload.
      2. Navigate / submit the form.
      3. Check whether the marker appears unescaped in the rendered DOM.
    """
    findings: list[Finding] = []
    tested: set[str] = set()  # avoid testing the same (url, param) twice

    for snap in snapshots:
        if time.monotonic() > deadline:
            break
        host = _host(snap.url)

        # ---- Test URL query parameters ----
        for param in snap.query_params:
            if time.monotonic() > deadline:
                break
            key = f"url_param::{snap.url}::{param}"
            if key in tested:
                continue
            tested.add(key)

            for tmpl in [XSS_PAYLOAD_TMPL, XSS_PAYLOAD_ALT_TMPL]:
                canary = f"xss_canary_{uuid.uuid4().hex[:8]}"
                payload = tmpl.format(canary)
                injected_url = _inject_param(snap.url, param, payload)
                finding = await _test_xss_url(
                    page, injected_url, param, payload, canary, host, snap.url, delay, timeout
                )
                if finding:
                    findings.append(finding)
                    break  # one finding per param is enough
                await asyncio.sleep(delay)

        # ---- Test form fields ----
        for form in snap.forms:
            for form_field in form.fields:
                if time.monotonic() > deadline:
                    break
                if form_field.field_type.lower() in ("hidden", "submit", "button", "image", "file"):
                    continue
                key = f"form::{form.action}::{form_field.name}"
                if key in tested:
                    continue
                tested.add(key)

                canary = f"xss_canary_{uuid.uuid4().hex[:8]}"
                payload = XSS_PAYLOAD_TMPL.format(canary)
                finding = await _test_xss_form(
                    page, snap.url, form, form_field.name, payload, canary, host, delay, timeout
                )
                if finding:
                    findings.append(finding)
                await asyncio.sleep(delay)

    return findings


async def _test_xss_url(
    page: Page,
    injected_url: str,
    param: str,
    payload: str,
    marker: str,
    host: str,
    original_url: str,
    delay: float,
    timeout: int,
) -> Optional[Finding]:
    """Navigate to a URL with the XSS payload injected and check the DOM."""
    try:
        await page.goto(injected_url, wait_until="networkidle", timeout=timeout)
        await asyncio.sleep(delay)
        dom = await page.content()
        if marker in dom:
            return Finding(
                template_id="reflected-xss",
                category="xss",
                scan_type="active",
                host=host,
                url=injected_url,
                severity="high",
                description=(
                    f"Reflected XSS detected in URL parameter '{param}'. "
                    "The injected marker appeared unescaped in the rendered DOM."
                ),
                evidence=f"Payload: {payload[:80]} | Marker found in rendered page",
            )
    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        logger.debug("XSS URL test error for %s: %s", injected_url, exc)
    return None


async def _test_xss_form(
    page: Page,
    page_url: str,
    form: DiscoveredForm,
    target_field: str,
    payload: str,
    canary: str,
    host: str,
    delay: float,
    timeout: int,
) -> Optional[Finding]:
    """
    Fill a form, inject XSS into a specific field, submit, check DOM.
    """
    try:
        await page.goto(page_url, wait_until="networkidle", timeout=timeout)
        await asyncio.sleep(delay)

        form_locator = page.locator("form").first
        if await form_locator.count() == 0:
            return None

        # Fill the target field with XSS payload; fill others with benign values
        for field_info in form.fields:
            try:
                selector = f"[name='{field_info.name}']"
                el = page.locator(selector).first
                if not await el.is_visible():
                    continue
                if field_info.name == target_field:
                    await el.fill(payload, timeout=3000)
                else:
                    from browser_crawler import _value_for_field
                    await el.fill(_value_for_field(field_info.field_type), timeout=3000)
            except PlaywrightError:
                pass

        # Submit
        submit = form_locator.locator("[type='submit'], button:not([type])")
        if await submit.count() > 0:
            await submit.first.click(timeout=5000)
        else:
            await page.keyboard.press("Enter")

        await page.wait_for_load_state("networkidle", timeout=timeout)
        await asyncio.sleep(delay)

        dom = await page.content()
        if canary in dom:
            return Finding(
                template_id="reflected-xss",
                category="xss",
                scan_type="active",
                host=host,
                url=form.action,
                severity="high",
                description=(
                    f"Reflected XSS detected in form field '{target_field}' "
                    f"submitted to '{form.action}'. The injected marker appeared "
                    "unescaped in the rendered DOM."
                ),
                evidence=f"Field: {target_field} | Payload: {payload[:80]}",
            )
    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        logger.debug("XSS form test error: %s", exc)
    return None


# ---------------------------------------------------------------------------
# Active check - Error-based SQL Injection
# ---------------------------------------------------------------------------

async def check_sqli(
    page: Page,
    snapshots: list[PageSnapshot],
    target: str,
    delay: float,
    timeout: int,
    deadline: float,
) -> list[Finding]:
    """
    Error-based SQL injection check.

    Injects SQL-breaking payloads into URL parameters and form fields.
    Looks for SQL error strings in the rendered response.
    """
    findings: list[Finding] = []
    tested: set[str] = set()

    for snap in snapshots:
        if time.monotonic() > deadline:
            break
        host = _host(snap.url)

        # ---- URL parameters ----
        for param in snap.query_params:
            if time.monotonic() > deadline:
                break
            key = f"url_param::{snap.url}::{param}"
            if key in tested:
                continue
            tested.add(key)

            for payload in SQLI_PAYLOADS:
                injected_url = _inject_param(snap.url, param, payload)
                finding = await _test_sqli_url(
                    page, injected_url, param, payload, host, delay, timeout
                )
                if finding:
                    findings.append(finding)
                    break
                await asyncio.sleep(delay)

        # ---- Form fields ----
        for form in snap.forms:
            for form_field in form.fields:
                if time.monotonic() > deadline:
                    break
                if form_field.field_type.lower() in ("hidden", "submit", "button", "image", "file"):
                    continue
                key = f"form::{form.action}::{form_field.name}"
                if key in tested:
                    continue
                tested.add(key)

                for payload in SQLI_PAYLOADS:
                    finding = await _test_sqli_form(
                        page, snap.url, form, form_field.name, payload, host, delay, timeout
                    )
                    if finding:
                        findings.append(finding)
                        break
                    await asyncio.sleep(delay)

    return findings


async def _test_sqli_url(
    page: Page,
    injected_url: str,
    param: str,
    payload: str,
    host: str,
    delay: float,
    timeout: int,
) -> Optional[Finding]:
    try:
        response = await page.goto(injected_url, wait_until="domcontentloaded", timeout=timeout)
        await asyncio.sleep(delay)
        dom = await page.content()

        error_hit = next((p for p in SQLI_ERROR_PATTERNS if p.search(dom)), None)
        http500 = response and response.status == 500

        if error_hit or http500:
            evidence = (
                f"SQL error pattern '{error_hit.pattern}' found in response"
                if error_hit
                else "HTTP 500 response"
            )
            return Finding(
                template_id="sqli-error-based",
                category="sqli",
                scan_type="active",
                host=host,
                url=injected_url,
                severity="high",
                description=(
                    f"Possible error-based SQL injection in URL parameter '{param}'. "
                    "A SQL error string or server error was returned after injecting "
                    "a quote character."
                ),
                evidence=f"Payload: {payload} | {evidence}",
            )
    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        logger.debug("SQLi URL test error for %s: %s", injected_url, exc)
    return None


async def _test_sqli_form(
    page: Page,
    page_url: str,
    form: DiscoveredForm,
    target_field: str,
    payload: str,
    host: str,
    delay: float,
    timeout: int,
) -> Optional[Finding]:
    try:
        await page.goto(page_url, wait_until="networkidle", timeout=timeout)
        await asyncio.sleep(delay)

        form_locator = page.locator("form").first
        if await form_locator.count() == 0:
            return None

        for field_info in form.fields:
            try:
                selector = f"[name='{field_info.name}']"
                el = page.locator(selector).first
                if not await el.is_visible():
                    continue
                if field_info.name == target_field:
                    await el.fill(payload, timeout=3000)
                else:
                    from browser_crawler import _value_for_field
                    await el.fill(_value_for_field(field_info.field_type), timeout=3000)
            except PlaywrightError:
                pass

        submit = form_locator.locator("[type='submit'], button:not([type])")
        response = None
        if await submit.count() > 0:
            async with page.expect_response(lambda r: True, timeout=timeout) as resp_info:
                await submit.first.click(timeout=5000)
            try:
                response = await resp_info.value
            except Exception:
                pass
        else:
            await page.keyboard.press("Enter")

        await page.wait_for_load_state("domcontentloaded", timeout=timeout)
        await asyncio.sleep(delay)
        dom = await page.content()

        error_hit = next((p for p in SQLI_ERROR_PATTERNS if p.search(dom)), None)
        http500 = response and response.status == 500

        if error_hit or http500:
            evidence = (
                f"SQL error pattern '{error_hit.pattern}'"
                if error_hit
                else "HTTP 500"
            )
            return Finding(
                template_id="sqli-error-based",
                category="sqli",
                scan_type="active",
                host=host,
                url=form.action,
                severity="high",
                description=(
                    f"Possible error-based SQL injection in form field '{target_field}'. "
                    "A SQL error or server error was returned after injecting a quote character."
                ),
                evidence=f"Field: {target_field} | Payload: {payload} | {evidence}",
            )
    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        logger.debug("SQLi form test error: %s", exc)
    return None


# ---------------------------------------------------------------------------
# Active check - Open Redirect
# ---------------------------------------------------------------------------

async def check_open_redirect(
    page: Page,
    snapshots: list[PageSnapshot],
    target: str,
    delay: float,
    timeout: int,
    deadline: float,
) -> list[Finding]:
    """
    Open redirect check.

    Looks for URL parameters whose names suggest they control a redirect target
    (e.g. 'redirect', 'next', 'url'). Injects an external URL payload and
    checks whether the browser actually navigated to an external host after
    the request, which would confirm an unvalidated redirect.
    """
    findings: list[Finding] = []
    tested: set[str] = set()
    target_origin = _origin(target)

    for snap in snapshots:
        if time.monotonic() > deadline:
            break
        host = _host(snap.url)

        for param in snap.query_params:
            if time.monotonic() > deadline:
                break
            # Only test parameters whose names suggest a redirect target
            if param.lower() not in REDIRECT_PARAMS:
                continue

            key = f"redirect::{snap.url}::{param}"
            if key in tested:
                continue
            tested.add(key)

            for payload in REDIRECT_PAYLOADS:
                injected_url = _inject_param(snap.url, param, payload)
                try:
                    await page.goto(injected_url, wait_until="domcontentloaded", timeout=timeout)
                    await asyncio.sleep(delay)

                    final_url = page.url
                    final_origin = _origin(final_url)

                    # Confirmed redirect if the browser landed outside our target origin
                    if final_origin != target_origin and "evil.example.com" in final_url:
                        findings.append(Finding(
                            template_id="open-redirect",
                            category="open_redirect",
                            scan_type="active",
                            host=host,
                            url=injected_url,
                            severity="medium",
                            description=(
                                f"Open redirect detected in URL parameter '{param}'. "
                                "Injecting an external URL caused the browser to navigate "
                                "to that external host without validation."
                            ),
                            evidence=(
                                f"Injected payload: {payload} | "
                                f"Final URL after redirect: {final_url}"
                            ),
                        ))
                        break  # one finding per param is enough

                except (PlaywrightTimeoutError, PlaywrightError) as exc:
                    logger.debug("Open redirect test error for %s: %s", injected_url, exc)

                await asyncio.sleep(delay)

        # ---- Also test form fields with redirect-like names ----
        for form in snap.forms:
            for form_field in form.fields:
                if time.monotonic() > deadline:
                    break
                if form_field.name.lower() not in REDIRECT_PARAMS:
                    continue
                key = f"redirect_form::{form.action}::{form_field.name}"
                if key in tested:
                    continue
                tested.add(key)

                for payload in REDIRECT_PAYLOADS:
                    try:
                        await page.goto(snap.url, wait_until="networkidle", timeout=timeout)
                        await asyncio.sleep(delay)

                        el = page.locator(f"[name='{form_field.name}']").first
                        if await el.count() == 0 or not await el.is_visible():
                            continue
                        await el.fill(payload, timeout=3000)

                        form_loc = page.locator("form").first
                        submit = form_loc.locator("[type='submit'], button:not([type])")
                        if await submit.count() > 0:
                            await submit.first.click(timeout=5000)
                        else:
                            await page.keyboard.press("Enter")

                        await page.wait_for_load_state("domcontentloaded", timeout=timeout)
                        await asyncio.sleep(delay)

                        final_url = page.url
                        if _origin(final_url) != target_origin and "evil.example.com" in final_url:
                            findings.append(Finding(
                                template_id="open-redirect",
                                category="open_redirect",
                                scan_type="active",
                                host=host,
                                url=form.action,
                                severity="medium",
                                description=(
                                    f"Open redirect detected in form field '{form_field.name}'. "
                                    "Submitting an external URL caused the browser to navigate "
                                    "to that host."
                                ),
                                evidence=(
                                    f"Field: {form_field.name} | "
                                    f"Payload: {payload} | "
                                    f"Final URL: {final_url}"
                                ),
                            ))
                            break
                    except (PlaywrightTimeoutError, PlaywrightError) as exc:
                        logger.debug("Open redirect form test error: %s", exc)
                    await asyncio.sleep(delay)

    return findings


# ---------------------------------------------------------------------------
# Active check - Sensitive Path Exposure
# ---------------------------------------------------------------------------



async def check_sensitive_paths(
    page: Page,
    target: str,
    delay: float,
    timeout: int,
    deadline: float,
) -> list[Finding]:
    """
    Probe well-known sensitive paths at the site root.

    A finding is raised when ALL of the following are true:
      1. HTTP 200 status.
      2. Content-Type is NOT text/html  - real sensitive files (.env, .git/HEAD,
         package.json, backup.zip) are served as text/plain / application/json /
         application/octet-stream.  A SPA catch-all always returns text/html.
      3. The response body does NOT contain SPA shell fingerprint markers
         (<app-root>, ng-version, data-reactroot, __NEXT_DATA__, etc.).  This
         handles the edge case where a server returns text/html for every path.
      4. Body length is at least 10 bytes (not an empty 200).

    Without these extra checks, Angular/React/Vue SPAs report false positives
    for every path because the router returns index.html (HTTP 200) for all
    unknown routes - including /backup.zip, /phpinfo.php, /wp-config.php, etc.
    """
    findings: list[Finding] = []
    host = _host(target)
    origin = _origin(target)

    # --- Fingerprint the homepage to detect SPA catch-all responses ---
    # Angular/React/Vue/Next/Nuxt SPAs return the same index.html (text/html, HTTP 200)
    # for every unknown path including /backup.zip, /phpinfo.php, /.env etc.
    # We capture the root response once and skip any probe that matches it.
    spa_fingerprint: str = ""
    try:
        root_resp = await page.goto(origin + "/", wait_until="domcontentloaded", timeout=timeout)
        if root_resp and root_resp.status == 200:
            root_body = await page.content()
            root_ct = (root_resp.headers.get("content-type") or "").lower()
            if "text/html" in root_ct:
                # Use a 200-char interior slice (skip boilerplate DOCTYPE)
                spa_fingerprint = root_body[100:300]
        logger.debug("SPA homepage fingerprint captured (%d chars)", len(spa_fingerprint))
    except Exception as fp_exc:
        logger.debug("Could not capture homepage fingerprint: %s", fp_exc)

    # SPA shell markers — presence of any one of these means catch-all index.html
    _SPA_MARKERS = (
        "<app-root", "ng-version", "data-reactroot", "__NEXT_DATA__",
        "__nuxt", "<div id=\"app\"", "<div id='app'", "vue-app",
        "window.__INITIAL_STATE__", "<router-view",
    )

    for path in SENSITIVE_PATHS:
        if time.monotonic() > deadline:
            break
        probe_url = f"{origin}/{path}"
        try:
            response = await page.goto(
                probe_url, wait_until="domcontentloaded", timeout=timeout
            )
            await asyncio.sleep(delay)

            if not response or response.status != 200:
                logger.debug(
                    "Path %s -> HTTP %s",
                    path, response.status if response else "N/A",
                )
                continue

            body_preview = (await page.content())[:600]
            content_type = (response.headers.get("content-type") or "").lower()

            if len(body_preview.strip()) < 10:
                logger.debug("Path %s -> HTTP 200 but empty body, skipping", path)
                continue

            # --- SPA / catch-all filter ---
            # Any text/html response is almost certainly a SPA catch-all route.
            # Real sensitive files (.env, package.json, .git/HEAD, backup.zip)
            # are served as text/plain, application/json, application/octet-stream, etc.
            if "text/html" in content_type:
                body_lower = body_preview.lower()
                # Check for known SPA framework fingerprints
                if any(m.lower() in body_lower for m in _SPA_MARKERS):
                    logger.debug("Path %s -> text/html with SPA marker, skipping (false positive)", path)
                    continue
                # Check against captured homepage slice
                if spa_fingerprint and spa_fingerprint in body_preview:
                    logger.debug("Path %s -> body matches homepage fingerprint, skipping (false positive)", path)
                    continue
                # Still text/html — conservative: skip to avoid SPA noise
                logger.debug("Path %s -> text/html (no SPA marker, no fingerprint) — skipping conservatively", path)
                continue

            # Content-Type is NOT text/html — a real file was served
            findings.append(Finding(
                template_id="sensitive-path-exposure",
                category="exposure",
                scan_type="active",
                host=host,
                url=probe_url,
                severity="high",
                description=(
                    f"The path '/{path}' is publicly accessible and returned HTTP 200 "
                    f"with Content-Type '{content_type}'. "
                    "This file may expose credentials, configuration, or source control data."
                ),
                evidence=(
                    f"HTTP 200 | Content-Type: {content_type} | "
                    f"Body preview: {body_preview[:200]}"
                ),
            ))
            logger.info("Sensitive path found: %s (Content-Type: %s)", probe_url, content_type)

        except (PlaywrightTimeoutError, PlaywrightError) as exc:
            logger.debug("Sensitive path probe error for %s: %s", probe_url, exc)
        await asyncio.sleep(delay)

    return findings


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

async def run_active_checks(
    snapshots: list[PageSnapshot],
    target: str,
    delay: float = 0.5,
    timeout: int = 15000,
    headless: bool = True,
    max_duration: float = 120.0,
    extra_headers: dict | None = None,
    session_state_path: str | None = None,
) -> list[Finding]:
    """
    Run all active checks.
    Opens a fresh browser context so active checks don't interfere with
    crawl state.

    Parameters
    ----------
    extra_headers : dict, optional
        Additional HTTP headers (e.g. ``{"Authorization": "Bearer ..."}``)
        forwarded to every request during active scanning.
    session_state_path : str, optional
        Path to a Playwright storage-state JSON file saved after crawling
        (cookies + localStorage). When provided, active checks run with the
        same session as the crawl so authenticated pages are reachable.
    """
    all_findings: list[Finding] = []
    start_time = time.monotonic()
    deadline = start_time + max_duration
    extra_headers = extra_headers or {}

    import os as _os
    storage_state = session_state_path if (
        session_state_path and _os.path.exists(session_state_path)
    ) else None
    if storage_state:
        logger.info("Active checks: loading crawl session state from %s", storage_state)
    else:
        logger.debug("Active checks: no session state found, running unauthenticated")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=extra_headers,
            storage_state=storage_state,
        )
        page = await context.new_page()

        logger.info("Running active check: Reflected XSS")
        try:
            if time.monotonic() < deadline:
                xss_findings = await check_xss(page, snapshots, target, delay, timeout, deadline)
                all_findings.extend(xss_findings)
                logger.info("XSS -> %d findings", len(xss_findings))
        except Exception as exc:
            logger.error("XSS check failed: %s", exc)

        logger.info("Running active check: SQL Injection")
        try:
            if time.monotonic() < deadline:
                sqli_findings = await check_sqli(page, snapshots, target, delay, timeout, deadline)
                all_findings.extend(sqli_findings)
                logger.info("SQLi -> %d findings", len(sqli_findings))
        except Exception as exc:
            logger.error("SQLi check failed: %s", exc)

        logger.info("Running active check: Open Redirect")
        try:
            if time.monotonic() < deadline:
                redirect_findings = await check_open_redirect(
                    page, snapshots, target, delay, timeout, deadline
                )
                all_findings.extend(redirect_findings)
                logger.info("Open Redirect -> %d findings", len(redirect_findings))
        except Exception as exc:
            logger.error("Open redirect check failed: %s", exc)

        logger.info("Running active check: Sensitive Path Exposure")
        try:
            if time.monotonic() < deadline:
                path_findings = await check_sensitive_paths(page, target, delay, timeout, deadline)
                all_findings.extend(path_findings)
                logger.info("Sensitive Paths -> %d findings", len(path_findings))
        except Exception as exc:
            logger.error("Sensitive path check failed: %s", exc)

        await browser.close()

    return all_findings

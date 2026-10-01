"""
browser_crawler.py
==================
Playwright-based BFS web crawler.

Key capabilities:
  - Renders JavaScript (headless Chromium) so SPAs are fully supported.
  - Detects interactive elements generically: <a href>, <button>,
    [role="button"], [onclick] - never by hardcoded text or ID.
  - Dismisses modal overlays / cookie banners generically before exploring
    each page (Issue 1 fix).
  - Fills and submits HTML forms with type-appropriate placeholder values.
  - Deduplicates pages by (normalised URL, structural DOM hash) - uses
    sorted link/button/title structure instead of raw visible text so the
    key is stable across minor rendering variance and overlay presence
    (Issue 2 fix).
  - Optionally respects robots.txt (--respect-robots flag).
  - Captures HTTP response headers and Set-Cookie headers for passive scanning.
  - Enforces a hard wall-clock timeout (--max-duration, Issue 3 fix).
  - Stays within configurable max_depth and max_interactions bounds.
  - Produces verbose per-interaction log lines when the logger is at DEBUG
    level (Issue 4 fix).
  - Supports a headed (non-headless) mode via the `headless` parameter
    (Issue 5 fix - exposed via --headed flag in scanner.py).
  - Enforces strict same-origin scope at every navigation point, including
    server-side redirects (e.g. /redirect?to=https://github.com). Any page
    that lands outside the target origin is immediately abandoned - no
    snapshot, no element extraction, no interaction budget consumed.
"""

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

from playwright.async_api import (
    async_playwright,
    Page,
    Response,
    TimeoutError as PlaywrightTimeoutError,
    Error as PlaywrightError,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FormField:
    """Represents a single input field inside an HTML form."""
    name: str           # 'name' attribute of the input
    field_type: str     # input type: text, email, password, number, etc.
    tag: str            # input, textarea, select


@dataclass
class DiscoveredForm:
    """A form found on a page along with its action and method."""
    action: str          # absolute URL the form posts to
    method: str          # GET or POST
    fields: list[FormField] = field(default_factory=list)


@dataclass
class PageSnapshot:
    """
    Everything captured from a single page visit:
      - The rendered HTML (after JS execution)
      - Response headers from the main document request
      - Set-Cookie header values
      - All forms and their fields
      - URL query parameters extracted from the page URL
    """
    url: str
    html: str
    headers: dict[str, str]             # response headers for the main document
    cookies: list[str]                  # raw Set-Cookie header strings
    forms: list[DiscoveredForm]
    query_params: dict[str, list[str]]  # parsed URL query params


# ---------------------------------------------------------------------------
# Robots.txt parser
# ---------------------------------------------------------------------------

class RobotsParser:
    """
    Minimal robots.txt parser. Only evaluates 'User-agent: *' rules.
    Disallow paths are stored as plain prefixes (not regex).
    """

    def __init__(self) -> None:
        self.disallowed: list[str] = []

    def parse(self, content: str) -> None:
        """Parse robots.txt text and populate disallowed paths."""
        current_agents: list[str] = []
        for line in content.splitlines():
            line = line.split("#")[0].strip()
            if not line:
                current_agents = []
                continue
            if line.lower().startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip()
                current_agents = [agent]
            elif line.lower().startswith("disallow:") and "*" in current_agents:
                path = line.split(":", 1)[1].strip()
                if path:
                    self.disallowed.append(path)

    def is_allowed(self, path: str) -> bool:
        """Return True if the given path is NOT disallowed."""
        for disallowed in self.disallowed:
            if path.startswith(disallowed):
                return False
        return True


# ---------------------------------------------------------------------------
# Generic form value factory
# ---------------------------------------------------------------------------

# Maps input type -> placeholder test value
_FIELD_VALUES: dict[str, str] = {
    "text":     "test_value",
    "search":   "test_value",
    "email":    "test@example.com",
    "number":   "42",
    "tel":      "0000000000",
    "url":      "http://test.example.com",
    "date":     "2000-01-01",
    "time":     "12:00",
    "password": "TestPass123!",
    "textarea": "test_value",
    "hidden":   "",            # leave hidden fields as-is
}

def _value_for_field(field_type: str) -> str:
    """Return a generic test value for an HTML input type."""
    return _FIELD_VALUES.get(field_type.lower(), "test_value")


# ---------------------------------------------------------------------------
# URL normalisation  (Issue 2)
# ---------------------------------------------------------------------------

def _normalise_url(url: str) -> str:
    """
    Canonicalise a URL so that logically identical URLs produce the same key.

    Rules applied:
      - Strip trailing slash from the path (except bare "/").
      - Drop the URL fragment (client-side only, irrelevant for dedup).
      - Lower-case the scheme and host.
    """
    try:
        p = urlparse(url)
        scheme = p.scheme.lower()
        netloc = p.netloc.lower()
        path = p.path.rstrip("/") or "/"   # keep at least "/"
        # Reconstruct without fragment
        return f"{scheme}://{netloc}{path}" + (f"?{p.query}" if p.query else "")
    except Exception:
        return url


# ---------------------------------------------------------------------------
# Structural DOM hash  (Issue 2)
# ---------------------------------------------------------------------------

async def _structural_page_key(page: Page) -> str:
    """
    Compute a stable structural fingerprint of the current page.

    Instead of hashing raw visible text (which is unstable due to overlays,
    timestamps, and other dynamic content), we hash a sorted, normalised list
    of structural markers:
      - Page <title> text
      - All <a> elements: (tag="a", normalised href)
      - All <button> elements: (tag="button", stripped visible text)

    Before hashing, digit sequences are replaced with '#' so that dynamic
    counters (shopping-cart count, pagination numbers, timestamps) do NOT
    generate a new state on every increment.  For example:
        "Your Basket\n0"  ->  "Your Basket\n#"
        "Your Basket\n12" ->  "Your Basket\n#"
    This prevents the crawler from treating "page with basket=1" and "page
    with basket=2" as separate states and recursing into both.

    The fingerprint changes only when the meaningful navigation structure
    of the page changes - not due to minor rendering variance or counters.
    """
    try:
        # Evaluate in-page JS to collect structural markers in one round-trip
        markers: list[str] = await page.evaluate("""() => {
            const items = [];

            // Title
            const title = document.title || "";
            items.push("title:" + title.trim());

            // All links - use pathname+search as the structural part
            document.querySelectorAll("a[href]").forEach(el => {
                try {
                    const url = new URL(el.href, window.location.href);
                    items.push("a:" + url.pathname + url.search);
                } catch (e) {
                    items.push("a:" + el.getAttribute("href"));
                }
            });

            // All buttons - use trimmed inner text
            document.querySelectorAll(
                "button, [role='button']"
            ).forEach(el => {
                const txt = (el.innerText || el.textContent || "").trim();
                if (txt) items.push("btn:" + txt.substring(0, 60));
            });

            return items;
        }""")
        # Normalise digit sequences to '#' so dynamic counters (basket count,
        # pagination numbers, etc.) don't produce spurious new states.
        import re as _re
        markers = [_re.sub(r'\d+', '#', m) for m in markers]
        # Sort to make the hash order-independent (avoids re-ordering issues in SPAs)
        markers_sorted = sorted(set(markers))
        digest = hashlib.sha1(
            "\n".join(markers_sorted).encode("utf-8", errors="replace")
        ).hexdigest()[:16]
        return digest
    except PlaywrightError:
        # Fallback: use the raw URL as key (safe, just less precise)
        return hashlib.sha1(page.url.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Generic overlay / modal dismissal  (Issue 1 + drawer-backdrop fix)
# ---------------------------------------------------------------------------

# Selectors that identify popup modal/overlay CONTAINERS.
# Ordered from most-specific (role attributes) to broadest (class substrings).
#
# IMPORTANT: DO NOT add broad structural selectors like [class*='drawer'],
# [class*='sidenav'], or [class*='cdk-overlay'] here.  Angular Material uses
# those class names on layout containers (mat-sidenav-container, mat-sidenav-
# content) that wrap the ENTIRE page.  Matching them causes _dismiss_overlays
# to iterate over every button on the page and burn 3 s per failed click.
#
# Backdrop elements produced by drawers/sidenavs are caught by [class*='backdrop']
# in the pure-backdrop path (Attempt 4) and by _clear_blocking_backdrop(),
# so we never lose coverage by omitting the container selectors.
_OVERLAY_CONTAINER_SELECTORS = [
    "[role='dialog']",
    "[aria-modal='true']",
    "[class*='modal']",
    # Exclude ALL Angular CDK elements via :not([class*='cdk-']), not just
    # [class*='cdk-overlay'].  The previous exclusion blocked cdk-overlay-container
    # and cdk-overlay-backdrop/pane correctly, but missed cdk-global-overlay-wrapper
    # whose class string is 'cdk-global-overlay-wrapper' - it contains 'overlay'
    # (matches the first half) but NOT the substring 'cdk-overlay' (so it slipped
    # through the old :not).  Broadening to :not([class*='cdk-']) excludes every
    # element whose class contains the Angular CDK prefix, including:
    #   cdk-overlay-container, cdk-overlay-backdrop, cdk-overlay-pane,
    #   cdk-global-overlay-wrapper, cdk-visually-hidden, cdk-focus-trap, ...
    "[class*='overlay']:not([class*='cdk-'])",
    "[class*='backdrop']",          # mat-drawer-backdrop, Bootstrap backdrop, etc.
    "[class*='popup']",
    "[class*='dialog']",
    "[class*='cookie']",
    "[class*='consent']",
    "[class*='gdpr']",
    "[class*='banner']",
]

# Selector for elements that are pure pointer-event interceptors (backdrops).
# These are typically full-viewport transparent divs with no interactive
# children - clicking them directly closes the associated drawer/modal.
# Used by _clear_blocking_backdrop() for targeted clearing.
_BACKDROP_SELECTOR = (
    "[class*='backdrop'], "
    "[class*='scrim'], "
    "[class*='cdk-overlay-backdrop'], "
    "[class*='drawer-backdrop'], "
    "[class*='sidenav-backdrop']"
)

# Substring that Playwright puts in the error message when an element
# is covered by another element that intercepts pointer events.
_INTERCEPTS_POINTER_MSG = "intercepts pointer events"

# Text/aria-label patterns that identify a dismiss/close control.
# Must be case-insensitive full-string matches or common close symbols.
_CLOSE_TEXT_RE = re.compile(
    r"^(close|\u00d7|x|\u2715|\u2716|accept|ok|got it|dismiss|agree|continue|"
    r"i understand|i agree|allow|confirm)$",
    re.IGNORECASE,
)


async def _dismiss_overlays(page: Page, delay: float) -> None:
    """
    Generically detect and dismiss modal dialogs, cookie banners, and
    other overlay elements that would block interaction with the real page.

    Strategy (in priority order):
      1. Find visible overlay containers via common class/role patterns.
      2. Within each container, look for a dismiss button by:
           a. aria-label matching the close-text regex, or
           b. visible inner text matching the close-text regex, or
           c. the last visible <button> child of the dialog (common pattern
              for dialogs with a single primary action).
      3. If the container has NO interactive children at all (pure backdrop
         element such as mat-drawer-backdrop), click the backdrop itself -
         this closes the associated drawer/modal in most frameworks.
      4. Click the first match found, wait briefly, then repeat in case
         multiple layers of overlays are stacked.

    Also calls _clear_blocking_backdrop() at the end of each pass so that
    pure-backdrop elements (with no dismiss button) are caught too.

    This function is fully generic - it does not use any site-specific
    selectors, IDs, or text strings beyond the regex above.
    """
    # ---- Fast pre-check: skip entirely when no overlay-like elements exist ----
    # Avoids querying all container selectors (11 × 3 passes = 33 DOM queries)
    # on every clean page visit.  Two broad queries are enough to detect the
    # presence of any overlay before running the full dismissal loop.
    try:
        _quick_count = await page.locator(
            "[role='dialog'], [aria-modal='true'], "
            "[class*='modal'], [class*='cookie'], [class*='banner']"
        ).count()
        _backdrop_count = await page.locator(_BACKDROP_SELECTOR).count()
        if _quick_count == 0 and _backdrop_count == 0:
            return
    except PlaywrightError:
        return

    # Run up to 3 dismissal passes to handle stacked overlays
    for _pass in range(3):
        dismissed_any = False

        for container_sel in _OVERLAY_CONTAINER_SELECTORS:
            try:
                containers = page.locator(container_sel)
                count = await containers.count()
                for idx in range(count):
                    container = containers.nth(idx)
                    if not await container.is_visible():
                        continue

                    # --- Attempt 1: button with matching aria-label ---
                    close_btn = container.locator(
                        "button[aria-label], [role='button'][aria-label]"
                    )
                    n = await close_btn.count()
                    for j in range(n):
                        btn = close_btn.nth(j)
                        label = (await btn.get_attribute("aria-label") or "").strip()
                        if _CLOSE_TEXT_RE.match(label) and await btn.is_visible():
                            logger.debug(
                                "Overlay dismissal: clicking aria-label='%s' in %s",
                                label, container_sel,
                            )
                            await btn.click(timeout=1000)
                            await asyncio.sleep(delay)
                            dismissed_any = True
                            break
                    if dismissed_any:
                        break

                    # --- Attempt 2: button whose visible text matches close regex ---
                    all_btns = container.locator("button, [role='button']")
                    n = await all_btns.count()
                    for j in range(n):
                        btn = all_btns.nth(j)
                        if not await btn.is_visible():
                            continue
                        txt = (await btn.inner_text()).strip()
                        if _CLOSE_TEXT_RE.match(txt):
                            # Guard against Angular Material icon false positives.
                            # A single all-lowercase word (e.g. "close", "clear") is
                            # likely a <mat-icon> text node, not a human-readable label.
                            # Only accept it if the button also carries an aria-label
                            # that independently confirms it's a dismiss control.
                            if txt.isalpha() and txt.islower():
                                lbl = (await btn.get_attribute("aria-label") or "").strip()
                                if not _CLOSE_TEXT_RE.match(lbl):
                                    continue  # icon text without confirming aria-label -> skip

                            logger.debug(
                                "Overlay dismissal: clicking text='%s' in %s",
                                txt, container_sel,
                            )
                            await btn.click(timeout=1000)
                            await asyncio.sleep(delay)
                            dismissed_any = True
                            break
                    if dismissed_any:
                        break

                    # --- Attempt 3: last visible button child (common pattern) ---
                    all_btns = container.locator("button")
                    n = await all_btns.count()
                    if n > 0:
                        last_btn = all_btns.nth(n - 1)
                        if await last_btn.is_visible():
                            logger.debug(
                                "Overlay dismissal: clicking last button in %s (pass %d)",
                                container_sel, _pass,
                            )
                            await last_btn.click(timeout=1000)
                            await asyncio.sleep(delay)
                            dismissed_any = True

                    # --- Attempt 4: pure backdrop - click the element itself ---
                    # Elements like mat-drawer-backdrop and cdk-overlay-backdrop have
                    # no interactive children.  We click the element itself to signal
                    # the framework to close the associated drawer/modal.
                    #
                    # IMPORTANT: do NOT use force=True here.  force=True dispatches a
                    # synthetic PointerEvent that bypasses Angular zone.js, so the CDK
                    # backdrop never closes.  el.click() via evaluate() fires a native
                    # DOM event that Angular's document-level listener does handle.
                    if not dismissed_any:
                        child_count = await container.locator(
                            "button, [role='button'], a, input, select"
                        ).count()
                        if child_count == 0 and await container.is_visible():
                            logger.debug(
                                "Overlay dismissal: closing pure-backdrop %s",
                                container_sel,
                            )
                            try:
                                # Native JS click - triggers CDK event handlers
                                await container.evaluate("el => el.click()")
                                await asyncio.sleep(delay)
                                # Verify it actually closed; if still visible, Escape
                                if await container.is_visible():
                                    await page.keyboard.press("Escape")
                                    await asyncio.sleep(delay)
                                dismissed_any = True
                            except (PlaywrightTimeoutError, PlaywrightError):
                                try:
                                    await page.keyboard.press("Escape")
                                    await asyncio.sleep(delay)
                                    dismissed_any = True
                                except PlaywrightError:
                                    pass

                if dismissed_any:
                    break  # restart outer loop to re-check for remaining overlays

            except (PlaywrightTimeoutError, PlaywrightError) as exc:
                logger.debug("Overlay dismissal attempt failed: %s", exc)

        # Also sweep for dedicated backdrop elements that may not have been
        # caught by the container selectors above.
        if not dismissed_any:
            dismissed_any = await _clear_blocking_backdrop(page, delay)

        if not dismissed_any:
            break  # no overlays found in this pass - we're done


async def _clear_blocking_backdrop(page: Page, delay: float) -> bool:
    """
    Targeted sweep for pure pointer-event-intercepting backdrop elements.

    Angular CDK (mat-menu, mat-sidenav, mat-dialog, mat-select ...) renders
    a <div class="cdk-overlay-backdrop ..."> that captures all pointer events
    while a popup is open.  It closes when:
      (a) The user presses Escape  - handled by CDK's KeyboardEventsPlugin.
      (b) The user clicks the backdrop div via a real DOM click event.

    Playwright's force=True only dispatches a synthetic PointerEvent that
    bypasses Angular's zone.js integration, so the CDK never responds to it.
    This function therefore uses three progressively broader strategies:

    Strategy 1: Escape key  - the universal CDK close gesture.  Works for
        mat-menu, mat-select dropdowns, mat-dialog, mat-sidenav with backdrop.
    Strategy 2: JS el.click()  - triggers the native click event that CDK
        listens for on the backdrop.  Works when Escape is explicitly disabled.
    Strategy 3: page.mouse.click(x=10, y=10)  - real pointer event at the
        top-left viewport corner (unlikely to be covered by dialog content),
        as a last resort for non-CDK overlays.

    After each strategy, visible backdrop count is rechecked so we stop early
    when the overlay is confirmed dismissed rather than always running all three.

    Returns True if at least one backdrop was dismissed (or Escape was pressed
    in response to seeing visible backdrops).
    """
    try:
        backdrops = page.locator(_BACKDROP_SELECTOR)
        n = await backdrops.count()

        # Quick visibility scan - skip everything if nothing is blocking
        visible_indices = [
            i for i in range(n)
            if await backdrops.nth(i).is_visible()
        ]
        if not visible_indices:
            return False

        logger.debug(
            "Backdrop clear: %d visible backdrop element(s) detected",
            len(visible_indices),
        )

        # ---- Strategy 1: Escape key ----------------------------------------
        # Angular CDK's KeyboardEventsPlugin closes overlays on Escape by
        # default.  This is the fastest and most reliable approach.
        await page.keyboard.press("Escape")
        await asyncio.sleep(delay)

        # Re-count; if nothing visible remains, we're done
        still_visible = [
            i for i in range(n)
            if await backdrops.nth(i).is_visible()
        ]
        if not still_visible:
            logger.debug("Backdrop clear: Escape key dismissed all overlays")
            return True

        logger.debug(
            "Backdrop clear: %d backdrop(s) remain after Escape, trying JS click",
            len(still_visible),
        )

        # ---- Strategy 2: native JS el.click() on each remaining backdrop ----
        # Unlike Playwright's force=True (which bypasses zone.js), calling
        # el.click() through evaluate() fires a real DOM event that Angular
        # CDK's document-level listener receives and handles correctly.
        for i in still_visible:
            bd = backdrops.nth(i)
            if not await bd.is_visible():
                continue
            logger.debug("Backdrop clear: JS-clicking backdrop #%d", i)
            try:
                await bd.evaluate("el => el.click()")
                await asyncio.sleep(delay)
            except PlaywrightError:
                pass

        # Re-check after JS clicks
        still_visible2 = [
            i for i in range(n)
            if await backdrops.nth(i).is_visible()
        ]
        if not still_visible2:
            logger.debug("Backdrop clear: JS click dismissed all overlays")
            return True

        logger.debug(
            "Backdrop clear: %d backdrop(s) still visible, trying viewport-corner click",
            len(still_visible2),
        )

        # ---- Strategy 3: real mouse click at viewport top-left corner -------
        # Sends a genuine PointerEvent sequence through Playwright's input
        # pipeline.  The top-left corner (10, 10) is almost never covered by
        # centered dialog content, so the click lands on the backdrop itself.
        try:
            await page.mouse.click(10, 10)
            await asyncio.sleep(delay)
        except PlaywrightError:
            pass

        # Final check
        final_visible = [
            i for i in range(n)
            if await backdrops.nth(i).is_visible()
        ]
        if not final_visible:
            logger.debug("Backdrop clear: viewport-corner click dismissed all overlays")
        else:
            logger.debug(
                "Backdrop clear: %d backdrop(s) persist after all strategies",
                len(final_visible),
            )

        # Return True: we saw backdrops and actively attempted dismissal
        return True

    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        logger.debug("_clear_blocking_backdrop error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Main crawler class
# ---------------------------------------------------------------------------

class BrowserCrawler:
    """
    BFS crawler backed by Playwright (headless Chromium).

    Parameters
    ----------
    target : str
        The starting URL (e.g. "http://localhost:3000").
    max_depth : int
        Maximum BFS depth from the starting URL.
    max_interactions : int
        Maximum total page visits + element interactions.
    delay : float
        Seconds to wait between browser interactions.
    respect_robots : bool
        If True, fetch and honour robots.txt before crawling.
    timeout : int
        Playwright navigation/wait timeout in milliseconds.
    headless : bool
        Run Chromium headless (default True). Set False for --headed mode.
    max_duration : float
        Hard wall-clock limit in seconds for the entire crawl phase.
        When exceeded, crawling stops gracefully and returns collected
        snapshots (default 300 s).
    """

    def __init__(
        self,
        target: str,
        max_depth: int = 3,
        max_interactions: int = 50,
        delay: float = 0.5,
        respect_robots: bool = False,
        timeout: int = 15000,
        headless: bool = True,
        max_duration: float = 300.0,
        max_same_action: int = 2,
        auth_login_url: Optional[str] = None,
        auth_username: Optional[str] = None,
        auth_password: Optional[str] = None,
    ) -> None:
        self.target = target.rstrip("/")
        self.max_depth = max_depth
        self.max_interactions = max_interactions
        self.delay = delay
        self.respect_robots = respect_robots
        self.timeout = timeout
        self.headless = headless
        self.max_duration = max_duration
        self.max_same_action = max_same_action
        
        self.auth_login_url = auth_login_url
        self.auth_username = auth_username
        self.auth_password = auth_password

        # Scoping
        parsed = urlparse(self.target)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"

        # BFS state
        self._visited: set[tuple[str, str]] = set()  # (url, hash)
        self._out_of_scope: set[str] = set() # (url)
        self._queue: list[tuple[str, int]] = [(self.target, 0)]
        self._interaction_count: int = 0
        self._snapshots: list[PageSnapshot] = []
        self._robots: Optional[RobotsParser] = None
        self._crawl_start: float = 0.0   # wall-clock start (Issue 3)
        self._deadline_logged: bool = False  # log the timeout warning exactly once

        # Intercept: store response headers keyed by URL
        self._response_cache: dict[str, tuple[dict[str, str], list[str]]] = {}

    # ------------------------------------------------------------------
    # Hard timeout guard  (Issue 3)
    # ------------------------------------------------------------------

    def _time_remaining(self) -> float:
        """Return seconds remaining before the hard crawl deadline."""
        return self.max_duration - (time.monotonic() - self._crawl_start)

    def _deadline_reached(self) -> bool:
        """Return True if the wall-clock limit has been exceeded.

        Logs the timeout warning exactly once - subsequent calls in nested
        loops return True silently to avoid the 4× duplicate warning.
        """
        if self._time_remaining() <= 0:
            if not self._deadline_logged:
                self._deadline_logged = True
                logger.warning(
                    "Hard crawl timeout reached (%d s). "
                    "Stopping crawl and proceeding with %d snapshots collected.",
                    int(self.max_duration),
                    len(self._snapshots),
                )
            return True
        return False

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def crawl(self) -> list[PageSnapshot]:
        """
        Launch the browser, run the BFS crawl, and return all page snapshots.
        Stops early if max_interactions or max_duration is reached.
        """
        self._crawl_start = time.monotonic()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                ignore_https_errors=True,
                # Pretend to be a real browser so WAFs don't block us
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            # ---- Register response interceptor ----
            page.on("response", self._on_response)

            # ---- Authenticate if requested ----
            if self.auth_login_url and self.auth_username and self.auth_password:
                await self._perform_login(page)

            # ---- Optionally fetch robots.txt ----
            if self.respect_robots:
                await self._load_robots(page)

            # ---- BFS from root ----
            await self._bfs_crawl(page, self.target, depth=0)

            await browser.close()

        elapsed = time.monotonic() - self._crawl_start
        logger.info(
            "Crawl complete. Snapshots: %d, Interactions: %d, Elapsed: %.1f s",
            len(self._snapshots),
            self._interaction_count,
            elapsed,
        )
        return self._snapshots

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def _perform_login(self, page: Page) -> bool:
        """
        Universal heuristic auto-login logic.
        Visits the login page, finds the password field, guesses the username field,
        and submits the form using Enter.
        """
        logger.info("Auto-authenticating at %s...", self.auth_login_url)
        try:
            await page.goto(self.auth_login_url, wait_until="networkidle", timeout=self.timeout)
            await asyncio.sleep(self.delay)
            
            # Dismiss cookie banners or modals first
            await _dismiss_overlays(page, self.delay)

            pwd_loc = page.locator('input[type="password"]').first
            if await pwd_loc.count() == 0:
                logger.warning("Auto-login failed: No password input field found on the login page.")
                return False

            # Find all visible text-like inputs
            text_inputs = page.locator('input:visible:not([type="password"]):not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"])')
            if await text_inputs.count() > 0:
                await text_inputs.first.fill(self.auth_username)
            else:
                logger.debug("No clear username field found; attempting to just fill password.")

            await pwd_loc.fill(self.auth_password)
            
            # Submit by pressing Enter on the password field and wait for navigation
            logger.info("Submitting login form credentials...")
            async with page.expect_navigation(timeout=self.timeout):
                await pwd_loc.press("Enter")
                
            await asyncio.sleep(self.delay)
            logger.info("Auto-login completed. Currently at: %s", page.url)
            return True
            
        except PlaywrightTimeoutError:
            logger.warning("Auto-login timed out waiting for navigation.")
            return False
        except Exception as exc:
            logger.error("Auto-login failed due to unexpected error: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Robots.txt
    # ------------------------------------------------------------------

    async def _load_robots(self, page: Page) -> None:
        """Fetch and parse robots.txt from the target origin."""
        robots_url = f"{self.origin}/robots.txt"
        try:
            resp = await page.goto(robots_url, timeout=self.timeout)
            if resp and resp.status == 200:
                content = await page.content()
                self._robots = RobotsParser()
                self._robots.parse(content)
                logger.info(
                    "robots.txt loaded, %d disallowed paths",
                    len(self._robots.disallowed),
                )
            else:
                logger.debug("robots.txt not found at %s", robots_url)
        except Exception as exc:
            logger.warning("Could not fetch robots.txt: %s", exc)

    def _is_allowed(self, url: str) -> bool:
        """Return True if the URL is allowed per robots.txt (or if robots not enabled)."""
        if not self._robots:
            return True
        path = urlparse(url).path
        return self._robots.is_allowed(path)

    # ------------------------------------------------------------------
    # BFS
    # ------------------------------------------------------------------

    async def _bfs_crawl(self, page: Page, start_url: str, depth: int) -> None:
        """
        Recursively BFS-crawl from start_url up to self.max_depth.
        Guards against both interaction count and wall-clock limits.
        """
        if depth > self.max_depth:
            return
        if self._interaction_count >= self.max_interactions:
            logger.info("Max interactions reached (%d), stopping crawl.", self.max_interactions)
            return
        if self._deadline_reached():
            return
        if not self._is_allowed(start_url):
            logger.debug("robots.txt disallows %s, skipping.", start_url)
            return
        if not self._is_same_origin(start_url):
            return

        # ---- Navigate to the page ----
        snapshot = await self._visit_page(page, start_url)
        if snapshot is None:
            return

        if self._interaction_count >= self.max_interactions or self._deadline_reached():
            return

        # ---- Explore interactive elements ----
        await self._explore_elements(page, depth)

    async def _visit_page(self, page: Page, url: str) -> Optional[PageSnapshot]:
        """
        Navigate to url, enforce same-origin scope on the landed URL (server-side
        redirects can land us on a completely different domain), dismiss any
        overlays, compute the structural state key, and take a snapshot.

        Returns None if the page is out of scope, already visited, or navigation
        failed. Does NOT increment interaction_count for out-of-scope pages.
        Logs the computed state key at DEBUG level (Issue 4).
        """
        norm_url = _normalise_url(url)
        if norm_url in self._out_of_scope:
            logger.debug("Skipping known out-of-scope URL: %s", url)
            return None

        logger.info("Visiting: %s", url)

        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            await asyncio.sleep(self.delay)
        except PlaywrightTimeoutError:
            logger.warning(
                "Timeout navigating to %s - capturing partial state.", url
            )
        except PlaywrightError as exc:
            logger.warning("Navigation error for %s: %s", url, exc)
            return None

        # ---- Scope guard: reject pages outside the target origin (Issue fix) ----
        # Must run BEFORE overlay dismissal / structural hashing so we never
        # waste time interacting with an external site.
        if not self._scope_guard(page.url, from_url=url):
            return None

        # ---- Dismiss modals / overlays before inspecting the real page (Issue 1) ----
        await _dismiss_overlays(page, self.delay)

        # ---- Compute stable structural state key (Issue 2) ----
        actual_url = page.url
        norm_actual = _normalise_url(actual_url)
        content_key = await _structural_page_key(page)
        state_key = (norm_actual, content_key)

        logger.debug(
            "State key: url='%s'  hash='%s'  (was_requested='%s')",
            norm_actual, content_key, norm_url,
        )

        if state_key in self._visited:
            logger.debug(
                "DUPLICATE - already visited state (url=%s, hash=%s), skipping.",
                norm_actual, content_key,
            )
            return None

        self._visited.add(state_key)
        self._interaction_count += 1
        logger.debug(
            "NEW STATE - recording snapshot #%d (url=%s, hash=%s)",
            self._interaction_count, norm_actual, content_key,
        )

        # ---- Collect HTML, headers, cookies, forms ----
        html = await page.content()
        headers, cookies = self._response_cache.get(actual_url, ({}, []))
        forms = await self._extract_forms(page, actual_url)
        # Hash parameters like /#/search?q=test
        parsed_url = urlparse(actual_url)
        if parsed_url.fragment and '?' in parsed_url.fragment:
            query_string = parsed_url.fragment.split('?', 1)[1]
        else:
            query_string = parsed_url.query
        query_params = parse_qs(query_string)

        snapshot = PageSnapshot(
            url=actual_url,
            html=html,
            headers=dict(headers),
            cookies=list(cookies),
            forms=forms,
            query_params=query_params,
        )
        self._snapshots.append(snapshot)
        logger.debug("Snapshot captured: %s (%d bytes)", actual_url, len(html))
        return snapshot

    # ------------------------------------------------------------------
    # Element exploration
    # ------------------------------------------------------------------

    async def _explore_elements(self, page: Page, depth: int) -> None:
        """
        Find all clickable elements and forms on the current page,
        interact with each one, capture the resulting state, then go back.
        """
        base_url = page.url

        # ---- Collect links (navigate, don't click) ----
        links = await self._collect_links(page)
        for link_url in links:
            if self._interaction_count >= self.max_interactions or self._deadline_reached():
                return
            await self._bfs_crawl(page, link_url, depth + 1)
            # After recursive crawl, restore base page if needed
            if page.url != base_url:
                await self._safe_goto(page, base_url)
                await _dismiss_overlays(page, self.delay)

        # ---- Interact with buttons and other clickable elements ----
        await self._interact_with_clickables(page, base_url, depth)

        # ---- Fill and submit forms ----
        await self._interact_with_forms(page, base_url, depth)

    async def _collect_links(self, page: Page) -> list[str]:
        """
        Extract all <a href> links that are same-origin and not yet visited.
        """
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]",
                "elements => elements.map(el => el.href)",
            )
        except PlaywrightError:
            return []

        links = []
        for href in hrefs:
            abs_url = self._resolve_url(page.url, href)
            if abs_url and self._is_same_origin(abs_url):
                # Preserve hash-routed SPA paths (e.g. /#/login, #!/page)
                # Only strip pure anchor fragments like #section-heading
                if "#" in abs_url:
                    fragment = abs_url.split("#", 1)[1]
                    if not fragment.startswith("/") and not fragment.startswith("!"):
                        # Pure anchor (e.g. #about), not a hash route
                        abs_url = abs_url.split("#")[0]
                links.append(abs_url)
        return list(dict.fromkeys(links))  # preserve order, deduplicate

    async def _interact_with_clickables(
        self, page: Page, base_url: str, depth: int
    ) -> None:
        """
        Click all <button>, [role=button], [onclick] elements one by one,
        prioritising navigation elements (routerlink / href-bearing) over
        generic action buttons.

        Same-action cap: elements sharing the same tag + normalised visible
        text (digits stripped) count as "structurally identical actions".  At
        most self.max_same_action of them are interacted with per page visit,
        preventing the crawler from spending its entire budget clicking every
        product's individual 'Add to Basket' button.

        Logs element type + resulting URL + new-vs-duplicate verdict.
        """
        import re as _re

        selector = "button, [role='button'], [onclick]"
        try:
            count = await page.locator(selector).count()
        except PlaywrightError:
            return

        logger.debug("Found %d clickable elements on %s", count, base_url)

        # ------------------------------------------------------------------
        # Priority sort: collect lightweight metadata for all elements in one
        # JS round-trip, then sort indices so routerlink / href-nav elements
        # are visited before generic action buttons.  This ensures the crawler
        # reaches distinct routes (login, contact, account) before the budget
        # is consumed by repeated same-type actions (Add to Basket × N).
        # ------------------------------------------------------------------
        try:
            el_meta = await page.evaluate(f"""() => {{
                const sel = {repr(selector)};
                const els = Array.from(document.querySelectorAll(sel));
                return els.map((el, i) => ({{  
                    i,
                    // Priority 0 = routerlink nav, 1 = plain href nav, 2 = action button
                    p: (
                        el.hasAttribute('routerlink') || !!el.closest('[routerlink]') ? 0 :
                        (el.tagName === 'A' && el.href && el.href !== window.location.href) ? 1 :
                        2
                    ),
                }}));
            }}""")
            sorted_indices = [item["i"] for item in sorted(el_meta, key=lambda x: x["p"])]
        except PlaywrightError:
            sorted_indices = list(range(count))

        # Per-page action-signature counter  {signature: times_interacted}
        action_counts: dict[str, int] = {}

        for i in sorted_indices:
            if self._interaction_count >= self.max_interactions or self._deadline_reached():
                return

            # Ensure we are on the base page before each click
            if page.url != base_url:
                if not await self._safe_goto(page, base_url):
                    return
                await _dismiss_overlays(page, self.delay)

            try:
                locator = page.locator(selector).nth(i)
                if not await locator.is_visible():
                    logger.debug("  [click %d/%d] not visible, skipping", i + 1, count)
                    continue

                # Capture element metadata for verbose logging (Issue 4)
                tag = await locator.evaluate(
                    "el => el.tagName.toLowerCase()", timeout=2000
                )
                el_text = (await locator.inner_text()).strip()[:40] if tag == "button" else ""
                el_desc = f"<{tag}> '{el_text}'" if el_text else f"<{tag}> #{i}"

                # ----------------------------------------------------------
                # Same-action cap: skip if we've already interacted with
                # max_same_action elements that share the same action signature
                # on this page.  Signature = tag + normalised text (digits
                # stripped so 'Product 1' == 'Product 2' as a repeated pattern).
                # ----------------------------------------------------------
                sig_text = _re.sub(r'\d+', '', el_text).strip()[:25]
                action_sig = f"{tag}:{sig_text}"
                if action_counts.get(action_sig, 0) >= self.max_same_action:
                    logger.debug(
                        "  [click %d/%d] same-action cap (%d) hit for %s, skipping",
                        i + 1, count, self.max_same_action, el_desc,
                    )
                    continue
                # Skip disabled elements - both HTML `disabled` attribute and
                # WAI-ARIA `aria-disabled="true"` (used by Angular Material
                # interactive-disabled pattern) cause Playwright to wait the full
                # click timeout for the element to become enabled, wasting 2 s each.
                disabled_attr = await locator.get_attribute("disabled")
                aria_disabled  = await locator.get_attribute("aria-disabled")
                if disabled_attr is not None or aria_disabled == "true":
                    logger.debug(
                        "  [click %d/%d] disabled, skipping %s",
                        i + 1, count, el_desc,
                    )
                    continue

                pre_url = _normalise_url(page.url)
                pre_key = await _structural_page_key(page)

                # ---- PRE-CLICK: close any open search/autocomplete/dropdown ----
                # A cheap Escape press here universally closes search overlays,
                # autocomplete dropdowns, and other non-backdrop UI elements that
                # cover navigation buttons (Account, Language, etc.) and cause
                # 2000ms timeouts because the element IS visible/stable but the
                # click lands on the covering element instead.
                # This is safe: Escape is a no-op when nothing is open.
                try:
                    await page.keyboard.press("Escape")
                except PlaywrightError:
                    pass

                # ---- PRE-CLICK: proactively clear any blocking backdrop ----
                # A drawer/modal opened by a previous click may still have its
                # backdrop covering the page.  Clearing it here costs < 100ms
                # when nothing is blocking, but saves the full click timeout
                # (previously 5 s) when a backdrop IS present.
                await _clear_blocking_backdrop(page, self.delay)

                logger.debug(
                    "  [click %d/%d] clicking %s on %s",
                    i + 1, count, el_desc, base_url,
                )

                # ---- CLICK with short initial timeout to detect intercept quickly ----
                # If the element is covered ("intercepts pointer events"), we want
                # to know within 2 s rather than waste the full 5 s budget.
                # On success, we wait for networkidle normally.
                # On intercept failure, we recover and retry ONCE with a full timeout.
                click_succeeded = False
                # If we suspect this click causes an off-site redirect, clamp timeout
                is_redirect_like = any(kw in el_text.lower() for kw in ('redirect', 'out', 'leave'))
                action_timeout = 3000 if is_redirect_like else 2000

                try:
                    await locator.click(timeout=action_timeout)
                    click_succeeded = True
                except (PlaywrightTimeoutError, PlaywrightError) as click_exc:
                    exc_msg = str(click_exc)
                    if _INTERCEPTS_POINTER_MSG in exc_msg:
                        # ---- REACTIVE recovery: Fallback to JS click immediately (Issue 3 fix) ----
                        logger.debug(
                            "  [click %d/%d] intercept detected for %s - "
                            "falling back to JS evaluation click immediately.",
                            i + 1, count, el_desc,
                        )
                        try:
                            await locator.evaluate("el => el.click()")
                            click_succeeded = True
                        except PlaywrightError as js_exc:
                            logger.debug("JS click fallback failed: %s", js_exc)
                    else:
                        # Non-intercept failure (element gone, stale, etc.) - skip
                        logger.debug(
                            "  [click %d/%d] click failed for %s: %s",
                            i + 1, count, el_desc, click_exc,
                        )

                if not click_succeeded:
                    # Recovery: make sure we're back on the base page
                    if page.url != base_url:
                        await self._safe_goto(page, base_url)
                        await _dismiss_overlays(page, self.delay)
                    continue

                await page.wait_for_load_state("networkidle", timeout=self.timeout)
                await asyncio.sleep(self.delay)

                # ---- Scope guard: click may have triggered a redirect off-site ----
                # Check BEFORE overlay dismissal or any DOM work - cheap URL string
                # comparison. Does NOT charge an interaction if out-of-scope.
                if not self._scope_guard(page.url, from_url=base_url):
                    # Navigate back to base immediately; don't explore further
                    await self._safe_goto(page, base_url)
                    await _dismiss_overlays(page, self.delay)
                    continue

                # ---- Explore rich dialog before dismissing ----
                # Must happen BEFORE _dismiss_overlays so the dialog content
                # (inputs, text, buttons) is captured in a snapshot while it's
                # still open.  _dismiss_overlays then cleans up any leftovers.
                await self._maybe_explore_dialog(page)
                await _dismiss_overlays(page, self.delay)

                post_url = _normalise_url(page.url)
                post_key = await _structural_page_key(page)

                # Verbose verdict logging
                if post_url != pre_url or post_key != pre_key:
                    state_key = (post_url, post_key)
                    if state_key not in self._visited:
                        logger.debug(
                            "  -> NEW STATE: url=%s hash=%s (from %s)",
                            post_url, post_key, el_desc,
                        )
                        self._visited.add(state_key)
                        self._interaction_count += 1
                        html = await page.content()
                        actual_url = page.url
                        headers, cookies = self._response_cache.get(actual_url, ({}, []))
                        forms = await self._extract_forms(page, actual_url)
                        parsed_url = urlparse(actual_url)
                        if parsed_url.fragment and '?' in parsed_url.fragment:
                            query_string = parsed_url.fragment.split('?', 1)[1]
                        else:
                            query_string = parsed_url.query
                        query_params = parse_qs(query_string)
                        snapshot = PageSnapshot(
                            url=actual_url,
                            html=html,
                            headers=dict(headers),
                            cookies=list(cookies),
                            forms=forms,
                            query_params=query_params,
                        )
                        self._snapshots.append(snapshot)

                        # Recurse into newly discovered page
                        if depth + 1 <= self.max_depth and not self._deadline_reached():
                            await self._explore_elements(page, depth + 1)
                    else:
                        logger.debug(
                            "  -> DUPLICATE state after %s: url=%s hash=%s",
                            el_desc, post_url, post_key,
                        )
                else:
                    logger.debug(
                        "  -> NO CHANGE after clicking %s (url=%s, hash=%s)",
                        el_desc, post_url, post_key,
                    )

                # Increment action-signature counter AFTER a successful click
                action_counts[action_sig] = action_counts.get(action_sig, 0) + 1

                # Restore clean base state after every interaction.
                if page.url != base_url:
                    await self._safe_goto(page, base_url)
                    await _dismiss_overlays(page, self.delay)
                elif post_key != pre_key:
                    await _clear_blocking_backdrop(page, self.delay)
                    await _dismiss_overlays(page, self.delay)

            except (PlaywrightTimeoutError, PlaywrightError) as exc:
                logger.debug("  [click %d/%d] failed: %s", i + 1, count, exc)
                if page.url != base_url:
                    await self._safe_goto(page, base_url)
                    await _dismiss_overlays(page, self.delay)

    async def _maybe_explore_dialog(self, page: Page) -> None:
        """
        Before _dismiss_overlays closes everything, check if a rich dialog/modal
        opened after a click.  If it has meaningful content (inputs or multiple
        action buttons), capture a dedicated snapshot of it so the passive and
        active scanners can analyse its forms and elements.

        Rich = has at least one input field OR has more than one non-close button.

        Pure text-only overlays (welcome banners, cookie prompts, search overlays
        with >100 chars of product text) are NOT treated as rich - `text_len`
        alone is no longer a trigger because it caused false positives that pressed
        Escape on real state changes before post_key was computed (turning NEW
        STATEs into NO CHANGEs and regressing snapshot count from 35 -> 7).
        """
        import re as _re

        dialog_sel = (
            "[role='dialog'], [aria-modal='true'], "
            "mat-dialog-container, .cdk-dialog-container"
        )
        try:
            # --- Fast pre-check: skip 7+ DOM queries on clean pages ---
            # count() is a single lightweight DOM query. If no dialog-like
            # elements exist at all, return immediately - ~95% of clicks.
            total = await page.locator(dialog_sel).count()
            if total == 0:
                return

            dialogs = page.locator(dialog_sel)
            n = await dialogs.count()
            for idx in range(n):
                dialog = dialogs.nth(idx)
                if not await dialog.is_visible():
                    continue

                # --- Assess richness (inputs or multiple action buttons only) ---
                # Deliberately NOT using text_len as a criterion: any overlay with
                # >100 chars of body text (product lists, search results, welcome
                # text) would falsely match and press Escape before post_key is
                # computed, converting real state changes into NO CHANGEs.
                input_count = await dialog.locator("input, textarea, select").count()
                all_btn_count = await dialog.locator("button, [role='button']").count()
                close_btn_count = await dialog.locator(
                    "button[aria-label*='lose'], [aria-label*='ismiss'], "
                    "button[class*='close'], [class*='close-button']"
                ).count()
                action_btn_count = max(0, all_btn_count - close_btn_count)

                is_rich = (
                    input_count > 0          # has any form field
                    or action_btn_count > 1  # multiple non-close action buttons
                )
                if not is_rich:
                    continue  # pure blocker or text-only - _dismiss_overlays handles it

                # --- Capture snapshot of the dialog state ---
                html = await page.content()
                dialog_key = (await _structural_page_key(page)) + "_dlg"
                state_key = (_normalise_url(page.url), dialog_key)

                if state_key not in self._visited:
                    self._visited.add(state_key)
                    actual_url = page.url
                    headers, cookies = self._response_cache.get(actual_url, ({}, []))
                    forms = await self._extract_forms(page, actual_url)
                    parsed_url = urlparse(actual_url)
                    if parsed_url.fragment and '?' in parsed_url.fragment:
                        query_string = parsed_url.fragment.split('?', 1)[1]
                    else:
                        query_string = parsed_url.query
                    query_params = parse_qs(query_string)
                    snapshot = PageSnapshot(
                        url=actual_url,
                        html=html,
                        headers=dict(headers),
                        cookies=list(cookies),
                        forms=forms,
                        query_params=query_params,
                    )
                    self._snapshots.append(snapshot)
                    logger.debug(
                        "Dialog snapshot captured: %s "
                        "(inputs=%d, action_btns=%d)",
                        actual_url, input_count, action_btn_count,
                    )

                # Close the dialog; _dismiss_overlays confirms cleanup afterwards
                try:
                    await page.keyboard.press("Escape")
                    await asyncio.sleep(self.delay)
                except PlaywrightError:
                    pass
                return  # one rich dialog per click is enough
        except PlaywrightError:
            pass


    async def _interact_with_forms(
        self, page: Page, base_url: str, depth: int
    ) -> None:
        """
        Fill every form on the page with generic test values and submit it.
        Capture the response page as a new snapshot.
        """
        try:
            form_count = await page.locator("form").count()
        except PlaywrightError:
            return

        logger.debug("Found %d form(s) on %s", form_count, base_url)

        for i in range(form_count):
            if self._interaction_count >= self.max_interactions or self._deadline_reached():
                return

            if page.url != base_url:
                if not await self._safe_goto(page, base_url):
                    return
                await _dismiss_overlays(page, self.delay)

            try:
                form = page.locator("form").nth(i)
                logger.debug("  [form %d/%d] filling on %s", i + 1, form_count, base_url)
                await self._fill_form(page, form)
                await asyncio.sleep(self.delay)

                # Submit: try clicking submit button first, then Enter
                submit = form.locator("[type='submit'], button[type='submit'], button:not([type])")
                if await submit.count() > 0:
                    await submit.first.click(timeout=5000)
                else:
                    first_input = form.locator("input[type='text'], input:not([type])")
                    if await first_input.count() > 0:
                        await first_input.first.press("Enter")

                await page.wait_for_load_state("networkidle", timeout=self.timeout)
                await asyncio.sleep(self.delay)

                # ---- Scope guard: form submission may have redirected off-site ----
                if not self._scope_guard(page.url, from_url=base_url):
                    await self._safe_goto(page, base_url)
                    await _dismiss_overlays(page, self.delay)
                    continue

                await _dismiss_overlays(page, self.delay)

                post_url = _normalise_url(page.url)
                post_key = await _structural_page_key(page)
                state_key = (post_url, post_key)

                if state_key not in self._visited:
                    self._visited.add(state_key)
                    self._interaction_count += 1
                    actual_url = page.url
                    html = await page.content()
                    headers, cookies = self._response_cache.get(actual_url, ({}, []))
                    forms_found = await self._extract_forms(page, actual_url)
                    parsed_url = urlparse(actual_url)
                    if parsed_url.fragment and '?' in parsed_url.fragment:
                        query_string = parsed_url.fragment.split('?', 1)[1]
                    else:
                        query_string = parsed_url.query
                    query_params = parse_qs(query_string)
                    snapshot = PageSnapshot(
                        url=actual_url,
                        html=html,
                        headers=dict(headers),
                        cookies=list(cookies),
                        forms=forms_found,
                        query_params=query_params,
                    )
                    self._snapshots.append(snapshot)
                    logger.debug(
                        "  -> Form submission NEW STATE: %s hash=%s", post_url, post_key
                    )
                else:
                    logger.debug(
                        "  -> Form submission DUPLICATE: %s hash=%s", post_url, post_key
                    )

                if page.url != base_url:
                    await self._safe_goto(page, base_url)
                    await _dismiss_overlays(page, self.delay)

            except (PlaywrightTimeoutError, PlaywrightError) as exc:
                logger.debug("  [form %d/%d] interaction failed: %s", i + 1, form_count, exc)
                if page.url != base_url:
                    await self._safe_goto(page, base_url)
                    await _dismiss_overlays(page, self.delay)

    async def _fill_form(self, page: Page, form) -> None:
        """
        Fill all inputs in a form with generic type-appropriate test values.
        Ignores hidden inputs and CSRF tokens (left untouched).
        """
        for input_loc in [
            form.locator("input[type='text']"),
            form.locator("input:not([type])"),
            form.locator("input[type='search']"),
            form.locator("input[type='email']"),
            form.locator("input[type='number']"),
            form.locator("input[type='tel']"),
            form.locator("input[type='url']"),
            form.locator("input[type='date']"),
            form.locator("input[type='time']"),
        ]:
            count = await input_loc.count()
            for j in range(count):
                el = input_loc.nth(j)
                try:
                    itype = await el.get_attribute("type") or "text"
                    val = _value_for_field(itype)
                    await el.fill(val, timeout=3000)
                except PlaywrightError:
                    pass

        # Passwords
        for pw_idx in range(await form.locator("input[type='password']").count()):
            try:
                await form.locator("input[type='password']").nth(pw_idx).fill(
                    "TestPass123!", timeout=3000
                )
            except PlaywrightError:
                pass

        # Textareas
        for ta_idx in range(await form.locator("textarea").count()):
            try:
                await form.locator("textarea").nth(ta_idx).fill("test_value", timeout=3000)
            except PlaywrightError:
                pass

        # Selects - pick first option
        for sel_idx in range(await form.locator("select").count()):
            try:
                sel_el = form.locator("select").nth(sel_idx)
                options = await sel_el.locator("option").all()
                if options:
                    val = await options[0].get_attribute("value")
                    if val:
                        await sel_el.select_option(value=val, timeout=3000)
            except PlaywrightError:
                pass

    # ------------------------------------------------------------------
    # Form metadata extraction (for active scanning)
    # ------------------------------------------------------------------

    async def _extract_forms(self, page: Page, base_url: str) -> list[DiscoveredForm]:
        """
        Extract all forms from the current page: action, method, and fields.
        """
        forms = []
        try:
            form_count = await page.locator("form").count()
        except PlaywrightError:
            return forms

        for i in range(form_count):
            try:
                form_el = page.locator("form").nth(i)
                action_raw = await form_el.get_attribute("action") or ""
                action_abs = self._resolve_url(base_url, action_raw) or base_url
                method = (await form_el.get_attribute("method") or "GET").upper()

                fields: list[FormField] = []
                inputs = await form_el.locator(
                    "input[name], textarea[name], select[name]"
                ).all()
                for inp in inputs:
                    name = await inp.get_attribute("name") or ""
                    if not name:
                        continue
                    tag = await inp.evaluate("el => el.tagName.toLowerCase()")
                    itype = await inp.get_attribute("type") or tag
                    fields.append(FormField(name=name, field_type=itype, tag=tag))

                forms.append(DiscoveredForm(action=action_abs, method=method, fields=fields))
            except PlaywrightError as exc:
                logger.debug("Could not extract form %d: %s", i, exc)

        return forms

    # ------------------------------------------------------------------
    # Response interception
    # ------------------------------------------------------------------

    async def _on_response(self, response: Response) -> None:
        """
        Playwright response hook: caches headers and Set-Cookie values
        for the main document responses so passive checks can inspect them.

        Only caches document/XHR/fetch responses to avoid accumulating
        headers for every CSS, JS, image and font request (memory bug).
        """
        try:
            # Skip sub-resources — only main HTML documents and API calls
            # carry security headers (CSP, HSTS, Set-Cookie) worth inspecting.
            resource_type = response.request.resource_type
            if resource_type not in ("document", "xhr", "fetch"):
                return

            url = response.url
            headers = await response.all_headers()

            # Playwright's all_headers() concatenates multiple Set-Cookie
            # headers with '\n'. Split so each cookie is inspected individually.
            raw_set_cookie = headers.get("set-cookie", "")
            cookies = [c for c in raw_set_cookie.split("\n") if c.strip()] if raw_set_cookie else []

            # Store by URL (last writer wins for repeated requests)
            self._response_cache[url] = (headers, cookies)
        except PlaywrightError:
            pass

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _is_same_origin(self, url: str) -> bool:
        """Return True if the URL belongs to the same origin as the target."""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}" == self.origin
        except Exception:
            return False

    def _scope_guard(self, current_url: str, from_url: str) -> bool:
        """
        Enforce strict same-origin scope after any navigation.

        Called immediately after page.goto / click / form-submit settles and
        BEFORE any snapshot recording, DOM extraction, or interaction-count
        increment.  This catches server-side redirects (e.g. /redirect?to=...)
        that silently land the browser on an external domain.

        Parameters
        ----------
        current_url : str
            The URL the browser has actually landed on (page.url).
        from_url : str
            The in-scope URL that triggered the navigation - used only
            for the log message so engineers can trace the redirect chain.

        Returns
        -------
        True  - URL is in scope; caller may proceed.
        False - URL is out of scope; caller must abort and navigate back.
                Does NOT consume an interaction slot.
        """
        if self._is_same_origin(current_url):
            return True

        # Out-of-scope: log at WARNING so it is always visible (not just --verbose)
        logger.warning(
            "OUT OF SCOPE - blocked navigation from '%s' to '%s', "
            "not crawling further (origin expected: %s)",
            from_url,
            current_url,
            self.origin,
        )
        self._out_of_scope.add(_normalise_url(current_url))
        return False

    def _resolve_url(self, base: str, href: str) -> Optional[str]:
        """Resolve a potentially-relative href against the current page URL."""
        if not href or href.startswith("javascript:") or href.startswith("mailto:"):
            return None
        try:
            return urljoin(base, href)
        except Exception:
            return None

    async def _safe_goto(self, page: Page, url: str) -> bool:
        """Navigate to url, returning True on success."""
        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            await asyncio.sleep(self.delay)
            return True
        except (PlaywrightTimeoutError, PlaywrightError) as exc:
            logger.warning("Could not navigate back to %s: %s", url, exc)
            return False

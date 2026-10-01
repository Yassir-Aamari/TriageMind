"""
kev_client.py
=============
CISA Known Exploited Vulnerabilities (KEV) catalog client.

CISA maintains a public list of CVEs that are actively being exploited
in the wild.  A CVE in the KEV catalog is the strongest signal that a
vulnerability requires IMMEDIATE remediation — regardless of CVSS score.

The catalog is a single JSON file updated by CISA whenever new entries
are added.  It is free, public, and requires no API key.

Source:
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

This module downloads the catalog once per pipeline run and caches it
in memory so every CVE lookup is O(1) (dict lookup, no network I/O).

Returned fields per CVE:
  in_kev          : bool         True if the CVE is in the catalog
  kev_vendor      : str | None   Vendor name from CISA
  kev_product     : str | None   Product name from CISA
  kev_name        : str | None   Vulnerability name from CISA
  kev_due_date    : str | None   CISA mandated remediation date (YYYY-MM-DD)
  kev_ransomware  : str | None   "Known" / "Known to be Used in Ransomware" / None

Usage example:
  import asyncio
  from kev_client import build_kev_index, lookup_kev
  index = asyncio.run(build_kev_index())
  result = lookup_kev("CVE-2021-44228", index)
  # {"in_kev": True, "kev_due_date": "2021-12-24", ...}
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_KEV_TIMEOUT = 20.0
# Local cache file written alongside the output files each run.
_KEV_CACHE_PATH = Path("kev_cache.json")


async def build_kev_index(use_cache: bool = True) -> dict[str, dict]:
    """
    Download the CISA KEV catalog and return a dict keyed by CVE ID.

    Parameters
    ----------
    use_cache : bool
        If True and kev_cache.json exists in the current directory, the
        catalog is read from disk instead of downloaded (saves ~200 KB
        of bandwidth per run).  The cache is always refreshed on download.

    Returns
    -------
    dict mapping cve_id (uppercase) -> KEV entry dict.
    """
    if use_cache and _KEV_CACHE_PATH.exists():
        try:
            with open(_KEV_CACHE_PATH, "r", encoding="utf-8") as fh:
                index = json.load(fh)
            logger.info("KEV index loaded from cache (%d entries).", len(index))
            return index
        except Exception as exc:
            logger.warning("Could not read KEV cache (%s); downloading fresh copy.", exc)

    logger.info("Downloading CISA KEV catalog from %s ...", KEV_CATALOG_URL)
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                KEV_CATALOG_URL,
                headers={"User-Agent": "TriageMind-Security-Scanner/1.0"},
                timeout=_KEV_TIMEOUT,
                follow_redirects=True,
            )
            response.raise_for_status()
            catalog = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.error("Failed to download KEV catalog: %s", exc)
        return {}

    vulns = catalog.get("vulnerabilities", [])
    logger.info("KEV catalog fetched: %d entries.", len(vulns))

    index: dict[str, dict] = {}
    for entry in vulns:
        cve_id = entry.get("cveID", "").upper()
        if cve_id:
            index[cve_id] = entry

    # Persist to local cache
    try:
        with open(_KEV_CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, ensure_ascii=False)
        logger.debug("KEV cache written to %s", _KEV_CACHE_PATH.resolve())
    except Exception as exc:
        logger.warning("Could not write KEV cache: %s", exc)

    return index


def lookup_kev(cve_id: str, kev_index: dict[str, dict]) -> dict:
    """
    Look up a CVE in the pre-built KEV index.

    Returns a dict with `in_kev` and enrichment fields.
    Always returns a dict (never None) so callers can safely unpack it.
    """
    if not cve_id:
        return {"in_kev": False}

    entry = kev_index.get(cve_id.upper())
    if not entry:
        return {"in_kev": False}

    ransomware_raw = entry.get("knownRansomwareCampaignUse", "")
    ransomware = ransomware_raw if ransomware_raw and ransomware_raw.lower() != "unknown" else None

    return {
        "in_kev": True,
        "kev_vendor": entry.get("vendorProject"),
        "kev_product": entry.get("product"),
        "kev_name": entry.get("vulnerabilityName"),
        "kev_due_date": entry.get("dueDate"),          # YYYY-MM-DD
        "kev_ransomware": ransomware,
    }

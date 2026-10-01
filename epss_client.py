"""
epss_client.py
==============
EPSS (Exploit Prediction Scoring System) client — FIRST.org API.

EPSS provides a daily-updated probability score (0–1) that a given CVE
will be exploited in the wild within the next 30 days.  It is maintained
by FIRST.org, is free, and requires no API key.

API endpoint:
  GET https://api.first.org/data/v1/epss?cve=CVE-xxxx

Returned fields per CVE:
  epss_score       : float  0.0–1.0  (exploitation probability)
  epss_percentile  : float  0.0–1.0  (rank among all scored CVEs)

Usage example:
  import asyncio
  from epss_client import fetch_epss_batch
  scores = asyncio.run(fetch_epss_batch(["CVE-2021-44228", "CVE-2017-0144"]))
"""

import asyncio
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
_EPSS_TIMEOUT = 10.0


async def fetch_epss(cve_id: str, client: Optional[httpx.AsyncClient] = None) -> Optional[dict]:
    """
    Fetch the EPSS score for a single CVE.

    Returns a dict:
      { "epss_score": 0.974, "epss_percentile": 0.999 }

    Returns None on network error or if the CVE has no EPSS record.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient()

    try:
        response = await client.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            headers={"User-Agent": "TriageMind-Security-Scanner/1.0"},
            timeout=_EPSS_TIMEOUT,
        )
        if response.status_code != 200:
            logger.warning("EPSS API returned HTTP %d for %s", response.status_code, cve_id)
            return None

        data = response.json()
        items = data.get("data", [])
        if not items:
            logger.debug("No EPSS record for %s (not yet scored)", cve_id)
            return None

        item = items[0]
        return {
            "epss_score": float(item.get("epss", 0.0)),
            "epss_percentile": float(item.get("percentile", 0.0)),
        }

    except (httpx.RequestError, httpx.TimeoutException, ValueError) as exc:
        logger.warning("EPSS fetch failed for %s: %s", cve_id, exc)
        return None
    finally:
        if own_client:
            await client.aclose()


async def fetch_epss_batch(cve_ids: list[str]) -> dict[str, Optional[dict]]:
    """
    Fetch EPSS scores for a list of unique CVE IDs in parallel.

    Returns a mapping  { cve_id: { epss_score, epss_percentile } | None }

    Uses a single shared httpx client for all requests so that the TCP
    connection is reused, which is faster than opening one per CVE.
    """
    if not cve_ids:
        return {}

    results: dict[str, Optional[dict]] = {}

    async with httpx.AsyncClient() as client:
        tasks = {cve: fetch_epss(cve, client=client) for cve in cve_ids}
        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for cve, result in zip(tasks.keys(), gathered):
            if isinstance(result, Exception):
                logger.warning("EPSS batch error for %s: %s", cve, result)
                results[cve] = None
            else:
                results[cve] = result
                if result:
                    logger.info(
                        "EPSS %s -> score=%.4f (%.1f%% percentile)",
                        cve, result["epss_score"], result["epss_percentile"] * 100,
                    )

    return results

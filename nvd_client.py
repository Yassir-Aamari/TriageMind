"""
nvd_client.py
=============
NVD API client for fetching CVE metadata.

Extracts per CVE:
  - CVSS v3.1 / v3.0 base score, severity label, and full vector string
  - CWE ID (primary weakness category)
  - English description
"""

import asyncio
import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Base URL for NVD API v2.0
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def fetch_cve_details(cve_id: str, max_retries: int = 3) -> Optional[dict]:
    """
    Fetch CVE metadata from the NVD API.

    Returns a dict with keys:
      cve_id, description, cvss_score, cvss_severity,
      cvss_vector, cvss_version, cwe_id

    Returns None if the CVE cannot be fetched or parsed.
    """
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"User-Agent": "TriageMind-Security-Scanner/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    params = {"cveId": cve_id}

    # NVD API rate limits:
    # 5 requests / 30 seconds (without API key)
    # 50 requests / 30 seconds (with API key)
    base_delay = 6.0 if not api_key else 1.0

    async with httpx.AsyncClient() as client:
        for attempt in range(max_retries):
            try:
                response = await client.get(
                    NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=10.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    return _extract_cve_data(data, cve_id)
                elif response.status_code in (403, 429, 503):
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        "NVD API rate limited (HTTP %d) for %s. Retrying in %.1f s...",
                        response.status_code, cve_id, delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    logger.error("NVD API returned HTTP %d for %s", response.status_code, cve_id)
                    return None

            except (httpx.RequestError, httpx.TimeoutException) as exc:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    "Network error fetching %s: %s. Retrying in %.1f s...",
                    cve_id, exc, delay,
                )
                await asyncio.sleep(delay)

    logger.error("Failed to fetch %s from NVD after %d attempts.", cve_id, max_retries)
    return None


def _extract_cve_data(nvd_data: dict, cve_id: str) -> Optional[dict]:
    """Parse the raw NVD JSON payload into standardised enrichment fields."""
    try:
        vulnerabilities = nvd_data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.debug("No vulnerability records found for %s", cve_id)
            return None

        cve_node = vulnerabilities[0].get("cve", {})

        # --- 1. English description ---
        description_en = ""
        for desc in cve_node.get("descriptions", []):
            if desc.get("lang") == "en":
                description_en = desc.get("value", "")
                break

        # --- 2. CVSS metrics: prefer v3.1, then v3.0, then v2 ---
        metrics = cve_node.get("metrics", {})
        cvss_data = None
        cvss_version = None

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_version = "3.1"
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_version = "3.0"
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_version = "2.0"
            # v2 stores severity at the metric level, not inside cvssData
            if cvss_data and "baseSeverity" not in cvss_data:
                cvss_data["baseSeverity"] = (
                    metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
                )

        # --- 3. CWE ID from weaknesses list ---
        cwe_id = None
        for weakness in cve_node.get("weaknesses", []):
            for wdesc in weakness.get("description", []):
                val = wdesc.get("value", "")
                if val.startswith("CWE-") and val not in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                    cwe_id = val
                    break
            if cwe_id:
                break

        if not cvss_data:
            return {
                "cve_id": cve_id,
                "description": description_en,
                "cvss_score": None,
                "cvss_severity": "UNKNOWN",
                "cvss_vector": None,
                "cvss_version": None,
                "cwe_id": cwe_id,
            }

        return {
            "cve_id": cve_id,
            "description": description_en,
            "cvss_score": cvss_data.get("baseScore"),
            "cvss_severity": cvss_data.get("baseSeverity", "UNKNOWN").upper(),
            "cvss_vector": cvss_data.get("vectorString"),
            "cvss_version": cvss_version,
            "cwe_id": cwe_id,
        }

    except Exception as exc:
        logger.error("Error parsing NVD response for %s: %s", cve_id, exc)
        return None

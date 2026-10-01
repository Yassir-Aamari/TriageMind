"""
parser.py
=========
Telemetry Parser & Multi-Source Enrichment Engine.

Reads raw scan results (results.json), extracts CVE identifiers with regex,
then queries THREE sources in parallel for each unique CVE:

  1. NVD (nvd_client)   — CVSS v3.1 score, vector, severity, CWE, description
  2. EPSS (epss_client) — Exploitation probability from FIRST.org (0-1, daily ML)
  3. CISA KEV (kev_client) — Active exploitation status from CISA catalog

All three fetches use asyncio.gather() so the total enrichment time for N CVEs
is approximately max(NVD_latency, EPSS_latency, KEV_download) instead of N * latency.

Exports enriched_results.json with the following added fields per finding:
  cvss_score, cvss_severity, cvss_vector, cvss_version, cwe_id
  epss_score, epss_percentile
  in_kev, kev_vendor, kev_product, kev_name, kev_due_date, kev_ransomware
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from nvd_client import fetch_cve_details
from epss_client import fetch_epss_batch
from kev_client import build_kev_index, lookup_kev

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(module)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


async def parse_and_enrich(input_file: str, output_file: str) -> None:
    input_path = Path(input_file)
    if not input_path.exists():
        logger.error("Input file %s not found.", input_file)
        raise FileNotFoundError(f"Input file not found: {input_file}")

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse JSON from %s: %s", input_file, exc)
        raise ValueError(f"Invalid JSON in {input_file}") from exc

    logger.info("Loaded %d findings from %s", len(findings), input_file)

    # ------------------------------------------------------------------
    # Step 1: Extract CVE IDs (regex scan, no network I/O)
    # ------------------------------------------------------------------
    cve_per_finding: list[Optional[str]] = []
    for finding in findings:
        cve_id = finding.get("cve")
        if not cve_id:
            search_text = f"{finding.get('description', '')} {finding.get('evidence', '')}"
            match = CVE_REGEX.search(search_text)
            cve_id = match.group(0).upper() if match else None
        cve_per_finding.append(cve_id)

    unique_cves = list({cve for cve in cve_per_finding if cve})
    logger.info("Unique CVEs detected: %d", len(unique_cves))

    # ------------------------------------------------------------------
    # Step 2: Fetch NVD + EPSS + KEV in parallel
    # ------------------------------------------------------------------
    nvd_cache: dict[str, Any] = {}
    epss_cache: dict[str, Any] = {}
    kev_index: dict[str, dict] = {}

    if unique_cves:
        logger.info("Enriching %d CVE(s) from NVD, EPSS, and CISA KEV in parallel...", len(unique_cves))

        # Run all three source fetches concurrently
        nvd_results_raw, epss_results, kev_index = await asyncio.gather(
            # NVD: one coroutine per CVE, gather internally
            asyncio.gather(
                *[fetch_cve_details(cve) for cve in unique_cves],
                return_exceptions=True,
            ),
            # EPSS: batch call (single shared HTTP client)
            fetch_epss_batch(unique_cves),
            # KEV: download catalog once, cache locally
            build_kev_index(use_cache=True),
            return_exceptions=False,
        )

        # Build NVD cache dict
        for cve, result in zip(unique_cves, nvd_results_raw):
            if isinstance(result, Exception):
                logger.warning("NVD fetch failed for %s: %s", cve, result)
                nvd_cache[cve] = None
            else:
                nvd_cache[cve] = result
                if result:
                    logger.info(
                        "NVD  %s -> CVSS %s (%s) | CWE: %s",
                        cve,
                        result.get("cvss_score"),
                        result.get("cvss_severity"),
                        result.get("cwe_id") or "n/a",
                    )

        epss_cache = epss_results  # already a dict
    else:
        logger.info("No CVEs found in findings — skipping NVD/EPSS/KEV enrichment.")

    # ------------------------------------------------------------------
    # Step 3: Attach enrichment data to each finding
    # ------------------------------------------------------------------
    enriched_findings: list[dict[str, Any]] = []

    for finding, cve_id in zip(findings, cve_per_finding):
        finding["cve"] = cve_id

        # --- NVD data ---
        nvd = nvd_cache.get(cve_id) if cve_id else None
        finding["nvd_data"] = nvd

        # Promote NVD fields to top-level so Gemini receives them directly
        if nvd:
            finding["cvss_score"]    = nvd.get("cvss_score")
            finding["cvss_severity"] = nvd.get("cvss_severity")
            finding["cvss_vector"]   = nvd.get("cvss_vector")
            finding["cvss_version"]  = nvd.get("cvss_version")
            finding["cwe_id"]        = nvd.get("cwe_id")
            finding["nvd_description"] = nvd.get("description")
        else:
            finding.setdefault("cvss_score", None)
            finding.setdefault("cvss_severity", None)
            finding.setdefault("cvss_vector", None)
            finding.setdefault("cvss_version", None)
            finding.setdefault("cwe_id", None)
            finding.setdefault("nvd_description", None)

        # --- EPSS data ---
        epss = epss_cache.get(cve_id) if cve_id else None
        if epss:
            finding["epss_score"]       = epss.get("epss_score")
            finding["epss_percentile"]  = epss.get("epss_percentile")
        else:
            finding["epss_score"]       = None
            finding["epss_percentile"]  = None

        # --- CISA KEV data ---
        kev = lookup_kev(cve_id, kev_index) if cve_id else {"in_kev": False}
        finding["in_kev"]          = kev.get("in_kev", False)
        finding["kev_vendor"]      = kev.get("kev_vendor")
        finding["kev_product"]     = kev.get("kev_product")
        finding["kev_name"]        = kev.get("kev_name")
        finding["kev_due_date"]    = kev.get("kev_due_date")
        finding["kev_ransomware"]  = kev.get("kev_ransomware")

        if cve_id and finding["in_kev"]:
            logger.warning(
                "KEV ALERT: %s is in the CISA Known Exploited Vulnerabilities catalog! (due: %s)",
                cve_id, finding["kev_due_date"],
            )

        enriched_findings.append(finding)

    # ------------------------------------------------------------------
    # Step 4: Write enriched_results.json
    # ------------------------------------------------------------------
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(enriched_findings, f, indent=2, ensure_ascii=False)
        logger.info(
            "Enrichment complete: %d findings written to %s",
            len(enriched_findings), output_file,
        )
    except IOError as exc:
        logger.error("Failed to write to %s: %s", output_file, exc)
        raise RuntimeError(f"Failed to write enriched findings to {output_file}") from exc

    # Summary log
    kev_hits = sum(1 for f in enriched_findings if f.get("in_kev"))
    epss_hits = sum(1 for f in enriched_findings if f.get("epss_score") is not None)
    if kev_hits:
        logger.warning("%d finding(s) linked to CVEs in the CISA KEV catalog.", kev_hits)
    logger.info("EPSS scores obtained for %d finding(s).", epss_hits)


def main() -> None:
    input_file = "results.json"
    output_file = "enriched_results.json"

    logger.info("Starting Phase 2: Parser & Multi-Source Enrichment")
    asyncio.run(parse_and_enrich(input_file, output_file))
    logger.info("Phase 2 complete.")


if __name__ == "__main__":
    main()

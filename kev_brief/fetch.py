"""Download the CISA KEV catalog and FIRST EPSS scores."""

from __future__ import annotations

import sys
from typing import Any

import pandas as pd
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
HEADERS = {"User-Agent": "kev-brief/0.1"}
KEV_COLUMNS = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
]


def _get_json(
    url: str,
    params: dict[str, str] | None = None,
    retries: int = 3,
    timeout: int = 30,
) -> dict[str, Any]:
    """GET JSON. Each attempt uses `timeout` seconds; failed attempts are retried."""
    last_error: requests.RequestException | None = None
    for _attempt in range(retries):
        try:
            resp = requests.get(url, params=params, headers=HEADERS, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


def fetch_kev() -> list[dict[str, Any]]:
    """Download the full CISA KEV catalog. Exit non-zero if that download fails."""
    try:
        data = _get_json(KEV_URL)
        return list(data["vulnerabilities"])
    except (requests.RequestException, KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: Failed to fetch KEV catalog: {exc}", file=sys.stderr)
        sys.exit(1)


def fetch_epss(cve_ids: list[str], batch_size: int = 50) -> dict[str, float]:
    """Fetch EPSS scores in batches of 50. CVEs with no score are omitted."""
    scores: dict[str, float] = {}
    for start in range(0, len(cve_ids), batch_size):
        batch = cve_ids[start : start + batch_size]
        try:
            payload = _get_json(EPSS_URL, params={"cve": ",".join(batch)})
        except requests.RequestException as exc:
            print(f"WARNING: EPSS batch failed: {exc}", file=sys.stderr)
            continue
        for entry in payload.get("data", []):
            try:
                scores[str(entry["cve"])] = float(entry["epss"])
            except (KeyError, TypeError, ValueError) as exc:
                print(f"WARNING: EPSS parse error: {exc}", file=sys.stderr)
    return scores


def _cwe_ids(raw: Any) -> list[str]:
    """Normalize KEV `cwes` (list of strings or objects) to CWE ID strings."""
    if not isinstance(raw, list):
        return []
    ids: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            cwe_id = str(item.get("cweID", "")).strip()
        else:
            cwe_id = str(item).strip()
        if cwe_id:
            ids.append(cwe_id)
    return ids


def kev_to_dataframe(vulns: list[dict[str, Any]]) -> pd.DataFrame:
    """Keep the KEV fields the brief uses and parse dateAdded."""
    rows: list[dict[str, Any]] = []
    for vuln in vulns:
        row = {col: vuln.get(col, "") for col in KEV_COLUMNS}
        row["cwes"] = _cwe_ids(vuln.get("cwes", []))
        rows.append(row)
    frame = pd.DataFrame(rows)
    frame["dateAdded"] = pd.to_datetime(frame["dateAdded"], errors="coerce")
    return frame

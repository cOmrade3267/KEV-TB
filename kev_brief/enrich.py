"""Date filter, cloud/CI-CD tagging, and EPSS merge."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pandas as pd
import yaml


def load_keywords(path: str) -> list[str]:
    """Load the cloud/CI-CD keyword list from YAML."""
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return [str(word).lower() for word in data.get("keywords", [])]


def filter_by_date(df: pd.DataFrame, days: int) -> pd.DataFrame:
    """Keep rows whose dateAdded falls in the last `days` calendar days.

    The cutoff is a date, not a timestamp. An entry added exactly N days
    ago stays in. Comparing to `now - N days` would drop that calendar day
    after midnight.
    """
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=days)
    added = pd.to_datetime(df["dateAdded"], errors="coerce").dt.date
    return df.loc[added >= cutoff].copy()


def _keyword_pattern(keywords: list[str]) -> re.Pattern[str]:
    """Whole-word match so 'cloud' does not fire inside VeloCloud or ownCloud."""
    parts = [re.escape(word) for word in keywords if word.strip()]
    if not parts:
        return re.compile(r"(?!)")
    return re.compile(r"\b(?:" + "|".join(parts) + r")\b", re.IGNORECASE)


def tag_cloud_cicd(df: pd.DataFrame, keywords: list[str]) -> pd.DataFrame:
    """Add a cloud_cicd flag. Non-matching rows are kept.

    Keywords must match a whole word in vendorProject, product, or
    vulnerabilityName. 'VeloCloud' does not match 'cloud'.
    """
    frame = df.copy()
    pattern = _keyword_pattern(keywords)

    def matches(row: pd.Series) -> bool:
        text = " ".join(
            [
                str(row.get("vendorProject", "")),
                str(row.get("product", "")),
                str(row.get("vulnerabilityName", "")),
            ]
        )
        return pattern.search(text) is not None

    frame["cloud_cicd"] = frame.apply(matches, axis=1)
    return frame


def merge_epss(df: pd.DataFrame, scores: dict[str, float]) -> pd.DataFrame:
    """Attach EPSS scores. A CVE with no score stays NaN."""
    frame = df.copy()
    frame["epss"] = frame["cveID"].map(scores)
    return frame


def sort_for_report(df: pd.DataFrame) -> pd.DataFrame:
    """Cloud/CI-CD rows first, then EPSS descending. Missing EPSS sorts last."""
    frame = df.copy()
    frame["_sort_epss"] = frame["epss"].fillna(-1)
    frame = frame.sort_values(
        ["cloud_cicd", "_sort_epss"],
        ascending=[False, False],
    ).drop(columns=["_sort_epss"])
    return frame.reset_index(drop=True)

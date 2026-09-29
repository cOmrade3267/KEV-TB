"""Tests for enrichment functions."""

import math
from datetime import datetime, timedelta, timezone

import pandas as pd

from kev_brief.enrich import filter_by_date, merge_epss, tag_cloud_cicd


def test_keyword_match_docker():
    """Docker should match cloud/CI-CD keywords."""
    df = pd.DataFrame([{
        "vendorProject": "Docker",
        "product": "Docker Engine",
        "vulnerabilityName": "RCE",
    }])
    keywords = ["docker", "kubernetes", "jenkins"]
    result = tag_cloud_cicd(df, keywords)
    assert bool(result["cloud_cicd"].iloc[0]) is True


def test_keyword_no_match():
    """Microsoft Windows should not match cloud keywords."""
    df = pd.DataFrame([{
        "vendorProject": "Microsoft",
        "product": "Windows",
        "vulnerabilityName": "Buffer Overflow",
    }])
    keywords = ["docker", "kubernetes", "jenkins"]
    result = tag_cloud_cicd(df, keywords)
    assert bool(result["cloud_cicd"].iloc[0]) is False


def test_epss_merge_with_missing():
    """EPSS merge should handle missing scores gracefully."""
    df = pd.DataFrame({
        "cveID": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
    })
    scores = {"CVE-2024-0001": 0.95, "CVE-2024-0003": 0.10}
    result = merge_epss(df, scores)

    assert result.loc[0, "epss"] == 0.95
    assert math.isnan(result.loc[1, "epss"])  # missing score
    assert result.loc[2, "epss"] == 0.10


def test_date_filter_boundary():
    """Date filter should include entries exactly at the boundary."""
    now = datetime.now(timezone.utc)
    df = pd.DataFrame({
        "dateAdded": pd.to_datetime([
            (now - timedelta(days=5)).strftime("%Y-%m-%d"),    # within
            (now - timedelta(days=30)).strftime("%Y-%m-%d"),   # within
            (now - timedelta(days=31)).strftime("%Y-%m-%d"),   # outside
        ]),
    })
    result = filter_by_date(df, days=30)
    assert len(result) == 2


def test_date_filter_empty():
    """Date filter should return empty if nothing matches."""
    df = pd.DataFrame({
        "dateAdded": pd.to_datetime(["2020-01-01", "2020-06-01"]),
    })
    result = filter_by_date(df, days=7)
    assert len(result) == 0

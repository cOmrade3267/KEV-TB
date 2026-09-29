"""Tests for enrichment functions."""

import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from kev_brief.enrich import filter_by_date, load_keywords, merge_epss, tag_cloud_cicd


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


def test_word_boundary_skips_compound_cloud_names():
    """'cloud' matches a separate word, not VeloCloud or ownCloud."""
    df = pd.DataFrame([
        {"vendorProject": "Arista", "product": "VeloCloud Orchestrator", "vulnerabilityName": "Bug"},
        {"vendorProject": "ownCloud", "product": "ownCloud", "vulnerabilityName": "Bug"},
        {"vendorProject": "Oracle", "product": "Cloud Infrastructure", "vulnerabilityName": "Bug"},
    ])
    result = tag_cloud_cicd(df, ["cloud"])
    assert bool(result["cloud_cicd"].iloc[0]) is False
    assert bool(result["cloud_cicd"].iloc[1]) is False
    assert bool(result["cloud_cicd"].iloc[2]) is True


def test_shipped_keywords_skip_known_noise():
    """The shipped list does not tag the three known false positives."""
    keywords = load_keywords(str(Path(__file__).resolve().parents[1] / "config" / "keywords.yaml"))
    df = pd.DataFrame([
        {"vendorProject": "Arista", "product": "VeloCloud Orchestrator", "vulnerabilityName": "Bug"},
        {"vendorProject": "ownCloud", "product": "ownCloud", "vulnerabilityName": "Bug"},
        {
            "vendorProject": "Cisco",
            "product": "Secure Firewall Management Center (FMC) and Security Cloud Control (SCC)",
            "vulnerabilityName": "Auth bypass",
        },
        {"vendorProject": "JFrog", "product": "Artifactory", "vulnerabilityName": "Bug"},
        {"vendorProject": "GitLab", "product": "Community Edition", "vulnerabilityName": "Bug"},
    ])
    flags = [bool(value) for value in tag_cloud_cicd(df, keywords)["cloud_cicd"]]
    assert flags == [False, False, False, True, True]


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


def test_top10_puts_ransomware_ahead_of_high_epss():
    """The top 10 is not sorted by EPSS."""
    from kev_brief.report import build_context

    frame = pd.DataFrame([
        {
            "cveID": "CVE-OLD",
            "vendorProject": "Ajax",
            "product": "Net",
            "vulnerabilityName": "Old bug",
            "knownRansomwareCampaignUse": "Unknown",
            "epss": 0.99,
            "dueDate": "2020-01-01",
            "cloud_cicd": False,
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "mapping_confidence": "default",
            "requiredAction": "Patch.",
        },
        {
            "cveID": "CVE-RANSOM",
            "vendorProject": "JetBrains",
            "product": "TeamCity",
            "vulnerabilityName": "Deserialization",
            "knownRansomwareCampaignUse": "Known",
            "epss": float("nan"),
            "dueDate": "2026-08-08",
            "cloud_cicd": True,
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "mapping_confidence": "cwe",
            "requiredAction": "Patch.",
        },
    ])
    context = build_context(frame, 90, 2, 1)
    assert context["top10"][0]["cveID"] == "CVE-RANSOM"
    assert context["top10"][0]["epss_fmt"] == "n/a"


def test_date_filter_empty():
    """Date filter should return empty if nothing matches."""
    df = pd.DataFrame({
        "dateAdded": pd.to_datetime(["2020-01-01", "2020-06-01"]),
    })
    result = filter_by_date(df, days=7)
    assert len(result) == 0

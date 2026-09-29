"""Tests for fetch module with mocked network calls."""

from unittest.mock import MagicMock, patch

import pytest

from kev_brief.fetch import fetch_epss, fetch_kev, kev_to_dataframe


@patch("kev_brief.fetch.requests.get")
def test_fetch_kev_success(mock_get):
    """Successful KEV fetch returns vulnerability list."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "vulnerabilities": [{"cveID": "CVE-2024-0001"}]
    }
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    result = fetch_kev()
    assert len(result) == 1
    assert result[0]["cveID"] == "CVE-2024-0001"


@patch("kev_brief.fetch.requests.get")
def test_fetch_kev_failure(mock_get):
    """Failed KEV fetch should exit with non-zero code."""
    import requests
    mock_get.side_effect = requests.RequestException("Connection error")

    with pytest.raises(SystemExit) as exc_info:
        fetch_kev()
    assert exc_info.value.code == 1


@patch("kev_brief.fetch.requests.get")
def test_fetch_epss_success(mock_get):
    """Successful EPSS fetch returns score dict."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "data": [
            {"cve": "CVE-2024-0001", "epss": "0.95"},
            {"cve": "CVE-2024-0002", "epss": "0.10"},
        ]
    }
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    result = fetch_epss(["CVE-2024-0001", "CVE-2024-0002"])
    assert result["CVE-2024-0001"] == 0.95
    assert result["CVE-2024-0002"] == 0.10


@patch("kev_brief.fetch.requests.get")
def test_fetch_epss_partial_failure(mock_get):
    """EPSS fetch should handle batch failures gracefully."""
    import requests
    mock_get.side_effect = requests.RequestException("Timeout")

    result = fetch_epss(["CVE-2024-0001"])
    assert result == {}  # empty, no crash


def test_kev_to_dataframe():
    """KEV to DataFrame should extract correct columns."""
    vulns = [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Test",
            "product": "TestProduct",
            "vulnerabilityName": "Test Vuln",
            "dateAdded": "2024-01-01",
            "shortDescription": "A test.",
            "requiredAction": "Update.",
            "dueDate": "2024-02-01",
            "knownRansomwareCampaignUse": "Known",
            "cwes": [{"cweID": "CWE-79"}, {"cweID": "CWE-89"}],
        }
    ]
    df = kev_to_dataframe(vulns)
    assert len(df) == 1
    assert df.iloc[0]["cveID"] == "CVE-2024-0001"
    assert df.iloc[0]["cwes"] == ["CWE-79", "CWE-89"]

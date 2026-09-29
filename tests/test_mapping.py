"""Tests for ATT&CK mapping logic."""

from pathlib import Path

from kev_brief.mapping import load_mapping_config, map_single_cve


def test_cwe_match(sample_mapping_config):
    """CWE rule should take priority."""
    result = map_single_cve(
        cwes=["CWE-79"],
        vuln_name="Some XSS Vulnerability",
        short_desc="Cross-site scripting",
        config=sample_mapping_config,
    )
    assert result["technique_id"] == "T1059.007"
    assert result["mapping_confidence"] == "cwe"


def test_keyword_match(sample_mapping_config):
    """Keyword rule should match when no CWE match."""
    result = map_single_cve(
        cwes=[],
        vuln_name="Privilege Escalation via Kernel",
        short_desc="Local privilege escalation",
        config=sample_mapping_config,
    )
    assert result["technique_id"] == "T1068"
    assert result["mapping_confidence"] == "keyword"


def test_fallback(sample_mapping_config):
    """Fallback should apply when nothing matches."""
    result = map_single_cve(
        cwes=[],
        vuln_name="Unknown Issue",
        short_desc="Something generic",
        config=sample_mapping_config,
    )
    assert result["technique_id"] == "T1190"
    assert result["mapping_confidence"] == "default"


def test_cwe_priority_over_keyword(sample_mapping_config):
    """CWE match should take priority over keyword match."""
    result = map_single_cve(
        cwes=["CWE-79"],
        vuln_name="Privilege Escalation XSS",  # matches keyword too
        short_desc="Escalation via XSS",
        config=sample_mapping_config,
    )
    assert result["technique_id"] == "T1059.007"  # CWE wins
    assert result["mapping_confidence"] == "cwe"


def test_shipped_fallback_is_public_facing_exploit():
    """The shipped fallback is T1190 with the required rationale text."""
    config_path = Path(__file__).resolve().parents[1] / "config" / "mapping.yaml"
    config = load_mapping_config(str(config_path))
    assert config["fallback"]["technique_id"] == "T1190"
    assert config["fallback"]["rationale"] == "default for KEV entries"


def test_upload_via_traversal_is_not_file_read():
    """WSO2 CVE-2026-5430 describes upload and RCE, so it is not T1005."""
    config_path = Path(__file__).resolve().parents[1] / "config" / "mapping.yaml"
    config = load_mapping_config(str(config_path))
    result = map_single_cve(
        cwes=["CWE-347"],
        vuln_name="WSO2 Multiple Products Path Traversal Vulnerability",
        short_desc=(
            "WSO2 API Manager contains a path traversal vulnerability that could "
            "allow for unrestricted file upload and lead to remote code execution."
        ),
        config=config,
    )
    assert result["technique_id"] == "T1505.003"
    assert result["mapping_confidence"] == "keyword"


def test_plain_traversal_stays_file_read():
    """A traversal with no upload or RCE language still maps to T1005."""
    config_path = Path(__file__).resolve().parents[1] / "config" / "mapping.yaml"
    config = load_mapping_config(str(config_path))
    result = map_single_cve(
        cwes=["CWE-35"],
        vuln_name="GitLab Path Traversal Vulnerability",
        short_desc="A path traversal vulnerability allows reading files.",
        config=config,
    )
    assert result["technique_id"] == "T1005"
    assert result["mapping_confidence"] == "keyword"


def test_unknown_cwe_falls_to_keyword(sample_mapping_config):
    """Unknown CWE should fall through to keyword matching."""
    result = map_single_cve(
        cwes=["CWE-9999"],
        vuln_name="Remote Code Execution",
        short_desc="RCE bug",
        config=sample_mapping_config,
    )
    assert result["technique_id"] == "T1210"
    assert result["mapping_confidence"] == "keyword"

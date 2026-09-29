"""Map each CVE to one ATT&CK technique using config/mapping.yaml.

Priority is CWE, then keyword, then the YAML fallback. The first CWE on the
CVE that has a rule wins. Nothing in this module invents a technique.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import yaml


def load_mapping_config(path: str) -> dict[str, Any]:
    """Load ATT&CK rules from YAML."""
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _keyword_hit(rule: dict[str, Any], text: str) -> bool:
    """True when a keyword is present and no exclude_if phrase is present."""
    keywords = [str(word).lower() for word in rule.get("keywords", [])]
    if not any(word in text for word in keywords):
        return False
    blocked = [str(word).lower() for word in rule.get("exclude_if", [])]
    return not any(word in text for word in blocked)


def _tagged(rule: dict[str, Any], confidence: str) -> dict[str, str]:
    """Copy a YAML rule and record which tier matched."""
    return {
        "technique_id": rule["technique_id"],
        "technique_name": rule["technique_name"],
        "mapping_confidence": confidence,
        "rationale": rule["rationale"],
    }


def map_single_cve(
    cwes: list[str],
    vuln_name: str,
    short_desc: str,
    config: dict[str, Any],
) -> dict[str, str]:
    """Map one CVE. Returns technique_id, technique_name, mapping_confidence, rationale."""
    cwe_rules: dict[str, dict[str, str]] = config.get("cwe_rules", {})
    for cwe_id in cwes:
        if cwe_id in cwe_rules:
            return _tagged(cwe_rules[cwe_id], "cwe")

    text = f"{vuln_name} {short_desc}".lower()
    for rule in config.get("keyword_rules", []):
        if _keyword_hit(rule, text):
            return _tagged(rule, "keyword")

    return _tagged(config["fallback"], "default")


def _cwe_list(value: object) -> list[str]:
    """Return a list of CWE IDs from a dataframe cell."""
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def apply_mapping(df: pd.DataFrame, config: dict[str, Any]) -> pd.DataFrame:
    """Add technique columns to every row."""
    frame = df.copy()
    mapped = [
        map_single_cve(
            cwes=_cwe_list(row.get("cwes", [])),
            vuln_name=str(row.get("vulnerabilityName", "")),
            short_desc=str(row.get("shortDescription", "")),
            config=config,
        )
        for _, row in frame.iterrows()
    ]
    extra = pd.DataFrame(mapped, index=frame.index)
    for column in extra.columns:
        frame[column] = extra[column]
    return frame

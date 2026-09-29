"""Shared test fixtures."""

import pytest


@pytest.fixture
def sample_mapping_config():
    """Sample ATT&CK mapping config for tests."""
    return {
        "cwe_rules": {
            "CWE-79": {
                "technique_id": "T1059.007",
                "technique_name": "Command and Scripting Interpreter: JavaScript",
                "rationale": "XSS test",
            },
            "CWE-89": {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "rationale": "SQLi test",
            },
        },
        "keyword_rules": [
            {
                "keywords": ["privilege", "escalat"],
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "rationale": "Privilege escalation test",
            },
            {
                "keywords": ["remote code"],
                "technique_id": "T1210",
                "technique_name": "Exploitation of Remote Services",
                "rationale": "RCE test",
            },
        ],
        "fallback": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "rationale": "Fallback test",
        },
    }


@pytest.fixture
def sample_kev_entries():
    """Sample KEV vulnerability entries."""
    return [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Docker",
            "product": "Docker Engine",
            "vulnerabilityName": "Docker Engine Remote Code Execution",
            "dateAdded": "2026-09-25",
            "shortDescription": "A remote code execution vulnerability in Docker.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2026-10-15",
            "knownRansomwareCampaignUse": "Known",
            "cwes": [{"cweID": "CWE-78"}],
        },
        {
            "cveID": "CVE-2024-0002",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "Windows Privilege Escalation",
            "dateAdded": "2026-09-20",
            "shortDescription": "A privilege escalation vulnerability.",
            "requiredAction": "Apply updates.",
            "dueDate": "2026-10-10",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": [],
        },
        {
            "cveID": "CVE-2024-0003",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server Buffer Overflow",
            "dateAdded": "2026-01-01",
            "shortDescription": "A buffer overflow in Apache.",
            "requiredAction": "Apply updates.",
            "dueDate": "2026-02-01",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": [{"cweID": "CWE-120"}],
        },
        {
            "cveID": "CVE-2024-0004",
            "vendorProject": "Jenkins",
            "product": "Jenkins Core",
            "vulnerabilityName": "Jenkins Cross-Site Scripting",
            "dateAdded": "2026-09-28",
            "shortDescription": "A stored XSS in Jenkins.",
            "requiredAction": "Update Jenkins to latest.",
            "dueDate": "2026-10-20",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": [{"cweID": "CWE-79"}],
        },
    ]

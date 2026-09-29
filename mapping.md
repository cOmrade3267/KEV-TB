# ATT&CK mapping rules

Each CVE gets one technique. The rules live in `config/mapping.yaml`. Python does not add its own mappings.

Priority:

1. **CWE.** Walk the CVE's CWE list in catalog order. The first CWE that has a rule wins.
2. **Keyword.** If no CWE rule matches, check the vulnerability name and short description. Rules are tried in the order they appear in the file.
3. **Fallback.** Otherwise use T1190, Exploit Public-Facing Application, with the rationale `default for KEV entries`.

`mapping_confidence` is `cwe`, `keyword`, or `default`.

## CWE rules

| Rule | Technique | Why this technique |
|------|-----------|--------------------|
| CWE-78 OS Command Injection | T1059 Command and Scripting Interpreter | The exploit runs an OS command. The parent technique is used because the shell (Unix, PowerShell, etc.) is not known from the CWE alone. |
| CWE-94 Code Injection | T1059 Command and Scripting Interpreter | The product is made to execute attacker-controlled code. That is an interpreter or runtime, not a separate ATT&CK technique. |
| CWE-79 Cross-site Scripting | T1059.007 Command and Scripting Interpreter: JavaScript | The injected code is JavaScript in a browser. Drive-by Compromise (T1189) would describe delivery, which many admin-console XSS bugs are not. |
| CWE-89 SQL Injection | T1190 Exploit Public-Facing Application | ATT&CK has no SQL injection technique. The weakness is exploited through an application. |
| CWE-22 Path Traversal | T1005 Data from Local System | In KEV these bugs are used to read files (configs, secrets), which is collection. File and Directory Discovery (T1083) would only cover listing. |
| CWE-502 Deserialization of Untrusted Data | T1190 Exploit Public-Facing Application | The deserialization entries in this catalog are server-side (SharePoint, TeamCity, Ajax.NET). Exploitation for Client Execution (T1203) would be the wrong place in the kill chain. |
| CWE-918 Server-Side Request Forgery | T1090 Proxy | ATT&CK has no SSRF technique. The server is forced to relay a request, which is what Proxy describes. This is the closest fit, not a perfect one. |
| CWE-434 Unrestricted Upload | T1505.003 Server Software Component: Web Shell | The upload entries in the current window are CMS plugins. The exploited result is a web shell, not a generic file copy (T1105). |
| CWE-287 Improper Authentication | T1078 Valid Accounts | The attacker reaches a state the product treats as an account. This does **not** mean a password was phished. Hunt the exposed service, not only stolen credentials. |
| CWE-288 Authentication Bypass Using an Alternate Path | T1078 Valid Accounts | Same class as CWE-287: an alternate path reaches an authenticated state. |
| CWE-259 Use of Hard-coded Password | T1078 Valid Accounts | Unlike a bypass, this one is a real password embedded in the product. Valid Accounts is the direct technique. |
| CWE-306 Missing Authentication for Critical Function | T1190 Exploit Public-Facing Application | No account is checked and none is used. Mapping this to T1078 would send people looking for credentials that are not part of the bug. |
| CWE-269 Improper Privilege Management | T1068 Exploitation for Privilege Escalation | The weakness is exploited to raise privileges. Abuse Elevation Control Mechanism (T1548) is the wrong parent: that technique is UAC, sudo, and setuid, not a missing check. |
| CWE-862 Missing Authorization | T1068 Exploitation for Privilege Escalation | A caller who should be limited reaches a privileged function. If the CVE lists CWE-269 first, that rule wins and the technique is the same. |

## Keyword rules

Used only when no CWE rule matched. Matching is a case-insensitive substring of the vulnerability name plus the short description.

| Keywords | Technique | Why this technique |
|----------|-----------|--------------------|
| escalat, elevat, privileged access | T1068 Exploitation for Privilege Escalation | Catches "privilege escalation", "elevate privileges", and "gain privileged access" when no CWE rule matched. The bare word "privilege" is not a keyword: Cisco IOS CVE-2008-4128 says `show privilege`, which is a CLI command, not escalation. |
| command injection, code injection | T1059 Command and Scripting Interpreter | Catches CWE-77 and CWE-96, which are the same class as CWE-78 and CWE-94 but are not separate CWE rules. |
| traversal | T1005 Data from Local System | Catches path-traversal names whose CWE is a variant such as CWE-35 rather than CWE-22. |

## Fallback

| Condition | Technique | Why |
|-----------|-----------|-----|
| No CWE or keyword rule matched | T1190 Exploit Public-Facing Application | KEV is already a list of exploited vulnerabilities. When the weakness class does not pick a more specific technique, the honest label is exploitation of the vulnerable product. The rationale string is exactly `default for KEV entries`. |

## Left at the default on purpose

These showed up in the 90-day catalog and were **not** given their own rule:

| Weakness | Why it stays on T1190 |
|----------|------------------------|
| CWE-787, CWE-119, CWE-122, CWE-121, CWE-416 (memory corruption) | The same CWE covers a browser (Chromium V8), a kernel, and a firewall. Client Execution (T1203) would be wrong for the firewall. Privilege Escalation (T1068) would be wrong for the browser. The CWE cannot decide, so the row stays `default`. |
| CWE-284 Improper Access Control, CWE-863 Incorrect Authorization | Too broad to call privilege escalation every time. A Magento incorrect-authorization bug is closer to exploiting the application. |
| CWE-20 Improper Input Validation | Parent class. It does not say what the attacker gains. |
| CWE-352 Cross-Site Request Forgery | No clean single technique. Forcing a browser to send a request is not, by itself, Valid Accounts or command execution. |

If a later week is dominated by one of these and the product is consistent (all browsers, all local kernel bugs), add a rule then. Do not encode that guess in Python.

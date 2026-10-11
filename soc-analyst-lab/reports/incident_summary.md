# SOC Triage Summary

Generated: 2026-10-11T08:24:37+00:00
Total findings: **8**

## Severity breakdown

- High: 4
- Medium: 4

## Findings

### 1. [HIGH] Repeated failed logons (5 events)
- **Rule:** `failed_logon_burst`
- **When:** 2026-09-18T08:01:00Z
- **Host / account:** `WS-014` / `jsingh`
- **Source IP:** `198.51.100.24`
- **Event IDs:** 4625
- **MITRE ATT&CK:** T1110
- **Related event count:** 5
- **Why it was flagged:** 5 failed logons for this host/account occurred within 10 minutes. Source IPs observed: 198.51.100.24.
- **Status:** needs_review

### 2. [HIGH] Security group membership changed
- **Rule:** `privileged_group_change`
- **When:** 2026-09-18T08:14:00Z
- **Host / account:** `DC-01` / `helpdesk-temp`
- **Source IP:** `10.0.4.12`
- **Event IDs:** 4732
- **MITRE ATT&CK:** T1098
- **Related event count:** 1
- **Why it was flagged:** Confirm the actor, target group, and change request; unexpected membership changes can grant access.
- **Status:** needs_review

### 3. [HIGH] PowerShell script block logged
- **Rule:** `powershell_script_block`
- **When:** 2026-09-18T08:20:00Z
- **Host / account:** `WS-014` / `jsingh`
- **Source IP:** `198.51.100.24`
- **Event IDs:** 4104
- **MITRE ATT&CK:** T1059.001
- **Related event count:** 1
- **Why it was flagged:** Review the complete script block and parent process. Keyword matches are triage hints, not proof of malicious activity.
- **Status:** needs_review

### 4. [HIGH] Windows audit log cleared
- **Rule:** `audit_log_cleared`
- **When:** 2026-09-18T08:26:00Z
- **Host / account:** `DC-01` / ``
- **Source IP:** `10.0.4.12`
- **Event IDs:** 1102
- **MITRE ATT&CK:** T1070.001
- **Related event count:** 1
- **Why it was flagged:** Check whether this was an approved administrative action and preserve other telemetry promptly.
- **Status:** needs_review

### 5. [MEDIUM] Successful logon after failed attempts
- **Rule:** `success_after_failures`
- **When:** 2026-09-18T08:06:00Z
- **Host / account:** `WS-014` / `jsingh`
- **Source IP:** `198.51.100.24`
- **Event IDs:** 4625, 4624
- **MITRE ATT&CK:** T1078
- **Related event count:** 6
- **Why it was flagged:** A successful logon followed failed attempts for the same host/account within 10 minutes. Correlate source IP, logon type, MFA, and identity-provider telemetry.
- **Status:** needs_review

### 6. [MEDIUM] New local/domain account created
- **Rule:** `account_created`
- **When:** 2026-09-18T08:12:00Z
- **Host / account:** `DC-01` / `svc_backup`
- **Source IP:** `10.0.4.12`
- **Event IDs:** 4720
- **MITRE ATT&CK:** T1136.001
- **Related event count:** 1
- **Why it was flagged:** Account creation should be matched to an approved change or onboarding ticket.
- **Status:** needs_review

### 7. [MEDIUM] Explicit credentials used
- **Rule:** `explicit_credentials`
- **When:** 2026-09-18T08:30:00Z
- **Host / account:** `WS-014` / `jsingh`
- **Source IP:** `10.0.4.12`
- **Event IDs:** 4648
- **MITRE ATT&CK:** T1550.002
- **Related event count:** 1
- **Why it was flagged:** Validate the initiating process, destination, and whether alternate credentials were expected.
- **Status:** needs_review

### 8. [MEDIUM] New service installed
- **Rule:** `service_installed`
- **When:** 2026-09-18T08:33:00Z
- **Host / account:** `WS-014` / `svc_update`
- **Source IP:** `10.0.4.12`
- **Event IDs:** 4697
- **MITRE ATT&CK:** T1543.003
- **Related event count:** 1
- **Why it was flagged:** Verify service name, binary path, signer, account, and change ticket.
- **Status:** needs_review

## Analyst reminder

These are leads for investigation, not verdicts. Check surrounding events, logon type, source reputation, asset criticality, approved changes, and endpoint telemetry before escalating.

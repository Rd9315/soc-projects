# Playbook: Repeated Failed Logons

**Trigger:** A burst of Windows Security event `4625` records for one host/account.

## Triage
1. Confirm the event provider and inspect status/substatus and logon type.
2. Group failures by source IP, target account, host, and time window.
3. Check whether one source targeted many accounts (possible password spray) or one account was targeted repeatedly.
4. Look for a nearby `4624` success and compare source IP, logon type, and workstation.
5. Check identity-provider, VPN, firewall, and endpoint telemetry.

## Decision
- **Likely benign:** known service with stale credentials, documented scanner, expected user typo.
- **Needs escalation:** unfamiliar source, many accounts, privileged target, or success after failures.
- **Do not conclude:** a high count by itself does not prove an attack.

## Response notes
Record time range, affected account(s), source IPs, affected assets, evidence references, and confidence. Follow the organization's account lockout and containment policy; avoid locking out business-critical service accounts without owner validation.

# Windows Event ID Reference for SOC Triage

This is a starter reference, not an exhaustive list. Event IDs are scoped to an event provider and can vary with OS version, enabled audit subcategories, and installed components. Always verify the provider, event XML, and Microsoft documentation for the system being investigated.

## Windows Security / audit events

| Event ID | Meaning | Typical SOC use | First checks |
|---:|---|---|---|
| 1102 | Security audit log cleared | Possible evidence tampering or admin maintenance | Actor, timestamp, other telemetry, change ticket |
| 4624 | Successful logon | Baseline logons; correlate after failures | Logon type, source IP, target account, workstation |
| 4625 | Failed logon | Password spray, brute force, mistyped credentials | Status/substatus, source IP, account spread, rate |
| 4634 | Logoff | Session timeline | Logon ID and matching 4624 |
| 4648 | Logon attempted with explicit credentials | Alternate credentials / lateral movement investigation | Process, target server, actor, approved admin workflow |
| 4672 | Special privileges assigned to new logon | Privileged session review | Account, logon ID, expected admin activity |
| 4688 | Process created | Process execution investigation (if auditing enabled) | Image path, parent, command line, user |
| 4697 | Service installed | Potential persistence / remote service activity | Service name, binary path, signer, account |
| 4720 | User account created | Unexpected account creation | Subject vs target account, ticket, domain/local scope |
| 4722 | User account enabled | Dormant account re-enabled | Who enabled it, why, last use |
| 4724 | Password reset attempted | Account recovery / takeover context | Subject, target, result, helpdesk ticket |
| 4728 | Member added to security-enabled global group | Privilege escalation review | Group name, actor, target member |
| 4732 | Member added to security-enabled local group | Local admin / group membership change | Group, actor, endpoint, change record |
| 4738 | User account changed | Identity changes | Changed attributes and actor |
| 4740 | Account locked out | Password spray or repeated bad passwords | Caller computer, surrounding 4625 events |
| 4768 | Kerberos TGT requested | Kerberos authentication triage | Result code, client address, account |
| 4769 | Kerberos service ticket requested | Service access / Kerberoasting context | Service name, encryption type, volume |
| 4771 | Kerberos pre-authentication failed | Kerberos password failure pattern | Failure code, client address |
| 4776 | NTLM credential validation | NTLM authentication triage | Workstation, status, account |
| 5140 | Network share accessed | Share access timeline | Share name, source address, account |
| 5145 | Detailed network share check | File/share authorization review | Relative target name, access mask, source |
| 5156 | Windows Filtering Platform allowed connection | Network connection evidence when enabled | Direction, app path, local/remote address |
| 5157 | Windows Filtering Platform blocked connection | Blocked network activity | App, destination, filter/runtime context |

## PowerShell Operational events

| Event ID | Meaning | Typical SOC use |
|---:|---|---|
| 400 | PowerShell engine state changed to available | Session timeline; not inherently malicious |
| 403 | PowerShell engine state changed to stopped | Session end context |
| 4103 | Module logging | Cmdlet/pipeline activity when configured |
| 4104 | Script block logging | Review script content and execution context |

## Important caveats

- `4624` and `4625` alone are not enough to prove compromise.
- `4688` usefulness depends on process-creation auditing and command-line policy.
- PowerShell logs require the relevant logging policy to be configured.
- Event IDs are not globally unique; always use provider + channel + ID.
- For production use, enrich this table from the official documentation matching your Windows release and log source.

## Detection implementation status

The current engine has active starter handling for 4624, 4625, 4648, 4672, 4688, 4697, 4720, 4722, 4724, 4728, 4732, 4738, 4740, 4768, 4769, 4771, 4776, 5140, 5145, 5157, 1102, 4104. Not every reference-table ID has a dedicated detection. Events such as 4634 and 5156 are currently reference-only. Event 4103 is documented but does not yet have a dedicated detection. Always inspect raw event XML for fields that the normalized record does not expose.

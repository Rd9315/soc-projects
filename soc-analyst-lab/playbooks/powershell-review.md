# Playbook: PowerShell Script Block Review

**Relevant events:** `4103`, `4104`; correlate with Security `4688` when available.

## Triage
1. Collect the full script block, not only the matching line.
2. Identify user, host, parent process, command line, and execution time.
3. Look for obfuscation, encoded content, download-and-execute behavior, credential access, or unusual remote destinations.
4. Check script signing, software deployment tools, admin tickets, and known automation.
5. Correlate with DNS, proxy, EDR, and process telemetry.

Keyword detections are noisy. Do not run suspicious content to “see what it does” on a production endpoint. Use an isolated analysis environment and follow internal handling procedures.

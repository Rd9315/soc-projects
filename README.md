# SOC Analyst Lab — Windows Event Triage & Detection

A small, practical SOC home-lab project for learning how to triage Windows security events, flag suspicious patterns, and document an investigation. It runs locally against the included synthetic dataset; no SIEM subscription or real endpoint is required.

## What it does

- Parses a normalized CSV of Windows event records.
- Flags a starter set of suspicious patterns (failed logon bursts, successful logon after failures, new account creation, privileged-group changes, and PowerShell activity).
- Adds severity, rationale, relevant Event IDs, and MITRE ATT&CK technique references to each finding.
- Exports findings as JSON and a readable Markdown incident summary.
- Includes an optional Streamlit dashboard, local SQLite case tracking, and EVTX ingestion.
- Includes a basic password-spray heuristic across distinct accounts.
- Includes a Windows Event ID reference, Sigma-style starter rules, and analyst playbooks.

> **Scope note:** Windows does not have one universal, finite list of “all Event IDs.” IDs vary by provider, Windows version, audit policy, and installed products. This repo focuses on commonly useful Windows Security / PowerShell events for a learning SOC workflow. Validate detections against your own environment before operational use.

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

python -m pip install -r requirements.txt
python src/soc_triage.py --input data/sample_events.csv --out reports
```

The command creates:
- `reports/findings.json`
- `reports/incident_summary.md`

## Input format

CSV columns:

`timestamp,host,channel,event_id,provider,account,src_ip,message`

Use ISO-8601 timestamps. Keep the original event XML or EVTX separately when possible; the normalized CSV is for training and quick triage, not a replacement for evidence preservation.

## Example workflow

1. Review the generated summary and sort findings by severity.
2. Open the matching playbook in `playbooks/`.
3. Validate the alert with surrounding events and endpoint/network telemetry.
4. Record scope, timeline, evidence, containment, and recovery actions.
5. Tune rules to your baseline; do not treat a single event as proof of compromise.

## Project layout

```text
soc-analyst-lab/
├── data/                  # Synthetic training events
├── docs/                  # Event ID reference and investigation notes
├── playbooks/             # Human-readable triage procedures
├── rules/sigma/           # Starter Sigma-style detections
├── src/soc_triage.py      # Local triage engine
├── tests/                 # Unit tests
└── reports/               # Generated at runtime
```

## Detection coverage

Active starter detections include failed-logon bursts, successful logon after failures, password-spray heuristics, account creation/enabling/changes, group membership changes, explicit credentials, special privileges, process creation review, service installation, audit-log clearing, PowerShell script blocks, account lockouts, selected Kerberos/NTLM events, and network share / blocked-connection events. Some are informational triage leads and can be noisy.

## Optional components

Dashboard:
```bash
python -m pip install -r requirements-dashboard.txt
streamlit run src/dashboard.py
```

EVTX dependency:
```bash
python -m pip install -r requirements-evtx.txt
```

The CLI accepts `.evtx` files when the optional `python-evtx` dependency is installed. Validate parsed fields against your provider's XML schema before relying on them; event schemas differ.

## Safety and limitations

- All included events are synthetic and intended for defensive training.
- The rules are intentionally transparent and simple; they are not a replacement for an EDR, SIEM, threat hunting, or incident response process.
- Detection depends on audit policy and log collection. Missing events do not prove that activity did not happen.
- Do not upload real usernames, public IPs, hostnames, or logs containing sensitive information to a public repository.

## Ideas for the next iteration

- Add an EVTX parser and preserve raw event XML.
- Add enrichment from an internal asset inventory.
- Send alerts to a local OpenSearch / Elastic stack.
- Add allowlists and per-host baselines.
- Build a dashboard with alert review status and case notes.

## License

MIT License

Copyright (c) 2026 RAHUL DAGAR

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

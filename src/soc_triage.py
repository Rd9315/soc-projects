#!/usr/bin/env python3
"""A transparent, local-first triage engine for normalized Windows event CSVs."""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_COLUMNS = {
    "timestamp", "host", "channel", "event_id", "provider",
    "account", "src_ip", "message"
}

EVENT_NAMES = {
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4648: "Logon using explicit credentials",
    4672: "Special privileges assigned to new logon",
    4688: "Process creation",
    4697: "Service installed",
    4720: "User account created",
    4722: "User account enabled",
    4724: "Password reset attempted",
    4728: "Member added to security-enabled global group",
    4732: "Member added to security-enabled local group",
    4738: "User account changed",
    4740: "User account locked out",
    4768: "Kerberos authentication ticket requested",
    4769: "Kerberos service ticket requested",
    4771: "Kerberos pre-authentication failed",
    4776: "NTLM credential validation",
    5140: "Network share accessed",
    5145: "Detailed network share access check",
    5156: "Windows Filtering Platform allowed connection",
    5157: "Windows Filtering Platform blocked connection",
    1102: "Audit log cleared",
    4103: "PowerShell module logging",
    4104: "PowerShell script block logging",
}

MITRE = {
    "failed_logon_burst": ["T1110"],
    "success_after_failures": ["T1078"],
    "account_created": ["T1136.001"],
    "privileged_group_change": ["T1098"],
    "powershell_script_block": ["T1059.001"],
    "audit_log_cleared": ["T1070.001"],
    "explicit_credentials": ["T1550.002"],
    "service_installed": ["T1543.003"],
}

def parse_time(value: str) -> datetime:
    """Parse ISO timestamps; assume UTC if the input has no timezone."""
    value = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed

def load_events(path: Path) -> list[dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError("CSV missing required columns: " + ", ".join(sorted(missing)))
        events = []
        for row in reader:
            try:
                row["event_id"] = int(row["event_id"])
                row["_time"] = parse_time(row["timestamp"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid timestamp/event_id in row: {row}") from exc
            events.append(row)
    return sorted(events, key=lambda item: item["_time"])

def finding(rule_id: str, title: str, severity: str, event: dict[str, Any],
            rationale: str, event_ids: list[int], techniques: list[str],
            related_count: int = 1) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "timestamp": event["timestamp"],
        "host": event["host"],
        "account": event["account"],
        "src_ip": event["src_ip"],
        "event_ids": event_ids,
        "event_names": [EVENT_NAMES.get(eid, "See provider documentation") for eid in event_ids],
        "mitre_attack": techniques,
        "related_event_count": related_count,
        "rationale": rationale,
        "status": "needs_review",
    }

def analyze(events: list[dict[str, Any]], threshold: int = 5, window_minutes: int = 10) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failures_by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        eid = event["event_id"]
        key = (event["host"], event["account"])
        if eid == 4625:
            failures_by_key[key].append(event)

        if eid == 4720:
            findings.append(finding(
                "account_created", "New local/domain account created", "medium", event,
                "Account creation should be matched to an approved change or onboarding ticket.",
                [4720], MITRE["account_created"]))
        elif eid in (4728, 4732):
            findings.append(finding(
                "privileged_group_change", "Security group membership changed", "high", event,
                "Confirm the actor, target group, and change request; unexpected membership changes can grant access.",
                [eid], MITRE["privileged_group_change"]))
        elif eid == 4104:
            message = event["message"].lower()
            suspicious_terms = ("downloadstring", "encodedcommand", "frombase64string", "invoke-expression", " iwr ")
            severity = "high" if any(term in message for term in suspicious_terms) else "low"
            findings.append(finding(
                "powershell_script_block", "PowerShell script block logged", severity, event,
                "Review the complete script block and parent process. Keyword matches are triage hints, not proof of malicious activity.",
                [4104], MITRE["powershell_script_block"]))
        elif eid == 1102:
            findings.append(finding(
                "audit_log_cleared", "Windows audit log cleared", "high", event,
                "Check whether this was an approved administrative action and preserve other telemetry promptly.",
                [1102], MITRE["audit_log_cleared"]))
        elif eid == 4648:
            findings.append(finding(
                "explicit_credentials", "Explicit credentials used", "medium", event,
                "Validate the initiating process, destination, and whether alternate credentials were expected.",
                [4648], MITRE["explicit_credentials"]))
        elif eid == 4697:
            findings.append(finding(
                "service_installed", "New service installed", "medium", event,
                "Verify service name, binary path, signer, account, and change ticket.",
                [4697], MITRE["service_installed"]))
        elif eid == 4672:
            findings.append(finding(
                "special_privileges", "Special privileges assigned to logon", "medium", event,
                "Validate the account and logon session; this event is common for administrative and service accounts.",
                [4672], ["T1078"]))
        elif eid == 4688:
            message = event["message"].lower()
            suspicious = any(term in message for term in (
                "powershell -enc", " -encodedcommand", " rundll32", " regsvr32",
                " mshta", " certutil -urlcache", " wscript", " cscript"
            ))
            findings.append(finding(
                "process_creation_review", "Process creation event requires review",
                "medium" if suspicious else "low", event,
                "Review image path, parent process, command line, signer, and user context. "
                "Command-line keyword matches are triage hints only.",
                [4688], ["T1059"] if suspicious else []))
        elif eid == 4722:
            findings.append(finding(
                "account_enabled", "User account enabled", "medium", event,
                "Confirm the actor, target account, and whether re-enabling the account was approved.",
                [4722], ["T1098"]))
        elif eid == 4724:
            findings.append(finding(
                "password_reset_attempt", "Password reset attempt", "medium", event,
                "Confirm the requesting actor, target account, result, and helpdesk/change ticket.",
                [4724], ["T1098"]))
        elif eid == 4738:
            findings.append(finding(
                "account_changed", "User account attributes changed", "low", event,
                "Inspect changed attributes and verify the action against identity-management records.",
                [4738], ["T1098"]))
        elif eid == 4740:
            findings.append(finding(
                "account_lockout", "Account locked out", "medium", event,
                "Correlate caller computer and nearby 4625 events; stale credentials can cause benign lockouts.",
                [4740], ["T1110"]))
        elif eid == 4771:
            findings.append(finding(
                "kerberos_preauth_failure", "Kerberos pre-authentication failed", "medium", event,
                "Review failure code, client address, account spread, and nearby authentication events.",
                [4771], ["T1110"]))
        elif eid == 4776:
            findings.append(finding(
                "ntlm_validation", "NTLM credential validation event", "low", event,
                "Review workstation, account, status, and whether NTLM use is expected.",
                [4776], []))
        elif eid in (4768, 4769):
            findings.append(finding(
                "kerberos_ticket_activity", EVENT_NAMES[eid], "low", event,
                "Baseline ticket volume and inspect account, service name, client address, and encryption details.",
                [eid], ["T1558"] if eid == 4769 else []))
        elif eid in (5140, 5145):
            findings.append(finding(
                "network_share_access", EVENT_NAMES[eid], "low", event,
                "Check share path, access mask, source address, account, and whether access matches the user's role.",
                [eid], ["T1039"]))
        elif eid == 5157:
            findings.append(finding(
                "network_connection_blocked", "Windows Filtering Platform blocked a connection", "low", event,
                "Review application path, destination, direction, and surrounding endpoint/network events.",
                [5157], []))

    # Burst detection is scoped to host + account. The simple rolling window is
    # deliberately easy to inspect and tune for a first portfolio project.
    for key, failures in failures_by_key.items():
        for index, event in enumerate(failures):
            start = event["_time"]
            cluster = [
                item for item in failures[index:]
                if (item["_time"] - start).total_seconds() <= window_minutes * 60
            ]
            if len(cluster) >= threshold:
                unique_ips = sorted({item["src_ip"] for item in cluster if item["src_ip"]})
                findings.append(finding(
                    "failed_logon_burst", f"Repeated failed logons ({len(cluster)} events)", "high", event,
                    f"{len(cluster)} failed logons for this host/account occurred within {window_minutes} minutes. "
                    f"Source IPs observed: {', '.join(unique_ips) if unique_ips else 'not recorded'}.",
                    [4625], MITRE["failed_logon_burst"], len(cluster)))
                break

        if failures:
            first_failure = failures[0]
            success = next((item for item in events
                            if item["host"] == key[0] and item["account"] == key[1]
                            and item["event_id"] == 4624
                            and 0 <= (item["_time"] - first_failure["_time"]).total_seconds() <= window_minutes * 60
                            and (not item.get("src_ip") or not first_failure.get("src_ip")
                                 or item.get("src_ip") == first_failure.get("src_ip"))), None)
            if success:
                findings.append(finding(
                    "success_after_failures", "Successful logon after failed attempts", "medium", success,
                    f"A successful logon followed failed attempts for the same host/account within {window_minutes} minutes. "
                    "Correlate source IP, logon type, MFA, and identity-provider telemetry.",
                    [4625, 4624], MITRE["success_after_failures"], len(failures) + 1))

    # Password-spray heuristic: one source IP failing against several accounts.
    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["event_id"] == 4625 and event.get("src_ip"):
            failures_by_ip[event["src_ip"]].append(event)
    for ip, failures in failures_by_ip.items():
        for index, event in enumerate(failures):
            start = event["_time"]
            cluster = [
                item for item in failures[index:]
                if (item["_time"] - start).total_seconds() <= window_minutes * 60
            ]
            accounts = sorted({item["account"] for item in cluster if item.get("account")})
            if len(accounts) >= threshold:
                findings.append(finding(
                    "password_spray_heuristic",
                    f"Possible password spray ({len(accounts)} accounts)",
                    "high", event,
                    f"Source {ip} generated failed logons against {len(accounts)} distinct accounts "
                    f"within {window_minutes} minutes. Validate VPN/NAT, scanner, and identity-provider context.",
                    [4625], ["T1110.003"], len(cluster)))
                break

    # De-duplicate identical rule/host/account/time alerts.
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in findings:
        key = (item["rule_id"], item["host"], item["account"], item["timestamp"])
        unique[key] = item
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(unique.values(), key=lambda item: (order.get(item["severity"], 9), item["timestamp"]))

def write_reports(findings: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "findings.json").open("w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2, ensure_ascii=False)

    counts: dict[str, int] = defaultdict(int)
    for item in findings:
        counts[item["severity"]] += 1
    lines = [
        "# SOC Triage Summary", "",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Total findings: **{len(findings)}**", "",
        "## Severity breakdown", "",
    ]
    if counts:
        for severity in ("critical", "high", "medium", "low", "info"):
            if counts.get(severity):
                lines.append(f"- {severity.title()}: {counts[severity]}")
    else:
        lines.append("- No findings generated.")
    lines += ["", "## Findings", ""]
    for index, item in enumerate(findings, start=1):
        lines += [
            f"### {index}. [{item['severity'].upper()}] {item['title']}",
            f"- **Rule:** `{item['rule_id']}`",
            f"- **When:** {item['timestamp']}",
            f"- **Host / account:** `{item['host']}` / `{item['account']}`",
            f"- **Source IP:** `{item['src_ip'] or 'not recorded'}`",
            f"- **Event IDs:** {', '.join(map(str, item['event_ids']))}",
            f"- **MITRE ATT&CK:** {', '.join(item['mitre_attack']) or 'not mapped'}",
            f"- **Related event count:** {item['related_event_count']}",
            f"- **Why it was flagged:** {item['rationale']}",
            f"- **Status:** {item['status']}", "",
        ]
    lines += ["## Analyst reminder", "",
              "These are leads for investigation, not verdicts. Check surrounding events, logon type, "
              "source reputation, asset criticality, approved changes, and endpoint telemetry before escalating.", ""]
    (out_dir / "incident_summary.md").write_text("\n".join(lines), encoding="utf-8")

def main() -> None:
    parser = argparse.ArgumentParser(description="Triage normalized Windows events from CSV.")
    parser.add_argument("--input", type=Path, required=True, help="Path to normalized CSV or Windows EVTX file")
    parser.add_argument("--out", type=Path, default=Path("reports"), help="Output directory")
    parser.add_argument("--threshold", type=int, default=5, help="Failed logon count to flag")
    parser.add_argument("--window", type=int, default=10, help="Failed logon window in minutes")
    args = parser.parse_args()
    if args.threshold < 2 or args.window < 1:
        parser.error("--threshold must be >= 2 and --window must be >= 1")
    if args.input.suffix.lower() == ".evtx":
        try:
            from evtx_ingest import parse_evtx
            raw_events = parse_evtx(args.input)
        except (RuntimeError, ImportError) as exc:
            parser.error(str(exc))
        events = []
        for row in raw_events:
            try:
                row["event_id"] = int(row["event_id"])
                row["_time"] = parse_time(row["timestamp"])
                events.append(row)
            except (TypeError, ValueError):
                continue
        events.sort(key=lambda item: item["_time"])
    else:
        events = load_events(args.input)
    results = analyze(events, threshold=args.threshold, window_minutes=args.window)
    write_reports(results, args.out)
    print(f"Processed {len(events)} events; wrote {len(results)} findings to {args.out}")

if __name__ == "__main__":
    main()

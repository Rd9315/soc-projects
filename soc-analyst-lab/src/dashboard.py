
"""SOC Analyst Lab dashboard and local case workflow.

Run from the project root:
    python -m streamlit run src/dashboard.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import streamlit as st

# Resolve paths relative to this file, not the current terminal directory.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
REPORT_PATH = ROOT / "reports" / "findings.json"
DB_PATH = ROOT / "data" / "cases.sqlite3"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from case_store import (
        VALID_STATUSES,
        finding_key,
        list_cases,
        update_case,
        upsert_finding,
    )
except ImportError as exc:
    st.error(
        "Could not import case_store. Ensure that "
        "'src/case_store.py' exists and contains the case-store functions."
    )
    st.code(str(exc))
    st.stop()


SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["open", "investigating", "escalated", "closed"]


def load_findings(path: Path) -> list[dict[str, Any]]:
    """Read and validate the findings JSON report."""
    try:
        content = path.read_text(encoding="utf-8")
        loaded = json.loads(content)
    except FileNotFoundError as exc:
        raise ValueError(f"Report not found: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read valid JSON: {exc}") from exc

    if not isinstance(loaded, list):
        raise ValueError("findings.json must contain a JSON list.")

    findings: list[dict[str, Any]] = []
    skipped = 0

    for item in loaded:
        if not isinstance(item, dict):
            skipped += 1
            continue

        # These fields are required by case_store.upsert_finding().
        if not item.get("rule_id") or not item.get("title") or not item.get("timestamp"):
            skipped += 1
            continue

        finding = dict(item)
        severity = str(finding.get("severity", "low")).lower()
        finding["severity"] = (
            severity if severity in SEVERITIES else "low"
        )

        finding.setdefault("host", "")
        finding.setdefault("account", "")
        finding.setdefault("rationale", "No rationale provided.")

        if not isinstance(finding.get("event_ids"), list):
            value = finding.get("event_ids")
            finding["event_ids"] = [] if value is None else [value]

        if not isinstance(finding.get("mitre_attack"), list):
            value = finding.get("mitre_attack")
            finding["mitre_attack"] = [] if value is None else [value]

        findings.append(finding)

    if skipped:
        st.warning(f"Skipped {skipped} invalid finding record(s).")

    return findings


st.set_page_config(
    page_title="SOC Analyst Lab",
    page_icon="🛡️",
    layout="wide",
)

st.title("SOC Analyst Lab")
st.caption("Local training dashboard · Use synthetic or sanitized data only")

# Check report availability before attempting to read it.
if not REPORT_PATH.is_file():
    st.warning("No findings report found. Generate one first.")
    st.code(
        "python src/soc_triage.py "
        "--input data/sample_events.csv --out reports"
    )
    st.stop()

try:
    findings = load_findings(REPORT_PATH)
except ValueError as exc:
    st.error(str(exc))
    st.stop()

if not findings:
    st.success("No valid findings were found in this report.")
    st.download_button(
        "Download empty findings JSON",
        data="[]",
        file_name="filtered-findings.json",
        mime="application/json",
    )
    st.stop()

# Create/update cases in SQLite, preserving existing case status and notes.
try:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    for finding in findings:
        upsert_finding(finding, DB_PATH)

    cases = list_cases(DB_PATH)

except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
    st.error(f"Could not load or update the case database: {exc}")
    st.stop()

case_by_key = {
    case["finding_key"]: case
    for case in cases
    if case.get("finding_key")
}

# Summary metrics.
st.subheader("Finding Overview")
columns = st.columns(len(SEVERITIES))

for column, severity in zip(columns, SEVERITIES):
    count = sum(
        finding["severity"] == severity
        for finding in findings
    )
    column.metric(severity.title(), count)

# Filters.
st.subheader("Filter Findings")
left, middle, right = st.columns(3)

with left:
    selected_severities = st.multiselect(
        "Severity",
        options=SEVERITIES,
        default=SEVERITIES,
        key="severity_filter",
    )

with middle:
    hosts = sorted({
        str(finding.get("host") or "Unknown host")
        for finding in findings
    })
    selected_hosts = st.multiselect(
        "Host",
        options=hosts,
        default=hosts,
        key="host_filter",
    )

with right:
    selected_statuses = st.multiselect(
        "Case status",
        options=STATUSES,
        default=["open", "investigating", "escalated"],
        key="status_filter",
    )

# Apply filters using the same canonical key as case_store.py.
filtered: list[tuple[dict[str, Any], str, dict[str, Any]]] = []

for finding in findings:
    key = finding_key(finding)
    case = case_by_key.get(key, {})

    status = case.get("status", "open")
    if status not in VALID_STATUSES:
        status = "open"

    host = str(finding.get("host") or "Unknown host")

    if (
        finding["severity"] in selected_severities
        and host in selected_hosts
        and status in selected_statuses
    ):
        filtered.append(
            (finding, key, {**case, "status": status})
        )

st.write(
    f"Showing **{len(filtered)}** matching case(s) "
    f"out of **{len(findings)}** finding(s)."
)

if not filtered:
    st.info(
        "No findings match the selected filters. "
        "Try selecting more severities, hosts, or statuses."
    )

# Finding details and case workflow.
for index, (finding, key, case) in enumerate(filtered):
    host = str(finding.get("host") or "Unknown host")
    title = (
        f'[{finding["severity"].upper()}] '
        f'{finding["title"]} — {host}'
    )

    with st.expander(title):
        st.write(f'**Rule:** `{finding["rule_id"]}`')
        st.write(f'**Account:** {finding.get("account") or "—"}')
        st.write(f'**Timestamp:** {finding.get("timestamp") or "—"}')

        event_ids = finding.get("event_ids", [])
        st.write(
            "**Event IDs:** "
            + (", ".join(map(str, event_ids)) if event_ids else "—")
        )

        techniques = finding.get("mitre_attack", [])
        st.write(
            "**MITRE ATT&CK:** "
            + (
                ", ".join(map(str, techniques))
                if techniques
                else "Not mapped"
            )
        )
        st.write(
            f'**Rationale:** '
            f'{finding.get("rationale") or "No rationale provided."}'
        )

        # Index makes Streamlit widget keys unique even for duplicate findings.
        with st.form(f"case_form_{index}"):
            status = st.selectbox(
                "Status",
                options=STATUSES,
                index=STATUSES.index(case["status"]),
                key=f"case_status_{index}",
            )
            analyst = st.text_input(
                "Analyst",
                value=str(case.get("analyst") or ""),
                key=f"case_analyst_{index}",
            )
            notes = st.text_area(
                "Investigation notes",
                value=str(case.get("notes") or ""),
                key=f"case_notes_{index}",
            )

            submitted = st.form_submit_button("Save case")

        if submitted:
            try:
                update_case(
                    key,
                    status,
                    analyst.strip(),
                    notes,
                    DB_PATH,
                )
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                st.error(f"Could not save case: {exc}")
            else:
                st.success("Case saved successfully.")
                st.rerun()

# Export only the findings currently visible after filtering.
export_data = json.dumps(
    [finding for finding, _, _ in filtered],
    indent=2,
    ensure_ascii=False,
)

st.download_button(
    "Download filtered findings (JSON)",
    data=export_data,
    file_name="filtered-findings.json",
    mime="application/json",
)

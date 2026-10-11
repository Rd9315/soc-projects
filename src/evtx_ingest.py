"""Optional EVTX ingestion adapter; preserves raw event XML in normalized records."""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None

def _field(xml: str, name: str) -> str:
    match = re.search(rf'<Data\b[^>]*\bName="{re.escape(name)}"[^>]*>(.*?)</Data>', xml, re.S)
    return html.unescape(match.group(1).strip()) if match else ""

def parse_evtx(path: Path) -> list[dict[str, Any]]:
    if Evtx is None:
        raise RuntimeError("EVTX support requires python-evtx. Install it with: pip install -r requirements-evtx.txt")
    rows: list[dict[str, Any]] = []
    with Evtx(str(path)) as log:
        for record in log.records():
            xml = record.xml()
            event_match = re.search(r'<EventID(?:\s+[^>]*)?>(\d+)</EventID>', xml)
            channel_match = re.search(r'<Channel>(.*?)</Channel>', xml)
            provider_match = re.search(r'<Provider[^>]*Name="([^"]+)"', xml)
            computer_match = re.search(r'<Computer>(.*?)</Computer>', xml)
            time_match = re.search(r'<TimeCreated[^>]*SystemTime="([^"]+)"', xml)
            if not event_match:
                continue
            try:
                timestamp = datetime.fromisoformat((time_match.group(1) if time_match else "").replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
            except ValueError:
                timestamp = datetime.fromtimestamp(0, tz=timezone.utc)
            account = (_field(xml, "TargetUserName") or _field(xml, "SubjectUserName")
                       or _field(xml, "AccountName"))
            ip = _field(xml, "IpAddress") or _field(xml, "ClientAddress") or _field(xml, "SourceAddress")
            rows.append({
                "timestamp": timestamp.isoformat(),
                "host": html.unescape(computer_match.group(1)) if computer_match else "",
                "channel": html.unescape(channel_match.group(1)) if channel_match else "",
                "event_id": int(event_match.group(1)),
                "provider": html.unescape(provider_match.group(1)) if provider_match else "",
                "account": account,
                "src_ip": ip,
                "message": "Parsed from EVTX; inspect raw_xml for full event details.",
                "raw_xml": xml,
            })
    return rows

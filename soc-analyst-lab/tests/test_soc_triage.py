import sys
import unittest
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from soc_triage import analyze, load_events

class TriageTests(unittest.TestCase):
    def test_sample_data_generates_expected_rules(self):
        events = load_events(ROOT / "data" / "sample_events.csv")
        findings = analyze(events)
        rule_ids = {item["rule_id"] for item in findings}
        self.assertIn("failed_logon_burst", rule_ids)
        self.assertIn("success_after_failures", rule_ids)
        self.assertIn("account_created", rule_ids)
        self.assertIn("audit_log_cleared", rule_ids)


    def test_password_spray_heuristic(self):
        events = []
        for i, account in enumerate(["alice", "bob", "carol", "dave", "erin"]):
            events.append({
                "timestamp": f"2026-09-18T09:0{i}:00Z",
                "host": "DC-01", "channel": "Security", "event_id": 4625,
                "provider": "Microsoft-Windows-Security-Auditing",
                "account": account, "src_ip": "203.0.113.77",
                "message": "failed logon",
                "_time": __import__("datetime").datetime.fromisoformat(f"2026-09-18T09:0{i}:00+00:00")
            })
        findings = analyze(events)
        self.assertIn("password_spray_heuristic", {f["rule_id"] for f in findings})


    def test_account_lockout_detection(self):
        from datetime import datetime, timezone
        event = {
            "timestamp": "2026-09-18T10:00:00Z", "host": "WS-1",
            "channel": "Security", "event_id": 4740, "provider": "Security",
            "account": "testuser", "src_ip": "", "message": "locked out",
            "_time": datetime(2026, 9, 18, 10, 0, tzinfo=timezone.utc)
        }
        findings = analyze([event])
        self.assertIn("account_lockout", {f["rule_id"] for f in findings})


    def test_invalid_threshold_is_rejected_by_cli(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "src" / "soc_triage.py"),
             "--input", str(ROOT / "data" / "sample_events.csv"),
             "--threshold", "1"],
            capture_output=True, text=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--threshold must be >= 2", result.stderr)

    def test_findings_have_review_status(self):
        events = load_events(ROOT / "data" / "sample_events.csv")
        for item in analyze(events):
            self.assertEqual(item["status"], "needs_review")
            self.assertIn("event_ids", item)

if __name__ == "__main__":
    unittest.main()

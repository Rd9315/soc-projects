import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from case_store import finding_key, list_cases, update_case, upsert_finding

class CaseStoreTests(unittest.TestCase):
    def test_case_is_created_and_updated(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cases.sqlite3"
            finding = {
                "rule_id": "audit_log_cleared", "title": "Audit log cleared",
                "host": "DC-01", "account": "admin", "severity": "high",
                "timestamp": "2026-09-18T10:00:00Z"
            }
            upsert_finding(finding, db)
            cases = list_cases(db)
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["status"], "open")
            update_case(cases[0]["finding_key"], "investigating", "analyst1", "Checking change ticket", db)
            updated = list_cases(db)[0]
            self.assertEqual(updated["status"], "investigating")
            self.assertEqual(updated["analyst"], "analyst1")
            self.assertEqual(updated["notes"], "Checking change ticket")


    def test_dashboard_and_store_share_canonical_key(self):
        finding = {
            "rule_id": "test_rule", "title": "Test", "host": "HOST-1",
            "account": "alice", "timestamp": "2026-09-18T10:00:00Z",
        }
        expected = "test_rule|HOST-1|alice|2026-09-18T10:00:00Z"
        self.assertEqual(finding_key(finding), expected)

    def test_finding_missing_required_fields_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cases.sqlite3"
            with self.assertRaises(ValueError):
                upsert_finding({"rule_id": "bad"}, db)

    def test_invalid_status_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cases.sqlite3"
            with self.assertRaises(ValueError):
                update_case("missing", "not-a-status", "", "", db)

if __name__ == "__main__":
    unittest.main()

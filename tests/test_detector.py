"""Run with: python -m unittest discover -s tests -v"""

import unittest
from datetime import datetime, timedelta, timezone

from detector import (
    analyze,
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
    load_events,
    risk_score,
    LoginEvent,
)

BASE = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)


def event(minutes: int, ip: str = "203.0.113.5", user: str = "alex", status: str = "failed") -> LoginEvent:
    return LoginEvent(BASE + timedelta(minutes=minutes), ip, user, status)


class DetectionTests(unittest.TestCase):
    def test_brute_force_detects_burst(self):
        findings = detect_brute_force([event(i) for i in range(7)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 7)
        self.assertEqual(findings[0].username, "alex")

    def test_spread_out_failures_do_not_trigger_brute_force(self):
        self.assertEqual(detect_brute_force([event(i * 11) for i in range(9)]), [])

    def test_password_spraying_across_accounts(self):
        events = [event(i // 2, user=f"user{i % 7}") for i in range(14)]
        findings = detect_password_spraying(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].mitre_technique, "T1110.003")

    def test_one_account_is_not_password_spraying(self):
        self.assertEqual(detect_password_spraying([event(1) for _ in range(20)]), [])

    def test_success_after_failures(self):
        events = [event(i) for i in range(4)] + [event(5, status="success")]
        findings = detect_success_after_failures(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "Critical")

    def test_success_without_prior_failures_is_not_flagged(self):
        self.assertEqual(detect_success_after_failures([event(1, status="success")]), [])

    def test_irrelevant_ip_does_not_trigger_success(self):
        events = [event(i) for i in range(5)] + [event(6, ip="192.0.2.1", status="success")]
        self.assertEqual(detect_success_after_failures(events), [])

    def test_csv_parsing_ignores_invalid_rows(self):
        csv_text = (
            "timestamp,ip_address,username,status\n"
            "2026-10-01T08:00:00Z,203.0.113.5,alex,failed\n"
            "2026-10-01T08:01:00Z,invalid-ip,alex,success\n"
        )
        events, errors = load_events(csv_text)
        self.assertEqual(len(events), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("Row 3", errors[0])

    def test_missing_csv_header_column_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing required"):
            load_events("timestamp,ip_address,status\n2026-10-01T08:00:00Z,203.0.113.5,failed")

    def test_score_empty(self):
        self.assertEqual(risk_score(analyze([])), 0)


if __name__ == "__main__":
    unittest.main()

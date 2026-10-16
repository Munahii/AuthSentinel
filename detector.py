"""Rule-based authentication threat detection (standard library only).

AuthSentinel is a portfolio / training tool, not a production SIEM.
All detections are heuristic and must be reviewed by a human analyst.
"""

from __future__ import annotations

import csv
import io
import ipaddress
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

REQUIRED_COLUMNS = {"timestamp", "ip_address", "username", "status"}
VALID_STATUSES = {"success", "failed"}
MITRE_URLS = {
    "Brute Force": "https://attack.mitre.org/techniques/T1110/",
    "Password Spraying": "https://attack.mitre.org/techniques/T1110/003/",
    "Success After Failures": "https://attack.mitre.org/techniques/T1110/",
}
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass(frozen=True)
class LoginEvent:
    timestamp: datetime
    ip_address: str
    username: str
    status: str


@dataclass(frozen=True)
class Finding:
    detection: str
    severity: str
    ip_address: str
    username: str
    count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    recommendation: str
    mitre_technique: str
    mitre_url: str

    def to_dict(self) -> dict:
        result = asdict(self)
        result["first_seen"] = self.first_seen.isoformat()
        result["last_seen"] = self.last_seen.isoformat()
        return result


def parse_timestamp(value: str) -> datetime:
    """Parse ISO-8601 timestamps; naive input is treated as UTC."""
    value = (value or "").strip()
    if not value:
        raise ValueError("Missing timestamp")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid timestamp: use ISO-8601") from exc
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def load_events(csv_content: str | bytes) -> tuple[list[LoginEvent], list[str]]:
    """Read a CSV and return valid rows plus human-readable row errors."""
    if isinstance(csv_content, bytes):
        csv_content = csv_content.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(csv_content))
    if not reader.fieldnames:
        raise ValueError("The CSV is empty or has no header.")
    reader.fieldnames = [name.strip().lstrip("\ufeff") for name in reader.fieldnames]
    missing = REQUIRED_COLUMNS - set(reader.fieldnames)
    if missing:
        raise ValueError("Missing required CSV columns: " + ", ".join(sorted(missing)))

    valid: list[LoginEvent] = []
    errors: list[str] = []
    for line_number, row in enumerate(reader, start=2):
        try:
            timestamp = parse_timestamp(row.get("timestamp", ""))
            ip = (row.get("ip_address") or "").strip()
            ipaddress.ip_address(ip)
            username = (row.get("username") or "").strip()
            status = (row.get("status") or "").strip().lower()
            if not username:
                raise ValueError("username is empty")
            if status not in VALID_STATUSES:
                raise ValueError("status must be success or failed")
            valid.append(LoginEvent(timestamp, ip, username, status))
        except (ValueError, TypeError) as exc:
            errors.append(f"Row {line_number}: {exc}")
    return sorted(valid, key=lambda event: event.timestamp), errors


def _best_window(events: list[LoginEvent], minutes: int) -> list[LoginEvent]:
    """Pick the busiest fixed-duration sliding window."""
    if not events:
        return []
    events = sorted(events, key=lambda event: event.timestamp)
    left = 0
    best: list[LoginEvent] = []
    window = timedelta(minutes=minutes)
    for right, event in enumerate(events):
        while event.timestamp - events[left].timestamp > window:
            left += 1
        current = events[left : right + 1]
        if len(current) > len(best):
            best = current
    return best


def detect_brute_force(events: Iterable[LoginEvent], threshold: int = 6, minutes: int = 10) -> list[Finding]:
    by_target: dict[tuple[str, str], list[LoginEvent]] = defaultdict(list)
    for event in events:
        if event.status == "failed":
            by_target[(event.ip_address, event.username)].append(event)

    findings = []
    for (ip, user), attempts in by_target.items():
        burst = _best_window(attempts, minutes)
        if len(burst) < threshold:
            continue
        severity = "High" if len(burst) >= 10 else "Medium"
        findings.append(Finding(
            detection="Brute Force", severity=severity, ip_address=ip,
            username=user, count=len(burst), first_seen=burst[0].timestamp,
            last_seen=burst[-1].timestamp,
            description=f"{len(burst)} failed logins against one account within {minutes} minutes.",
            recommendation="Review source IP and affected account; consider rate limits, MFA and temporary lockout.",
            mitre_technique="T1110", mitre_url=MITRE_URLS["Brute Force"],
        ))
    return findings


def detect_password_spraying(
    events: Iterable[LoginEvent], min_users: int = 5, min_failures: int = 8, minutes: int = 10
) -> list[Finding]:
    by_ip: dict[str, list[LoginEvent]] = defaultdict(list)
    for event in events:
        if event.status == "failed":
            by_ip[event.ip_address].append(event)

    findings = []
    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda event: event.timestamp)
        window = timedelta(minutes=minutes)
        left = 0
        best: list[LoginEvent] = []
        for right, event in enumerate(attempts):
            while event.timestamp - attempts[left].timestamp > window:
                left += 1
            subset = attempts[left : right + 1]
            if len(subset) >= min_failures and len({e.username for e in subset}) >= min_users:
                if len(subset) > len(best) or (
                    len(subset) == len(best) and len({e.username for e in subset}) > len({e.username for e in best})
                ):
                    best = subset
        if not best:
            continue
        distinct = len({e.username for e in best})
        findings.append(Finding(
            detection="Password Spraying", severity="High", ip_address=ip,
            username=f"{distinct} accounts", count=len(best),
            first_seen=best[0].timestamp, last_seen=best[-1].timestamp,
            description=f"{len(best)} failed logins across {distinct} accounts within {minutes} minutes.",
            recommendation="Investigate source IP, validate affected accounts, and enforce MFA and failed-login controls.",
            mitre_technique="T1110.003", mitre_url=MITRE_URLS["Password Spraying"],
        ))
    return findings


def detect_success_after_failures(
    events: Iterable[LoginEvent], threshold: int = 4, minutes: int = 15
) -> list[Finding]:
    by_target: dict[tuple[str, str], list[LoginEvent]] = defaultdict(list)
    for event in events:
        by_target[(event.ip_address, event.username)].append(event)

    findings = []
    for (ip, user), attempts in by_target.items():
        attempts.sort(key=lambda event: event.timestamp)
        best: tuple[LoginEvent, list[LoginEvent]] | None = None
        for index, event in enumerate(attempts):
            if event.status != "success":
                continue
            start = event.timestamp - timedelta(minutes=minutes)
            failures = [a for a in attempts[:index] if a.status == "failed" and a.timestamp >= start]
            if len(failures) >= threshold and (best is None or len(failures) > len(best[1])):
                best = (event, failures)
        if best is None:
            continue
        success, failures = best
        findings.append(Finding(
            detection="Success After Failures", severity="Critical", ip_address=ip,
            username=user, count=len(failures),
            first_seen=failures[0].timestamp, last_seen=success.timestamp,
            description=f"Successful login after {len(failures)} failed attempts within {minutes} minutes.",
            recommendation="Prioritize triage: verify the sign-in with the user, review session activity, and reset credentials if compromised.",
            mitre_technique="T1110", mitre_url=MITRE_URLS["Success After Failures"],
        ))
    return findings


def analyze(events: Iterable[LoginEvent]) -> list[Finding]:
    events = sorted(events, key=lambda event: event.timestamp)
    findings = (
        detect_brute_force(events)
        + detect_password_spraying(events)
        + detect_success_after_failures(events)
    )
    return sorted(findings, key=lambda item: (SEVERITY_RANK[item.severity], -item.count, item.ip_address))


def risk_score(findings: Iterable[Finding]) -> int:
    """Informal dashboard summary, not a validated security risk model."""
    weights = {"Critical": 45, "High": 25, "Medium": 10, "Low": 5}
    return min(100, sum(weights[item.severity] for item in findings))

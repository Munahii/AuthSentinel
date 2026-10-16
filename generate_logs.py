"""Generate a SAFE synthetic CSV dataset (no real user data or scanning)."""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path(__file__).parent / "data" / "sample_auth_logs.csv"


def generate(destination: Path = OUTPUT, seed: int = 29) -> Path:
    rng = random.Random(seed)
    start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(hours=20)
    users = ["alex", "sara", "noura", "faisal", "reem", "omar", "lana", "salem", "mona", "khalid"]
    # TEST-NET address blocks reserved for documentation (RFC 5737).
    normal_ips = ["192.0.2.10", "192.0.2.11", "192.0.2.12", "198.51.100.7", "198.51.100.9"]
    rows = []

    for _ in range(260):
        rows.append({
            "timestamp": start + timedelta(minutes=rng.randrange(0, 18 * 60)),
            "ip_address": rng.choice(normal_ips),
            "username": rng.choice(users),
            "status": "success" if rng.random() < 0.88 else "failed",
        })

    # Scenario 1: repeated failures on one account (Brute Force).
    for i in range(12):
        rows.append({
            "timestamp": start + timedelta(hours=18, minutes=i // 2),
            "ip_address": "203.0.113.25", "username": "alex", "status": "failed",
        })

    # Scenario 2: one IP targets many accounts (Password Spraying).
    for i in range(10):
        rows.append({
            "timestamp": start + timedelta(hours=18, minutes=20 + i // 2),
            "ip_address": "203.0.113.42", "username": users[i], "status": "failed",
        })

    # Scenario 3: a success directly after multiple failures.
    for i in range(5):
        rows.append({
            "timestamp": start + timedelta(hours=18, minutes=40 + i),
            "ip_address": "203.0.113.66", "username": "faisal", "status": "failed",
        })
    rows.append({
        "timestamp": start + timedelta(hours=18, minutes=46),
        "ip_address": "203.0.113.66", "username": "faisal", "status": "success",
    })

    rows.sort(key=lambda row: row["timestamp"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["timestamp", "ip_address", "username", "status"])
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "timestamp": row["timestamp"].isoformat()})
    return destination


if __name__ == "__main__":
    print(f"Synthetic sample created: {generate()}")

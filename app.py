"""AuthSentinel local web dashboard. Runs on Python 3.10+ with no pip installs.

Start: python app.py
Only binds to localhost. Uploaded CSV bytes remain in memory and are not saved.
"""
from __future__ import annotations

import json
import os
import threading
import webbrowser
from collections import Counter, defaultdict
from datetime import timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from detector import analyze, load_events, risk_score
from generate_logs import generate

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "data" / "sample_auth_logs.csv"
STATIC = ROOT / "static"
MAX_BYTES = 5 * 1024 * 1024
MAX_EVENTS = 50000
HOST = "127.0.0.1"
PORT = int(os.environ.get("AUTHSENTINEL_PORT", "8502"))


def summarize(raw: bytes) -> dict:
    events, invalid = load_events(raw)
    if len(events) > MAX_EVENTS:
        raise ValueError("CSV has too many valid rows (maximum 50,000).")
    findings = analyze(events)
    by_hour = defaultdict(lambda: {"success": 0, "failed": 0})
    by_ip = defaultdict(lambda: {"events": 0, "failed": 0})
    by_user = Counter()
    for event in events:
        key = event.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:00")
        by_hour[key][event.status] += 1
        by_ip[event.ip_address]["events"] += 1
        if event.status == "failed":
            by_ip[event.ip_address]["failed"] += 1
            by_user[event.username] += 1
    return {
        "summary": {
            "total": len(events),
            "failed": sum(event.status == "failed" for event in events),
            "success": sum(event.status == "success" for event in events),
            "ips": len(by_ip),
            "findings": len(findings),
            "risk": risk_score(findings),
        },
        "timeline": [{"hour": hour, **item} for hour, item in sorted(by_hour.items())],
        "top_ips": [{"ip": ip, **metrics} for ip, metrics in sorted(by_ip.items(), key=lambda pair: (-pair[1]["failed"], -pair[1]["events"], pair[0]))[:10]],
        "findings": [finding.to_dict() for finding in findings],
        "events": [{"timestamp": event.timestamp.isoformat(), "ip_address": event.ip_address,
                    "username": event.username, "status": event.status} for event in reversed(events)],
        "invalid_rows": invalid[:30],
        "invalid_count": len(invalid),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AuthSentinel/1.0"

    def log_message(self, fmt, *args):
        # Do not log uploaded CSV rows or request bodies.
        super().log_message(fmt, *args)

    def _response(self, code, body, mime="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._response(status, data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            file, mime = STATIC / "index.html", "text/html; charset=utf-8"
        elif path == "/static/dashboard.css":
            file, mime = STATIC / "dashboard.css", "text/css; charset=utf-8"
        elif path == "/static/dashboard.js":
            file, mime = STATIC / "dashboard.js", "text/javascript; charset=utf-8"
        elif path == "/api/sample":
            if not SAMPLE.exists():
                generate(SAMPLE)
            try:
                self._json(summarize(SAMPLE.read_bytes()))
            except (ValueError, UnicodeError) as exc:
                self._json({"error": str(exc)}, 422)
            return
        elif path == "/api/sample/csv":
            if not SAMPLE.exists():
                generate(SAMPLE)
            return self._response(200, SAMPLE.read_bytes(), "text/csv; charset=utf-8")
        else:
            return self._json({"error": "Not found"}, 404)
        return self._response(200, file.read_bytes(), mime)

    def do_POST(self):
        if urlsplit(self.path).path != "/api/analyze":
            return self._json({"error": "Not found"}, 404)
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._json({"error": "Invalid Content-Length"}, 400)
        if size < 1 or size > MAX_BYTES:
            return self._json({"error": "CSV must be between 1 byte and 5 MB."}, 413)
        if self.headers.get("Content-Type", "").split(";")[0].lower() not in ("text/csv", "application/octet-stream", "application/vnd.ms-excel"):
            return self._json({"error": "Please upload a CSV file."}, 415)
        raw = self.rfile.read(size)
        try:
            self._json(summarize(raw))
        except (UnicodeError, ValueError) as exc:
            self._json({"error": str(exc)}, 422)


def main():
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        raise SystemExit(f"Cannot start dashboard on {HOST}:{PORT}: {exc}") from exc
    url = f"http://{HOST}:{PORT}"
    print("\n" + "=" * 52)
    print("AuthSentinel — Security Threat Analytics")
    print(f"OPEN IN YOUR BROWSER: {url}")
    print("Stop server: Ctrl + C")
    print("=" * 52 + "\n")
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

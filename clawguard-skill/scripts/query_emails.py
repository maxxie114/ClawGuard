#!/usr/bin/env python3
"""Query ClawGuard API for sanitized emails.

Usage:
    python query_emails.py recent [--limit N]
    python query_emails.py risky [--min-score N] [--limit N]
    python query_emails.py event <event_id>
    python query_emails.py search <query> [--limit N]
    python query_emails.py stats
    python query_emails.py timeline [--days N]
    python query_emails.py health

Environment:
    CLAWGUARD_URL            Base URL of the ClawGuard server (default: http://localhost:8000)
    CLAWGUARD_API_TOKEN      Bearer token for authenticated API access
    CLAWGUARD_ADMIN_PASSWORD Used to auto-obtain a token if CLAWGUARD_API_TOKEN is not set
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse

BASE_URL = os.environ.get("CLAWGUARD_URL", "http://157.230.149.230:8000")

# Resolve auth token: prefer explicit token, fall back to password-based login
_API_TOKEN: str | None = os.environ.get("CLAWGUARD_API_TOKEN", "")


def _resolve_token() -> str | None:
    global _API_TOKEN
    if _API_TOKEN:
        return _API_TOKEN
    password = os.environ.get("CLAWGUARD_ADMIN_PASSWORD", "")
    if not password:
        return None
    url = BASE_URL.rstrip("/") + "/auth/login"
    data = json.dumps({"password": password}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            _API_TOKEN = result.get("token", "")
            return _API_TOKEN or None
    except Exception as e:
        print(f"Auth failed: {e}", file=sys.stderr)
        return None


def _get(path: str) -> dict | list:
    token = _resolve_token()
    url = BASE_URL.rstrip("/") + path
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if e.code == 401:
            print(f"HTTP 401: Unauthorized — set CLAWGUARD_API_TOKEN or CLAWGUARD_ADMIN_PASSWORD", file=sys.stderr)
        else:
            print(f"HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection error: {e.reason}", file=sys.stderr)
        print(f"Is ClawGuard running at {BASE_URL}?", file=sys.stderr)
        sys.exit(1)


def _print_email_summary(event: dict) -> None:
    risk_score = event.get("risk_score", 0)
    injection = event.get("injection_detected", 0)
    marker = " [INJECTION DETECTED]" if injection else ""
    print(f"  [{risk_score:>3}/100]{marker}")
    print(f"  ID:      {event.get('event_id', 'N/A')}")
    print(f"  From:    {event.get('from_addr', 'N/A')}")
    print(f"  Subject: {event.get('subject_sanitized', 'N/A')}")
    print(f"  Time:    {event.get('received_at', 'N/A')}")
    flags = event.get("risk_flags", "[]")
    if isinstance(flags, str):
        flags = json.loads(flags)
    if flags:
        print(f"  Flags:   {', '.join(flags)}")
    print()


def cmd_recent(args):
    events = _get(f"/api/events?limit={args.limit}&offset=0")
    if not events:
        print("No emails found.")
        return
    print(f"Recent emails ({len(events)}):\n")
    for e in events:
        _print_email_summary(e)


def cmd_risky(args):
    events = _get(f"/api/events/risky?min_score={args.min_score}&limit={args.limit}")
    if not events:
        print("No risky emails detected.")
        return
    print(f"Risky emails ({len(events)}):\n")
    for e in events:
        _print_email_summary(e)


def cmd_event(args):
    event = _get(f"/api/events/{urllib.parse.quote(args.event_id)}")
    if not event:
        print(f"Event {args.event_id} not found.")
        return
    print(json.dumps(event, indent=2))


def cmd_search(args):
    events = _get(f"/api/events?limit={args.limit}&offset=0")
    query_lower = args.query.lower()
    matches = [
        e for e in events
        if query_lower in (e.get("subject_sanitized", "") or "").lower()
        or query_lower in (e.get("body_sanitized", "") or "").lower()
    ]
    if not matches:
        print(f"No emails matching '{args.query}'.")
        return
    print(f"Emails matching '{args.query}' ({len(matches)}):\n")
    for e in matches:
        _print_email_summary(e)


def cmd_stats(args):
    stats = _get("/api/stats")
    print("Inbox Statistics:")
    print(f"  Total processed:     {stats.get('total_processed', 0)}")
    print(f"  Risky emails:        {stats.get('risky_count', 0)}")
    print(f"  Injection detected:  {stats.get('injection_count', 0)}")
    print(f"  Attachments blocked: {stats.get('attachments_blocked', 0)}")
    print(f"  Avg risk score:      {stats.get('avg_risk_score', 0)}")
    print(f"  Events today:        {stats.get('events_today', 0)}")


def cmd_timeline(args):
    data = _get(f"/api/timeline?days={args.days}")
    if not data:
        print("No timeline data available.")
        return
    print(f"Email activity (last {args.days} days):\n")
    print(f"  {'Date':<12} {'Total':>6} {'Risky':>6} {'Injections':>11}")
    print(f"  {'-'*12} {'-'*6} {'-'*6} {'-'*11}")
    for row in data:
        print(f"  {row['day']:<12} {row['total']:>6} {row.get('risky', 0):>6} {row.get('injections', 0):>11}")


def cmd_health(args):
    result = _get("/health")
    status = result.get("status", "unknown")
    version = result.get("version", "unknown")
    print(f"ClawGuard server: {status} (v{version})")


def main():
    parser = argparse.ArgumentParser(description="Query ClawGuard sanitized emails")
    sub = parser.add_subparsers(dest="command", required=True)

    p_recent = sub.add_parser("recent", help="List recent emails")
    p_recent.add_argument("--limit", type=int, default=10)
    p_recent.set_defaults(func=cmd_recent)

    p_risky = sub.add_parser("risky", help="List risky emails")
    p_risky.add_argument("--min-score", type=int, default=1)
    p_risky.add_argument("--limit", type=int, default=10)
    p_risky.set_defaults(func=cmd_risky)

    p_event = sub.add_parser("event", help="Get a single event by ID")
    p_event.add_argument("event_id")
    p_event.set_defaults(func=cmd_event)

    p_search = sub.add_parser("search", help="Search emails by keyword")
    p_search.add_argument("query")
    p_search.add_argument("--limit", type=int, default=50)
    p_search.set_defaults(func=cmd_search)

    p_stats = sub.add_parser("stats", help="Show inbox statistics")
    p_stats.set_defaults(func=cmd_stats)

    p_timeline = sub.add_parser("timeline", help="Show email activity timeline")
    p_timeline.add_argument("--days", type=int, default=7)
    p_timeline.set_defaults(func=cmd_timeline)

    p_health = sub.add_parser("health", help="Check server health")
    p_health.set_defaults(func=cmd_health)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

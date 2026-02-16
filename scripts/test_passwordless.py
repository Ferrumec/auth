#!/usr/bin/env python3
"""Minimal manual test runner for passwordless.rs endpoints.

Usage:
  python scripts/test_passwordless.py --base-url http://localhost:8080 --email test@example.com
Optional:
  --user-id <id> to skip register and go straight to challenge
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def http_request(method: str, url: str, data: dict | None = None) -> tuple[int, str]:
    headers = {
        "Content-Type": "application/json",
    }
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")

    print("using url", url)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"Request failed: {e}", file=sys.stderr)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Test passwordless.rs endpoints")
    parser.add_argument(
        "--base-url", required=True, help="Base URL, e.g. http://localhost:8080"
    )
    parser.add_argument("--email", required=True, help="Email to register/login")
    parser.add_argument(
        "--user-id", help="Existing user_id to challenge (skip register)"
    )
    parser.add_argument(
        "--confirm-token", help="Token from email (skip waiting for prompt)"
    )
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    print("== Step 1: register ==")
    user_id = args.user_id
    if user_id is None:
        status, body = http_request(
            "POST", f"{base}/register/start", {"email": args.email}
        )
        print(f"POST /register -> {status}, body: {body!r}")
        # passwordless.rs currently returns empty body; if it returns a user_id, capture it.
        if body:
            user_id = body.strip().strip('"')

    if not user_id:
        print(
            "No user_id available. If your API returns it, pass --user-id or update endpoint."
        )
        print("Skipping challenge/confirm tests.")
        return 0

    print("== Step 2: confirm registration ==")
    token = args.confirm_token
    if not token:
        token = input("Paste the token printed by the server email log: ").strip()
    if not token:
        print("No token provided; skipping confirm.")
        return 0

    status, body = http_request("GET", f"{base}/register/confirm_link/{token}")
    print(f"GET /confirm_link/<token> -> {status}, body: {body!r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

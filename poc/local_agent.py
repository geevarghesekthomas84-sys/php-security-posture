#!/usr/bin/env python3
"""Local authenticated evidence agent; binds to 127.0.0.1 only by default."""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

from php2shell_guard import parse_php_info


def collect() -> dict:
    try:
        output = subprocess.check_output(["php", "-i"], text=True, stderr=subprocess.STDOUT, timeout=15)
        fields = parse_php_info(output)
        return {
            "php_version": fields.get("PHP Version", "unknown"),
            "sapi": fields.get("Server API", "unknown"),
            "upload_progress": fields.get("session.upload_progress.enabled", "unknown"),
            "memory_limit": fields.get("memory_limit", "unknown"),
            "post_max_size": fields.get("post_max_size", "unknown"),
            "upload_max_filesize": fields.get("upload_max_filesize", "unknown"),
            "source": "local php -i",
        }
    except Exception as exc:
        return {"status": "unknown", "error": str(exc), "source": "local php -i"}


class Handler(BaseHTTPRequestHandler):
    token = ""

    def do_GET(self):  # noqa: N802
        if self.path != "/v1/posture" or self.headers.get("Authorization") != f"Bearer {self.token}":
            self.send_response(401)
            self.end_headers()
            return
        payload = json.dumps(collect()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="print local evidence and exit")
    parser.add_argument("--listen", type=int, default=8765)
    parser.add_argument("--token", help="bearer token; generated and printed if omitted")
    args = parser.parse_args()
    if args.once:
        print(json.dumps(collect(), indent=2))
        return 0
    token = args.token or secrets.token_urlsafe(24)
    Handler.token = token
    print(f"Local posture agent listening on http://127.0.0.1:{args.listen}/v1/posture")
    print("Authorization: Bearer " + token)
    print("Press Ctrl+C to stop.")
    HTTPServer(("127.0.0.1", args.listen), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

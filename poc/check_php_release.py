#!/usr/bin/env python3
"""Safe local exposure check for the PHP 2026-10 security release.

This performs one benign GET request to a user-supplied endpoint. It does not
send multipart data, allocate large buffers, or execute any remote command.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
from pathlib import Path
from urllib.parse import urlparse


FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}


def fetch(host: str, port: int, path: str) -> bytes:
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        "Connection: close\r\nAccept: text/plain\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=None, help="HTTP URL; overrides --host/--port")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--path", default="/health.php")
    parser.add_argument("--json-out", help="also write the assessment JSON to this file")
    args = parser.parse_args()

    host, port, path = args.host, args.port, args.path
    if args.target:
        parsed = urlparse(args.target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            parser.error("--target must be an http(s) URL")
        host, port, path = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), parsed.path or "/"

    response = fetch(host, port, path)
    text = response.decode("utf-8", "replace")
    body = text.split("\r\n\r\n", 1)[-1]
    match = re.search(r"PHP_VERSION=([0-9]+\.[0-9]+\.[0-9]+).*UPLOAD_PROGRESS=([01])", body, re.DOTALL)
    if not match:
        result = {"status": "unknown", "reason": "endpoint did not expose the expected health fields"}
        print(json.dumps(result, indent=2))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return 2

    version = tuple(map(int, match.group(1).split(".")))
    key = version[:2]
    fixed = FIXED.get(key)
    result = {"php_version": match.group(1), "upload_progress_enabled": match.group(2) == "1"}
    if fixed and version >= fixed:
        result["status"] = "patched_branch"
        result["guidance"] = "Keep current and verify vendor advisories/backports."
    else:
        result["status"] = "upgrade_required"
        result["guidance"] = "Upgrade to the vendor-fixed release before exposing the service."
    print(json.dumps(result, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if result["status"] == "patched_branch" else 1


if __name__ == "__main__":
    raise SystemExit(main())

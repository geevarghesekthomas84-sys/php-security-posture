#!/usr/bin/env python3
"""Safe external PHP posture check: GET only, no exploit payloads."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_URL = "https://github.com/geevarghesekthomas84-sys/php-security-posture"
AUTHOR = "GG"


def check(url: str, timeout: float, authorization: str | None, insecure: bool) -> dict:
    headers = {"Accept": "text/plain, application/json", "User-Agent": "php-security-posture-safecheck/1.0"}
    if authorization:
        headers["Authorization"] = authorization
    request = urllib.request.Request(url, headers=headers, method="GET")
    context = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(128 * 1024).decode("utf-8", "replace")
            fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
            return {
                "url": url,
                "http_status": response.status,
                "php_version": fields.get("PHP_VERSION", "not disclosed"),
                "upload_progress": fields.get("UPLOAD_PROGRESS", "unknown"),
                "sapi": fields.get("SAPI", "unknown"),
                "server_header": response.headers.get("Server", "not disclosed"),
                "powered_by": response.headers.get("X-Powered-By", "not disclosed"),
                "status": "review" if "PHP_VERSION" in fields else "reachable_unverified",
                "note": "GET-only check; absence of evidence is not proof of safety",
            }
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": "http_error", "http_status": exc.code, "error": str(exc)}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"url": url, "status": "unreachable", "error": str(exc)}


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.url or [])
    if args.targets_file:
        targets.extend(line.split("#", 1)[0].strip() for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines())
    return [target for target in targets if target]


def render_console(results: list[dict], animate: bool) -> str:
    colors = {
        "cyan": "\033[96m", "blue": "\033[94m", "green": "\033[92m",
        "yellow": "\033[93m", "red": "\033[91m", "dim": "\033[2m", "reset": "\033[0m",
    }
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    c = colors if use_color else {key: "" for key in colors}
    unicode_ok = (sys.stdout.encoding or "").lower().replace("-", "") in {"utf8", "utf16"}
    top, middle, bottom = ("╭────────────────────────────────────────────╮", "│", "╰────────────────────────────────────────────╯") if unicode_ok else ("+--------------------------------------------+", "|", "+--------------------------------------------+")
    check_icon = "✓" if unicode_ok else "OK"
    warn_icon = "!"
    frames = "|/-\\"
    if animate and sys.stdout.isatty():
        steps = ("connecting", "reading health data", "checking PHP posture", "building report")
        for index in range(12):
            step = steps[index % len(steps)]
            sys.stdout.write(f"\r  {c['cyan']}{step:<22} {frames[index % len(frames)]}{c['reset']}")
            sys.stdout.flush()
            time.sleep(0.05)
        sys.stdout.write("\r" + " " * 50 + "\r")
    lines = [
        f"{c['blue']}{top}{c['reset']}",
        f"{c['blue']}{middle}{c['reset']}  {c['cyan']}PHP SECURITY POSTURE - SAFE CHECK{c['reset']}  {c['blue']}{middle}{c['reset']}",
        f"{c['blue']}{bottom}{c['reset']}",
        f"  {c['dim']}by {AUTHOR}  |  {PROJECT_URL}{c['reset']}",
    ]
    for result in results:
        status = result["status"]
        color = c["green"] if status in {"review", "reachable_unverified"} else c["yellow"]
        icon = check_icon if status in {"review", "reachable_unverified"} else warn_icon
        lines.append(f"{color}{icon}{c['reset']} {status.upper():<20} {result['url']}")
        for key in ("php_version", "upload_progress", "sapi", "server_header", "powered_by", "error"):
            if key in result:
                lines.append(f"    {c['dim']}{key:<18}{c['reset']} {result[key]}")
    lines.append(f"\n{c['dim']}GET-only check - no exploit payloads sent{c['reset']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", action="append", help="approved HTTPS health endpoint; repeatable")
    parser.add_argument("--targets-file", help="one approved endpoint per line")
    parser.add_argument("--authorization", help="optional Authorization header value")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--insecure", action="store_true", help="allow invalid TLS certificates for lab use only")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--out", default="-")
    parser.add_argument("--plain", action="store_true", help="disable shell colors and animation")
    args = parser.parse_args()
    targets = load_targets(args)
    if not targets:
        parser.error("provide --url or --targets-file")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        results = list(pool.map(lambda item: check(item, args.timeout, args.authorization, args.insecure), targets))
    if args.format == "json":
        output = json.dumps({"results": results}, indent=2) + "\n"
    elif args.format == "csv":
        import io
        buffer = io.StringIO()
        fields = ("url", "status", "http_status", "php_version", "upload_progress", "sapi", "server_header", "powered_by", "error", "note")
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writeheader(); writer.writerows(results)
        output = buffer.getvalue()
    else:
        if args.plain:
            lines = [f"{result['status'].upper():<20} {result['url']}" for result in results]
            output = "\n".join(lines) + "\n"
        else:
            output = render_console(results, animate=True)
    if args.out == "-":
        print(output, end="")
    else:
        Path(args.out).write_text(output, encoding="utf-8")
    return 0 if all(result["status"] in {"review", "reachable_unverified"} for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

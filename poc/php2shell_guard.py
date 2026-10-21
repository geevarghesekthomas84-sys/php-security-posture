#!/usr/bin/env python3
"""Plain-language defensive guard for PHP2Shell exposure and investigation."""

from __future__ import annotations

import argparse
import re
import subprocess
import urllib.request
from pathlib import Path

FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}


def parse_php_info(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        if " => " in line:
            key, value = line.split(" => ", 1)
            fields[key.strip()] = value.split(" => ", 1)[0].strip()
    return fields


def version(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value or "")
    return tuple(map(int, match.groups())) if match else None


def local_check() -> int:
    try:
        text = subprocess.check_output(["php", "-i"], text=True, stderr=subprocess.STDOUT, timeout=15)
    except Exception as exc:
        print(f"UNKNOWN: could not run php -i ({exc})")
        return 2
    fields = parse_php_info(text)
    php_version = fields.get("PHP Version", "unknown")
    parsed = version(php_version)
    upload = fields.get("session.upload_progress.enabled", "unknown")
    print(f"PHP version: {php_version}")
    print(f"Upload progress: {upload}")
    print(f"Memory limit: {fields.get('memory_limit', 'unknown')}")
    print(f"POST limit: {fields.get('post_max_size', 'unknown')}")
    if parsed and parsed[:2] in FIXED and parsed >= FIXED[parsed[:2]]:
        print("PATCH STATUS: fixed branch detected")
    else:
        print("PATCH STATUS: upgrade or verify a vendor backport")
    if upload in {"On", "1"}:
        print("ACTION: disable session.upload_progress.enabled at server level and restart workers")
    else:
        print("ACTION: keep upload progress disabled unless it is required")
    print("NOTE: this is a posture check, not an exploit test")
    return 0


def target_check(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            fields = dict(line.split("=", 1) for line in response.read(65536).decode("utf-8", "replace").splitlines() if "=" in line)
    except Exception as exc:
        print(f"UNKNOWN: could not read {url} ({exc})")
        return 2
    print(f"Target: {url}")
    print(f"PHP version: {fields.get('PHP_VERSION', 'unknown')}")
    print(f"Upload progress: {'On' if fields.get('UPLOAD_PROGRESS') == '1' else 'Off'}")
    print(f"Memory limit: {fields.get('MEMORY_LIMIT', 'unknown')}")
    print(f"POST limit: {fields.get('POST_MAX_SIZE', 'unknown')}")
    parsed = version(fields.get("PHP_VERSION", ""))
    fixed = FIXED.get(parsed[:2]) if parsed else None
    if fixed and parsed >= fixed:
        print("PATCH STATUS: fixed branch detected")
    else:
        print("PATCH STATUS: upgrade or verify a vendor backport")
    if fields.get("UPLOAD_PROGRESS") == "1":
        print("ACTION: disable session.upload_progress.enabled at server level and restart workers")
    else:
        print("ACTION: keep upload progress disabled unless it is required")
    print("NOTE: this is a posture check, not an exploit test")
    return 0


INDICATORS = (
    (re.compile(r"in Unknown on line 0", re.I), "PHP fatal error outside normal script execution"),
    (re.compile(r"Allowed memory size .* exhausted", re.I), "PHP memory exhaustion"),
    (re.compile(r"(?:php-fpm|php-cgi|apache2|httpd|nginx).*?(?:sh -c|/bin/sh|curl |wget |nc |ncat )", re.I), "web worker spawning a suspicious shell or network utility"),
    (re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.I), "upload-progress field observed"),
)


def scan_log(path: str) -> int:
    counts = {label: 0 for _, label in INDICATORS}
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines:
        for pattern, label in INDICATORS:
            if pattern.search(line):
                counts[label] += 1
    print(f"Log: {path}")
    total = 0
    for label, count in counts.items():
        if count:
            print(f"{count:>6}  {label}")
            total += count
    if not total:
        print("No configured indicators found. This does not prove the host was not compromised.")
    else:
        print("ACTION: preserve logs, process telemetry, filesystem timelines, and credentials for investigation.")
    return 1 if total else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--local", action="store_true", help="check local PHP configuration")
    group.add_argument("--scan-log", metavar="FILE", help="scan an approved PHP/web log")
    group.add_argument("--target", help="check an approved health endpoint")
    args = parser.parse_args()
    if args.local:
        return local_check()
    if args.target:
        return target_check(args.target)
    return scan_log(args.scan_log)


if __name__ == "__main__":
    raise SystemExit(main())

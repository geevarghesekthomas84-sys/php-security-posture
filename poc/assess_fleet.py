#!/usr/bin/env python3
"""Assess multiple approved PHP endpoints and emit JSON, CSV, SARIF, or HTML."""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import socket
from pathlib import Path
from urllib.parse import urlparse

from check_php_release import FIXED


def parse_target(value: str) -> tuple[str, int, str, str]:
    raw = value.strip()
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError(f"only plain HTTP targets are supported: {value}")
    return parsed.hostname, parsed.port or 80, parsed.path or "/health.php", value.strip()


def fetch(host: str, port: int, path: str) -> str:
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(request)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode("utf-8", "replace").split("\r\n\r\n", 1)[-1]


def assess(target: str) -> dict:
    host, port, path, label = parse_target(target)
    try:
        body = fetch(host, port, path)
    except OSError as exc:
        return {"target": label, "status": "unknown", "reason": str(exc)}
    fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
    version = fields.get("PHP_VERSION")
    if not version:
        return {"target": label, "status": "unknown", "reason": "missing PHP_VERSION health field"}
    try:
        parsed = tuple(int(part) for part in version.split("."))
    except ValueError:
        return {"target": label, "status": "unknown", "reason": f"invalid PHP version: {version}"}
    fixed = FIXED.get(parsed[:2])
    result = {
        "target": label,
        "php_version": version,
        "sapi": fields.get("SAPI", "unknown"),
        "upload_progress_enabled": fields.get("UPLOAD_PROGRESS") == "1",
        "memory_limit": fields.get("MEMORY_LIMIT", "unknown"),
        "post_max_size": fields.get("POST_MAX_SIZE", "unknown"),
    }
    if fixed and parsed >= fixed:
        result.update(status="patched_branch", guidance="verify vendor package and worker restart")
    else:
        result.update(status="upgrade_required", guidance="upgrade to a vendor-fixed PHP build")
    return result


def render_sarif(results: list[dict]) -> dict:
    runs = [{"tool": {"driver": {"name": "php2shell-assessment", "version": "1.0"}}, "results": []}]
    for result in results:
        if result["status"] == "patched_branch":
            continue
        level = "error" if result["status"] == "upgrade_required" else "warning"
        runs[0]["results"].append({
            "ruleId": "php-security-release",
            "level": level,
            "message": {"text": f"{result['target']}: {result.get('guidance', result.get('reason', 'unknown'))}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": result["target"]}}}],
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def render_html(results: list[dict]) -> str:
    rows = []
    for item in results:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(item.get(key, '')))}</td>" for key in ("target", "status", "php_version", "sapi", "upload_progress_enabled", "guidance", "reason")) + "</tr>")
    return "<!doctype html><meta charset='utf-8'><title>PHP assessment</title><style>body{font:16px system-ui;margin:2rem}table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:.5rem}th{background:#eee}</style><h1>PHP security assessment</h1><table><tr><th>Target</th><th>Status</th><th>PHP</th><th>SAPI</th><th>Upload progress</th><th>Guidance</th><th>Reason</th></tr>" + "".join(rows) + "</table>"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", help="HTTP endpoint; repeatable")
    parser.add_argument("--targets-file", help="one HTTP endpoint per line; # comments allowed")
    parser.add_argument("--format", choices=("json", "csv", "sarif", "html"), default="json")
    parser.add_argument("--out", default="-", help="output path, or - for stdout")
    args = parser.parse_args()
    targets = list(args.target or [])
    if args.targets_file:
        targets.extend(line.split("#", 1)[0].strip() for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines())
    targets = [target for target in targets if target]
    if not targets:
        parser.error("provide --target or --targets-file")
    results = [assess(target) for target in targets]
    if args.format == "json":
        output = json.dumps({"results": results}, indent=2) + "\n"
    elif args.format == "sarif":
        output = json.dumps(render_sarif(results), indent=2) + "\n"
    elif args.format == "html":
        output = render_html(results) + "\n"
    else:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=("target", "status", "php_version", "sapi", "upload_progress_enabled", "memory_limit", "post_max_size", "guidance", "reason"))
        writer.writeheader()
        writer.writerows(results)
        output = buffer.getvalue()
    if args.out == "-":
        print(output, end="")
    else:
        Path(args.out).write_text(output, encoding="utf-8")
    return 0 if all(result["status"] == "patched_branch" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

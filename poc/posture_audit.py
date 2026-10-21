#!/usr/bin/env python3
"""Defensive PHP security-posture auditor using only the Python standard library."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import html
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    target: str
    rule_id: str
    severity: str
    title: str
    evidence: str
    remediation: str
    confidence: str = "medium"


def version_tuple(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value or "")
    return tuple(map(int, match.groups())) if match else None


def audit_fields(target: str, fields: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    version = version_tuple(fields.get("PHP_VERSION", ""))
    if not version:
        return [Finding(target, "PHP-UNKNOWN-VERSION", "high", "PHP version could not be verified", "PHP_VERSION was missing or invalid", "Verify the package/build directly on the host", "low")]
    fixed = FIXED.get(version[:2])
    if not fixed:
        findings.append(Finding(target, "PHP-UNSUPPORTED-BRANCH", "high", "PHP branch is outside the assessed fixed matrix", fields.get("PHP_VERSION", "unknown"), "Upgrade to a supported vendor branch and verify its security backports", "medium"))
    elif version < fixed:
        findings.append(Finding(target, "PHP-SECURITY-RELEASE", "critical", "PHP is below the vendor-fixed release", fields.get("PHP_VERSION", "unknown"), f"Upgrade to PHP {'.'.join(map(str, fixed))} or the vendor equivalent", "high"))
    if fields.get("UPLOAD_PROGRESS") == "1":
        findings.append(Finding(target, "PHP-UPLOAD-PROGRESS", "high", "Session upload progress is enabled", "UPLOAD_PROGRESS=1", "Disable session.upload_progress.enabled at server level and restart workers", "high"))
    if fields.get("PUBLIC_HEALTH_VERSION") == "1":
        findings.append(Finding(target, "PHP-VERSION-DISCLOSURE", "medium", "Health endpoint discloses the PHP version", "PHP_VERSION was returned by the endpoint", "Remove version details from public health responses or require authentication", "high"))
    if not findings:
        findings.append(Finding(target, "PHP-BASELINE-PASS", "info", "No assessed baseline violation found", fields.get("PHP_VERSION", "unknown"), "Keep vendor updates and worker restart evidence current", "medium"))
    return findings


def fetch_target(target: str, header: str | None) -> tuple[str, dict[str, str]]:
    request = urllib.request.Request(target, headers={"Accept": "text/plain", **({"Authorization": header} if header else {})})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read(64 * 1024).decode("utf-8", "replace")
    fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
    fields["PUBLIC_HEALTH_VERSION"] = "1" if "PHP_VERSION" in fields else "0"
    return target, fields


def audit_target(target: str, header: str | None) -> list[Finding]:
    try:
        _, fields = fetch_target(target, header)
        return audit_fields(target, fields)
    except (OSError, urllib.error.URLError) as exc:
        return [Finding(target, "PHP-ENDPOINT-UNREACHABLE", "medium", "PHP endpoint could not be assessed", str(exc), "Verify network access and assess the host locally", "high")]


def audit_local() -> list[Finding]:
    try:
        output = subprocess.check_output(["php", "-i"], text=True, stderr=subprocess.STDOUT, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return [Finding("local", "PHP-LOCAL-UNAVAILABLE", "high", "PHP CLI could not be inspected", str(exc), "Install or locate the PHP CLI, then rerun the audit", "high")]
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if " => " in line:
            key, value = line.split(" => ", 1)
            fields[key.strip()] = value.split(" => ", 1)[0].strip()
    fields["PHP_VERSION"] = fields.get("PHP Version", "")
    fields["UPLOAD_PROGRESS"] = "1" if fields.get("session.upload_progress.enabled", "") in {"On", "1"} else "0"
    return audit_fields("local", fields)


def render(findings: list[Finding], fmt: str) -> str:
    records = [asdict(item) for item in findings]
    if fmt == "json":
        return json.dumps({"findings": records}, indent=2) + "\n"
    if fmt == "csv":
        import io
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(records[0]) if records else list(Finding.__annotations__))
        writer.writeheader(); writer.writerows(records)
        return buffer.getvalue()
    if fmt == "html":
        rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(item.get(key, '')))}</td>" for key in records[0]) + "</tr>" for item in records) if records else ""
        return "<!doctype html><meta charset='utf-8'><title>PHP posture audit</title><style>body{font:16px system-ui;margin:2rem}table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:.5rem}</style><h1>PHP posture audit</h1><table><tr>" + "".join(f"<th>{key}</th>" for key in (records[0] if records else Finding.__annotations__)) + "</tr>" + rows + "</table>\n"
    if fmt == "markdown":
        lines = ["| Target | Severity | Rule | Finding | Remediation |", "| --- | --- | --- | --- | --- |"]
        lines += [f"| {item.target} | {item.severity} | `{item.rule_id}` | {item.title} | {item.remediation} |" for item in findings]
        return "\n".join(lines) + "\n"
    sarif_results = []
    for item in findings:
        if item.severity == "info":
            continue
        sarif_results.append({"ruleId": item.rule_id, "level": "error" if item.severity in {"critical", "high"} else "warning", "message": {"text": f"{item.title}: {item.remediation}"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.target}}}]})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "php-security-posture"}}, "results": sarif_results}]}, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", help="health endpoint; repeatable")
    parser.add_argument("--targets-file")
    parser.add_argument("--local", action="store_true", help="inspect local php -i output")
    parser.add_argument("--header", help="Authorization header value for approved endpoints")
    parser.add_argument("--format", choices=("json", "csv", "html", "markdown", "sarif"), default="json")
    parser.add_argument("--out", default="-"),
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="critical")
    args = parser.parse_args()
    targets = list(args.target or [])
    if args.targets_file:
        targets += [line.split("#", 1)[0].strip() for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines()]
    targets = [item for item in targets if item]
    findings = audit_local() if args.local else []
    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
            for result in pool.map(lambda target: audit_target(target, args.header), targets):
                findings.extend(result)
    if not findings:
        parser.error("provide --local, --target, or --targets-file")
    output = render(findings, args.format)
    if args.out == "-":
        print(output, end="")
    else:
        Path(args.out).write_text(output, encoding="utf-8")
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[item.severity] >= threshold for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())

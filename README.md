# PHP Security Posture

![PHP Security Posture banner](assets/security-posture-banner.png)

Defensive tooling for verifying PHP security releases, configuration posture,
and remediation evidence across local labs and approved fleets.

[![CI](https://github.com/geevarghesekthomas84-sys/php-security-posture/actions/workflows/ci.yml/badge.svg)](https://github.com/geevarghesekthomas84-sys/php-security-posture/actions/workflows/ci.yml)
[![CodeQL](https://github.com/geevarghesekthomas84-sys/php-security-posture/actions/workflows/codeql.yml/badge.svg)](https://github.com/geevarghesekthomas84-sys/php-security-posture/actions/workflows/codeql.yml)

## What this project does

PHP Security Posture turns a PHP security advisory into repeatable checks that
can be attached to a maintenance ticket, audit record, or CI pipeline.

- Verifies PHP release levels and selected runtime settings.
- Audits multiple approved health endpoints concurrently.
- Produces JSON, CSV, Markdown, HTML, and SARIF reports.
- Supports local `php -i` inspection when an endpoint is not available.
- Ships a disposable PHP-FPM/nginx lab for reproducible testing.
- Generates a CycloneDX software inventory for release artifacts.

This project is deliberately non-destructive. It does not contain exploit
payloads, RCE chains, heap sprays, memory-corruption triggers, or OOM/DoS
generators.

## Advisory summary

| Identifier | CVSS v4.0 | Summary | Fixed upstream branches |
| --- | ---: | --- | --- |
| CVE-2026-109618 | 9.2 Critical | Out-of-memory handling can leave internal request data partially initialized, after which cleanup may use invalid state. | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| CVE-2026-109619 | 9.2 Critical | Request-owned internal state can outlive its backing memory and be reused by a later request in the same worker. | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |

The complete remediation is a vendor-fixed PHP update. Configuration changes
can reduce exposure to specific paths but are not a substitute for patching.
Check your OS or PHP vendor for backported fixes on older branches.

## Quick start

Start the local lab:

```bash
cd lab
docker compose up -d
python3 ../poc/check_php_release.py --host 127.0.0.1 --port 18080
```

Expected result:

```json
{
  "php_version": "8.2.35",
  "upload_progress_enabled": false,
  "status": "patched_branch"
}
```

Stop the lab when finished:

```bash
docker compose down
```

## Production-style audit

Use only against systems you own or are explicitly authorized to assess.

Create a target file from the example:

```bash
cp targets.example.txt targets.txt
```

Run a fleet audit and generate a report:

```bash
python3 poc/posture_audit.py \
  --targets-file targets.txt \
  --format html \
  --out posture-report.html \
  --fail-on high
```

Available report formats are `json`, `csv`, `markdown`, `html`, and `sarif`.
SARIF can be uploaded to GitHub Code Scanning. Use `--local` to inspect the
local PHP CLI:

```bash
python3 poc/posture_audit.py --local --format markdown
```

For a simpler operator command:

```bash
python3 poc/php2shell_guard.py --local
python3 poc/php2shell_guard.py --target http://127.0.0.1:18080/health.php
python3 poc/php2shell_guard.py --scan-log /var/log/php-fpm.log
```

The guard checks local PHP settings and scans approved logs for defensive
investigation indicators. It never sends requests to a target.

For a real-world, GET-only external check:

```bash
python3 poc/real_world_check.py \
  --targets-file targets.txt \
  --format json \
  --out real-world-check.json
```

Use an authenticated health endpoint where possible. The checker reads at most
128 KB per response and does not send POST, multipart, memory-exhaustion, or
code-execution payloads. `--insecure` is only for disposable labs.

The auditor reports severity, evidence, remediation, and confidence. See the
[assessment runbook](docs/ASSESSMENT.md) and [report template](docs/REPORT.md)
for an operational workflow.

## Findings covered

- PHP below the assessed vendor-fixed release.
- Unsupported or unverified PHP branch.
- `session.upload_progress.enabled` enabled.
- Public health endpoint disclosing PHP version.
- Unreachable endpoints requiring host-level verification.

These checks reduce uncertainty; they do not replace vendor advisories,
package verification, or worker-restart evidence. Review the
[production baseline](docs/SECURITY_BASELINE.md).

## Repository structure

| Path | Purpose |
| --- | --- |
| `poc/` | Safe checkers, posture auditor, and tests |
| `lab/` | Local Docker Compose verification lab |
| `docs/` | Runbooks, research notes, baseline, and report template |
| `.github/workflows/` | CI, CodeQL, and release SBOM automation |
| `tools/` | Dependency-free SBOM generator |

## Development

```bash
make check
make test
make compose-config
make sbom
```

CI runs Python compilation, unit tests, a local lab audit, Compose validation,
and CodeQL analysis. Releases attach a CycloneDX SBOM.

## Scope and safety

Only test approved assets. Do not place credentials, cookies, private URLs, or
request bodies in reports. For vulnerability reports, follow [SECURITY.md](SECURITY.md).

Technical background: [Abstract ASTRO report](https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619) and [Wiz Research report](https://www.wiz.io/blog/php2shell-php-rce).

## References

- [PHP 2026 security advisories](https://www.php.net/archive/2026.php)
- [PHP security policy](https://wiki.php.net/security)

## License

MIT. See [LICENSE](LICENSE).

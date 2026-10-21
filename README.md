# CVE-2026-109618 & CVE-2026-109619

## Independent Research & Verification

This repository is a defensive, reproducible companion for reviewing the PHP
security release published on 21 October 2026. It provides a small local lab,
configuration checks, and evidence-collection helpers for defenders and
maintainers.

> **Safety:** The repository does not contain an exploit, RCE chain, heap spray,
> memory-corruption trigger, or crash/OOM generator. Run all checks only against
> systems you own or are explicitly authorized to assess.

## What the advisory says

| CVE | Officially described issue | Practical guidance |
| --- | --- | --- |
| CVE-2026-109618 | OOM handling can interrupt PHP while internal request data is partially initialized; request cleanup may use invalid data. | Upgrade. Reduce request/resource exposure while patching. |
| CVE-2026-109619 | Request-owned internal state can survive after its backing memory is freed and be reused by a later request in the same worker. | Upgrade. Disable upload progress before request parsing where appropriate and restart workers. |

The complete fix is a vendor PHP update. Fixed upstream versions listed in the
advisory are PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12. Older branches may have
vendor backports; check the package provider rather than relying on a version
string alone.

## Quick check

```bash
python3 poc/check_php_release.py --host 127.0.0.1 --port 18080
```

The checker reports the PHP version exposed by a local endpoint, whether upload
progress is enabled, and the corresponding remediation guidance. It sends one
small, benign request and never attempts to exhaust memory or execute code.

For an operational workflow, use [docs/ASSESSMENT.md](docs/ASSESSMENT.md).
It shows how to capture evidence for a maintenance ticket without collecting
secrets or request bodies. CI validates the checker and Compose configuration
on every push and pull request.

For multiple approved endpoints, use the fleet assessor:

```bash
python3 poc/assess_fleet.py --targets-file targets.txt --format sarif --out assessment.sarif
python3 poc/assess_fleet.py --targets-file targets.txt --format html --out assessment.html
```

CSV and JSON formats are also available. Run `make test` and `make sbom` before
opening a pull request. A CycloneDX inventory is generated for releases.

## Lab

The lab is intentionally local-only and uses an unprivileged Docker Compose
setup. See [lab/README.md](lab/README.md) for prerequisites, startup, cleanup,
and the evidence to capture.

```bash
cd lab
docker compose up -d
python3 ../poc/check_php_release.py --host 127.0.0.1 --port 18080
docker compose down
```

## Repository layout

- `poc/` — bounded, non-destructive verification helpers.
- `lab/` — disposable PHP-FPM/nginx lab configuration.
- `docs/ANALYSIS.md` — source-based research notes and evidence matrix.
- `SECURITY.md` — reporting and safe-use policy.

## References

- [PHP security release and advisory](https://www.php.net/)
- [PHP security policy](https://wiki.php.net/security)
- [CVE-2026-109618](https://www.cve.org/)
- [CVE-2026-109619](https://www.cve.org/)

The CVE links above point to the CVE program landing page because record URLs
can change during publication; use the identifiers to locate the canonical
records.

## License

MIT. See [LICENSE](LICENSE).

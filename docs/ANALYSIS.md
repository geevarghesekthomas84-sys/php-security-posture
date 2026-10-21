# Research notes

## Scope

This project tracks independent verification of CVE-2026-109618 and
CVE-2026-109619 using the PHP security release as the source of truth. The
repository deliberately avoids reproducing weaponized exploit chains.

## Evidence matrix

| Item | Status | Evidence to collect |
| --- | --- | --- |
| Installed PHP version | local check | `php -v`, package metadata, container image digest |
| Fixed-branch level | local check | Version and vendor advisory |
| Upload-progress state | local check | `php --ini`, `php -i`, FPM pool configuration |
| Worker restart | operational check | FPM/Apache service status and start time |
| Request limits | operational check | `post_max_size`, proxy body limits, upload limits |

## Defensive conclusions

1. Upgrade to a vendor-fixed PHP build. A configuration toggle is not a
   complete substitute for patching.
2. Where the advisory recommends it, disable
   `session.upload_progress.enabled` in server-level configuration before
   request parsing and restart all workers.
3. Enforce request-size and multipart limits at the edge and in PHP. Include
   requests without a usable `Content-Length`.
4. Treat OOM as an availability and security boundary: isolate workers and
   containers so a failed request cannot affect unrelated workloads.
5. Record the exact package version, build flags, SAPI, configuration source,
   and worker lifecycle in verification reports.

## Reproducibility standard

Every report should include the date, PHP version, vendor/package source, SAPI,
configuration source, container image digest if applicable, exact command,
stdout/stderr, and whether the test was run against a disposable local lab.

Do not publish claims of RCE, exploit reliability, or affected-version ranges
without a corresponding upstream advisory, patch diff, or independently
reproducible evidence.

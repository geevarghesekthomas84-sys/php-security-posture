# CVE-2026-109618 & CVE-2026-109619: an evidence-first verification guide

This project documents a safe way to review PHP's 21 October 2026 security
release. It focuses on version evidence, configuration review, worker restart
behavior, and bounded local checks—not exploit reproduction.

The official advisory describes two classes of issue: OOM handling that can
leave request data partially initialized, and stale request-owned state that
may be reused by a later request in the same worker. Both are serious enough
that upgrading is the primary action.

The accompanying lab is bound to localhost, uses a fixed PHP image, runs
without privileged mode, and exposes only a small health endpoint. The checker
performs one benign request and prints machine-readable results for incident
records.

For production systems, verify the vendor package and restart all PHP workers
after applying the update. Temporary configuration changes can reduce exposure
to specific paths, but they are not a replacement for patching.

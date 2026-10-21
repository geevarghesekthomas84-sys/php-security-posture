I published an evidence-first verification lab for PHP CVE-2026-109618 and
CVE-2026-109619.

The project is intentionally defensive: it checks the installed PHP release,
upload-progress configuration, request limits, and worker restart state without
sending exploit payloads or attempting memory exhaustion.

The safest remediation is to upgrade to a vendor-fixed PHP build, then restart
every PHP worker. Temporary configuration changes can reduce exposure to
specific paths but are not a complete fix.

#php #security #vulnerabilityresearch #defensivesecurity

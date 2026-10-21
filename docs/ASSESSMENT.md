# Assessment runbook

This is the workflow for a real-world maintenance or incident ticket. Run it
from an approved administration host and attach the JSON output to the ticket.

## 1. Record scope

Capture the hostname, environment, SAPI, package source, PHP version, worker
manager, and the time of the assessment. Do not include secrets, cookies, or
request bodies in the report.

## 2. Check the service

For a local lab:

```bash
python3 poc/check_php_release.py \
  --target http://127.0.0.1:18080/health.php \
  --json-out assessment.json
```

For production, prefer a pre-existing authenticated health endpoint or a
localhost/admin network path. The checker sends only one small GET request.

## 3. Verify the package, not only the banner

Confirm the installed package/build with the OS or vendor package manager and
record the build identifier. A reverse proxy or application banner can be
stale. Verify that every FPM, Apache, CGI, or other PHP worker has restarted.

## 4. Review compensating controls

Record the effective values and configuration source for:

- `session.upload_progress.enabled`
- `post_max_size` and `upload_max_filesize`
- edge/proxy request-size and multipart limits
- worker isolation and restart behavior

These controls reduce exposure to specific paths; they do not replace the
vendor fix.

## 5. Suggested ticket outcome

**Pass:** fixed vendor build verified, all workers restarted, and evidence
attached.

**Needs remediation:** version is below the vendor-fixed build, worker restart
is unconfirmed, or the service is running an unsupported branch.

**Unknown:** endpoint did not expose version evidence; use host-level package
inspection and repeat the assessment.

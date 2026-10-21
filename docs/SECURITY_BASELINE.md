# Production security baseline

Use this as a minimum deployment baseline for PHP services handling untrusted
HTTP requests.

- Install a vendor-fixed PHP build and record the package/build identifier.
- Restart every PHP-FPM, Apache, CGI, or equivalent worker after patching.
- Disable `session.upload_progress.enabled` at server level where it is not
  required.
- Enforce request size, upload size, multipart count, and timeout limits at the
  edge and in PHP.
- Do not expose PHP version, configuration, stack traces, or session paths from
  public health endpoints.
- Keep PHP workers isolated from unrelated services and sensitive host paths.
- Monitor failed requests, worker restarts, OOM events, and configuration drift.

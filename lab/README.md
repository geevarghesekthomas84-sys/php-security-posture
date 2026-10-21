# Local verification lab

The lab is a disposable PHP-FPM/nginx environment for checking configuration
and collecting version evidence. It is not an exploit environment.

Prerequisites: Docker Engine and Docker Compose v2.

```bash
docker compose up -d
python3 ../poc/check_php_release.py --host 127.0.0.1 --port 18080
docker compose logs --no-color php
docker compose down
```

The service binds to `127.0.0.1` only. Do not expose it to a network. The
container has no privileged mode, host filesystem mounts, or host networking.

The lab uses the fixed PHP 8.2.35 image. To compare a vendor build in an
approved disposable environment, change the image tag deliberately and record
the resulting digest in your assessment; do not use an unpinned `latest` tag.

For a real system, verify the package/vendor release and restart every PHP
worker after changing configuration. A runtime setting changed by application
code is too late for request-parser issues.

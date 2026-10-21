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

For a real system, verify the package/vendor release and restart every PHP
worker after changing configuration. A runtime setting changed by application
code is too late for request-parser issues.

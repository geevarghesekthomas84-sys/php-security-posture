#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p webroot

cat > webroot/health.php <<'PHP'
<?php
header('Content-Type: text/plain');
echo 'PHP_VERSION=' . PHP_VERSION . PHP_EOL;
echo 'SAPI=' . php_sapi_name() . PHP_EOL;
echo 'UPLOAD_PROGRESS=' . (int) ini_get('session.upload_progress.enabled') . PHP_EOL;
echo 'MEMORY_LIMIT=' . ini_get('memory_limit') . PHP_EOL;
echo 'POST_MAX_SIZE=' . ini_get('post_max_size') . PHP_EOL;
PHP

cat > php.ini <<'INI'
[Session]
session.save_handler = files
session.save_path = /tmp/sessions
session.use_strict_mode = 1
session.use_cookies = 1
session.use_only_cookies = 1
session.upload_progress.enabled = Off

[PHP]
display_errors = Off
log_errors = On
error_reporting = E_ALL
file_uploads = On
post_max_size = 8M
upload_max_filesize = 8M
memory_limit = 256M
INI

cat > nginx.conf <<'NGINX'
server {
    listen 80;
    root /var/www/html;
    index health.php;
    client_max_body_size 8m;
    location / { try_files $uri $uri/ /health.php; }
    location ~ \.php$ {
        fastcgi_pass php-fpm:9000;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
NGINX

docker compose up -d
echo
echo "Lab ready at http://127.0.0.1:18080/health.php"
echo "Run: python3 ../poc/check_php_release.py --host 127.0.0.1 --port 18080"

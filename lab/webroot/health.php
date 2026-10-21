<?php
header('Content-Type: text/plain');
echo 'PHP_VERSION=' . PHP_VERSION . PHP_EOL;
echo 'SAPI=' . php_sapi_name() . PHP_EOL;
echo 'UPLOAD_PROGRESS=' . (int) ini_get('session.upload_progress.enabled') . PHP_EOL;
echo 'MEMORY_LIMIT=' . ini_get('memory_limit') . PHP_EOL;
echo 'POST_MAX_SIZE=' . ini_get('post_max_size') . PHP_EOL;

.PHONY: check compose-config

check:
	python -m py_compile poc/check_php_release.py

compose-config:
	docker compose -f lab/docker-compose.yml config --quiet

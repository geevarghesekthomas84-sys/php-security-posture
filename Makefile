.PHONY: check compose-config test sbom

check:
	python -m py_compile poc/check_php_release.py

test:
	python -m unittest discover -s poc -p 'test_*.py'

audit-local:
	python poc/posture_audit.py --local --format markdown

sbom:
	python tools/generate_sbom.py

compose-config:
	docker compose -f lab/docker-compose.yml config --quiet

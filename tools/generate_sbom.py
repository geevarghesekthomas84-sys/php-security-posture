#!/usr/bin/env python3
"""Generate a dependency-light CycloneDX inventory for repository files."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", "__pycache__"}

components = []
for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or any(part in SKIP for part in path.parts):
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    components.append({"type": "file", "name": path.relative_to(ROOT).as_posix(), "version": "workspace", "hashes": [{"alg": "SHA-256", "content": digest}]})

document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": {"type": "application", "name": "php2shell"}}, "components": components}
output = ROOT / "sbom" / "bom.json"
output.parent.mkdir(exist_ok=True)
output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
print(output)

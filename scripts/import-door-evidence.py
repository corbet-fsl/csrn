#!/usr/bin/env python3
"""Import unchanged, synthetic public evidence from a successful cchr CI artifact."""
import hashlib
import json
import pathlib
import shutil
import sys

source = pathlib.Path(sys.argv[1])
run = sys.argv[2]
revision = sys.argv[3]
names = ["initial", "ordinary", "all", "any", "threshold", "schema", "revoked"]
names += [name + "-announcement" for name in names[2:]]
target = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures"
target.mkdir(parents=True, exist_ok=True)
hashes = {}
for name in names:
    path = source / (name + ".json")
    raw = path.read_bytes()
    json.loads(raw)
    shutil.copyfile(path, target / path.name)
    hashes[path.name] = hashlib.sha256(raw).hexdigest()
assert (target / "initial.json").read_bytes() == (target / "ordinary.json").read_bytes()
(target / "provenance.json").write_text(json.dumps({
    "producer_repository": "https://github.com/corbet-foss/cchr",
    "producer_revision": revision,
    "ci_url": "https://github.com/corbet-foss/cchr/actions/runs/" + run,
    "door_revision": "83c163e4239923fa45e38e3712561c42c90f16d8",
    "sha256": hashes,
}, indent=2) + "\n")

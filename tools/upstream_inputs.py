"""Generate small public test reports from the reviewed installations on disposable inputs."""

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

PINS = json.loads((Path(__file__).resolve().parents[1] / "docs/pins.json").read_bytes())


def published(root, repo, path):
    result = (
        subprocess.check_output(["git", "-C", str(root / repo), "rev-parse", "HEAD"])
        .decode()
        .strip()
    )
    if result != PINS[repo]:
        raise RuntimeError("reference checkout differs from the supported revision")
    return subprocess.check_output(["git", "-C", str(root / repo), "show", result + ":" + path])


def signed_inputs(root):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from research_integrity.inventory import scan
    from research_integrity.manifest import make_payload
    from research_integrity.signing import sign

    dataset = root / "dataset"
    dataset.mkdir()
    (dataset / "material.csv").write_bytes(b"mass\n1.2\n")
    key = Ed25519PrivateKey.generate()
    for name, public in [
        ("public", key.public_key()),
        ("other", Ed25519PrivateKey.generate().public_key()),
    ]:
        (root / name).write_bytes(
            public.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    manifest = sign(make_payload(scan(dataset)), key)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf8")
    return dataset


def supply_inputs(root, now):
    from science_supplychain.inventory import read_pins

    inventory = read_pins(b"demo-plasma==1\n")
    (root / "inventory.json").write_text(json.dumps(inventory.document()), encoding="utf8")
    row = {
        "name": "demo-plasma",
        "version": "1",
        "pages": 1,
        "status": "complete",
        "reason": None,
        "matches": [],
    }
    ev = {
        "schema_version": 1,
        "inventory_digest": inventory.digest,
        "source": "synthetic-fixture",
        "checked_at": now.isoformat(),
        "created_at": now.isoformat(),
        "request_count": 1,
        "results": [row],
    }
    (root / "advisories.json").write_text(json.dumps(ev), encoding="utf8")
    return ev


def generate(references):
    reports = {}
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()

        def run(name, module, args, code):
            result = subprocess.run(
                [sys.executable, "-I", "-m", module, *map(str, args)],
                cwd=root,
                capture_output=True,
                timeout=60,
                check=False,
            )
            if result.returncode != code:
                raise RuntimeError(f"{name} returned {result.returncode}, expected {code}")
            json.loads(result.stdout)
            reports[name] = result.stdout

        source = root / "source"
        source.mkdir()
        args = ["scan", source, "--format", "json", "--fail-on", "low"]
        run("source-empty", "sci_security", args, 0)
        (source / "solver.py").write_text("energy = 3\n", encoding="utf8")
        run("source-clean", "sci_security", args, 0)
        (source / "solver.py").write_text("import pickle\npickle.load(stream)\n", encoding="utf8")
        run("source-finding", "sci_security", args, 1)
        (source / "broken.py").write_text("if :\n", encoding="utf8")
        run("source-incomplete", "sci_security", args, 2)
        dataset = signed_inputs(root)
        args = [
            "verify",
            dataset,
            "--manifest",
            root / "manifest.json",
            "--format",
            "json",
            "--public-key",
            root / "public",
        ]
        run("integrity-clean", "research_integrity", args, 0)
        (dataset / "material.csv").write_bytes(b"mass\n1.3\n")
        run("integrity-changed", "research_integrity", args, 1)
        run("integrity-trust", "research_integrity", [*args[:-1], root / "other"], 3)
        now = datetime.now(UTC) - timedelta(seconds=1)
        ev = supply_inputs(root, now)
        args = [
            "audit",
            "--inventory",
            root / "inventory.json",
            "--evidence",
            root / "advisories.json",
            "--format",
            "json",
        ]
        run("dependency-clean", "science_supplychain", args, 0)
        row = ev["results"][0]
        row["matches"] = [{"id": "SYNTHETIC-001", "modified": now.isoformat()}]
        for label, code in [("finding", 1), ("partial", 2), ("stale", 2)]:
            if label == "partial":
                row.update(status="incomplete", reason="deadline")
            if label == "stale":
                ev["checked_at"] = (now - timedelta(days=10)).isoformat()
            (root / "advisories.json").write_text(json.dumps(ev), encoding="utf8")
            run("dependency-" + label, "science_supplychain", args, code)
    for name, path in [
        ("backup-full", "examples/sample-audit.json"),
        ("restore-ordinary", "examples/sample-restore-report.json"),
    ]:
        reports[name] = published(references, "research-backup-auditor", path)
    reports["parser-grid"] = published(
        references, "scientific-file-fuzzing", "docs/evidence/grid.json"
    )
    return reports


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("references", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    for name, raw in generate(args.references).items():
        (args.output / (name + ".json")).write_bytes(raw)
        print(name, len(raw))

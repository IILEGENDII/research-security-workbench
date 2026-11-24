"""Explicit developer setup for reviewed public upstreams. Run inside the test environment."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("directory", type=Path)
    root = cli.parse_args().directory.absolute()
    root.mkdir(mode=0o700)
    pins = json.loads((Path(__file__).resolve().parents[1] / "docs/pins.json").read_bytes())
    known = {
        "scientific-python-security",
        "research-data-integrity",
        "research-backup-auditor",
        "scientific-file-fuzzing",
        "scientific-supply-chain-auditor",
    }
    if pins.keys() != known:
        raise ValueError("unexpected reference set")
    for name, commit in pins.items():
        if not re.fullmatch("[a-f0-9]{40}", commit):
            raise ValueError("expected a full commit SHA")
        folder = root / name
        subprocess.run(["git", "init", "-q", folder], check=True)
        git = ["git", "-C", folder]
        subprocess.run(
            [*git, "fetch", "--depth=1", "https://github.com/IILEGENDII/" + name + ".git", commit],
            check=True,
        )
        subprocess.run([*git, "checkout", "--detach", "FETCH_HEAD"], check=True)
        if subprocess.check_output([*git, "rev-parse", "HEAD"]).decode().strip() != commit:
            raise RuntimeError("reference commit differs")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", *[str(root / name) for name in sorted(pins)]],
        check=True,
    )

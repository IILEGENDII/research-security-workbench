import os
import subprocess
import sys
from pathlib import Path

import pytest

from research_workbench.evidence import normalize
from research_workbench.formats import encode
from research_workbench.policy import parse_policy

pytestmark = pytest.mark.skipif(
    os.environ.get("WORKBENCH_INTEGRATION") != "1", reason="requires pinned upstream installations"
)


def test_real_reports(policy_doc):
    refs = os.environ.get("WORKBENCH_REFERENCES")
    if not refs:
        pytest.skip("requires exact upstream Git checkouts")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from test_adapters import CASES
    from upstream_inputs import generate

    policy = parse_policy(encode(policy_doc))
    for name, raw in generate(Path(refs)).items():
        check, code = CASES[name]
        obs = normalize(raw, policy.checks[check], code)
        assert obs.exit_code == code


def test_bundled_campaign(tmp_path, policy_doc):
    base = tmp_path.resolve() / "bundled"
    base.mkdir(mode=0o700)
    raw = subprocess.check_output(
        [
            sys.executable,
            "-I",
            "-m",
            "scientific_fuzz",
            "campaign",
            "--workspace",
            str(base),
            "--target",
            "grid",
            "--seed",
            "42",
            "--cases",
            "64",
            "--format",
            "json",
        ],
        cwd=base.parent,
        timeout=135,
    )
    check = parse_policy(encode(policy_doc)).checks["parser-validation"]
    obs = normalize(raw, check, 0)
    assert obs.coverage["attempts"] == 64 and not obs.gaps and obs.synthetic


def test_real_backup_and_plan_only(tmp_path, policy_doc):
    binary = os.environ.get("WORKBENCH_RESTIC")
    if not binary:
        pytest.skip("requires verified restic 0.20.0")
    from research_recovery.demo import DemoFixture

    root = tmp_path.resolve() / "backup"
    root.mkdir(mode=0o700)
    fixture = DemoFixture(root, Path(binary), 60)
    fixture.backup()
    policy = parse_policy(encode(policy_doc))

    def command(op, args):
        env = {
            k: os.environ[k]
            for k in ("SystemRoot", "WINDIR", "USERPROFILE", "TMP", "TEMP")
            if k in os.environ
        }
        env["RESTIC_PASSWORD"] = fixture.engine.env["RESTIC_PASSWORD"]
        return subprocess.check_output(
            [
                sys.executable,
                "-I",
                "-m",
                "research_recovery",
                op,
                "--restic",
                binary,
                "--repo",
                str(fixture.engine.repo),
                "--format",
                "json",
                *args,
            ],
            cwd=root,
            env=env,
            timeout=90,
        )

    raw = command("audit", ["--check-data", "full"])
    obs = normalize(raw, policy.checks["backup-check"], 0)
    assert obs.coverage["data_scope"] == "full" and not obs.gaps
    plan = command(
        "plan-restore", ["--snapshot", obs.snapshot, "--workspace", str(fixture.workspace)]
    )
    checked = normalize(plan, policy.checks["restore-check"], 0)
    assert checked.snapshot == obs.snapshot and checked.gaps == ["restore_not_executed"]
    assert not any(fixture.workspace.iterdir())

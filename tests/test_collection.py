import sys
from pathlib import Path

import pytest

from research_workbench.collect import capture_process, collect, prepare
from research_workbench.formats import Invalid, encode
from research_workbench.policy import initialize, parse_policy


def test_child_boundaries(tmp_path, monkeypatch):
    monkeypatch.setenv("SYNTHETIC_MARKER", "private-example")
    root = tmp_path.resolve()
    args = [sys.executable, "-I", "-c"]
    assert (
        capture_process([*args, "import os;print(os.environ.get('SYNTHETIC_MARKER'))"], root)[
            1
        ].strip()
        == b"None"
    )
    for code, expected, extra in [
        ("import time;time.sleep(9)", "child_timeout", {"timeout": 0.25}),
        ("print('x'*1024)", "child_output_limit", {"stdout_limit": 16}),
        ("import sys;sys.stderr.write('x'*1024)", "child_output_limit", {"stderr_limit": 16}),
    ]:
        with pytest.raises(Invalid, match=expected):
            capture_process([*args, code], root, **extra)


def test_literal_argument(tmp_path):
    root = tmp_path.resolve()
    source = root / "--online & data"
    source.mkdir()
    args, _ = prepare(root / "workspace", "source_scan", {"source": source})
    assert args == ["scan", source, "--format", "json", "--fail-on", "low"]
    with pytest.raises(Invalid):
        prepare(root / "workspace", "source_scan", {"source": source, "online": True})


def test_no_capture_on_error(tmp_path, policy_doc, monkeypatch):
    root = initialize(tmp_path.resolve() / "w", encode(policy_doc))
    policy = parse_policy(encode(policy_doc))
    source = tmp_path.resolve() / "src"
    source.mkdir()
    kwargs = {"inputs": {"source": source}, "data_class": "synthetic", "authorized": True}
    for name in ("restore-check", "backup-check", "parser-validation"):
        with pytest.raises(Invalid, match="import_only_operation"):
            collect(root, policy, name, **kwargs)
    with pytest.raises(Invalid, match="authorization"):
        collect(root, policy, "source-review", **{**kwargs, "authorized": False})
    monkeypatch.setattr("research_workbench.collect.installed_module", lambda kind: "sci_security")
    raw = (
        Path(__file__).resolve().parents[1] / "src/research_workbench/fixtures/source-clean.json"
    ).read_bytes()
    for outcome in [(0, b"bad"), (1, raw)]:
        monkeypatch.setattr(
            "research_workbench.collect.capture_process", lambda *a, result=outcome: result
        )
        with pytest.raises(Invalid):
            collect(root, policy, "source-review", **kwargs)
    from research_workbench.assessment import assess

    assert len(list((root / "evidence").iterdir())) == 2
    row = next(r for r in assess(root, policy)["checks"] if r["check_id"] == "source-review")
    assert (
        row["state"] == "inconclusive"
        and row["evidence"]["collection"] == "failed_capture"
        and row["evidence"]["exit_code"] is None
    )

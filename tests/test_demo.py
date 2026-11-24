import json

import pytest
from test_adapters import FIXTURES

from research_workbench.cli import main
from research_workbench.evidence import normalize
from research_workbench.formats import Invalid, encode
from research_workbench.policy import parse_policy


def test_demo_through_cli(tmp_path, capsys):
    ws = tmp_path.resolve() / "private"
    assert main(["demo", "--workspace", str(ws)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["scenario_exits"] == [0, 1, 2] and report["collection"] == "fixture_import"
    first, middle, last = [
        ws / "assessments" / i / "assessment.json" for i in report["assessment_ids"]
    ]
    assert json.loads(middle.read_bytes())["exit_code"] == 1
    assert main(["compare", "--before", str(first), "--after", str(last)]) == 1
    assert len(json.loads(capsys.readouterr().out)["changes"]) == 6
    assert main(["demo", "--workspace", str(ws)]) == 2


@pytest.mark.parametrize(
    "variant,expected",
    [
        ("structure", "insufficient_read_scope"),
        ("plan", "restore_not_executed"),
        ("target", "insufficient_parser_coverage"),
        ("truncated", "invalid"),
    ],
)
def test_limited_reports(policy_doc, variant, expected):
    policy = parse_policy(encode(policy_doc))
    name, check = {
        "structure": ("backup-full", "backup-check"),
        "plan": ("restore-ordinary", "restore-check"),
        "target": ("parser-grid", "parser-validation"),
        "truncated": ("parser-grid", "parser-validation"),
    }[variant]
    d = json.loads((FIXTURES / (name + ".json")).read_bytes())
    c = policy.checks[check].copy()
    if variant == "structure":
        d["check_mode"] = "none"
        d["repository_check"]["data_scope"] = "structure"
    elif variant == "plan":
        d["operation"] = "plan-restore"
        d["restore"] = {"executed": False}
    elif variant == "target":
        c["target"] = "metadata"
    else:
        d["cases"].pop()
    if expected == "invalid":
        with pytest.raises(Invalid):
            normalize(encode(d), c, 0)
    else:
        assert expected in normalize(encode(d), c, 0).gaps

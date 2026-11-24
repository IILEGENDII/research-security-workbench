import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from research_workbench import __file__ as package_file
from research_workbench.evidence import load_records, normalize, store_report
from research_workbench.formats import Invalid, encode, stamp
from research_workbench.policy import initialize, parse_policy

FIXTURES = Path(package_file).parent / "fixtures"
CASES = {
    "source-clean": ("source-review", 0),
    "source-empty": ("source-review", 0),
    "source-finding": ("source-review", 1),
    "source-incomplete": ("source-review", 2),
    "integrity-clean": ("dataset-match", 0),
    "integrity-changed": ("dataset-match", 1),
    "integrity-trust": ("dataset-match", 3),
    "backup-full": ("backup-check", 0),
    "restore-ordinary": ("restore-check", 0),
    "parser-grid": ("parser-validation", 0),
    "dependency-clean": ("dependency-audit", 0),
    "dependency-finding": ("dependency-audit", 1),
    "dependency-partial": ("dependency-audit", 2),
    "dependency-stale": ("dependency-audit", 2),
}


@pytest.mark.parametrize("name", CASES)
def test_pinned_reports(policy_doc, name):
    check, code = CASES[name]
    raw = (FIXTURES / (name + ".json")).read_bytes()
    policy = parse_policy(encode(policy_doc))
    obs = normalize(raw, policy.checks[check], code)
    assert obs.exit_code == code
    if name in ("integrity-trust", "source-empty", "restore-ordinary", "dependency-partial"):
        assert obs.gaps
    if name in ("source-incomplete", "dependency-partial", "integrity-changed"):
        assert obs.findings
    with pytest.raises(Invalid):
        normalize(raw, policy.checks[check], (code + 1) % 4)


@pytest.mark.parametrize(
    "name,path,value",
    [
        ("source-clean", ("summary", "scan_errors"), True),
        ("source-finding", ("findings", 0, "rule_id"), "unknown"),
        ("integrity-clean", ("summary", "expected_files"), 0),
        ("integrity-changed", ("summary", "unchanged"), 1),
        ("backup-full", ("repository_check", "passed"), False),
        ("restore-ordinary", ("restore", "independent_sha256"), True),
        ("parser-grid", ("summary", "unique"), 1),
        ("parser-grid", ("cases", 0, "expected"), "rejected"),
        ("dependency-clean", ("coverage", "selected"), 0),
        ("dependency-partial", ("authenticity",), "service_response"),
        ("dependency-stale", ("findings", 0, "assessment"), "current"),
    ],
)
def test_contradiction(policy_doc, name, path, value):
    check, code = CASES[name]
    report = json.loads((FIXTURES / (name + ".json")).read_bytes())
    node = report
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    with pytest.raises(Invalid):
        normalize(encode(report), parse_policy(encode(policy_doc)).checks[check], code)


def test_receipt_and_tamper(tmp_path, policy_doc):
    now = datetime.now(UTC)
    policy = parse_policy(encode(policy_doc))
    root = initialize(tmp_path.resolve() / "wb", encode(policy_doc))
    raw = (FIXTURES / "source-clean.json").read_bytes() + b" "
    args = {
        "version": "0.1.0",
        "observed_at": stamp(now),
        "exit_code": 0,
        "data_class": "synthetic",
        "now": now,
    }
    receipt = store_report(root, policy, "source-review", raw, **args)
    assert receipt["collection"] == "imported" and receipt["subject_binding"] == "operator_declared"
    path = root / "evidence" / receipt["receipt_id"] / "report.json"
    assert path.read_bytes() == raw
    assert len(load_records(root, policy, now)[0]) == 1
    for key, value in (
        ("version", "0.2"),
        ("observed_at", stamp(now + timedelta(seconds=1))),
        ("exit_code", True),
    ):
        with pytest.raises(Invalid):
            store_report(root, policy, "source-review", raw, **{**args, key: value})
    path.write_bytes(raw + b" ")
    assert load_records(root, policy, now)[1][0]["reason"] == "digest_mismatch"

import json
from datetime import UTC, datetime, timedelta

import pytest
from test_adapters import FIXTURES

from research_workbench.assessment import assess, compare, read_assessment, save_assessment
from research_workbench.evidence import store_report
from research_workbench.formats import Invalid, encode, stamp
from research_workbench.policy import initialize, parse_policy

NOW = datetime(2027, 1, 1, tzinfo=UTC)


def workspace(tmp_path, doc, profile="synthetic"):
    doc["profile"] = profile
    raw = encode(doc)
    return initialize(tmp_path.resolve() / "w", raw), parse_policy(raw)


def put(root, policy, name, check, code=0, hours=0):
    return store_report(
        root,
        policy,
        check,
        (FIXTURES / (name + ".json")).read_bytes(),
        version="0.1.0",
        observed_at=stamp(NOW - timedelta(hours=hours)),
        data_class="synthetic",
        exit_code=code,
        now=NOW,
    )


@pytest.mark.parametrize(
    "name,code,age,expected",
    [
        ("source-clean", 0, 0, 0),
        ("source-finding", 1, 0, 1),
        ("source-empty", 0, 0, 2),
        ("source-incomplete", 2, 0, 2),
        ("source-finding", 1, 169, 2),
    ],
)
def test_precedence(tmp_path, policy_doc, name, code, age, expected):
    policy_doc["checks"] = policy_doc["checks"][:1]
    root, policy = workspace(tmp_path, policy_doc)
    before = assess(root, policy, NOW)
    assert before["exit_code"] == 2
    put(root, policy, name, "source-review", code, age)
    after = assess(root, policy, NOW)
    assert after["exit_code"] == expected
    if code in (1, 2):
        assert after["checks"][0]["findings"] == ["SCI001"]
    assert compare(encode(before), encode(after))["changes"][0]["before_state"] == "inconclusive"
    assert read_assessment(encode(after)) == after


def test_ambiguous_newest_and_immutable(tmp_path, policy_doc):
    policy_doc["checks"] = policy_doc["checks"][:1]
    root, policy = workspace(tmp_path, policy_doc)
    put(root, policy, "source-clean", "source-review", hours=2)
    baseline = assess(root, policy, NOW)
    folder = save_assessment(root, baseline)
    put(root, policy, "source-finding", "source-review", 1, 1)
    assert assess(root, policy, NOW)["exit_code"] == 1
    put(root, policy, "source-clean", "source-review", hours=1)
    row = assess(root, policy, NOW)["checks"][0]
    assert row["state"] == "inconclusive" and row["findings"] == ["SCI001"]
    assert (root / "assessments" / folder / "assessment.json").read_bytes() == encode(baseline)


def test_workstation_and_optional(tmp_path, policy_doc):
    root, policy = workspace(tmp_path, policy_doc, "workstation")
    put(root, policy, "source-clean", "source-review")
    rows = {r["check_id"]: r for r in assess(root, policy, NOW)["checks"]}
    assert rows["source-review"]["reasons"] == ["imported_unverified", "synthetic_only"]
    assert rows["parser-validation"]["state"] == "not_applicable"


def test_backup_reaged(tmp_path, policy_doc):
    root, policy = workspace(tmp_path, policy_doc)
    put(root, policy, "backup-full", "backup-check")
    row = next(r for r in assess(root, policy, NOW)["checks"] if r["check_id"] == "backup-check")
    assert row["state"] == "finding" and row["findings"] == ["snapshot_not_current"]


def test_changed_policy_comparison(tmp_path, policy_doc):
    root, policy = workspace(tmp_path, policy_doc)
    before = assess(root, policy, NOW)
    policy_doc["checks"][0]["max_age_hours"] += 1
    after = assess(root, parse_policy(encode(policy_doc)), NOW)
    assert compare(encode(before), encode(after))["status"] == "policy_changed"
    after["counts"]["required"]["satisfied"] = 12
    with pytest.raises(Invalid):
        read_assessment(encode(after))


def test_corrupt_receipt_blocks_clean_neighbor(tmp_path, policy_doc):
    root, policy = workspace(tmp_path, policy_doc)
    receipt = put(root, policy, "source-finding", "source-review", 1)
    put(root, policy, "integrity-clean", "dataset-match")
    p = root / "evidence" / receipt["receipt_id"] / "receipt.json"
    bad = json.loads(p.read_bytes())
    bad["asset_id"] = "material-data"
    p.write_bytes(encode(bad))
    report = assess(root, policy, NOW)
    assert report["exit_code"] == 2 and report["issues"][0]["reason"] == "asset_mismatch"
    assert not any(r["state"] == "satisfied" for r in report["checks"])

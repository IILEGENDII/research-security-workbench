import json
import socket
from datetime import UTC, datetime

import pytest
from test_adapters import FIXTURES

from research_workbench.assessment import assess
from research_workbench.cli import main
from research_workbench.evidence import normalize, store_report
from research_workbench.formats import Invalid, encode, stamp
from research_workbench.policy import initialize, parse_policy


def test_offline_commands(tmp_path, monkeypatch, capsys):
    def blocked(*args, **kwargs):
        raise AssertionError("unexpected socket")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    ws = tmp_path.resolve() / "new"
    assert main(["demo", "--workspace", str(ws)]) == 0
    capsys.readouterr()
    assert main(["evidence", "--workspace", str(ws)]) == 0
    assert all(
        r["collection"] == "fixture_import" for r in json.loads(capsys.readouterr().out)["receipts"]
    )
    assert main(["assess", "--workspace", str(ws)]) == 2
    assert json.loads(capsys.readouterr().out)["exit_code"] == 2


def test_no_marker_in_summary(policy_doc, tmp_path):
    now = datetime.now(UTC)
    p = parse_policy(encode(policy_doc))
    root = initialize(tmp_path.resolve() / "safe", encode(policy_doc))
    raw = (FIXTURES / "source-finding.json").read_bytes()
    d = json.loads(raw)
    d["findings"][0]["path"] = "PRIVATE-EXAMPLE\u001b[1;2m"
    store_report(
        root,
        p,
        "source-review",
        encode(d),
        version="0.1.0",
        observed_at=stamp(now),
        exit_code=1,
        data_class="synthetic",
        now=now,
    )
    assert b"PRIVATE-EXAMPLE" not in encode(assess(root, p, now))


def test_mismatch_snapshots(tmp_path, policy_doc):
    root = initialize(tmp_path.resolve() / "safe", encode(policy_doc))
    p = parse_policy(encode(policy_doc))
    now = datetime.now(UTC)
    for check, name in (("backup-check", "backup-full"), ("restore-check", "restore-ordinary")):
        doc = json.loads((FIXTURES / (name + ".json")).read_bytes())
        if check == "restore-check":
            doc["snapshot"]["selected_id"] = "c" * 64
        store_report(
            root,
            p,
            check,
            encode(doc),
            version="0.1.0",
            observed_at=stamp(now),
            exit_code=0,
            data_class="synthetic",
            now=now,
        )
    for row in assess(root, p, now)["checks"]:
        if row["asset_id"] == "research-backup":
            assert "snapshot_mismatch" in row["reasons"] and row["state"] == "inconclusive"


def test_dropped_campaign_oracles(policy_doc):
    d = json.loads((FIXTURES / "parser-grid.json").read_bytes())
    d["cases"][0]["expected"] = None
    d["summary"]["controls"] -= 1
    with pytest.raises(Invalid):
        normalize(encode(d), parse_policy(encode(policy_doc)).checks["parser-validation"], 0)


def test_missing_inventory_coverage(policy_doc):
    d = json.loads((FIXTURES / "dependency-clean.json").read_bytes())
    d["coverage"].update(total_components=2, unassessed=1)
    d.update(
        status="incomplete", unassessed=[{"component_index": 1, "reason": "unsupported_identity"}]
    )
    obs = normalize(encode(d), parse_policy(encode(policy_doc)).checks["dependency-audit"], 2)
    assert obs.gaps == ["advisory_partial"]


def test_crashed_writer(tmp_path, policy_doc):
    p = parse_policy(encode(policy_doc))
    root = initialize(tmp_path.resolve() / "w", encode(policy_doc))
    (root / "write.lock").write_bytes(b"interrupted")
    result = assess(root, p)
    assert result["exit_code"] == 2 and result["issues"] == [
        {"reason": "workspace_write_in_progress"}
    ]


def test_unsupported_version_and_receipt_traversal(tmp_path, policy_doc):
    p = parse_policy(encode(policy_doc))
    root = initialize(tmp_path.resolve() / "w", encode(policy_doc))
    now = datetime.now(UTC)
    raw = (FIXTURES / "source-clean.json").read_bytes()
    with pytest.raises(Invalid):
        store_report(
            root,
            p,
            "source-review",
            raw,
            version="9",
            observed_at=stamp(now),
            exit_code=0,
            data_class="synthetic",
        )
    (root / "evidence" / "unexpected").mkdir()
    assert assess(root, p)["exit_code"] == 2

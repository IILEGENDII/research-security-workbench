import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from research_workbench.collect import collect
from research_workbench.evidence import load_records
from research_workbench.formats import encode
from research_workbench.policy import initialize, parse_policy


@pytest.mark.skipif(
    os.environ.get("WORKBENCH_INTEGRATION") != "1", reason="requires pinned upstream installations"
)
def test_three_fixed_collectors(tmp_path, policy_doc):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from upstream_inputs import signed_inputs, supply_inputs

    base = tmp_path.resolve()
    root = initialize(base / "workbench", encode(policy_doc))
    p = parse_policy(encode(policy_doc))
    source = base / "source"
    source.mkdir()
    (source / "calc.py").write_text("energy=1\n", encoding="utf8")
    dataset = signed_inputs(base)
    supply_inputs(base, datetime.now(UTC))
    for check, inputs in [
        ("source-review", {"source": source}),
        (
            "dataset-match",
            {"dataset": dataset, "manifest": base / "manifest.json", "public_key": base / "public"},
        ),
        (
            "dependency-audit",
            {"inventory": base / "inventory.json", "advisory_evidence": base / "advisories.json"},
        ),
    ]:
        receipt = collect(root, p, check, inputs, "synthetic", True)
        assert receipt["collection"] == "local_capture" and receipt["exit_code"] == 0
        assert set(receipt["capture"]["inputs"]) == inputs.keys()
        assert str(base).encode() not in encode(receipt)
    records, issues, _ = load_records(root, p, datetime.now(UTC))
    assert len(records) == 3 and not issues

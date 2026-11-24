from datetime import timedelta
from importlib.resources import files

from .assessment import assess, compare, save_assessment
from .evidence import store_report
from .formats import REPORT_LIMIT, decode, encode, require, stamp, utc
from .policy import initialize, open_workspace


def demo(path):
    examples = files("research_workbench").joinpath("fixtures")
    root = initialize(path, examples.joinpath("policy.json").read_bytes())
    _, policy = open_workspace(root)
    # The upstream samples were recorded at different times. Replay on a named fixture clock.
    start = utc("2026-11-24T21:05:00Z")

    def add(check, name, code, at, raw=None):
        return store_report(
            root,
            policy,
            check,
            raw if raw is not None else examples.joinpath(name + ".json").read_bytes(),
            version="0.1.0",
            observed_at=stamp(at),
            exit_code=code,
            data_class="synthetic",
            method="fixture_import",
            now=at,
        )

    for check, name in (
        ("source-review", "source-clean"),
        ("dataset-match", "integrity-clean"),
        ("backup-check", "backup-full"),
        ("dependency-audit", "dependency-clean"),
        ("parser-validation", "parser-grid"),
    ):
        add(check, name, 0, start)
    # Only this constructed control claims a synthetic independent digest comparison.
    restore = decode(examples.joinpath("restore-ordinary.json").read_bytes(), REPORT_LIMIT)
    backup = decode(examples.joinpath("backup-full.json").read_bytes(), REPORT_LIMIT)
    restore.update(
        operation="demo",
        check_mode="full",
        repository_check=backup["repository_check"],
        warnings=[],
    )
    restore["restore"]["independent_sha256"] = True
    add("restore-check", None, 0, start, encode(restore))
    baseline = assess(root, policy, start)
    require(baseline["exit_code"] == 0, "demo_baseline_failed")
    before = save_assessment(root, baseline)
    later = start + timedelta(minutes=1)
    add("source-review", "source-finding", 1, later)
    add("dataset-match", "integrity-changed", 1, later)
    adverse = assess(root, policy, later)
    require(adverse["exit_code"] == 1, "demo_findings_failed")
    middle = save_assessment(root, adverse)
    later += timedelta(minutes=1)
    add("dependency-audit", "dependency-partial", 2, later)
    add("restore-check", "restore-ordinary", 0, later)
    partial = assess(root, policy, later)
    require(
        partial["exit_code"] == 2 and any(r["findings"] for r in partial["checks"]),
        "demo_incomplete_failed",
    )
    after = save_assessment(root, partial)
    return {
        "schema_version": 1,
        "operation": "demo",
        "status": "expected_synthetic_results",
        "collection": "fixture_import",
        "clock": "simulated_utc",
        "started_at": stamp(start),
        "constructed_controls": ["demo independent restore digest"],
        "assessment_ids": [before, middle, after],
        "scenario_exits": [0, 1, 2],
        "comparison": compare(encode(baseline), encode(partial)),
    }

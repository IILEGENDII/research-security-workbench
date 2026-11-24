from collections import Counter
from dataclasses import dataclass, field

from .formats import choice, digest, fields, flag, items, number, require, string, utc
from .policy import LEVELS, SCOPES


@dataclass
class Observation:
    exit_code: int = 0
    coverage: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    synthetic: bool = False
    snapshot: str | None = None


def source(report, check):
    fields(report, "schema_version tool summary findings errors")
    require(
        report["schema_version"] == "1.0" and report["tool"] == "sci-security",
        "unsupported_contract",
    )
    s = report["summary"]
    fields(s, "files_scanned findings scan_errors")
    files = number(s["files_scanned"])
    rows = items(report["findings"])
    errors = items(report["errors"])
    require(
        number(s["findings"]) == len(rows) and number(s["scan_errors"]) == len(errors),
        "count_mismatch",
    )
    result = Observation(
        2 if errors else int(bool(rows)), {"files_scanned": files, "errors": len(errors)}
    )
    rules = {
        "SCI001": "high",
        "SCI002": "high",
        "SCI003": "high",
        "SCI004": "medium",
        "SCI005": "high",
    }
    found = set()
    locations = set()
    paths = set()
    for row in rows:
        fields(row, "rule_id severity confidence path line column message explanation remediation")
        rule = choice(row["rule_id"], rules)
        require(row["severity"] == rules[rule] and row["confidence"] == "high")
        for name in ("path", "message", "explanation", "remediation"):
            string(row[name])
        key = (row["path"], number(row["line"], 1), number(row["column"], 1), rule)
        require(key not in locations, "duplicate_location")
        locations.add(key)
        paths.add(row["path"])
        if LEVELS.index(rules[rule]) >= LEVELS.index(check["min_severity"]):
            found.add(rule)
    require(len(paths) <= files, "count_mismatch")
    for row in errors:
        fields(row, "kind path message line")
        choice(row["kind"], ("target", "io", "size", "encoding", "syntax", "complexity"))
        string(row["message"])
        string(row["path"])
        if row["line"] is not None:
            number(row["line"], 1)
    result.findings = sorted(found)
    if errors or not files:
        result.gaps.append("incomplete_scan" if errors else "empty_scan")
    return result


def integrity(report):
    fields(report, "schema_version result manifest_trust summary findings errors")
    number(report["schema_version"], 1, 1)
    trust = choice(report["manifest_trust"], ("verified", "unauthenticated", "unknown", "failed"))
    changes = ("unchanged", "added", "missing", "modified")
    issues = ("unreadable", "unsupported", "unstable", "signature_invalid")
    s = report["summary"]
    fields(
        s, " ".join((*changes, *issues, "files_scanned", "expected_files", "bytes_read", "errors"))
    )
    counts = Counter()
    names = set()
    for row in items(report["findings"]):
        require(isinstance(row, dict))
        status = choice(row.get("status"), changes)
        fields(
            row,
            "path status"
            + (
                " expected_size expected_sha256 observed_size observed_sha256"
                if status == "modified"
                else ""
            ),
        )
        path = string(row["path"])
        require(path not in names, "duplicate_location")
        names.add(path)
        counts[status] += 1
        if status == "modified":
            expected = (number(row["expected_size"]), digest(row["expected_sha256"]))
            observed = (number(row["observed_size"]), digest(row["observed_sha256"]))
            require(expected != observed, "contradictory_change")
    errors = items(report["errors"])
    for row in errors:
        fields(row, "status path message")
        status = choice(row["status"], (*issues, "input_error", "io_error"))
        counts[status] += 1
        string(row["message"])
        if row["path"] is not None:
            string(row["path"])
    require(
        all(number(s[k]) == counts[k] for k in (*changes, *issues))
        and number(s["errors"]) == len(errors),
        "count_mismatch",
    )
    scanned = number(s["files_scanned"])
    number(s["bytes_read"])
    expected = s["expected_files"]
    if expected is not None:
        number(expected)
    require(scanned == sum(counts[k] for k in ("unchanged", "added", "modified")), "count_mismatch")
    accounted = counts["unchanged"] + counts["modified"] + counts["missing"]
    require(
        (expected is None and errors and accounted == 0)
        or (expected is not None and (accounted <= expected if errors else accounted == expected)),
        "count_mismatch",
    )
    changed = [k for k in ("modified", "added", "missing") if counts[k]]
    code = 3 if trust == "failed" else 2 if errors else int(bool(changed))
    require(report["result"] == ("clean", "differences", "incomplete", "trust_failure")[code])
    require(
        (trust == "failed") == bool(counts["signature_invalid"]) and (trust != "unknown" or errors),
        "trust_conflict",
    )
    result = Observation(
        code,
        {"manifest_trust": trust, "expected_files": expected, "files_scanned": scanned},
        changed,
    )
    if trust != "verified":
        result.gaps.append("manifest_unverified")
    if errors or not expected or not scanned:
        result.gaps.append("incomplete_inventory" if errors else "empty_inventory")
    return result


def recovery(report, check):
    fields(
        report,
        "schema_version tool operation status completed restic_version check_mode snapshot repository_check restore warnings errors",
    )
    require(
        report["schema_version"] == "1.0" and report["tool"] == "research-recovery",
        "unsupported_contract",
    )
    audit = check["type"] == "backup_audit"
    op = choice(
        report["operation"], ("audit",) if audit else ("restore-test", "plan-restore", "demo")
    )
    status = choice(report["status"], ("healthy", "warning", "failed", "inconclusive"))
    complete = flag(report["completed"])
    for key in ("warnings", "errors"):
        for value in items(report[key]):
            string(value)
    code = {"healthy": 0 if complete else 2, "failed": 1, "warning": 1, "inconclusive": 2}[status]
    result = Observation(code, {"operation": op}, synthetic=op == "demo")
    if status != "healthy" or not complete:
        result.gaps.append("incomplete_recovery_check")
        if code == 1:
            result.findings.append("backup_policy_failure")
    if report["errors"] and status == "healthy":
        result.gaps.append("upstream_errors")
    require(all(isinstance(report[k], dict) for k in ("snapshot", "repository_check", "restore")))
    if report["restic_version"] != "0.20.0":
        result.gaps.append("unsupported_engine")
    snap = report["snapshot"]
    if "selected_id" in snap:
        result.snapshot = digest(snap["selected_id"])
    if audit:
        require(not report["restore"])
        repo = report["repository_check"]
        if not complete or not snap or not repo:
            result.gaps.append("missing_backup_evidence")
            return result
        fields(
            snap,
            "selected_id latest_time_utc matched_count selection_status age_hours max_age_hours freshness_status",
        )
        fields(repo, "completed passed data_scope return_code seconds subset")
        require(snap["selection_status"] == "unambiguous")
        number(snap["matched_count"], 1)
        utc(snap["latest_time_utc"])
        hours = number(snap["max_age_hours"], 1)
        age = snap["age_hours"]
        require(type(age) in (int, float) and age >= 0)
        choice(snap["freshness_status"], ("fresh", "stale"))
        require(
            (age <= hours) == (snap["freshness_status"] == "fresh") or abs(age - hours) < 0.000001
        )
        scope = choice(repo["data_scope"], SCOPES)
        require(
            report["check_mode"] == {"structure": "none", "subset": "subset", "full": "full"}[scope]
        )
        require(
            (scope == "subset" and isinstance(repo["subset"], str))
            or (scope != "subset" and repo["subset"] is None)
        )
        require(type(repo["seconds"]) in (int, float) and repo["seconds"] >= 0)
        passed = flag(repo["passed"])
        require(flag(repo["completed"]) and number(repo["return_code"], 0, 1) == int(not passed))
        require(status != "healthy" or (passed and snap["freshness_status"] == "fresh"))
        result.coverage.update(data_scope=scope, snapshot_time=snap["latest_time_utc"])
        if SCOPES.index(scope) < SCOPES.index(check["min_data_scope"]):
            result.gaps.append("insufficient_read_scope")
        if not passed:
            result.findings.append("repository_check_failed")
    else:
        if not result.snapshot or snap.get("selection_status") != "pinned":
            result.gaps.append("snapshot_unbound")
        r = report["restore"]
        if not r or not flag(r.get("executed")):
            result.gaps.append("restore_not_executed")
            return result
        require(op != "plan-restore")
        if status != "healthy" or not complete:
            return result
        fields(
            r,
            "executed allowed max_files max_bytes target_policy files directories logical_bytes sandbox verified return_code seconds observed_files observed_bytes independent_sha256",
        )
        require(flag(r["allowed"]) and flag(r["verified"]) and number(r["return_code"]) == 0)
        count = number(r["files"], 1, number(r["max_files"], 1))
        size = number(r["logical_bytes"], 0, number(r["max_bytes"], 1))
        require(number(r["observed_files"]) == count and number(r["observed_bytes"]) == size)
        number(r["directories"])
        string(r["sandbox"])
        require(
            r["target_policy"] == "new private child of empty workspace"
            and type(r["seconds"]) in (int, float)
            and r["seconds"] >= 0
        )
        independent = flag(r["independent_sha256"])
        require(not independent or op == "demo", "unsupported_digest_claim")
        result.coverage.update(files=count, independent_sha256=independent)
        if check["require_independent_digest"] and not independent:
            result.gaps.append("digest_baseline_missing")
    return result

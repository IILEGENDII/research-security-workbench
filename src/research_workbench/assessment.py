from datetime import UTC, datetime, timedelta
from uuid import uuid4

from . import __version__
from .evidence import CONTRACTS, load_records
from .formats import (
    ASSESSMENT_LIMIT,
    Invalid,
    choice,
    decode,
    digest,
    encode,
    fields,
    flag,
    items,
    matches,
    number,
    require,
    sha,
    stamp,
    utc,
)
from .policy import TYPES, parse_policy
from .storage import children, write_new

SCOPE = {
    "source_scan": "Static patterns in parsed Python files",
    "signed_integrity": "File equality to the selected signed baseline",
    "backup_audit": "Read scope of the selected backup snapshot",
    "restore_test": "Recovery of the selected snapshot",
    "dependency_audit": "Known advisories for eligible PyPI identities",
    "fuzz_campaign": "Bundled parser contract on generated inputs",
}
ACTION = {
    "satisfied": "Retain evidence and recheck before it expires.",
    "finding": "Review the observed findings before using this asset.",
    "inconclusive": "Resolve the listed evidence gaps and reassess.",
    "not_applicable": "Collect this optional check when needed.",
}


def measured(check, records, profile, now):
    kind = check["type"]
    row = {
        "check_id": check["id"],
        "asset_id": check["asset"],
        "check_type": kind,
        "required": check["required"],
        "required_assurance": check,
        "scope": SCOPE[kind],
        "state": "inconclusive",
        "reasons": [],
        "findings": [],
        "evidence": None,
        "coverage": {},
    }
    gaps = row["reasons"]
    if not records:
        gaps.append("missing_evidence")
        if not check["required"]:
            row["state"] = "not_applicable"
        return row
    latest = max(utc(r.receipt["observed_at"]) for r in records)
    chosen = [r for r in records if utc(r.receipt["observed_at"]) == latest]
    if len(chosen) > 1:
        gaps.append("ambiguous_receipts")
        row["findings"] = sorted({f for r in chosen for f in r.observation.findings})
        row["coverage"] = {"conflicting_receipts": sorted(r.receipt["receipt_id"] for r in chosen)}
        return row
    record = chosen[0]
    r = record.receipt
    o = record.observation
    row["evidence"] = {
        **{
            k: r[k]
            for k in (
                "receipt_id",
                "report_sha256",
                "contract",
                "tool",
                "tool_version",
                "observed_at",
                "imported_at",
                "collection",
                "subject_binding",
                "data_class",
                "exit_code",
            )
        },
        "receipt_sha256": record.receipt_digest,
        "operation": o.coverage.get("operation", TYPES[kind][2]),
        "age_seconds": int((now - latest).total_seconds()),
    }
    if r["collection"] == "local_capture":
        row["evidence"]["capture"] = r["capture"]
    row["findings"] = list(o.findings)
    gaps.extend(o.gaps)
    row["coverage"] = {**o.coverage}
    if profile == "workstation":
        if r["data_class"] == "synthetic" or o.synthetic:
            gaps.append("synthetic_only")
        if r["collection"] != "local_capture":
            gaps.append("imported_unverified")
    if now - latest > timedelta(hours=check["max_age_hours"]):
        gaps.append("stale_evidence")
    if o.snapshot:
        row["coverage"]["snapshot_id"] = o.snapshot
    if "snapshot_time" in o.coverage:
        time = utc(o.coverage["snapshot_time"])
        if time > latest:
            gaps.append("future_snapshot")
        elif now - time > timedelta(hours=check["max_snapshot_age_hours"]):
            row["findings"].append("snapshot_not_current")
    if "checked_at" in o.coverage:
        checked = utc(o.coverage["checked_at"])
        if checked > latest or (
            "latest_advisory_time" in o.coverage
            and utc(o.coverage["latest_advisory_time"]) > latest
        ):
            gaps.append("future_advisory_evidence")
        if now - checked > timedelta(
            hours=min(check["max_age_hours"], o.coverage["max_age_hours"])
        ):
            gaps.append("stale_advisory_evidence")
    return row


def status(rows, profile, issues):
    counts = {name: dict.fromkeys(ACTION, 0) for name in ("required", "optional")}
    for row in rows:
        counts["required" if row["required"] else "optional"][row["state"]] += 1
    required = counts["required"]
    if required["inconclusive"] or issues:
        return counts, "incomplete", 2
    if required["finding"]:
        return counts, "policy_findings", 1
    return (
        counts,
        (
            "synthetic_assessment_satisfied"
            if profile == "synthetic"
            else "requirements_satisfied_in_declared_scope"
        ),
        0,
    )


def assess(root, policy, now=None):
    now = now or datetime.now(UTC)
    try:
        require(not (root / "write.lock").exists(), "workspace_write_in_progress")
        records, errors, _ = load_records(root, policy, now)
    except (Invalid, OSError) as exc:
        records, errors = (
            [],
            [{"reason": str(exc) if isinstance(exc, Invalid) else "unreadable_workspace"}],
        )
    profile = policy.document["profile"]
    rows = []
    for name, check in sorted(policy.checks.items()):
        rows.append(
            measured(check, [r for r in records if r.receipt["check_id"] == name], profile, now)
        )
    snapshots = {}
    for row in rows:
        snapshot = row["coverage"].get("snapshot_id")
        if snapshot:
            snapshots.setdefault(row["asset_id"], set()).add(snapshot)
    for row in rows:
        if len(snapshots.get(row["asset_id"], ())) > 1:
            row["reasons"].append("snapshot_mismatch")
        if errors:
            row["reasons"].append("invalid_stored_evidence")
        if row["state"] != "not_applicable":
            row["state"] = (
                "inconclusive" if row["reasons"] else "finding" if row["findings"] else "satisfied"
            )
        row["reasons"] = sorted(set(row["reasons"]))
        row["next_action"] = ACTION[row["state"]]
    counts, outcome, code = status(rows, profile, errors)
    result = {
        "schema_version": 1,
        "operation": "assess",
        "tool": "research-security",
        "tool_version": __version__,
        "policy_id": policy.document["policy_id"],
        "policy": policy.document,
        "policy_digest": policy.digest,
        "policy_raw_sha256": policy.raw_digest,
        "profile": profile,
        "evaluated_at": stamp(now),
        "status": outcome,
        "exit_code": code,
        "counts": counts,
        "checks": rows,
        "issues": errors,
    }
    require(len(encode(result)) <= ASSESSMENT_LIMIT, "assessment_size_limit")
    return result


def render(report):
    if report["operation"] == "compare":
        lines = [report["status"]]
        for row in report["changes"]:
            lines.append(
                f"{row['check_id']}  {row['before_state']} -> {row['after_state']}  "
                + ", ".join(row["changed"])
            )
    else:
        lines = [
            f"{report['policy_id']}  {report['profile']}  {report['status']}",
            report["evaluated_at"],
        ]
        for row in report["checks"]:
            line = f"{row['check_id']}  {row['state']}  {row['scope']}"
            details = row["reasons"] + row["findings"]
            if details:
                line += "  " + ", ".join(details)
            lines.append(line)
    return "\n".join(lines) + "\n"


def save_assessment(root, report):
    parent = root / "assessments"
    require(len(children(parent, 200)) < 200, "assessment_count_limit")
    folder = parent / uuid4().hex
    folder.mkdir(mode=0o700)
    write_new(folder / "assessment.txt", render(report).encode())
    write_new(folder / "assessment.json", encode(report))
    return folder.name


def read_assessment(raw):
    doc = decode(raw, ASSESSMENT_LIMIT)
    fields(
        doc,
        "schema_version tool tool_version operation policy policy_id policy_digest policy_raw_sha256 profile evaluated_at status exit_code counts checks issues",
    )
    number(doc["schema_version"], 1, 1)
    require(
        doc["tool"] == "research-security"
        and doc["tool_version"] in ("0.1.0", __version__)
        and doc["operation"] == "assess",
        "unsupported_contract",
    )
    policy = parse_policy(encode(doc["policy"]))
    require(
        doc["policy_digest"] == policy.digest
        and doc["profile"] == policy.document["profile"]
        and doc["policy_id"] == policy.document["policy_id"]
    )
    digest(doc["policy_raw_sha256"])
    now = utc(doc["evaluated_at"])
    rows = items(doc["checks"], 200)
    require(len(rows) == len(policy.checks))
    for name, row in zip(sorted(policy.checks), rows, strict=True):
        fields(
            row,
            "check_id asset_id check_type required required_assurance scope state reasons findings evidence coverage next_action",
        )
        check = policy.checks[name]
        require(
            row["check_id"] == name
            and row["asset_id"] == check["asset"]
            and row["check_type"] == check["type"]
            and flag(row["required"]) == check["required"]
            and encode(row["required_assurance"]) == encode(check)
        )
        state = choice(row["state"], ACTION)
        require(row["scope"] == SCOPE[check["type"]] and row["next_action"] == ACTION[state])
        for label in (*items(row["reasons"], 64), *items(row["findings"], 64)):
            matches(label, "[A-Za-z0-9_]{1,64}")
        expected = (
            "inconclusive" if row["reasons"] else "finding" if row["findings"] else "satisfied"
        )
        if state == "not_applicable":
            require(
                not check["required"]
                and row["evidence"] is None
                and "missing_evidence" in row["reasons"]
            )
        else:
            require(state == expected)
        ev = row["evidence"]
        require(isinstance(row["coverage"], dict))
        if ev is None:
            require(state in ("inconclusive", "not_applicable"))
        else:
            fields(
                ev,
                "receipt_id report_sha256 contract tool tool_version observed_at imported_at collection subject_binding data_class exit_code receipt_sha256 operation age_seconds",
                "capture",
            )
            matches(ev["receipt_id"], "[a-f0-9]{32}")
            digest(ev["report_sha256"])
            digest(ev["receipt_sha256"])
            method = choice(
                ev["collection"], ("fixture_import", "imported", "local_capture", "failed_capture")
            )
            require(
                ev["tool"] == TYPES[check["type"]][1]
                and ev["tool_version"] == "0.1.0"
                and ev["contract"] == CONTRACTS[check["type"]]
            )
            require(
                ev["subject_binding"]
                == {"local_capture": "local_capture", "failed_capture": "unverified"}.get(
                    method, "operator_declared"
                )
            )
            choice(ev["data_class"], ("synthetic", "owner_declared"))
            if method == "failed_capture":
                require(
                    ev["exit_code"] is None
                    and state == "inconclusive"
                    and ev["operation"] == "capture_failure"
                )
            else:
                number(ev["exit_code"], 0, 3)
            require(("capture" in ev) == (method == "local_capture"))
            if state == "satisfied":
                require((now - utc(ev["observed_at"])) <= timedelta(hours=check["max_age_hours"]))
                require(
                    doc["profile"] == "synthetic"
                    or (method == "local_capture" and ev["data_class"] == "owner_declared")
                )
            require(
                utc(ev["observed_at"]) <= utc(ev["imported_at"]) <= now
                and number(ev["age_seconds"]) == int((now - utc(ev["observed_at"])).total_seconds())
            )
    for issue in items(doc["issues"], 200):
        fields(issue, "reason", "receipt_id")
        matches(issue["reason"], "[a-z_]{1,64}")
    counts, outcome, code = status(rows, doc["profile"], doc["issues"])
    require(
        encode(doc["counts"]) == encode(counts)
        and doc["status"] == outcome
        and number(doc["exit_code"]) == code
    )
    return doc


def compare(before, after):
    a, b = read_assessment(before), read_assessment(after)
    same = a["policy_digest"] == b["policy_digest"]
    result = {
        "schema_version": 1,
        "operation": "compare",
        "before_sha256": sha(before),
        "after_sha256": sha(after),
        "before_policy": a["policy_digest"],
        "after_policy": b["policy_digest"],
        "raw_policy_changed": a["policy_raw_sha256"] != b["policy_raw_sha256"],
        "status": "policy_changed",
        "changes": [],
        "exit_code": 2,
    }
    if not same:
        return result
    for old, new in zip(a["checks"], b["checks"], strict=True):
        e1, e2 = old["evidence"] or {}, new["evidence"] or {}
        changed = [k for k in ("state", "reasons", "findings", "coverage") if old[k] != new[k]]
        changed.extend(
            k
            for k in (
                "receipt_id",
                "receipt_sha256",
                "age_seconds",
                "subject_binding",
                "data_class",
                "capture",
            )
            if e1.get(k) != e2.get(k)
        )
        if changed:
            result["changes"].append(
                {
                    "check_id": old["check_id"],
                    "before_state": old["state"],
                    "after_state": new["state"],
                    "before_receipt": e1.get("receipt_id"),
                    "after_receipt": e2.get("receipt_id"),
                    "changed": changed,
                }
            )
    result.update(
        status="changed" if result["changes"] else "unchanged",
        exit_code=int(bool(result["changes"])),
    )
    return result

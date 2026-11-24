from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from .adapters import integrity, recovery, source
from .campaign import campaign
from .dependencies import dependencies
from .formats import (
    RECEIPT_LIMIT,
    REPORT_LIMIT,
    TOTAL_LIMIT,
    Invalid,
    choice,
    decode,
    digest,
    encode,
    fields,
    items,
    matches,
    number,
    require,
    sha,
    stamp,
    utc,
)
from .policy import TYPES
from .storage import children, private_dir, read, write_new

CONTRACTS = {
    "source_scan": "source-1.0",
    "signed_integrity": "integrity-1",
    "backup_audit": "backup-1.0",
    "restore_test": "restore-1.0",
    "fuzz_campaign": "campaign-1",
    "dependency_audit": "advisory-1",
}
INPUTS = {
    "source_scan": ("source",),
    "signed_integrity": ("dataset", "manifest", "public_key"),
    "dependency_audit": ("inventory", "advisory_evidence"),
}
OPTIONS = {
    "source_scan": ["scan", "format-json", "fail-on-low"],
    "signed_integrity": ["verify", "manifest", "public-key", "format-json"],
    "dependency_audit": ["audit", "inventory", "evidence", "format-json"],
}


def normalize(raw, check, code):
    doc = decode(raw, REPORT_LIMIT)
    kind = check["type"]
    if kind == "source_scan":
        obs = source(doc, check)
    elif kind == "signed_integrity":
        obs = integrity(doc)
    elif kind in ("backup_audit", "restore_test"):
        obs = recovery(doc, check)
    elif kind == "dependency_audit":
        obs = dependencies(doc, check)
    else:
        obs = campaign(doc, check)
    require(number(code, 0, 3) == obs.exit_code, "exit_code_conflict")
    return obs


@dataclass
class Record:
    receipt: dict
    receipt_digest: str
    observation: object


def verify(policy, identifier, metadata, raw, now):
    receipt = decode(metadata, RECEIPT_LIMIT)
    fields(
        receipt,
        "schema_version receipt_id policy_digest policy_raw_sha256 check_id asset_id tool tool_version contract collection subject_binding data_class observed_at imported_at report_sha256 report_bytes exit_code",
        "capture",
    )
    number(receipt["schema_version"], 1, 1)
    matches(identifier, "[a-f0-9]{32}")
    require(identifier == receipt["receipt_id"], "receipt_id_mismatch")
    require(
        receipt["policy_digest"] == policy.digest
        and receipt["policy_raw_sha256"] == policy.raw_digest,
        "changed_policy",
    )
    check = policy.checks.get(matches(receipt["check_id"], "[a-z][a-z0-9-]{0,47}"))
    require(check and check["asset"] == receipt["asset_id"], "asset_mismatch")
    kind = check["type"]
    require(
        receipt["tool_version"] == "0.1.0"
        and receipt["contract"] == CONTRACTS[kind]
        and receipt["tool"] == TYPES[kind][1],
        "unsupported_contract",
    )
    observed = utc(receipt["observed_at"])
    imported = utc(receipt["imported_at"])
    require(observed <= imported <= now, "invalid_time_order")
    method = choice(receipt["collection"], ("imported", "fixture_import", "local_capture"))
    choice(receipt["data_class"], ("synthetic", "owner_declared"))
    require(method != "fixture_import" or receipt["data_class"] == "synthetic")
    if method == "local_capture":
        require(kind in INPUTS and receipt["subject_binding"] == "local_capture")
        capture = receipt.get("capture")
        fields(capture, "started_at ended_at elapsed_seconds executable_sha256 inputs options")
        start, end = utc(capture["started_at"]), utc(capture["ended_at"])
        require(
            start <= end == observed
            and type(capture["elapsed_seconds"]) in (float, int)
            and 0 <= capture["elapsed_seconds"] <= 180
            and abs((end - start).total_seconds() - capture["elapsed_seconds"]) <= 1,
            "invalid_capture_interval",
        )
        digest(capture["executable_sha256"])
        fields(capture["inputs"], " ".join(INPUTS[kind]))
        for value in capture["inputs"].values():
            digest(value)
        require(items(capture["options"]) == OPTIONS[kind])
    else:
        require("capture" not in receipt and receipt["subject_binding"] == "operator_declared")
    require(
        number(receipt["report_bytes"], 1, REPORT_LIMIT) == len(raw)
        and receipt["report_sha256"] == sha(raw),
        "digest_mismatch",
    )
    obs = normalize(raw, check, receipt["exit_code"])
    return Record(receipt, sha(metadata), obs)


def receipt_ids(root):
    names = children(root / "evidence", 200)
    for name in names:
        matches(name, "[a-f0-9]{32}")
    return names


def load_records(root, policy, now):
    records = []
    errors = []
    total = 0
    for identifier in receipt_ids(root):
        try:
            folder = private_dir(root / "evidence" / identifier)
            require(children(folder, 2) == ["receipt.json", "report.json"], "incomplete_receipt")
            metadata = read(folder / "receipt.json", RECEIPT_LIMIT)
            # Charge even invalid evidence to the aggregate budget.
            length = (folder / "report.json").lstat().st_size
            total += len(metadata) + length
            require(total <= TOTAL_LIMIT, "workspace_size_limit")
            raw = read(folder / "report.json", REPORT_LIMIT)
            records.append(verify(policy, identifier, metadata, raw, now))
        except (Invalid, OSError) as exc:
            errors.append(
                {
                    "receipt_id": identifier,
                    "reason": str(exc) if isinstance(exc, Invalid) else "unreadable_receipt",
                }
            )
            if total > TOTAL_LIMIT:
                break
    return records, errors, total


def store_report(
    root,
    policy,
    check_id,
    raw,
    *,
    version,
    observed_at,
    exit_code,
    data_class,
    method="imported",
    capture=None,
    now=None,
):
    now = now or datetime.now(UTC)
    require(isinstance(check_id, str) and check_id in policy.checks, "unknown_check")
    check = policy.checks[check_id]
    kind = check["type"]
    identifier = uuid4().hex
    receipt = {
        "schema_version": 1,
        "receipt_id": identifier,
        "policy_digest": policy.digest,
        "policy_raw_sha256": policy.raw_digest,
        "check_id": check_id,
        "asset_id": check["asset"],
        "tool": TYPES[kind][1],
        "tool_version": version,
        "contract": CONTRACTS[kind],
        "collection": method,
        "subject_binding": "local_capture" if method == "local_capture" else "operator_declared",
        "data_class": data_class,
        "observed_at": observed_at,
        "imported_at": stamp(now),
        "report_sha256": sha(raw),
        "report_bytes": len(raw),
        "exit_code": exit_code,
    }
    if capture is not None:
        receipt["capture"] = capture
    metadata = encode(receipt)
    verify(policy, identifier, metadata, raw, now)
    records, errors, total = load_records(root, policy, now)
    require(
        not errors and len(records) < 200 and total + len(raw) + len(metadata) <= TOTAL_LIMIT,
        "workspace_evidence_invalid_or_full",
    )
    folder = root / "evidence" / identifier
    folder.mkdir(mode=0o700)
    write_new(folder / "report.json", raw)
    # The receipt is the final record. A crashed import remains visibly incomplete.
    write_new(folder / "receipt.json", metadata)
    return receipt

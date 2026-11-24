from dataclasses import dataclass

from .formats import (
    POLICY_LIMIT,
    choice,
    decode,
    encode,
    fields,
    flag,
    items,
    matches,
    number,
    require,
    sha,
)
from .storage import new_workspace, private_dir, read, write_new

TYPES = {
    "source_scan": ("source", "sci-security", "scan", "min_severity"),
    "signed_integrity": ("dataset", "research-integrity", "verify", ""),
    "backup_audit": (
        "backup",
        "research-recovery",
        "audit",
        "min_data_scope max_snapshot_age_hours",
    ),
    "restore_test": ("backup", "research-recovery", "restore-test", "require_independent_digest"),
    "dependency_audit": (
        "dependencies",
        "science-supplychain",
        "audit",
        "allow_reviewed_offline_evidence",
    ),
    "fuzz_campaign": ("parser-tests", "scientific-fuzz", "campaign", "target min_attempts"),
}
LEVELS = ("low", "medium", "high")
SCOPES = ("structure", "subset", "full")


@dataclass
class Policy:
    document: dict
    raw_digest: str
    digest: str
    checks: dict


def parse_policy(raw):
    doc = decode(raw, POLICY_LIMIT)
    fields(doc, "schema_version policy_id profile assets checks")
    number(doc["schema_version"], 1, 1)
    pattern = "[a-z][a-z0-9-]{0,47}"
    matches(doc["policy_id"], pattern)
    choice(doc["profile"], ("synthetic", "workstation"))
    assets = {}
    for asset in items(doc["assets"], 100):
        fields(asset, "id kind")
        name = matches(asset["id"], pattern)
        require(name not in assets, "duplicate_asset")
        assets[name] = choice(asset["kind"], [v[0] for v in TYPES.values()])
    checks = {}
    for check in items(doc["checks"], 200):
        require(isinstance(check, dict))
        kind = choice(check.get("type"), TYPES)
        fields(check, "id asset type required max_age_hours " + TYPES[kind][3])
        name = matches(check["id"], pattern)
        require(name not in checks, "duplicate_check")
        require(assets.get(matches(check["asset"], pattern)) == TYPES[kind][0], "asset_mismatch")
        flag(check["required"])
        number(check["max_age_hours"], 1, 8760)
        if kind == "source_scan":
            choice(check["min_severity"], LEVELS)
        elif kind == "backup_audit":
            choice(check["min_data_scope"], SCOPES)
            number(check["max_snapshot_age_hours"], 1, 8760)
        elif kind == "fuzz_campaign":
            choice(check["target"], ("grid", "metadata", "table"))
            number(check["min_attempts"], 1, 10000)
        elif kind in ("restore_test", "dependency_audit"):
            flag(check[TYPES[kind][3]])
        checks[name] = check
    require(any(c["required"] for c in checks.values()), "no_required_checks")
    logical = {
        **doc,
        "assets": sorted(doc["assets"], key=lambda a: a["id"]),
        "checks": sorted(checks.values(), key=lambda c: c["id"]),
    }
    return Policy(doc, sha(raw), sha(encode(logical)), checks)


def initialize(path, raw):
    policy = parse_policy(raw)
    root = new_workspace(path)
    for name in ("evidence", "assessments"):
        (root / name).mkdir(mode=0o700)
    write_new(root / "policy.json", raw)
    write_new(
        root / "workspace.json", encode({"schema_version": 1, "policy_sha256": policy.raw_digest})
    )
    return root


def open_workspace(path):
    root = private_dir(path)
    for name in ("evidence", "assessments"):
        private_dir(root / name)
    policy = parse_policy(read(root / "policy.json", POLICY_LIMIT))
    marker = decode(read(root / "workspace.json", 1024), 1024)
    fields(marker, "schema_version policy_sha256")
    number(marker["schema_version"], 1, 1)
    require(marker["policy_sha256"] == policy.raw_digest, "changed_policy")
    return root, policy

from .adapters import Observation
from .formats import choice, digest, fields, items, matches, number, require, utc

REASONS = (
    "request_limit",
    "deadline",
    "response_limit",
    "transport_error",
    "http_error",
    "transient_http",
    "invalid_response",
    "page_limit",
    "token_cycle",
    "match_limit",
    "interrupted_lookup",
    "direct",
    "editable",
    "local_version",
    "unsupported_identity",
    "outside_evidence_selection",
    "stale_evidence",
)


def dependencies(report, check):
    fields(
        report,
        "schema_version operation status source evidence_source authenticity checked_at freshness max_age_hours inventory_digest inventory_scope coverage findings unassessed issues",
    )
    number(report["schema_version"], 1, 1)
    require(report["operation"] == "audit", "unsupported_contract")
    source = choice(report["source"], ("live-query", "offline-replay"))
    synthetic = (
        choice(report["evidence_source"], ("synthetic-fixture", "osv-live")) == "synthetic-fixture"
    )
    require(
        report["authenticity"]
        == ("service_response" if source == "live-query" else "unverified_local_file")
        and not (source == "live-query" and synthetic)
    )
    utc(report["checked_at"])
    number(report["max_age_hours"], 1, 8760)
    digest(report["inventory_digest"])
    choice(report["inventory_scope"], ("declared-pins", "installed-metadata", "sbom-components"))
    stale = choice(report["freshness"], ("stale", "current")) == "stale"
    c = report["coverage"]
    fields(
        c,
        "total_components eligible selected complete_lookups incomplete_lookups affected_components advisory_matches observed_matches unassessed",
    )
    for value in c.values():
        number(value, 0, 10000)
    total = c["total_components"]
    require(
        c["complete_lookups"] + c["unassessed"] == total and c["selected"] <= c["eligible"] <= total
    )
    require(
        (not c["complete_lookups"] and not c["incomplete_lookups"])
        if stale
        else c["complete_lookups"] + c["incomplete_lookups"] == c["selected"]
    )
    omitted = set()
    reasons = []
    for row in items(report["unassessed"]):
        fields(row, "component_index reason")
        i = number(row["component_index"], 0, total - 1)
        require(i not in omitted)
        omitted.add(i)
        reasons.append(choice(row["reason"], REASONS))
    require(len(omitted) == c["unassessed"])
    require(reasons.count("stale_evidence") == (c["selected"] if stale else 0))
    require(sum(r in REASONS[:11] for r in reasons) == c["incomplete_lookups"])
    current = set()
    seen = set()
    identities = {}
    matched = 0
    last_modified = None
    for row in items(report["findings"]):
        fields(row, "name version id modified assessment severity remediation")
        name = matches(row["name"], "[a-z0-9]+(?:-[a-z0-9]+)*")
        version = matches(row["version"], "[a-zA-Z0-9][a-zA-Z0-9.!+_-]{0,127}")
        advisory = matches(row["id"], "[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
        require(advisory.startswith("SYNTHETIC-") == synthetic)
        require((name, version, advisory) not in seen)
        seen.add((name, version, advisory))
        state = choice(row["assessment"], ("current", "partial", "historical"))
        require(identities.setdefault((name, version), state) == state)
        require(
            (state == "historical") == stale and row["severity"] == row["remediation"] == "unknown"
        )
        t = utc(row["modified"])
        last_modified = max(last_modified, t) if last_modified else t
        if state == "current":
            current.add((name, version))
            matched += 1
    require(
        len(seen) == c["observed_matches"]
        and matched == c["advisory_matches"]
        and len(current) == c["affected_components"] <= c["complete_lookups"]
    )
    require(
        len(identities) <= c["selected"]
        and sum(s == "partial" for s in identities.values()) <= c["incomplete_lookups"]
    )
    issues = items(report["issues"])
    for issue in issues:
        choice(issue, ("partial_sbom_scope", "empty_inventory"))
    incomplete = bool(omitted or issues or not c["complete_lookups"])
    require(
        report["status"]
        == (
            "incomplete"
            if incomplete
            else "advisory_matches"
            if current
            else "no_known_matches_in_assessed_scope"
        )
    )
    coverage = {
        **c,
        **{
            k: report[k]
            for k in (
                "inventory_digest",
                "inventory_scope",
                "source",
                "authenticity",
                "evidence_source",
                "checked_at",
                "max_age_hours",
            )
        },
    }
    if last_modified:
        coverage["latest_advisory_time"] = last_modified.isoformat()
    result = Observation(2 if incomplete else int(bool(current)), coverage, synthetic=synthetic)
    result.findings = sorted({f"{state}_advisory_match" for state in identities.values()})
    if incomplete or stale:
        result.gaps.append("advisory_partial" if not stale else "stale_advisory_evidence")
    if source == "offline-replay" and not check["allow_reviewed_offline_evidence"]:
        result.gaps.append("offline_replay_not_accepted")
    return result

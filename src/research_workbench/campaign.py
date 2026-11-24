from collections import Counter

from .adapters import Observation
from .formats import choice, digest, fields, flag, items, number, require, string

SEEDS = {
    "grid": {
        "9a86e7b815f7135d111ecc0fae2bd35438b17473bf74495493ed72b50a872088": {
            "cells": 2,
            "cols": 2,
            "rows": 1,
        },
        "558363c87417a913863c81e883c4f945af2372f369e786224905688b8ba43209": {
            "cells": 4,
            "cols": 2,
            "rows": 2,
        },
        "77906f601e5e87cecff7c708f2963601d88a3050d47a310c4d72b58596817758": {
            "cells": 8,
            "cols": 2,
            "rows": 4,
        },
    },
    "metadata": {
        "0dbb21b9e9767d54afec3a54ffc0a17558f1521b08e1b993df5cc8b90012c76f": {
            "nx": 1,
            "ny": 2,
            "steps": 7,
        },
        "b7279f1b16d20af06b8db7c6407d83c55907c19caf95fe955a2e21f3b85bbd6a": {
            "nx": 2,
            "ny": 2,
            "steps": 13,
        },
        "6375f240035483c8d541f9d8adb2ed739e04db3071ae7ca7085729263258c89e": {
            "nx": 4,
            "ny": 2,
            "steps": 31,
        },
    },
    "table": {
        "6a14393aa9c0046a106cca329ccb9876ab1e4a50cc2bf93b69e1cafa28299543": {
            "columns": 3,
            "rows": 1,
        },
        "b88a67956e337dfddd0dc14c615fb1a16ae1fbde3726ea3fd0c430934e391484": {
            "columns": 3,
            "rows": 2,
        },
        "06b8a326ce60300d5a5ce5aa36189c070756c8b5cd670623f7f06b3fd339f37a": {
            "columns": 3,
            "rows": 4,
        },
    },
}
OUTCOMES = (
    "accepted",
    "rejected",
    "contract_mismatch",
    "exception",
    "crash",
    "timeout",
    "resource_limit",
    "protocol_error",
    "infrastructure_error",
)


def outcome(row):
    fields(row, "status summary reason return_code")
    status = choice(row["status"], OUTCOMES)
    if row["return_code"] is not None:
        number(row["return_code"], -(2**31), 2**32)
    if row["reason"] is not None:
        string(row["reason"])
    if status == "accepted":
        require(isinstance(row["summary"], dict) and row["summary"] and row["reason"] is None)
        for n in row["summary"].values():
            number(n)
    else:
        require(row["summary"] is None)
    return status


def elapsed(value, high=86400):
    require(type(value) in (int, float) and 0 <= value <= high)


def campaign(report, check):
    fields(
        report,
        "schema_version tool operation tool_version python platform worker_protocol format_version target worker_limits seed limits mutation_version completed errors result seconds summary cases cases_saved seed_checks workspace_child",
    )
    require(
        report["tool"] == "scientific-fuzz"
        and report["operation"] == "campaign"
        and report["tool_version"] == "0.1.0",
        "unsupported_contract",
    )
    for k in ("schema_version", "worker_protocol", "format_version", "mutation_version"):
        number(report[k], 1, 1)
    target = choice(report["target"], SEEDS)
    number(report["seed"])
    elapsed(report["seconds"])
    s = report["summary"]
    fields(
        s,
        "requested generated unique started completed duplicates unexecuted controls saved_bytes outcomes",
    )
    for k in s.keys() - {"outcomes"}:
        number(s[k])
    limits = report["limits"]
    fields(limits, "cases timeout campaign_timeout max_input_bytes max_saved_bytes max_saved_cases")
    require(number(limits["cases"], 1, 10000) == s["requested"])
    number(limits["max_input_bytes"], 1, 1 << 20)
    number(limits["max_saved_cases"], 0, 100)
    number(limits["max_saved_bytes"], 0, 32 << 20)
    elapsed(limits["campaign_timeout"], 1800)
    elapsed(limits["timeout"], 15)
    worker = report["worker_limits"]
    fields(
        worker, "wall_seconds input_bytes hard_cpu_quota hard_memory_quota bytes_per_output_stream"
    )
    require(
        number(worker["input_bytes"]) == limits["max_input_bytes"]
        and number(worker["bytes_per_output_stream"]) == 16384
        and worker["hard_memory_quota"] is False
        and worker["hard_cpu_quota"] is False
        and worker["wall_seconds"] == limits["timeout"]
    )
    seeds = {}
    for row in items(report["seed_checks"], 3):
        fields(row, "digest outcome")
        key = digest(row["digest"])
        require(key not in seeds)
        outcome(row["outcome"])
        seeds[key] = row["outcome"]["summary"]
    counts = Counter()
    observed = {}
    ids = set()
    controls = 0
    started = completed = 0
    rows = items(report["cases"])
    for i, row in enumerate(rows):
        fields(
            row,
            "case_id index digest seed_digest mutation seconds size expected duplicate outcome observed",
        )
        key = digest(row["digest"])
        case = digest(row["case_id"])
        require(case not in ids and number(row["index"]) == i)
        ids.add(case)
        require(digest(row["seed_digest"]) in SEEDS[target])
        string(row["mutation"])
        elapsed(row["seconds"])
        number(row["size"], 0, limits["max_input_bytes"])
        status = outcome(row["outcome"])
        expected = row["expected"]
        if expected is not None:
            controls += 1
            require(expected == "rejected" or isinstance(expected, dict))
        if status == "contract_mismatch":
            actual = row["observed"]
            require(outcome(actual) in ("accepted", "rejected"))
        else:
            actual = row["outcome"]
            require(row["observed"] is None)
        if actual["status"] in ("accepted", "rejected") and expected is not None:
            matched = (expected == "rejected" and actual["status"] == "rejected") or (
                actual["status"] == "accepted" and actual["summary"] == expected
            )
            require(matched == (status != "contract_mismatch"), "oracle_conflict")
        duplicate = flag(row["duplicate"])
        require(duplicate == (key in observed), "duplicate_conflict")
        if duplicate:
            require(actual == observed[key])
        else:
            observed[key] = actual
            started += actual["reason"] not in ("spawn_failed", "deadline_before_start")
            completed += actual["status"] not in OUTCOMES[-2:]
        counts[status] += 1
    fields(s["outcomes"], " ".join(OUTCOMES))
    require(all(number(s["outcomes"][k]) == counts[k] for k in OUTCOMES))
    require(
        (
            s["generated"],
            s["unique"],
            s["duplicates"],
            s["completed"],
            s["started"],
            s["controls"],
            s["unexecuted"],
        )
        == (
            len(rows),
            len(observed),
            len(rows) - len(observed),
            completed,
            started,
            controls,
            s["requested"] - len(rows),
        ),
        "count_mismatch",
    )
    saved = items(report["cases_saved"], limits["max_saved_cases"])
    saved_keys = set()
    saved_bytes = 0
    for entry in saved:
        fields(entry, "index file source replay")
        row = rows[number(entry["index"], 0, len(rows) - 1)]
        require(
            entry["file"] == row["digest"] + ".bin"
            and entry["source"] == "bundled_parser"
            and row["digest"] not in saved_keys
            and row["outcome"]["status"] in OUTCOMES[2:-2]
        )
        saved_keys.add(row["digest"])
        saved_bytes += row["size"]
        for arg in items(entry["replay"], 32):
            string(arg)
    require(saved_bytes == s["saved_bytes"] <= limits["max_saved_bytes"])
    errors = items(report["errors"])
    for err in errors:
        string(err)
    complete = flag(report["completed"])
    require(
        not complete
        or (
            not errors
            and len(rows) == s["requested"]
            and started > 0
            and completed == len(observed)
            and seeds == SEEDS[target]
            and not any(counts[k] for k in OUTCOMES[-2:])
        )
    )
    adverse = [k for k in OUTCOMES[2:-2] if counts[k]]
    require(
        report["result"]
        == (
            "incomplete"
            if not complete
            else "unexpected_outcomes"
            if adverse
            else "no_unexpected_outcomes"
        )
    )
    result = Observation(
        2 if not complete else int(bool(adverse)),
        {"target": target, "attempts": len(rows), "unique": len(observed)},
        adverse,
        synthetic=True,
    )
    if not complete or target != check["target"] or len(rows) < check["min_attempts"]:
        result.gaps.append("insufficient_parser_coverage")
    return result

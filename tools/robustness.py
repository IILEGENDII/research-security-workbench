import argparse
import json
import random
import tempfile
from collections import Counter
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

from research_workbench.evidence import normalize, store_report, verify
from research_workbench.formats import Invalid, encode, stamp
from research_workbench.policy import initialize, parse_policy


def run(seed, count):
    if not 1 <= count <= 1000:
        raise ValueError("count must be between 1 and 1000")
    rng = random.Random(seed)
    examples = files("research_workbench").joinpath("fixtures")
    base = examples.joinpath("policy.json").read_bytes()
    raw = examples.joinpath("source-clean.json").read_bytes()
    p = parse_policy(base)
    now = datetime.now(UTC)
    with tempfile.TemporaryDirectory() as tmp:
        root = initialize(Path(tmp).resolve() / "private", base)
        receipt = store_report(
            root,
            p,
            "source-review",
            raw,
            version="0.1.0",
            observed_at=stamp(now),
            exit_code=0,
            data_class="synthetic",
            now=now,
        )
    cases = {
        "policy": (base, parse_policy),
        "receipt": (encode(receipt), lambda b: verify(p, receipt["receipt_id"], b, raw, now)),
        "report": (raw, lambda b: normalize(b, p.checks["source-review"], 0)),
    }
    results = {}
    for name, (original, reader) in cases.items():
        totals = Counter(accepted=0, rejected=0, incomplete=0, exceptions=0)
        for i in range(count):
            data = bytearray(original)
            j = rng.randrange(len(data))
            if i % 6 == 1:
                data[j] ^= rng.randint(1, 255)
            elif i % 6 == 2:
                del data[j:]
            elif i % 6 == 3:
                data[j:j] = b'{"unknown":'
            elif i % 6 == 4:
                data.extend(b" trailing")
            elif i % 6 == 5 and name == "report":
                doc = json.loads(data)
                doc["summary"]["files_scanned"] = 0
                data = encode(doc)
            try:
                value = reader(bytes(data))
            except Invalid:
                totals["rejected"] += 1
            else:
                totals["incomplete" if getattr(value, "gaps", []) else "accepted"] += 1
        results[name] = dict(totals)
    return {"seed": seed, "cases_per_reader": count, "results": results}


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--seed", type=int, default=61)
    cli.add_argument("--count", type=int, default=120)
    a = cli.parse_args()
    print(json.dumps(run(a.seed, a.count), sort_keys=True))

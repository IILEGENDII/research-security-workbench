import json
from pathlib import Path

import pytest


@pytest.fixture
def policy_doc():
    return json.loads((Path(__file__).resolve().parents[1] / "examples/policy.json").read_bytes())

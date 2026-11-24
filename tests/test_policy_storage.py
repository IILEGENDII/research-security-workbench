import json
import os

import pytest

from research_workbench.formats import Invalid, decode, encode, utc
from research_workbench.policy import initialize, open_workspace, parse_policy
from research_workbench.storage import local, read, write_new


@pytest.mark.parametrize(
    "edit",
    [
        lambda p: p.update(schema_version=True),
        lambda p: p.update(extra=1),
        lambda p: p.update(profile="demo"),
        lambda p: p["checks"][0].update(required=1),
        lambda p: p["checks"][0].update(asset="material-data"),
        lambda p: p["checks"][0].update(max_age_hours=True),
        lambda p: p["checks"][0].update(max_age_hours=8761),
        lambda p: p["checks"][0].update(id="../test"),
        lambda p: p["checks"][0].update(min_severity="all"),
        lambda p: p["checks"].append(p["checks"][0]),
        lambda p: p["assets"].append(p["assets"][0]),
        lambda p: p.update(checks=[]),
        lambda p: p["checks"][1].update(min_severity="low"),
    ],
)
def test_invalid_policy(policy_doc, edit):
    edit(policy_doc)
    with pytest.raises(Invalid):
        parse_policy(encode(policy_doc))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"x":' + b"1" * 30 + b"}",
        b'{"x":' + b"[" * 40 + b"]" * 40 + b"}",
        b"\xff",
        b"[]",
    ],
)
def test_json_limits(raw):
    with pytest.raises(Invalid):
        decode(raw, 300)


@pytest.mark.parametrize("slashes", [0, 1, 2, 3])
@pytest.mark.parametrize("punctuation", ["[" * 33, "}" * 33], ids=["open-brackets", "close-braces"])
def test_escaped_quotes_keep_json_punctuation_in_strings(slashes, punctuation):
    text = "\\" * slashes + '"' + punctuation
    document = {text: [text, "ends with a backslash\\"]}
    raw = json.dumps(document).encode()
    assert decode(raw, len(raw)) == document


def test_nesting_limit_after_an_escaped_quote():
    for depth in (31, 32):
        nested = None
        for _ in range(depth):
            nested = [nested]
        document = {"description": 'a quote " and a trailing backslash\\', "data": nested}
        raw = json.dumps(document).encode()
        if depth == 31:  # The enclosing object accounts for the other level.
            assert decode(raw, len(raw)) == document
        else:
            with pytest.raises(Invalid, match="nesting_limit"):
                decode(raw, len(raw))


def test_raw_and_logical_policy(policy_doc):
    a = parse_policy(encode(policy_doc))
    policy_doc["assets"].reverse()
    b = parse_policy(json.dumps(policy_doc, indent=2).encode())
    assert a.digest == b.digest and a.raw_digest != b.raw_digest


@pytest.mark.parametrize(
    "value", ["yesterday", "2025-02-29T12:00:00Z", "2025-02-28", "2025-02-28T12:00:00+01:00"]
)
def test_time(value):
    with pytest.raises(Invalid):
        utc(value)


def test_workspace(tmp_path, policy_doc):
    path = tmp_path.resolve() / "private"
    raw = encode(policy_doc)
    initialize(path, raw)
    assert open_workspace(path)[1].raw_digest == parse_policy(raw).raw_digest
    with pytest.raises(FileExistsError):
        initialize(path, raw)
    (path / "policy.json").write_bytes(raw + b" ")
    with pytest.raises(Invalid, match="changed_policy"):
        open_workspace(path)


@pytest.mark.parametrize(
    "value", ["../escape", "https://host/a", "//host/share", "\\\\host\\share"]
)
def test_unsafe_names(value):
    with pytest.raises(Invalid):
        local(value)


def test_exclusive(tmp_path):
    p = tmp_path.resolve() / "a"
    write_new(p, b"abc")
    with pytest.raises(FileExistsError):
        write_new(p, b"x")
    assert read(p, 3) == b"abc"
    with pytest.raises(Invalid):
        read(p, 2)


def test_repository_boundary(tmp_path, policy_doc):
    (tmp_path / ".git").mkdir()
    with pytest.raises(Invalid):
        initialize(tmp_path.resolve() / "evidence", encode(policy_doc))


def test_link(tmp_path):
    p = tmp_path.resolve() / "file"
    p.write_bytes(b"x")
    link = p.with_name("linked")
    try:
        link.symlink_to(p)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(Invalid):
        read(link, 12)


def test_hard_link(tmp_path):
    p = tmp_path.resolve() / "a"
    p.write_bytes(b"x")
    try:
        os.link(p, p.with_name("b"))
    except OSError:
        pytest.skip("hard links unavailable")
    with pytest.raises(Invalid):
        read(p, 1)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO")
def test_fifo(tmp_path):
    p = tmp_path.resolve() / "fifo"
    os.mkfifo(p)
    with pytest.raises(Invalid):
        read(p, 10)

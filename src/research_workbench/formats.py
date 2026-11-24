import hashlib
import json
import math
import re
from datetime import UTC, datetime

POLICY_LIMIT = 256 << 10
REPORT_LIMIT = 8 << 20
RECEIPT_LIMIT = 16 << 10
ASSESSMENT_LIMIT = 2 << 20
TOTAL_LIMIT = 128 << 20


class Invalid(ValueError):
    """A safe reason code suitable for an operator-facing report."""


def require(condition, reason="invalid_fields"):
    if not condition:
        raise Invalid(reason)


def fields(value, names, optional=""):
    required = set(names.split())
    require(
        isinstance(value, dict) and required <= value.keys() <= required.union(optional.split())
    )


def number(value, low=0, high=2**64 - 1):
    require(type(value) is int and low <= value <= high, "invalid_integer")
    return value


def choice(value, options):
    require(isinstance(value, str) and value in options, "unsupported_value")
    return value


def flag(value):
    require(type(value) is bool, "invalid_boolean")
    return value


def string(value):
    require(isinstance(value, str) and 0 < len(value) <= 4096, "invalid_string")
    return value


def matches(value, pattern):
    require(isinstance(value, str) and re.fullmatch(pattern, value, re.ASCII), "invalid_identifier")
    return value


def digest(value):
    return matches(value, "[a-f0-9]{64}")


def items(value, limit=10000):
    require(isinstance(value, list) and len(value) <= limit, "invalid_list")
    return value


def utc(value):
    require(
        isinstance(value, str)
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)",
            value,
        ),
        "invalid_time",
    )
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise Invalid("invalid_time") from None


def stamp(now=None):
    return (now or datetime.now(UTC)).isoformat(timespec="microseconds").replace("+00:00", "Z")


def encode(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "duplicate_key")
    return result


def decode(raw, limit):
    require(0 < len(raw) <= limit, "size_limit")
    try:
        text = raw.decode("utf-8")

        def integer(token):
            require(len(token) <= 21, "integer_limit")
            return int(token)

        def decimal(token):
            require(len(token) <= 40 and math.isfinite(float(token)), "number_limit")
            return float(token)

        # Scan before allocating the object tree, including unterminated strings.
        depth = tokens = length = 0
        quoted = escaped = False
        for ch in text:
            if quoted:
                length += 1
                require(length <= 32768, "token_limit")
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    quoted = False
            elif ch == '"':
                quoted = True
                length = 0
                tokens += 1
            elif ch in "[]{}:,":
                depth += int(ch in "[{") - int(ch in "]}")
                require(0 <= depth <= 32, "nesting_limit")
                tokens += 1
            require(tokens <= 450000, "token_limit")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=integer,
            parse_float=decimal,
            parse_constant=lambda _: require(False, "invalid_number"),
        )
        require(isinstance(value, dict), "expected_object")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError):
        raise Invalid("invalid_json") from None

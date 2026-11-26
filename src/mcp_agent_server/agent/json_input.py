"""JSON decoding at the untrusted provider boundary."""

import json
import math
from typing import Any, NoReturn


def reject_constant(_: str) -> NoReturn:
    raise ValueError("Invalid numeric constant")


def finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("Non-finite number")
    return value


def decode(raw: str | bytes | bytearray) -> Any:
    return json.loads(raw, parse_constant=reject_constant, parse_float=finite_float)

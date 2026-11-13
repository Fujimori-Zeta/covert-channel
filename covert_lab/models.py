"""Small, validated record types for the offline lab."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Event:
    kind: str
    source: str
    timestamp: float
    value: str = ""
    payload_size: int = 0
    expected: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Event":
        if not isinstance(raw, dict):
            raise ValueError("each record must be a JSON object")
        kind = raw.get("kind")
        if kind not in {"dns", "icmp", "http", "metadata"}:
            raise ValueError("kind must be dns, icmp, http, or metadata")
        source = raw.get("source")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("source must be a nonempty string")
        value = raw.get("value", "")
        if not isinstance(value, str):
            raise ValueError("value must be a string")
        try:
            timestamp = float(raw["timestamp"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("timestamp must be a number") from exc
        size = raw.get("payload_size", 0)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("payload_size must be a nonnegative integer")
        expected = raw.get("expected", False)
        if not isinstance(expected, bool):
            raise ValueError("expected must be a boolean")
        return cls(kind, source.strip(), timestamp, value, size, expected)


@dataclass(frozen=True)
class Frame:
    """One inspectable unit in an offline channel simulation."""

    channel: str
    sequence: int
    total: int
    timestamp: float
    wire_value: str
    payload_size: int
    metadata: dict[str, str]

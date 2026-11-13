"""Orchestration and measurements for the offline channel models."""

from dataclasses import asdict, dataclass
from random import Random

from .channels import CHANNELS, get_channel, with_timestamps
from .detectors import Finding, analyze
from .models import Event, Frame


DEFAULT_CHUNK_SIZES = {"dns": 24, "icmp": 96, "http": 72, "metadata": 72}
DEFAULT_INTERVALS = {"dns": 0.5, "icmp": 1.0, "http": 0.4, "metadata": 0.0}


def schedule(count: int, interval: float, profile: str = "steady", seed: int = 7) -> list[float]:
    """Create deterministic timestamps without sleeping or sending traffic."""
    if count < 0:
        raise ValueError("count cannot be negative")
    if interval < 0:
        raise ValueError("interval cannot be negative")
    if profile not in {"burst", "steady", "variable"}:
        raise ValueError("profile must be burst, steady, or variable")
    if profile == "burst":
        return [0.0] * count
    random = Random(seed)
    timestamps: list[float] = []
    current = 0.0
    for _ in range(count):
        timestamps.append(round(current, 6))
        if profile == "steady":
            current += interval
        else:
            current += interval * random.uniform(0.5, 1.5)
    return timestamps


def frames_to_events(frames: list[Frame], source: str = "offline-lab") -> list[Event]:
    return [Event(frame.channel, source, frame.timestamp, frame.wire_value,
                  frame.payload_size, expected=True) for frame in frames]


@dataclass(frozen=True)
class SimulationReport:
    channel: str
    scheme: str
    input_bytes: int
    encoded_bytes: int
    units: int
    duration_seconds: float
    useful_bandwidth_bps: float
    overhead_ratio: float
    flagged_units: int
    flagged_ratio: float
    mean_detection_score: float
    round_trip_ok: bool
    frames: list[Frame]
    findings: list[Finding]

    def summary(self) -> dict[str, int | float | str | bool]:
        return {
            "channel": self.channel,
            "scheme": self.scheme,
            "input_bytes": self.input_bytes,
            "encoded_bytes": self.encoded_bytes,
            "units": self.units,
            "duration_seconds": self.duration_seconds,
            "useful_bandwidth_bps": self.useful_bandwidth_bps,
            "overhead_ratio": self.overhead_ratio,
            "flagged_units": self.flagged_units,
            "flagged_ratio": self.flagged_ratio,
            "mean_detection_score": self.mean_detection_score,
            "round_trip_ok": self.round_trip_ok,
        }

    def as_dict(self, include_frames: bool = True) -> dict[str, object]:
        result: dict[str, object] = self.summary()
        if include_frames:
            result["frames"] = [asdict(frame) for frame in self.frames]
            result["findings"] = [
                {"score": finding.score, "flagged": finding.flagged, "reasons": list(finding.reasons)}
                for finding in self.findings
            ]
        return result


def simulate(channel_name: str, payload: bytes, scheme: str = "base32",
             chunk_size: int | None = None, interval: float | None = None,
             profile: str = "steady", dns_record_type: str = "TXT") -> SimulationReport:
    """Encode, schedule, inspect, decode, and measure one offline run."""
    channel = get_channel(channel_name, dns_record_type)
    size = chunk_size or DEFAULT_CHUNK_SIZES[channel_name]
    frames = channel.encode(payload, scheme, size)
    spacing = DEFAULT_INTERVALS[channel_name] if interval is None else interval
    frames = with_timestamps(frames, schedule(len(frames), spacing, profile))
    findings = analyze(frames_to_events(frames))
    decoded = channel.decode(frames)
    encoded_bytes = sum(len(frame.wire_value.encode("utf-8")) for frame in frames)
    duration = frames[-1].timestamp - frames[0].timestamp if len(frames) > 1 else 0.0
    effective_duration = duration or spacing or 1.0
    flagged = sum(finding.flagged for finding in findings)
    mean_score = sum(finding.score for finding in findings) / len(findings)
    return SimulationReport(
        channel=channel_name,
        scheme=scheme,
        input_bytes=len(payload),
        encoded_bytes=encoded_bytes,
        units=len(frames),
        duration_seconds=round(duration, 3),
        useful_bandwidth_bps=round(len(payload) / effective_duration, 3),
        overhead_ratio=round(encoded_bytes / len(payload), 3) if payload else 0.0,
        flagged_units=flagged,
        flagged_ratio=round(flagged / len(findings), 3),
        mean_detection_score=round(mean_score, 3),
        round_trip_ok=decoded == payload,
        frames=frames,
        findings=findings,
    )


def comparison(payload_size: int = 512, scheme: str = "base32") -> list[SimulationReport]:
    if not 0 <= payload_size <= 1_000_000:
        raise ValueError("payload_size must be between 0 and 1,000,000 bytes")
    payload = bytes((index * 37 + 11) % 256 for index in range(payload_size))
    return [simulate(name, payload, scheme) for name in CHANNELS]

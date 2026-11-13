"""In-memory channel models. None of these classes perform network I/O."""

from abc import ABC, abstractmethod
from dataclasses import replace

from .encoding import SCHEMES, decode_bytes, encode_bytes
from .models import Frame


def _chunks(payload: bytes, chunk_size: int) -> list[bytes]:
    if not 1 <= chunk_size <= 512:
        raise ValueError("chunk_size must be between 1 and 512 bytes")
    return [payload[index:index + chunk_size] for index in range(0, len(payload), chunk_size)] or [b""]


class Channel(ABC):
    """Common framing and validation for a simulated channel."""

    name: str
    default_chunk_size: int

    def encode(self, payload: bytes, scheme: str = "base32", chunk_size: int | None = None) -> list[Frame]:
        if scheme not in SCHEMES:
            raise ValueError(f"scheme must be one of: {', '.join(SCHEMES)}")
        pieces = _chunks(payload, chunk_size or self.default_chunk_size)
        total = len(pieces)
        return [self._make_frame(index, total, scheme, encode_bytes(piece, scheme))
                for index, piece in enumerate(pieces)]

    def decode(self, frames: list[Frame]) -> bytes:
        if not frames:
            raise ValueError("at least one frame is required")
        parsed = [self._parse_frame(frame) for frame in frames]
        totals = {item[1] for item in parsed}
        schemes = {item[2] for item in parsed}
        if len(totals) != 1 or len(schemes) != 1:
            raise ValueError("frames disagree about their total or encoding scheme")
        total = totals.pop()
        by_sequence = {item[0]: item[3] for item in parsed}
        if len(by_sequence) != len(parsed):
            raise ValueError("duplicate frame sequence")
        if set(by_sequence) != set(range(total)):
            raise ValueError("frame sequence is incomplete")
        scheme = schemes.pop()
        return b"".join(decode_bytes(by_sequence[index], scheme) for index in range(total))

    @abstractmethod
    def _make_frame(self, sequence: int, total: int, scheme: str, token: str) -> Frame:
        raise NotImplementedError

    @abstractmethod
    def _parse_frame(self, frame: Frame) -> tuple[int, int, str, str]:
        raise NotImplementedError


class DNSChannel(Channel):
    name = "dns"
    default_chunk_size = 24

    def __init__(self, record_type: str = "TXT") -> None:
        record_type = record_type.upper()
        if record_type not in {"A", "AAAA", "TXT", "MX"}:
            raise ValueError("record_type must be A, AAAA, TXT, or MX")
        self.record_type = record_type

    def _make_frame(self, sequence: int, total: int, scheme: str, token: str) -> Frame:
        label = f"{sequence:04d}-{total:04d}-{scheme}-{token}"
        if len(label) > 63:
            raise ValueError("chunk_size is too large for a DNS label")
        value = f"{label}.{self.record_type.lower()}.training.invalid"
        return Frame(self.name, sequence, total, 0.0, value, len(token),
                     {"scheme": scheme, "record_type": self.record_type, "direction": "query"})

    def _parse_frame(self, frame: Frame) -> tuple[int, int, str, str]:
        if frame.channel != self.name:
            raise ValueError("frame belongs to a different channel")
        try:
            sequence, total, scheme, token = frame.wire_value.split(".", 1)[0].split("-", 3)
            return int(sequence), int(total), scheme, token
        except (ValueError, IndexError) as exc:
            raise ValueError("malformed DNS simulation frame") from exc


class ICMPChannel(Channel):
    name = "icmp"
    default_chunk_size = 96

    def _make_frame(self, sequence: int, total: int, scheme: str, token: str) -> Frame:
        value = f"LAB1|{sequence}|{total}|{scheme}|{token}"
        return Frame(self.name, sequence, total, 0.0, value, len(value.encode("ascii")),
                     {"scheme": scheme, "icmp_type": "echo-request", "identifier": "4242"})

    def _parse_frame(self, frame: Frame) -> tuple[int, int, str, str]:
        if frame.channel != self.name:
            raise ValueError("frame belongs to a different channel")
        try:
            marker, sequence, total, scheme, token = frame.wire_value.split("|", 4)
            if marker != "LAB1":
                raise ValueError
            return int(sequence), int(total), scheme, token
        except ValueError as exc:
            raise ValueError("malformed ICMP simulation frame") from exc


class HTTPHeaderChannel(Channel):
    name = "http"
    default_chunk_size = 72

    def __init__(self, header_name: str = "X-Covert-Lab") -> None:
        if not header_name.startswith("X-") or any(character.isspace() for character in header_name):
            raise ValueError("the simulation requires an explicit X- lab header")
        self.header_name = header_name

    def _make_frame(self, sequence: int, total: int, scheme: str, token: str) -> Frame:
        value = f"lab/1;part={sequence}/{total};codec={scheme};data={token}"
        return Frame(self.name, sequence, total, 0.0, value, len(value.encode("ascii")),
                     {"scheme": scheme, "header_name": self.header_name, "method": "SIMULATED"})

    def _parse_frame(self, frame: Frame) -> tuple[int, int, str, str]:
        if frame.channel != self.name:
            raise ValueError("frame belongs to a different channel")
        try:
            marker, part, codec, data = frame.wire_value.split(";", 3)
            if marker != "lab/1":
                raise ValueError
            sequence, total = part.removeprefix("part=").split("/", 1)
            return int(sequence), int(total), codec.removeprefix("codec="), data.removeprefix("data=")
        except ValueError as exc:
            raise ValueError("malformed HTTP simulation frame") from exc


class MetadataChannel(Channel):
    """A synthetic metadata map; it never edits an image or document."""

    name = "metadata"
    default_chunk_size = 72

    def _make_frame(self, sequence: int, total: int, scheme: str, token: str) -> Frame:
        value = f"lab_part_{sequence:04d}/{total:04d}={scheme}:{token}"
        return Frame(self.name, sequence, total, 0.0, value, len(value.encode("ascii")),
                     {"scheme": scheme, "property": f"lab_part_{sequence:04d}", "artifact": "memory-only"})

    def _parse_frame(self, frame: Frame) -> tuple[int, int, str, str]:
        if frame.channel != self.name:
            raise ValueError("frame belongs to a different channel")
        try:
            part, encoded = frame.wire_value.split("=", 1)
            sequence, total = part.removeprefix("lab_part_").split("/", 1)
            scheme, token = encoded.split(":", 1)
            return int(sequence), int(total), scheme, token
        except ValueError as exc:
            raise ValueError("malformed metadata simulation frame") from exc


CHANNELS = {
    "dns": DNSChannel,
    "icmp": ICMPChannel,
    "http": HTTPHeaderChannel,
    "metadata": MetadataChannel,
}


def get_channel(name: str, dns_record_type: str = "TXT") -> Channel:
    try:
        if name == "dns":
            return DNSChannel(dns_record_type)
        return CHANNELS[name]()
    except KeyError as exc:
        raise ValueError(f"unknown channel: {name}") from exc


def with_timestamps(frames: list[Frame], timestamps: list[float]) -> list[Frame]:
    if len(frames) != len(timestamps):
        raise ValueError("each frame needs one timestamp")
    return [replace(frame, timestamp=timestamp) for frame, timestamp in zip(frames, timestamps)]

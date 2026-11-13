"""Explainable signals for synthetic network metadata."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from math import log2

from .models import Event


@dataclass(frozen=True)
class Finding:
    event: Event
    score: int
    reasons: tuple[str, ...]

    @property
    def flagged(self) -> bool:
        return self.score >= 2


def entropy(value: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * log2(count / length) for count in counts.values())


def _dns_domain(name: str) -> str:
    labels = name.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name.lower()


def analyze(events: list[Event]) -> list[Finding]:
    """Score records with context from other records in the same batch."""
    dns_names: dict[tuple[str, str], set[str]] = defaultdict(set)
    icmp_times: dict[str, list[float]] = defaultdict(list)
    for event in events:
        if event.kind == "dns":
            dns_names[(event.source, _dns_domain(event.value))].add(event.value.lower())
        elif event.kind == "icmp":
            icmp_times[event.source].append(event.timestamp)

    regular_icmp = set()
    for source, times in icmp_times.items():
        ordered = sorted(times)
        gaps = [b - a for a, b in zip(ordered, ordered[1:])]
        if len(gaps) >= 3 and min(gaps) > 0 and max(gaps) - min(gaps) <= 0.05:
            regular_icmp.add(source)

    findings = []
    for event in events:
        reasons: list[str] = []
        if event.kind == "dns":
            labels = event.value.rstrip(".").split(".")
            if any(len(label) > 40 for label in labels):
                reasons.append("long DNS label")
            if labels and len(labels[0]) >= 20 and entropy(labels[0]) >= 4.0:
                reasons.append("high-entropy first DNS label")
            if len(dns_names[(event.source, _dns_domain(event.value))]) >= 5:
                reasons.append("many distinct names under one domain")
        elif event.kind == "icmp":
            if event.payload_size > 128:
                reasons.append("large ICMP payload")
            if event.source in regular_icmp:
                reasons.append("regular ICMP timing")
        elif event.kind == "http":
            if len(event.value) > 120:
                reasons.append("long HTTP header value")
            if len(event.value) >= 40 and entropy(event.value) >= 4.5:
                reasons.append("high-entropy HTTP header value")
        else:
            if event.value.startswith("lab_part_"):
                reasons.append("unusual synthetic metadata property")
            if len(event.value) > 120:
                reasons.append("large metadata value")
            if len(event.value) >= 40 and entropy(event.value) >= 4.5:
                reasons.append("high-entropy metadata value")
        findings.append(Finding(event, len(reasons), tuple(reasons)))
    return findings

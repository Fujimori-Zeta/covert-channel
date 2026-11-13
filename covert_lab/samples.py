"""Deterministic synthetic records for demos and tests."""

from .models import Event


def sample_events() -> list[Event]:
    events = [
        Event("dns", "workstation-a", 0, "docs.example.org"),
        Event("http", "workstation-a", 1, "Mozilla/5.0 (Training Browser)"),
        Event("icmp", "monitor-a", 2, payload_size=32),
        Event("http", "workstation-b", 3, "trace-1234"),
    ]
    labels = [
        "q7p2m9x4b8n3v6c1z5k0r2t4",
        "m3q8v1x6b9p2c7n4z0k5r1t8",
        "v9c2x7m4q1b8n3p6z5k0r2t4",
        "b1n8q3x6m9v2c7p4z0k5r1t8",
        "x4v9q2m7b1c8n3p6z5k0r2t4",
    ]
    events.extend(
        Event("dns", "lab-host", 10 + index, f"{label}.training.invalid", expected=True)
        for index, label in enumerate(labels)
    )
    events.extend(
        Event("icmp", "lab-host", 20 + index, payload_size=256, expected=True)
        for index in range(5)
    )
    varied_header = "".join(chr(code) for code in range(33, 127)) * 2
    events.append(Event("http", "lab-host", 30, varied_header, expected=True))
    return events

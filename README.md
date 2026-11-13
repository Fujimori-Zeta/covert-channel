# Covert Channel Detection Lab

An offline framework for studying how covert-channel-shaped data appears to defenders. It can encode and reconstruct bytes through inspectable DNS, ICMP, HTTP-header, and document-metadata **models**, then measure bandwidth, latency, overhead, and how often transparent detection rules flag the generated records.

Every channel stops at a Python object. The project never opens a socket, constructs a raw packet, sends an HTTP request, edits a real document or image, reads payload files, or adapts itself to avoid a detector.

## Quick start

Python 3.10 or newer is enough; there are no third-party dependencies.

```sh
python -m covert_lab
python -m covert_lab simulate --channel dns --text "authorized lab sample"
python -m covert_lab simulate --channel dns --dns-record-type MX --scheme hex
python -m covert_lab simulate --channel icmp --scheme hex --profile variable --json
python -m covert_lab compare --bytes 512
python -m covert_lab detect --input examples/events.jsonl
python -m unittest discover -s tests -v
```

Running the module with no command prints a comparison of every channel.

## Implemented capabilities

| Area | What the lab implements |
| --- | --- |
| Reversible encodings | Base32, hexadecimal, and URL-safe Base64 with binary round-trip tests |
| DNS | Chunked subdomain records with sequence numbers and simulated A, AAAA, TXT, or MX metadata |
| ICMP | Inspectable echo-request envelopes with identifiers, sequence numbers, and payload-size accounting |
| HTTP | Explicit `X-Covert-Lab` header values; no browser imitation and no requests |
| File metadata | An in-memory metadata-property model; no JPEG, PDF, Office, or LSB file modification |
| Pacing | Burst, steady, and deterministic variable timestamp profiles; no sleeping or transmission |
| Detection | Long/high-entropy values, DNS fan-out, ICMP size/timing, and unusual metadata properties |
| Measurement | Unit count, simulated duration, useful bandwidth, encoding overhead, detection ratio, and round-trip integrity |
| Evaluation | Labeled samples, precision/recall, per-finding reasons, and cross-channel comparisons |

The frames are deliberately marked as lab data. This makes the mechanics and detector behavior easy to inspect without producing a deployable tunneling tool.

## How a run works

1. The selected channel splits input bytes into bounded chunks.
2. Each chunk is encoded and wrapped in a numbered, human-readable frame.
3. A pacing profile assigns synthetic timestamps.
4. The detector scores the resulting records and records its reasons.
5. Frames are decoded, reordered by sequence, and checked against the original bytes.
6. The report compares input size, framed size, duration, throughput, and detector results.

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the metrics and experiment design, and [docs/DEFENSIVE_GUIDE.md](docs/DEFENSIVE_GUIDE.md) for investigation context, evaluation steps, controls, and ATT&CK references.

## Sanitized event input

`detect` accepts newline-delimited JSON. Each line needs `kind`, `source`, and `timestamp`; it may also include `value`, `payload_size`, and `expected`.

```json
{"kind":"dns","source":"demo","timestamp":0,"value":"docs.example.org","expected":false}
```

Allowed kinds are `dns`, `icmp`, `http`, and `metadata`. Use exported or hand-built metadata only; this project does not capture traffic.

## Project layout

- `covert_lab/encoding.py`: reversible text encodings
- `covert_lab/channels.py`: in-memory channel frames and decoders
- `covert_lab/simulation.py`: pacing, orchestration, and measurement
- `covert_lab/detectors.py`: explainable detection rules
- `covert_lab/report.py`: labeled detection metrics
- `covert_lab/__main__.py`: command-line interface
- `tests/test_lab.py`: round-trip, validation, detector, and measurement tests

## Scope

This project is for authorized defensive training and reproducible classroom experiments. It intentionally excludes live tunneling, packet transmission, browser impersonation, interception bypass, real-file steganography, adaptive evasion, and monitoring-aware behavior changes.

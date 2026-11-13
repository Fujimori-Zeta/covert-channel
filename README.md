# Covert Channel Detection Lab

A small, offline lab for learning what unusual DNS, ICMP, and HTTP traffic can look like to a defender. It generates **synthetic records**, scores them with explainable rules, and prints a short report. It never opens a socket, captures packets, reads private files, or sends data anywhere.

The examples are deliberately simple. They are useful for discussing signals and false positives, not for claiming that a real DLP product will catch every covert channel.

## Try it

Python 3.10 or newer is enough; there are no third-party dependencies.

```sh
python -m covert_lab
python -m unittest discover -s tests -v
```

Pass `--json` for a machine-readable report or `--input path/to/events.jsonl` to score your own **sanitized** records. Each JSON line needs a `kind` (`dns`, `icmp`, or `http`) and the fields shown in `examples/events.jsonl`. The lab does not send these records over the network.

## What the rules look for

| Record | Signals | Common innocent explanations |
| --- | --- | --- |
| DNS | Long or high-entropy labels, many distinct subdomains of one domain | CDNs, tracking links, service discovery |
| ICMP | Large payloads or unusually regular intervals | Diagnostics, monitoring probes |
| HTTP | Long or high-entropy header values | Tokens, tracing headers, application metadata |

The score is a teaching aid, not a verdict. Inspect the reasons and surrounding context before investigating a host. The included sample has benign and suspicious-looking synthetic records so you can see both outcomes.

## Project layout

- `covert_lab/models.py`: validation and record types
- `covert_lab/detectors.py`: transparent scoring rules
- `covert_lab/samples.py`: reproducible synthetic examples
- `covert_lab/report.py`: summary metrics
- `covert_lab/__main__.py`: command-line interface

## Scope

This project supports authorized defensive training. It intentionally excludes live tunneling, exfiltration, stealth timing, adaptive evasion, and interception bypass. For real assessments, use an approved test plan and your organization's monitoring data.

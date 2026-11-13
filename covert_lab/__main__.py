"""Command-line interface for the offline lab."""

import argparse
import json
from pathlib import Path

from .channels import CHANNELS
from .detectors import analyze
from .encoding import SCHEMES
from .models import Event
from .report import metrics
from .samples import sample_events
from .simulation import comparison, simulate


def load_events(path: Path) -> list[Event]:
    events = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                events.append(Event.from_dict(json.loads(line)))
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return events


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explore covert-channel indicators without sending network traffic"
    )
    subparsers = parser.add_subparsers(dest="command")

    detect = subparsers.add_parser("detect", help="score sanitized JSONL records")
    detect.add_argument("--input", type=Path, help="JSONL records; defaults to the built-in sample")
    detect.add_argument("--json", action="store_true", help="print machine-readable output")

    run = subparsers.add_parser("simulate", help="run an in-memory encode/decode exercise")
    run.add_argument("--channel", choices=CHANNELS, default="dns")
    run.add_argument("--text", default="authorized offline lab sample")
    run.add_argument("--scheme", choices=SCHEMES, default="base32")
    run.add_argument("--chunk-size", type=int)
    run.add_argument("--interval", type=float)
    run.add_argument("--profile", choices=("burst", "steady", "variable"), default="steady")
    run.add_argument("--dns-record-type", choices=("A", "AAAA", "TXT", "MX"), default="TXT")
    run.add_argument("--json", action="store_true")

    compare = subparsers.add_parser("compare", help="compare every simulated channel")
    compare.add_argument("--bytes", type=int, default=512, dest="payload_size")
    compare.add_argument("--scheme", choices=SCHEMES, default="base32")
    compare.add_argument("--json", action="store_true")
    return parser


def _print_detection(events: list[Event], as_json: bool) -> None:
    findings = analyze(events)
    summary = metrics(findings)
    if as_json:
        print(json.dumps({"summary": summary, "findings": [
            {"kind": item.event.kind, "source": item.event.source,
             "score": item.score, "flagged": item.flagged, "reasons": item.reasons}
            for item in findings
        ]}, indent=2))
        return
    print(f"Scored {summary['records']} records; flagged {summary['flagged']}.")
    print(f"Precision: {summary['precision']:.3f}  Recall: {summary['recall']:.3f}")
    for item in findings:
        if item.flagged:
            print(f"- {item.event.kind.upper()} from {item.event.source}: {', '.join(item.reasons)}")


def _print_report(report, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.as_dict(), indent=2))
        return
    print(f"{report.channel.upper()} / {report.scheme}: {report.input_bytes} input bytes")
    print(f"Units: {report.units}  Duration: {report.duration_seconds:.3f}s  "
          f"Useful bandwidth: {report.useful_bandwidth_bps:.3f} B/s")
    print(f"Overhead: {report.overhead_ratio:.3f}x  Flagged: "
          f"{report.flagged_units}/{report.units}  Round trip: {report.round_trip_ok}")


def _print_comparison(reports, as_json: bool) -> None:
    if as_json:
        print(json.dumps([report.summary() for report in reports], indent=2))
        return
    print("channel   units  duration  bandwidth(B/s)  overhead  flagged  round-trip")
    for report in reports:
        print(f"{report.channel:<9} {report.units:>5}  {report.duration_seconds:>8.3f}  "
              f"{report.useful_bandwidth_bps:>14.3f}  {report.overhead_ratio:>8.3f}  "
              f"{report.flagged_ratio:>7.3f}  {str(report.round_trip_ok):>10}")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        if args.command == "detect":
            events = load_events(args.input) if args.input else sample_events()
            _print_detection(events, args.json)
        elif args.command == "simulate":
            report = simulate(args.channel, args.text.encode("utf-8"), args.scheme,
                              args.chunk_size, args.interval, args.profile, args.dns_record_type)
            _print_report(report, args.json)
        else:
            reports = comparison(
                getattr(args, "payload_size", 512), getattr(args, "scheme", "base32")
            )
            _print_comparison(reports, getattr(args, "json", False))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()

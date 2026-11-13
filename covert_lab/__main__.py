"""Run the offline lab from the command line."""

import argparse
import json
from pathlib import Path

from .detectors import analyze
from .models import Event
from .report import metrics
from .samples import sample_events


def load_events(path: Path) -> list[Event]:
    events = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                events.append(Event.from_dict(json.loads(line)))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Score offline synthetic network records")
    parser.add_argument("--input", type=Path, help="JSONL file of sanitized records")
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    args = parser.parse_args()
    try:
        events = load_events(args.input) if args.input else sample_events()
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    findings = analyze(events)
    summary = metrics(findings)
    if args.json:
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


if __name__ == "__main__":
    main()

"""Summarize the exercise without hiding individual reasons."""

from .detectors import Finding


def metrics(findings: list[Finding]) -> dict[str, int | float]:
    true_positive = sum(item.flagged and item.event.expected for item in findings)
    false_positive = sum(item.flagged and not item.event.expected for item in findings)
    false_negative = sum(not item.flagged and item.event.expected for item in findings)
    true_negative = sum(not item.flagged and not item.event.expected for item in findings)
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    return {
        "records": len(findings),
        "flagged": true_positive + false_positive,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
    }

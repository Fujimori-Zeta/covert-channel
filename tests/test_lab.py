import unittest

from covert_lab.detectors import analyze, entropy
from covert_lab.models import Event
from covert_lab.report import metrics
from covert_lab.samples import sample_events


class LabTests(unittest.TestCase):
    def test_empty_batch(self):
        self.assertEqual(analyze([]), [])
        self.assertEqual(metrics([])["precision"], 0.0)

    def test_sample_has_explainable_findings(self):
        findings = analyze(sample_events())
        summary = metrics(findings)
        self.assertGreater(summary["true_positive"], 0)
        self.assertEqual(summary["false_positive"], 0)
        self.assertTrue(all(item.reasons for item in findings if item.flagged))

    def test_regular_timing_needs_enough_observations(self):
        few = [Event("icmp", "a", float(i), payload_size=32) for i in range(3)]
        self.assertTrue(all(item.score == 0 for item in analyze(few)))

    def test_validation(self):
        with self.assertRaisesRegex(ValueError, "payload_size"):
            Event.from_dict({"kind": "icmp", "source": "a", "timestamp": 0, "payload_size": -1})

    def test_entropy(self):
        self.assertEqual(entropy(""), 0.0)
        self.assertEqual(entropy("aaaa"), 0.0)
        self.assertEqual(entropy("ab"), 1.0)


if __name__ == "__main__":
    unittest.main()

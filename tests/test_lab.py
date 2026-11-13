import unittest

from covert_lab.channels import CHANNELS, get_channel, with_timestamps
from covert_lab.detectors import analyze, entropy
from covert_lab.encoding import SCHEMES, decode_bytes, encode_bytes
from covert_lab.models import Event
from covert_lab.report import metrics
from covert_lab.samples import sample_events
from covert_lab.simulation import comparison, schedule, simulate


class EncodingTests(unittest.TestCase):
    def test_every_scheme_round_trips_binary_data(self):
        payload = bytes(range(256))
        for scheme in SCHEMES:
            with self.subTest(scheme=scheme):
                self.assertEqual(decode_bytes(encode_bytes(payload, scheme), scheme), payload)

    def test_every_channel_round_trips_out_of_order_frames(self):
        payload = b"A human-readable offline exercise" * 20
        for name in CHANNELS:
            for scheme in SCHEMES:
                with self.subTest(channel=name, scheme=scheme):
                    channel = get_channel(name)
                    frames = channel.encode(payload, scheme)
                    self.assertEqual(channel.decode(list(reversed(frames))), payload)

    def test_missing_frame_is_rejected(self):
        channel = get_channel("icmp")
        frames = channel.encode(b"x" * 300)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            channel.decode(frames[:-1])

    def test_dns_record_type_variants_are_labeled_and_reversible(self):
        for record_type in ("A", "AAAA", "TXT", "MX"):
            with self.subTest(record_type=record_type):
                channel = get_channel("dns", record_type)
                frames = channel.encode(b"record type exercise")
                self.assertEqual(frames[0].metadata["record_type"], record_type)
                self.assertEqual(channel.decode(frames), b"record type exercise")


class SimulationTests(unittest.TestCase):
    def test_schedule_is_deterministic(self):
        self.assertEqual(schedule(4, 1.0), [0.0, 1.0, 2.0, 3.0])
        self.assertEqual(schedule(3, 1.0, "variable"), schedule(3, 1.0, "variable"))

    def test_simulation_reports_round_trip_and_metrics(self):
        report = simulate("dns", b"measurement payload" * 30)
        self.assertTrue(report.round_trip_ok)
        self.assertGreater(report.encoded_bytes, report.input_bytes)
        self.assertGreater(report.units, 1)

    def test_comparison_covers_every_channel(self):
        reports = comparison(512)
        self.assertEqual({report.channel for report in reports}, set(CHANNELS))
        self.assertTrue(all(report.round_trip_ok for report in reports))

    def test_timestamp_count_must_match(self):
        frames = get_channel("http").encode(b"hello")
        with self.assertRaisesRegex(ValueError, "timestamp"):
            with_timestamps(frames, [])


class DetectionTests(unittest.TestCase):
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

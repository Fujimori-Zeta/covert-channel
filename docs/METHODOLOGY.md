# Experiment methodology

The lab treats a channel as a reversible transformation from bytes to a list of inspectable frames. Frames contain a sequence number, total count, synthetic timestamp, rendered value, and metadata describing the model. No frame is sent anywhere.

## Metrics

- **Input bytes**: length of the original payload.
- **Encoded bytes**: UTF-8 length of every rendered frame value, including framing text.
- **Overhead ratio**: encoded bytes divided by input bytes.
- **Duration**: last synthetic timestamp minus the first.
- **Useful bandwidth**: input bytes divided by the simulated duration. A single-frame or zero-duration run uses the configured interval, then one second if the interval is also zero.
- **Flagged ratio**: frames whose detector score reaches two divided by all frames.
- **Mean detection score**: average number of independent rule signals per frame.
- **Round-trip integrity**: whether reassembled bytes exactly equal the input.

These numbers compare this project's models; they are not measurements of a real network, product, or DLP deployment.

## Pacing profiles

`burst` assigns timestamp zero to every frame. `steady` uses a fixed interval. `variable` uses a seeded pseudorandom multiplier between 0.5 and 1.5, which keeps runs reproducible. The scheduler only calculates numbers and never sleeps.

## Detection experiment

Each simulated frame becomes a labeled event. Transparent rules inspect DNS label shape and fan-out, ICMP payload size and timing regularity, HTTP value length and entropy, and metadata property shape and entropy. The scoring threshold is intentionally simple so every decision can be explained.

Use the reported precision and recall only with the included labels or a carefully reviewed sanitized dataset. The rules are demonstrations, not production signatures.

## Reproducibility

The framework has no external dependencies, the variable scheduler uses a fixed seed, the comparison payload is deterministic, and all channel/encoding combinations have binary round-trip tests.

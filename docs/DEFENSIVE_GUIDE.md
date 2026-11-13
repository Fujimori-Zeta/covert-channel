# Defensive guide

Covert channels reuse fields that ordinary applications also need, so a single long value or periodic request is rarely enough to justify an incident. The lab combines small, explainable signals and keeps the raw reason attached to every score.

## Signals and context

| Area | Useful signals | Common benign explanations |
| --- | --- | --- |
| DNS | Long or high-entropy labels, many unique names below one domain, unexpected record types, unusual requesting process | CDNs, endpoint security, tracking, service discovery |
| ICMP | Payloads that are larger than local norms, repeated sizes, regular timing, unexpected endpoints | Monitoring, path diagnostics, network appliances |
| HTTP | Long or high-entropy header values, rare custom headers, destinations absent from normal browsing | Tracing IDs, authentication tokens, application metadata |
| File metadata | Unknown properties, large encoded values, metadata that changes after handling | Creative tools, document workflows, indexing systems |

Investigate the process, destination, data-access activity, and host role around a finding. Compare a host against its own baseline and its peers before escalating.

## Evaluation workflow

1. Export sanitized metadata from an approved source. Do not feed secrets or packet contents into the lab.
2. Label a small review set before tuning rules.
3. Keep benign controls and synthetic positive cases separate.
4. Record precision, recall, false positives, and false negatives for each rule change.
5. Review misses and noisy applications with network and endpoint context.
6. Re-run the same dataset after changes so the comparison remains reproducible.

The included metrics measure this framework. They do not claim to evaluate a commercial DLP product unless that product's alerts are independently collected and labeled under an approved test plan.

## Defensive controls

- Route DNS through managed resolvers and alert on clients that bypass them.
- Restrict outbound protocols and destinations to what each network segment needs.
- Retain DNS, proxy, firewall, and endpoint process telemetry long enough to correlate events.
- Inspect unusual custom HTTP headers at approved egress points.
- Baseline ICMP use by host role and limit it where it has no operational purpose.
- Scan document metadata at sharing boundaries and remove properties that the workflow does not need.
- Use DLP and intrusion-prevention controls as layers, then test their coverage with non-sensitive synthetic data.

## Threat-framework references

MITRE ATT&CK classifies alternate-protocol exfiltration as [T1048](https://attack.mitre.org/techniques/T1048/) and documents DNS as application-layer protocol abuse under [T1071.004](https://attack.mitre.org/techniques/T1071/004/). Its examples include DNS-based activity attributed to groups such as APT32 and APT41, while the web-protocol entry [T1071.001](https://attack.mitre.org/techniques/T1071/001/) covers abuse of HTTP/S fields. MITRE's mitigations include managed DNS, network filtering, DLP, intrusion prevention, and segmentation.

These references explain why the lab models the selected signals. They are not instructions for reproducing adversary infrastructure.

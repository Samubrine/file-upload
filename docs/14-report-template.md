# Short analysis report — fill after measurements

This is a template. Blank result sections are intentional; do not invent findings.

## Objective and assignment scope
Explain personal-storage workflow, required ciphers, expanded twelve AES configurations and two legacy configurations, and synthetic-data restriction.

## Design decisions
Summarize storage, permissions, key/mode selection, integrity authentication, password hashing, quotas, and no-preview interpretation. Refer to ADR IDs; identify lecturer-dependent interpretations and credential/technical metadata exceptions.

## Methods
State actual environment/build, fixture provenance/hash/bytes, repeated download protocol, warmups/sample count, run ordering, timer boundaries, statistic definitions and failed-run handling.

## Results
Insert measured per-fixture tables: variant, ciphertext/envelope bytes, encryption/decryption median/p95, client full-download median/p95, throughput and successes/failures. Link raw CSV/environment artifact. Add a chart only if it clarifies the actual measurements.

## Discussion
Explain padding/envelope overhead; hardware/library influence; crypto versus database/transport timing; AES key-size/mode differences supported by data; why timing/ciphertext appearance cannot establish security. Explain RC4/DES weakness and replicated weak-copy exposure.

## Verification and limitations
Give real test commands/results, unresolved defects, measurement variability, bounded file sizes/memory, index/access-graph leakage, server trust, revocation/in-flight boundary, synthetic-only privacy scope and deletion remnant limitations.

## Conclusion
State findings supported by results, not invented claims. List what assignment requirements have evidence and what remains unverified.

## References and contributions
Cite legal/library/fixture/vector sources. Attribute original code and each contributor. Disclose AI assistance according to course policy; do not claim compliance with an unknown policy.

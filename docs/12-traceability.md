# Assignment and requirement traceability

Assignment source: two user-supplied slides (Assignment 1 and continuation), transcribed from the visible images. No instructor interpretation beyond the visible text is asserted.

| Slide requirement | Project requirement | Evidence expected |
|---|---|---|
| Group of four | Delivery responsibilities | Contributor list and actual contribution attribution |
| Store private user data in database, reference GDPR/UU PDP | AUTH-01, PROF-01, PRIV-01/02 | Encrypted profile rows, own-profile tests, privacy sources |
| Store ID-card image | FILE-01/02/03 | Synthetic ID-card upload and byte-exact download |
| Store PDF/DOC/XLS | FILE-01/02/03 | Legacy and modern Office + PDF fixtures |
| Store video | FILE-01/02/03 | Valid video fixture, all-variant retrieval |
| All data encrypted with AES/RC4/DES | FILE-02, CRYPTO-01 | Fourteen variant completeness; explicit hash/index/technical-field exceptions |
| Retrieve decrypted data | FILE-03, PROF-01 | Original byte/hash equality across all variants; self-profile retrieval |
| Username/password access | AUTH-02/03 | Valid login, invalid/absent session denial |
| Non-ECB block mode | CRYPTO-01 | CBC/CFB128/OFB/CTR registry, DES-CBC; no ECB |
| Crypto library permitted | CRYPTO-01 | Libraries/version attribution, no custom primitives |
| Bug-free for full mark | QUAL-01 | Executed tests, defect resolution and honest limits |
| Compare time and ciphertext | BENCH-01/02 | Raw runtime/size data, measured analysis |
| Repeated downloads/time measurement | BENCH-01 | 30 runs/variant/fixture after warmups; full-body checks |
| Short analysis report | QUAL-01, BENCH-02 | Filled report template with real results |
| Justify decisions | QUAL-01 | ADRs and alternatives/limitations |
| Plagiarism zero mark | QUAL-01 | Attribution and original contribution declaration according to course policy |

All IDs in product doc must additionally link to actual implementation/test paths in the maintained traceability table during development. Current evidence status for every application requirement: specified, not implemented/verified. Package validation only checks artifacts/links/contracts, not rubric satisfaction.

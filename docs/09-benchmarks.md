# Reproducible comparison protocol

## Questions
Compare cipher/key/mode computation cost, cipher-only length, envelope overhead, and authorized full-download performance on identical plaintext. Do not infer security from speed, ciphertext appearance, or size. Three AES key sizes crossed with four modes form twelve comparisons; DES/RC4 add two legacy references.

## Fixtures and environment
Synthetic text profile JSON, mock ID PNG, sample PDF, DOCX/XLSX, small DOC/XLS, MP4/WebM; include 1 KiB, 1 MiB, 10 MiB random/incompressible binary fixtures for internal crypto benchmark, and near-limit valid image/video for end-to-end checks. Record generator/source, seed where reproducible, plaintext byte count and SHA-256, OS/CPU/RAM, Go/browser versions, build commit, library versions, storage type, hardware AES support, transport, limits and selected config. Fixed fixture seeds are allowed; keys/IVs remain CSPRNG and must never be seeded deterministically outside published primitive vectors.

## Runs
Run local warmed server, sequential jobs, no upload/backup workloads, one persistent authenticated client. Perform 5 warmups then 30 measured repetitions per (fixture,variant), shuffle balanced variant order with recorded order seed. Repeat authorized HTTP downloads, not just crypto microbenchmarks. Force no-store, consume full body, verify checksum each run. Treat failed/truncated/checksum-mismatched runs as failures, not discarded performance data. No outlier removal unless method declared before runs. Record warm-cache conditions; optionally report separate first-download/cold-cache series without mixing it into warm results.

## Timings
Use server monotonic clocks: database read; HKDF; MAC verify; decrypt/unpad; total service preparation. Client monotonic clock: before fetch to full body consumed. Encryption: primitive-only seal operation excluding HKDF/HMAC separately from full envelope creation. Do not describe middleware/DB/network time as pure cipher time. Deliver optional Server-Timing metrics only to authorized downloads under benchmark configuration; production-style default disabled. Local external harness writes measurement CSV without asking server to persist per-user timing records.

CSV fields: run_id, fixture_id, variant_id, iteration, warmup, plaintext_bytes, ciphertext_bytes, envelope_bytes, encrypt_cipher_ns, seal_total_ns, db_read_ns, kdf_ns, mac_verify_ns, decrypt_cipher_ns, open_total_ns, client_download_ns, checksum_ok, http_status, error_code, environment_id. Units explicit; NA for unavailable measures, never zero. Store seed/environment files beside raw CSV.

## Analysis
Report n, successes/failures, median, p95, mean, sample SD (n-1), and throughput MiB/s calculated from plaintext bytes. Define p95 using nearest-rank ceil(0.95*n) on ordered measured samples. Report per-fixture and variant; do not pool radically different sizes. Repeatability claims require repeated batches, not only one run. Microbenchmark and HTTP results are separate tables.

AES CBC length=16*(floor(n/16)+1); DES CBC=8*(floor(n/8)+1). Stream-like modes and RC4 ciphertext length=n. Envelope overhead = 9 + header_bytes + 32; bytes stored include envelope, not base64 expansion of whole ciphertext. Every variant should decrypt to identical original data; different ciphertext is expected from random keys/IVs, not evidence of correctness/security. RC4 key size label does not imply AES-256-equivalent security.

## Outputs
raw CSV + environment.json + summary CSV/charts + reproducible invocation + report. Do not embed fabricated values in UI/report. Browser comparison page reads an explicitly generated static synthetic summary; mark absence “No benchmark results yet.” Result exports contain no real account/file identifiers. Attribute fixtures and dependencies; compare the same functional path for each algorithm.

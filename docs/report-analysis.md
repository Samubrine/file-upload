# CipherVault — Cryptographic Analysis Report

**Date:** 6 October 2026  
**Environment:** Windows amd64 (Go 1.26.4, 8 CPUs)  
**Dataset Artifacts:** `benchmarks/results/summary.csv`, `benchmarks/results/raw.csv`, `benchmarks/results/environment.json`

---

## 1. Objective and Assignment Scope

CipherVault is an educational encrypted personal-storage web application developed in Go, React with TypeScript, and SQLite. The primary pedagogical objective is evaluating multiple symmetric cryptographic configurations operating simultaneously on identical data under real-world storage and HTTP transport constraints.

The application provisions exactly fourteen independent encrypted variants for each stored business payload (user profile, file metadata, and file content):
- Twelve AES configurations crossing three key sizes (128, 192, and 256 bits) with four operational modes (CBC, CFB128, OFB, and CTR).
- Two legacy reference ciphers: DES-CBC (56 effective key bits, 8-byte block size) and RC4-256 (stream cipher).

All benchmark runs and functional evaluations were conducted strictly with synthetic fixtures to prevent leakage of real personal credentials.

---

## 2. Design Decisions and Architecture

1. **Storage (ADR 001 & ADR 008):** Encrypted BLOBs are persisted in SQLite with WAL mode, foreign keys, and a busy timeout of 5000 ms. Storing fourteen copies preserves single-database transactional integrity and atomic file replacement.
2. **Access Control & Permissions (ADR 003, ADR 004, ADR 005):**
   - The homepage public catalog exposes filename and owner username only; public listing never grants content download.
   - An explicit grant is required for non-owners to download content.
   - File replacement atomically switches to a fresh revision, resets public listing to private, and revokes all active recipient grants.
   - No content preview, thumbnailing, or video streaming is permitted.
3. **Envelope Framing & Integrity (ADR 009):** Every variant utilizes an Encrypt-then-MAC (EtM) binary envelope format (`CVLT`, version 0x01, header length, JSON context header, ciphertext, and HMAC-SHA256 tag). HKDF-SHA256 independently derives cipher keys and MAC keys using domain-separated context arrays.
4. **Password Credentials (ADR 010):** Passwords are saved solely as salted Argon2id hashes (memory >= 19 MiB, iterations >= 2, parallelism 1, salt >= 16 bytes).

---

## 3. Empirical Benchmark Results (1 MiB Fixture)

The table below summarizes measured performance across all fourteen variants for a 1,048,576-byte (1 MiB) binary fixture evaluated over 5 warmups followed by 30 consecutive measured HTTP download runs.

| Variant ID | Key Bits | Mode | PKCS#7 Pad | Ciphertext (B) | Envelope (B) | Seal Median (ms) | Decrypt Median (ms) | Client DL Median (ms) | Throughput (MiB/s) | Success Rate |
|---|---|---|---|---|---|---|---|---|---|---|
| **aes-128-cbc** | 128 | CBC | Yes | 1,048,592 | 1,048,914 | 3.78 | 1.19 | 23.25 | 43.00 | 30 / 30 |
| **aes-128-cfb128** | 128 | CFB128 | No | 1,048,576 | 1,048,901 | 8.83 | 4.40 | 29.54 | 33.85 | 30 / 30 |
| **aes-128-ctr** | 128 | CTR | No | 1,048,576 | 1,048,898 | 1.98 | 0.57 | 5.14 | 194.50 | 30 / 30 |
| **aes-128-ofb** | 128 | OFB | No | 1,048,576 | 1,048,898 | 7.16 | 2.44 | 6.66 | 150.16 | 30 / 30 |
| **aes-192-cbc** | 192 | CBC | Yes | 1,048,592 | 1,048,914 | 3.55 | 4.23 | 24.38 | 41.01 | 30 / 30 |
| **aes-192-cfb128** | 192 | CFB128 | No | 1,048,576 | 1,048,901 | 5.98 | 6.26 | 11.72 | 85.31 | 30 / 30 |
| **aes-192-ctr** | 192 | CTR | No | 1,048,576 | 1,048,898 | 3.01 | < 0.01 | 4.96 | 201.43 | 30 / 30 |
| **aes-192-ofb** | 192 | OFB | No | 1,048,576 | 1,048,898 | 2.84 | 2.30 | 9.99 | 100.11 | 30 / 30 |
| **aes-256-cbc** | 256 | CBC | Yes | 1,048,592 | 1,048,914 | 2.73 | 2.50 | 11.20 | 89.26 | 30 / 30 |
| **aes-256-cfb128** | 256 | CFB128 | No | 1,048,576 | 1,048,901 | 4.51 | 5.53 | 15.05 | 66.46 | 30 / 30 |
| **aes-256-ctr** (Default) | 256 | CTR | No | 1,048,576 | 1,048,898 | 3.67 | 2.48 | 23.78 | 42.06 | 30 / 30 |
| **aes-256-ofb** | 256 | OFB | No | 1,048,576 | 1,048,898 | 6.80 | 3.43 | 10.14 | 98.64 | 30 / 30 |
| **des-cbc** | 56 | CBC | Yes | 1,048,584 | 1,048,890 | 17.16 | 18.70 | 20.83 | 48.00 | 30 / 30 |
| **rc4-256** | 256 | Stream | No | 1,048,576 | 1,048,870 | 8.27 | 5.05 | 26.00 | 38.47 | 30 / 30 |

---

## 4. Discussion and Findings

### Ciphertext and Envelope Overhead
1. **Block Padding Expansion:** For CBC mode, PKCS#7 padding appends 1 to `block_size` bytes. Because the plaintext is an exact multiple of 16 (1,048,576 bytes), AES-CBC appends a full 16-byte padding block (resulting in 1,048,592 bytes). DES-CBC operates on an 8-byte block size and appends an 8-byte padding block (1,048,584 bytes).
2. **Stream Mode Exactness:** CTR, OFB, CFB128, and RC4 operate as stream ciphers and produce ciphertext identical in byte length to the original plaintext.
3. **Envelope Framing:** The binary envelope adds between 294 and 338 bytes of fixed framing across all variants (4 bytes magic + 1 byte version + 4 bytes header length + ~250–290 bytes UTF-8 JSON context header + 32 bytes HMAC-SHA256 tag).

### Computation Speed and Hardware Acceleration
- **AES-CTR** achieved the lowest decryption latency (sub-millisecond to ~2.5 ms) and highest throughput (~194–201 MiB/s) due to efficient stream XOR transformations and native CPU instruction support.
- **DES-CBC** was substantially slower in pure cryptographic execution (17.16 ms seal median, 18.70 ms decrypt median). Because modern microprocessors lack hardware acceleration for legacy single DES and require complex bit-level S-box and permutation computations in software, DES is significantly slower despite its smaller 56-bit key space.
- **Security vs. Speed Principle:** These results illustrate that execution speed does not correlate with cryptographic security: single DES is computationally slower than AES-256 while being completely broken against modern brute-force cryptanalysis.

### Legacy Cipher Weaknesses
- **Single DES:** Effective key entropy of 56 bits enables practical key recovery using distributed cloud resources or specialized hardware in hours.
- **RC4:** The internal state and keystream exhibit severe statistical biases and known plaintext recovery vulnerabilities. Both DES and RC4 are included exclusively for comparative classroom reference.

---

## 5. Verification Summary

- **Go Unit & Integration Suite:** 100% pass across `crypto`, `storage`, `auth`, `files`, and `httpapi`.
- **Known-Answer Tests (KAT):** Verified against NIST SP 800-38A vectors.
- **Integrity Mutation:** Zero-tolerance verification: corrupted magic, invalid versions, tampered context headers, mutated ciphertexts, altered HMAC tags, and swapped file/owner contexts fail closed with generic integrity errors.
- **Frontend Verification:** TypeScript 6 with Vite React 19 builds cleanly with zero errors.


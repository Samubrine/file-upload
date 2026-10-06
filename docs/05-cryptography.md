# Cryptography specification

## Exact registry
AES-256-CBC, AES-256-CFB128, AES-256-OFB, AES-256-CTR;
DES-CBC; RC4-256.

Stable wire IDs use lowercase: aes-256-cbc, aes-256-cfb128, aes-256-ofb, aes-256-ctr, des-cbc, rc4-256. Default: aes-256-ctr. Exactly six copies per business payload. No ECB, no chained AES→RC4→DES construction. RC4 is a stream cipher, has no CBC/CFB/OFB/CTR mode. DES is single DES, not Triple DES.

## Cipher parameters
AES uses 16/24/32-byte derived keys and 16-byte IVs. CFB is full-block CFB128, not CFB8. DES uses an 8-byte key (56 effective key bits, parity ignored by typical libraries), 8-byte IV, CBC. RC4 uses a 32-byte key unique to each envelope, no IV, standard RC4 with no implicit drop bytes. DES weak/semiweak derived keys must be rejected and new salt generated; record this behavior in vectors/benchmarks. RC4 and DES are educational, not suitable for safeguarding real personal data. CFB/OFB may be deprecated in Go; isolate required educational usage and document exceptions rather than suppressing broad checks.

CBC adds PKCS#7 even on an exact block multiple; validate every padding byte. CFB128/OFB/CTR/RC4 add no padding. All IVs/salts are fresh cryptographic random bytes. A new upload, profile write, metadata rename, or replacement uses fresh salts/IVs even for identical plaintext. Never reuse a stream state across files or requests.

## Keys
External CRYPTO_ROOT_KEY_<id>: 32 random bytes; active key ID from environment/config, values never in repository/SQLite/logs. Separate IDENTITY_INDEX_KEY and BACKUP_KEY, each 32 random bytes. For each envelope, salt=32 random bytes. HKDF-SHA256 derives encryption key of appropriate length and 32-byte HMAC key separately using domain-separated info encoding [format_version, payload_id, owner_id, file_id-or-null, content_revision, variant_id, purpose]. Encode info as fixed-order compact JSON array bytes. encryption purpose='enc', authentication purpose='mac'. No shared raw DES/AES/RC4 key. Include root_key_id and salt in header. Changing passwords does not change encryption keys. This is server-side encryption at rest; the server can decrypt, and the application is not end-to-end encrypted.

Old root key IDs remain available while referenced; rotation is an offline migration that reseals every affected variant transactionally per payload, verifies byte equivalence, and keeps old key until a database/backup reference inventory permits removal. Index-key rotation requires rebuilding lookup tokens by decrypting profiles with collision checks. No automatic rotation UI. Loss of required keys makes corresponding data unrecoverable; no password recovery is implied. Missing active or referenced root keys fails startup integrity check.

## Envelope v1 binary layout
Magic bytes 'CVLT' (4); format version 0x01 (1); header length uint32 big-endian (4); UTF-8 header JSON bytes; ciphertext bytes; HMAC-SHA256 tag (32). Header max 4096 bytes. Ciphertext length is total length minus framing/header/tag; reject negative/inconsistent/oversized lengths.
Header fields in fixed serialization order: payload_id, owner_id, file_id (null if profile), content_revision, variant_id, root_key_id, salt (base64), iv (base64, empty for RC4), plaintext_bytes (nonnegative integer).
MAC covers exact stored magic/version/header-length/header/ciphertext byte sequence. Never parse and reserialize a header to verify its MAC. Validate framing and supported version, parse bounded header, reject duplicated/unknown fields, derive keys, compare MAC in constant time, validate authenticated context against expected SQL/caller context, then decrypt/padding-check and length-check. Header context is authenticated even if some parser validation precedes authentication. No plaintext emitted before successful authentication. On any failure return one generic integrity failure; never expose padding distinctions.

## Password exception
Passwords are Argon2id hashes with per-password CSPRNG salt >=16 bytes, memory >=19 MiB, iterations >=2, parallelism=1; calibrate reasonable login performance under bounded concurrency and record actual parameters. Store encoded algorithm/params/salt/hash. Plaintext passwords exist only during request handling; never store them as profile data, encrypted payloads, or logs. Hashes are the deliberate credential exception to encrypt-all business payloads.

## Correctness evidence
Known-answer vectors from trusted sources for underlying primitives; roundtrip across all fourteen variants; boundary lengths 0/1/block-1/block/block+1; invalid key/IV/mode; ciphertext/header/tag mutation; cross-user/payload/revision swapping; wrong key ID; CBC invalid padding; repeated identical plaintext creates different envelopes; concurrent RC4 requests never share cipher state. Internal empty payload tests are required even though empty file uploads are rejected.

# Decisions and change log

Baseline v1.0, 6 October 2026. Confirmed scope and delegated defaults distinguished below. To amend: append an ADR with reason, alternatives, effect on requirement IDs, contracts, tests, migration/backward compatibility, and decision authority; update canonical docs. Do not silently overwrite history.

| ADR | Decision | Authority / rationale |
|---|---|---|
| 001 | Go + React + SQLite | User-selected stack. |
| 002 | Fourteen independent payload variants | User approved separate ciphers and AES key sizes/modes; selected CBC/CFB128/OFB/CTR from assignment, DES-CBC and RC4-256 defaults. |
| 003 | No content preview | User explicitly means filename/owner metadata only. |
| 004 | Authenticated-only homepage | User-selected audience; listed metadata does not grant content. |
| 005 | Owner rename/replace/delete; replace resets ACL/listing | Owner capabilities confirmed; reset chosen to prevent new-data oversharing. |
| 006 | Five profile field types, birthday optional | User fixed field set; optional date selected for minimisation, no extra fields. |
| 007 | Owner identity is username | Chosen to keep full name private while meeting owner display. |
| 008 | SQLite encrypted BLOBs with bounded sizes | One transactional store for small classroom use; accept fourteen-copy footprint. |
| 009 | EtM for all comparison ciphers; external HKDF root | Integrity and version/context binding without falsely strengthening weak confidentiality. |
| 010 | Argon2id password hash and keyed identity lookups | Password/security exception to reversible business encryption; exact-match identity without plaintext indexes. |
| 011 | AES-256-CTR default retrieval | Assignment-listed mode with HMAC, consistent envelope path; no expanded GCM comparison. |
| 012 | Same-origin server sessions + CSRF | Avoid unnecessary JWT/token storage and cross-origin setup. |
| 013 | Synthetic classroom data; no compliance claim | Weak required ciphers and unexplored deployment applicability. |
| 014 | English restrained light-theme UI | Delegated design default, no content thumbnails. |
| 015 | No recovery, no retained revisions or external messaging | Recovery explicitly excluded; rest reduce assignment scope. |

## External grading dependencies
Lecturer has not confirmed the fourteen-copy interpretation, the four selected AES modes, or technical index/hash exceptions. Assignment may count modes differently. Documentation makes choices explicit without inventing approval. If clarified differently, amend registry/traceability and all affected acceptance checks together.

## Security hardening decisions (14 October 2026)

Recorded during the security audit (docs/security-audit.md). Each entry names the requirement it affects and the test that proves it.

| ADR | Decision | Authority / rationale | Effect on requirements, contracts and tests |
|---|---|---|---|
| 011 | Passwords are hashed with bcrypt (DefaultCost). Passwords over 72 UTF-8 bytes are refused with 422, never truncated. | User instruction to use bcrypt; bcrypt silently ignores bytes after 72, so two different passwords could log in to one account. Existing Argon2id hashes still verify. | AUTH-01 and PROF-01 input limits; docs/05 password section; contracts/openapi.json Register and PasswordChange descriptions. Tests: httpapi sec_v04_bcrypt_test.go. |
| 012 | Upload allowlist is the 12 specified extensions plus .jpe, .jfif, .gif, .bmp, .tif, .tiff, .m4v and .mkv. Every type must match its file signature. SVG, archives, plaintext, macro-enabled and legacy presentation formats are refused. | User decision to keep only aliases whose signatures can be verified. | FILE-01 allowlist in docs/01-product.md. Tests: files sec_v09_allowlist_test.go, sec_v10_filename_test.go. |
| 013 | With no key environment variables, the server generates random 32-byte development keys into data/dev-keys.json (owner-only, gitignored). No key constant is compiled in. Environment keys take priority. | User decision. Development convenience only: deleting the file makes development data unrecoverable, as documented in docs/05. | CRYPTO-01 key management. Test: cmd/server devkeys_test.go. |
| 014 | Browser-facing hardening: mutating requests from another origin are refused (Origin and Sec-Fetch-Site checks against -public-origin); login, registration and grant changes are rate limited in memory; -secure-cookies enables the __Host- cookie prefix, Secure, and HSTS; every response carries a restrictive Content-Security-Policy. | Plan approved by user. The app is a single process, so in-memory state is sufficient. | PRIV-01 and UX-01. Contracts: 429 and 413 responses in contracts/openapi.json. Tests: sec_v03, sec_v06, sec_v15, sec_v16_17. |


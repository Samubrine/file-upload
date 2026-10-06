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

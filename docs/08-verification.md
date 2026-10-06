# Verification and acceptance evidence

No tests have run against an application because it has not been implemented. This document specifies required evidence; packaging validation is distinct from software validation.

## Layers
Go unit tests for registry, envelope/keys/padding, quotas, validation, permission predicate. Database integration tests with real temporary SQLite and foreign_keys/WAL configuration. HTTP integration tests for auth/CSRF/ACL and DTO filtering. React typecheck/build, component behavior tests for permission states, and browser end-to-end workflows. Go race check on concurrent upload/download/revoke/replace and SQL transaction rollback cases. OpenAPI contract checks for actual responses.

## Critical cases
- Register and login synthetic user; reject duplicate normalized identity, future/invalid birthday, oversize password, bad credentials. Own profile only; change password invalidates prior sessions.
- Every allowed category including mock ID image, legacy DOC/XLS and DOCX/XLSX, videos; reject spoofed extension/MIME, encrypted Office containers, empty files, oversized requests and filename controls.
- Byte-exact downloads for fourteen variants, including image/document/video fixtures. Original checksum computed in memory by test; never treat ciphertext checksum as integrity authentication.
- User A owner, B metadata-only, C download, D unrelated, E visitor. Apply every permissions-matrix cell for hidden/listed state. Check HTTP responses contain only permitted fields and no content request from listing UI.
- Owner-only rename/delete/replace/listing/grants; arbitrary file IDs do not bypass checks; stale If-Match → 409. Download permission valid on hidden file; listing alone denied download.
- Replace resets grants/listing; unauthorized new revision rejected; old payloads removed; failed replacement keeps old file/download intact.
- Missing any one variant causes upload transaction rollback; storage full/quota races/cancelled request leave no orphan payloads/reservations.
- Revoke committed before authorization blocks download. Already authorized transfer may finish, matching documented boundary.
- Tamper header/tag/ciphertext; wrong root key; swap payload/owner/revision; no emitted plaintext and generic error. Missing referenced key blocks startup.
- Delete file/account; all payload/grant/session rows disappear including referenced parent payloads. Backup expiry/remnant limitation is verified/documented, not promised away.
- Listing/grant/profile API DTOs, logs, errors and database query fields inspected for accidental plaintext exposure.
- Session cookie flags, CSRF/Origin enforcement, login throttling, SQL injection strings and stored-XSS filenames; uploads served only as attachment.
- Mobile/desktop keyboard flows, modal focus, error states, no-download metadata state, screen reader labels and contrast.

## Done criteria
Each requirement ID linked to actual test/evidence file; all mandatory checks pass with commands/output stored in handoff; known limitations listed; no unresolved critical auth/data-loss defects; benchmark results reproducible; short report filled from real outputs; cited library/code/vector sources attributed. “Bug-free” rubric is addressed through evidence and defect resolution, never an absolute claim.

# Architecture

## Selected platform
Single Go process plus React/TypeScript static build, same origin. Go standard net/http routing and maintained SQLite driver through database/sql. React built with Vite. Resolve stable supported versions during implementation and pin Go toolchain, go.sum, and npm lockfile. No additional framework is mandatory.

## Components
| Unit | Responsibility | Boundary |
|---|---|---|
| HTTP/middleware | Session, CSRF, request validation/limits, DTO filtering | Calls services; never makes independent ACL rules |
| Auth | Registration/login/logout, Argon2id, session lifecycle | Uses user repository and dedicated identity index |
| Users | Profile updates/export/deletion | Only current user; encrypted business payloads |
| Files | Validate uploads, quotas, rename/replace/delete/download | Owner/grant checks and atomic storage |
| Sharing | Grants/listing transitions | Central permission functions in docs/02-permissions.md |
| Crypto | Registry, key derivation, seal/open, envelope validation | Does not know HTTP/session permissions |
| Storage | Parameterized SQL, migrations, transactions | No plaintext file/profile persistence |
| Benchmarks | Synthetic measurements and exports | Same crypto/service path; never bypass ACL |

## Storage and transaction flow
Foreign keys enabled on every connection; WAL enabled; busy timeout 5 seconds. One serialized writer; bounded reads. Upload buffers a bounded plaintext body in memory (never default multipart spill-to-disk), validates type/size and quota reservation, seals all variants, writes a short transaction, and clears/releases buffers. Avoid long crypto work while holding a write lock. Recheck quotas inside commit transaction. Serialize content-changing operations globally with a two-job queue and one active upload/replace; queue overflow → 503 with Retry-After. Required process budget: 2 GiB RAM and adequate database/WAL capacity. Reject overlimit while reading, not after unbounded buffering.

SQLite stores fourteen complete BLOB envelopes per content payload. Download loads one selected envelope, verifies integrity, then decrypts in bounded memory, and sends Content-Disposition: attachment with sanitized UTF-8 name and ASCII fallback. No range/partial content support (Range request → 416); no streaming video player. Bounded whole-file verification avoids emitting plaintext before MAC verification. Budget is deliberately small-file, not a large-media architecture.

Registration atomically creates user, lookup tokens, fourteen profile copies, and password hash. Profile edit atomically replaces its fourteen copies and affected email lookup. Replacement creates a fresh content payload and metadata, switches current pointers, clears grants/listing, and deletes old payloads in one transaction. On failure retain entire old state. Delete cascades variants and grants; account delete invalidates sessions and removes all owned records. No object-store cleanup worker required.

## Failure and operations
Invalid content → 415 or 422; overlimit → 413; quota → 409; SQLite lock exhaustion → 503; envelope corruption → 500 generic storage-integrity error; root key missing → startup fails. Never silently use another variant after corruption. Abort failed mutations completely. Client disconnect cancels work/transaction. Logs include request ID, opaque actor/file IDs, operation, result, duration; never filenames/profile fields/passwords/cookies/ciphertext.

## Runtime
HTTPS reverse proxy outside localhost; only proxy and Go exposed, SQLite file inaccessible over HTTP. Private app directory mode 0700, DB/key backups 0600. CSP permits app scripts/styles only; no inline media content. Same-origin cookies; no permissive CORS. Protect SQLite database, WAL/SHM, logs, and backups. Daily online snapshot via SQLite backup API (not a naked live-file copy), encrypt snapshots with a backup-specific AES-GCM key, retain 7 days. Restore atomically with matching external key IDs and purge expired sessions. Offline classroom deployment may disable scheduled backups explicitly in runtime config.

See security document for key lifecycle and threats. No application runtime exists yet; operational procedures are implementation requirements.

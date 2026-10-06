# Logical data model and persistence contract

This is a schema specification, not an executed migration. UUID identifiers, UTC RFC3339 timestamps, INTEGER byte counts and booleans with CHECK constraints. Avoid SQLite REAL for size/timing aggregates where exact integer nanoseconds are available.

| Table | Required columns / constraints |
|---|---|
| users | id PK; username_lookup BLOB UNIQUE; email_lookup BLOB UNIQUE; password_hash TEXT; profile_payload_id UNIQUE FK payloads; revision INTEGER; created_at |
| sessions | token_hash BLOB PK; user_id FK users ON DELETE CASCADE; csrf_token_hash BLOB; created_at, expires_at; no raw cookie |
| payloads | id PK; kind ENUM(profile,file_metadata,file_content); context_owner_id UUID; context_file_id nullable UUID; content_revision INTEGER; created_at |
| payload_variants | payload_id FK payloads ON DELETE CASCADE; variant_id TEXT from registry; envelope BLOB NOT NULL; envelope_bytes INTEGER; PRIMARY KEY(payload_id,variant_id) |
| files | id PK; owner_id FK users ON DELETE CASCADE; content_payload_id UNIQUE FK payloads; metadata_payload_id UNIQUE FK payloads; content_revision INTEGER; revision INTEGER; listed BOOLEAN DEFAULT false; logical_bytes INTEGER; physical_bytes INTEGER; created_at, updated_at |
| grants | file_id FK files ON DELETE CASCADE; recipient_id FK users ON DELETE CASCADE; view_metadata BOOLEAN; download BOOLEAN; created_at; PK(file_id,recipient_id); CHECK(view_metadata OR download); CHECK(NOT download OR view_metadata) |
| quota_reservations | id PK; user_id FK users ON DELETE CASCADE; logical_bytes; predicted_physical_bytes; expires_at |

## Encrypted payloads
Profile JSON: {full_name, username, email, birthday:null-or-YYYY-MM-DD}. Do not store password in it. File metadata JSON: {filename, extension, mime, category:image/document/video/id_card}. File bytes: exact uploaded plaintext sequence. Canonical JSON: UTF-8, fixed struct field order, no indentation; used identically for every variant in that payload. SQL payload context and authenticated envelope context must match.

Profile lookup indices use HMAC-SHA256 over normalized values with a separate identity-index key (domain-separated username/email). HMAC lookup token is not encryption and is still sensitive pseudonymous data. No plaintext usernames/emails in SQL. Owner username is decrypted after authorization when forming a listing; SQL ID joins cannot leak other profile fields. Application search of permitted filenames happens only after scoping candidate rows by ACL and decrypting their metadata; no plaintext filename index or FTS table.

## Constraints not expressible with simple foreign keys
Service transaction checks payload ownership, payload kind, matching file context, exactly fourteen unique registered variants, grant recipient != owner, quotas, and revision compare-and-swap. Add integrity-check tests for all these conditions. Do not rely on cascade of files to delete referenced payloads: explicitly delete those payload rows in same transaction when deleting/replacing files or deleting an account. Delete user's profile payload explicitly too. Cascades then delete their variants. Reservations expire after 5 minutes and are purged on startup and before reserving quota; actual final quota recheck is authoritative.

## Visibility and retention
Technical IDs, ownership relations, booleans, byte lengths, timestamps, password hashes and keyed lookup tokens remain structurally queryable. All user-entered business payloads are encrypted fourteen times. This is a declared interpretation of “all stored data,” not a claim that every SQLite page or technical index is encrypted. File-size/access-graph leakage is a documented residual risk. SQLite itself is not encrypted by this application design.

Deleting rows removes application access but SQLite pages/WAL, storage devices, and backups may retain bytes. Do not promise forensic erasure. After deletion, WAL checkpoint and secure_delete configuration reduce local remnants but are not a complete erasure guarantee. Encrypted backups expire within 7 days; restorations must replay deletion records from a protected operational deletion ledger or be restricted to pre-demonstration synthetic datasets. Baseline uses synthetic datasets only, and does not include a production deletion-ledger service.

## Payload revision context
For file content, authenticated content_revision equals files.content_revision. For metadata/profile, use the immutable generation number assigned when that payload was sealed (file revision at metadata creation, user revision at profile creation); compare against payloads.content_revision, not later ACL revisions. Public/grant changes can increment file revision without resealing metadata. Changing metadata creates a fresh metadata payload with its own context revision. Update profile generation/revision together. No cyclic SQL foreign key is required between payload context_owner_id and users; create payload + user/file transactionally and check context in the service.

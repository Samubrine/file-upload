# Integrated design brief

## Confirmed by user
Go backend, React frontend, SQLite database. Account fields are full name, username, email, password, and birthday only. Homepage requires login. Files start hidden. An owner may expose filename and owner on the homepage, without granting content access. Owners may rename, replace, and delete. Registered-user sharing is allowed. No content preview or password recovery. Store independent AES/RC4/DES versions and expand AES by key size and modes.

## Selected defaults
Fourteen variants: AES key 256 crossed with CBC/CFB128/OFB/CTR, plus DES-CBC and RC4-256. The four modes are the assignment's listed examples; GCM/ECB and all other modes are outside the comparison. Each business payload has fourteen copies; the normal retrieval variant is AES-256-CTR with HMAC authentication. Store encrypted BLOBs in SQLite for a single-process, small classroom deployment. Metadata owner means username, not full name. Birthday is optional. Download grants imply metadata visibility. A visibility-only grant is available. Replacement revokes grants and hides the new revision; rename preserves grants. English interface, calm light-theme file-manager design.

## Approaches considered
1. SQLite encrypted BLOBs — selected: one database backup and transactional creation/deletion; costs roughly fourteen times content size and serializes writers.
2. Encrypted disk files plus SQLite metadata — easier larger-file streaming, but adds filesystem/database consistency and backup coordination; not selected for this small assignment.
3. On-demand cipher generation — saves storage, but conflicts with the requested independently stored versions and makes comparisons include re-encryption; not selected.

## Module boundaries
React calls same-origin Go API. Go middleware resolves sessions/CSRF; services own authorization and transactions; crypto owns versioned envelopes; storage owns SQL. Go serves the built frontend and API behind HTTPS. No third-party identity provider, email service, CDN content delivery, or cloud object storage.

## Principal flow
Register → log in → upload validated file → generate fourteen variants → atomically commit file and payloads → owner may list/share → eligible user requests download variant → authorize current revision → verify HMAC → decrypt → return attachment. No browser request ever retrieves content merely to display a listing.

## Review boundaries
The documents define the full baseline and selected defaults. They do not claim legal compliance or lecturer approval of the expanded matrix. Instructor interpretation remains an external grading dependency, especially exceptions for hashes/technical metadata and the inclusion of all four modes. Product implementation requires a reviewed implementation plan; no implementation or deployment is included here.

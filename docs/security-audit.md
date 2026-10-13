# Security audit findings ledger

Branch: codex/security-hardening. Baseline commit 061aa68 (14 Oct 2026). Every finding has a regression test written first and observed failing before the fix; each fix is its own commit gated on go test -race ./... .

| ID | Severity | Location | Proof test | Fix commit | Status | Finding |
|---|---|---|---|---|---|---|
| V1 | Critical | backend/cmd/server/main.go | cmd/server/devkeys_test.go | fix(sec): V1 generate local dev keys instead of hardcoded constants | fixed | Hardcoded dev root/index keys committed in source |
| V2 | High | httpapi/handlers_auth.go handleGetSession | httpapi/sec_v02_csrf_test.go | fix(sec): V2 issue fresh CSRF token on session restore | fixed | GET /auth/session echoes request CSRF header; reload leaves client without CSRF token |
| V3 | High | httpapi/middleware.go | httpapi/sec_v03_origin_test.go | fix(sec): V3 reject cross-site mutating requests via Origin/Sec-Fetch-Site | fixed | No Origin/Sec-Fetch-Site check (login CSRF, cross-site mutations) |
| V4 | High | auth/password.go, users/users.go | httpapi/sec_v04_bcrypt_test.go | fix(sec): V4 reject passwords over 72 bytes instead of truncating for bcrypt | fixed | bcrypt truncates at 72 bytes; different long passwords authenticate |
| V5 | High | sharing/sharing.go GetGrants | httpapi/sec_v05_grants_test.go | fix(sec): V5 return recipient usernames in grant list instead of user IDs | fixed | Grant list returns internal user UUID instead of username |
| V6 | High | httpapi (login/register/grant) | httpapi/sec_v06_ratelimit_test.go | 49f07ef; test pin 9d675be | fixed | No rate limiting; spec requires 429 |
| V7 | Medium | 8 JSON decode sites in httpapi | httpapi/sec_v07_json_test.go | fix(sec): V7 cap JSON bodies at 64 KiB and reject unknown or trailing fields | fixed | Unbounded JSON bodies, unknown fields accepted |
| V8 | Medium | httpapi/handlers_files.go upload/replace | httpapi/sec_v08_upload_test.go | fix(sec): V8 stream uploads with a 52 MiB cap, one file part, no extra fields | fixed | ParseMultipartForm spills to disk, body not bounded (gosec G120) |
| V9 | Medium | files/validation.go | files/sec_v09_allowlist_test.go | fix(sec): V9 V10 restrict uploads to verifiable types and validate filenames | fixed | Allowlist accepts SVG/archives/plaintext/macro formats; no-op MP4 and short-DOC checks |
| V10 | Medium | files/files.go upload/rename | files/sec_v10_filename_test.go | fix(sec): V9 V10 restrict uploads to verifiable types and validate filenames | fixed | Filenames not checked for control characters or length |
| V11 | Medium | 38 err.Error() sites in httpapi | httpapi/sec_v11_errors_test.go | fix(sec): V11 map service errors to fixed messages and never send storage or crypto text | fixed | Internal error text leaks to clients |
| V12 | Medium | users/users.go Login/Register | users/sec_v12_enum_test.go | fix(sec): V12 equalize login timing and use one message for duplicate registration | fixed | Username enumeration via timing and conflict messages |
| V13 | Medium | crypto/envelope.go Open | crypto/sec_v13_header_test.go | fix(sec): V13 refuse unknown, duplicate and trailing fields in envelope headers | fixed | Envelope header accepts unknown/duplicate fields |
| V14 | Low | httpapi/handlers_me.go handleDeleteMe | httpapi/sec_v14_deleteme_test.go | fix(sec): V14 check If-Match revision when deleting an account | fixed | DELETE /me ignores If-Match revision |
| V15 | Low | httpapi/handlers_auth.go cookies | httpapi/sec_v15_cookie_test.go | fix(sec): V15-V20 secure __Host- cookies and HSTS, CSP, requ | fixed | Cookie never Secure, never __Host- (gosec G124) |
| V16 | Low | httpapi/middleware.go | httpapi/sec_v16_csp_test.go | fix(sec): V15-V20 secure __Host- cookies and HSTS, CSP, requ | fixed | No Content-Security-Policy; downloads not sandboxed (gosec G705) |
| V17 | Low | httpapi/middleware.go RequestIDMiddleware | httpapi/sec_v17_reqid_test.go | fix(sec): V15-V20 secure __Host- cookies and HSTS, CSP, requ | fixed | Client X-Request-ID reflected unvalidated |
| V18 | Low | httpapi/handlers_files.go download | httpapi/sec_v18_disposition_test.go | fix(sec): V15-V20 secure __Host- cookies and HSTS, CSP, requ | fixed | Content-Disposition %q mangles non-ASCII names |
| V19 | Low | httpapi/handlers_files.go download | httpapi/sec_v19_variant_test.go | fix(sec): V15-V20 secure __Host- cookies and HSTS, CSP, requ | fixed | Bad variant returns 500; Timing-Allow-Origin: * on benchmark downloads |
| V20 | Low | storage/storage.go, cmd/server | storage/sec_v20_purge_test.go | fix(sec): V15-V20 secure __Host- cookies and HSTS, CSP, requ | fixed | Expired sessions never purged |
| V21 | High | backend/go.mod toolchain | govulncheck ./... | — | open | 12 reachable stdlib vulns in go1.26.4 (net/http, crypto/tls, textproto, asn1); fixed in go1.26.9 |
| V22 | Medium | httpapi/server.go static fallback | httpapi/sec_v22_static_test.go | — | open | Static fallback joins request path to disk path (gosec G703) |
| V23 | Low | auth/password.go, storage/storage.go, cmd/server | gosec ./... rerun | — | open | Hygiene: uint8 narrowing in legacy Argon2 parse (G115), 0755 data dir (G301), env value logged raw (G706), unchecked errors (G104) |

## Accepted scanner findings (justified, not fixed)

- gosec G405/G502/G503 and staticcheck SA1019 (DES, RC4, CFB, OFB): required by the assignment comparison registry (ADR 002). Every variant is wrapped in HMAC-SHA256 encrypt-then-MAC, and DES/RC4 are labelled educational only.
- gosec G115 at crypto/envelope.go header length (int to uint32) and crypto/padding.go (int to byte): bounded by MaxHeaderLength=4096 and by the explicit blockSize<=255 check.
- gosec G705 on the download body write: responses are application/octet-stream attachments with nosniff and a sandbox CSP (V16).

## Coverage evidence (graphify + rg, baseline)

- {file_id} routes (9), all behind RequireAuth:

```text
88:	authed("GET /files/{file_id}", s.handleGetFile)
89:	authed("PATCH /files/{file_id}", s.handleRenameFile)
90:	authed("DELETE /files/{file_id}", s.handleDeleteFile)
91:	mux.Handle("PUT /files/{file_id}/content", authMiddleware.RequireAuth(s.uploadQueue.Limit(http.HandlerFunc(s.handleReplaceContent))))
92:	authed("PUT /files/{file_id}/listing", s.handleSetListing)
93:	authed("GET /files/{file_id}/grants", s.handleGetGrants)
94:	authed("PUT /files/{file_id}/grants/{username}", s.handlePutGrant)
95:	authed("DELETE /files/{file_id}/grants/{username}", s.handleDeleteGrant)
96:	authed("GET /files/{file_id}/download", s.handleDownload)
```

- crypto.Open callers (4), all inside files/users services after an ownership or permission check:

```text
backend\internal\files\files.go:132:	pt, _, err := crypto.Open(ctx, s.keyProvider, variantRow.Envelope)
backend\internal\files\files.go:157:	pt, _, err := crypto.Open(ctx, s.keyProvider, variantRow.Envelope)
backend\internal\files\files.go:352:		pt, openTimings, err := crypto.Open(ctx, s.keyProvider, vRow.Envelope)
backend\internal\users\users.go:332:	plaintext, _, err := crypto.Open(ctx, s.keyProvider, variantRow.Envelope)
```

- err.Error() sites in httpapi (38 before V11):

```text
backend/internal/httpapi\handlers_files.go:23
backend/internal/httpapi\handlers_me.go:7
backend/internal/httpapi\handlers_grants.go:5
backend/internal/httpapi\handlers_auth.go:3
```

- Raw JSON decode sites (8 before V7):

```text
backend/internal/httpapi\handlers_auth.go:41:	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
backend/internal/httpapi\handlers_auth.go:74:	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
backend/internal/httpapi\handlers_grants.go:50:	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
backend/internal/httpapi\handlers_me.go:51:	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
backend/internal/httpapi\handlers_me.go:80:	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
backend/internal/httpapi\handlers_me.go:107:	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
backend/internal/httpapi\handlers_files.go:202:	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
backend/internal/httpapi\handlers_files.go:317:	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
```

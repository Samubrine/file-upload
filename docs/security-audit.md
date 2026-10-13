# Security audit findings ledger

Branch: codex/security-hardening (baseline 061aa68, then fixes in order). Every finding has a proof test that was observed failing before its fix. Commits V11 to V20 carry red proof tests first (4ab355c), then fix commits that turn them green without breaking any earlier passing test.

## Findings

| ID | Severity | Location | Proof test | Fix commit | Status | Finding |
|---|---|---|---|---|---|---|
| V1 | Critical | backend/cmd/server/main.go | cmd/server/devkeys_test.go | 8f11cb7 | fixed | Hardcoded dev root/index keys committed in source |
| V2 | High | httpapi/handlers_auth.go handleGetSession | httpapi/sec_v02_csrf_test.go | e1dac22 | fixed | GET /auth/session echoes request CSRF header; reload leaves client without CSRF token |
| V3 | High | httpapi/middleware.go | httpapi/sec_v03_origin_test.go | 449a8e5 | fixed | No Origin/Sec-Fetch-Site check (login CSRF, cross-site mutations) |
| V4 | High | auth/password.go, users/users.go | httpapi/sec_v04_bcrypt_test.go | 7ea2f5 | fixed | bcrypt truncates at 72 bytes; different long passwords authenticate |
| V5 | High | sharing/sharing.go GetGrants | httpapi/sec_v05_grants_test.go | 44a7cf3 | fixed | Grant list returns internal user UUID instead of username |
| V6 | High | httpapi (login/register/grant) | httpapi/sec_v06_ratelimit_test.go | 49f07ef (test pin 9d675be) | fixed | No rate limiting; spec requires 429 |
| V7 | Medium | 8 JSON decode sites in httpapi | httpapi/sec_v07_json_test.go | f5c7b3b | fixed | Unbounded JSON bodies, unknown fields accepted |
| V8 | Medium | httpapi/handlers_files.go upload/replace | httpapi/sec_v08_upload_test.go | b3cca9c | fixed | ParseMultipartForm spills to disk, body not bounded (gosec G120) |
| V9 | Medium | files/validation.go | files/sec_v09_allowlist_test.go | dcdf3b5 | fixed | Allowlist accepts SVG/archives/plaintext/macro formats; no-op MP4 and short-DOC checks |
| V10 | Medium | files/files.go upload/rename | files/sec_v10_filename_test.go | dcdf3b5 | fixed | Filenames not checked for control characters or length |
| V11 | Medium | 38 err.Error() sites in httpapi | httpapi/sec_v11_errors_test.go | 173f31d | fixed | Internal error text leaks to clients |
| V12 | Medium | users/users.go Login/Register | users/sec_v12_enum_test.go | 9d675be | fixed | Username enumeration via timing and conflict messages |
| V13 | Medium | crypto/envelope.go Open | crypto/sec_v13_header_test.go | 2c23514 | fixed | Envelope header accepts unknown/duplicate fields |
| V14 | Low | httpapi/handlers_me.go handleDeleteMe | httpapi/sec_v14_deleteme_test.go | 8ec1109 | fixed | DELETE /me ignores If-Match revision |
| V15 | Low | httpapi/handlers_auth.go cookies | httpapi/sec_v15_cookie_test.go | 6906d7e | fixed | Cookie never Secure, never __Host- (gosec G124) |
| V16 | Low | httpapi/middleware.go | httpapi/sec_v16_csp_test.go | 6906d7e | fixed | No Content-Security-Policy; downloads not sandboxed (gosec G705) |
| V17 | Low | httpapi/middleware.go RequestIDMiddleware | httpapi/sec_v17_reqid_test.go | 6906d7e | fixed | Client X-Request-ID reflected unvalidated |
| V18 | Low | httpapi/handlers_files.go download | httpapi/sec_v18_disposition_test.go | 6906d7e | fixed | Content-Disposition %q mangles non-ASCII names |
| V19 | Low | httpapi/handlers_files.go download | httpapi/sec_v19_variant_test.go | 6906d7e | fixed | Bad variant returns 500; Timing-Allow-Origin: * on benchmark downloads |
| V20 | Low | storage/storage.go, cmd/server | storage/sec_v20_purge_test.go | 6906d7e | fixed | Expired sessions never purged |
| V21 | High | backend/go.mod toolchain | govulncheck ./... | 23942c4 | fixed | 12 reachable stdlib vulns in go1.26.4 (net/http, crypto/tls, textproto, asn1); fixed in go1.26.9 |
| V22 | Medium | httpapi/server.go static fallback | httpapi/sec_v22_static_test.go | 23942c4 | fixed | Static fallback joins request path to disk path (gosec G703) |
| V23 | Low | auth/password.go, storage/storage.go, cmd/server | gosec ./... rerun | 23942c4 | fixed | Hygiene: uint8 narrowing in legacy Argon2 parse (G115), 0755 data dir (G301), env value logged raw (G706), unchecked errors (G104) |

V9 and V10 share one commit (dcdf3b5) because the allowlist and the filename validator live in the same file. V6 has a follow-up test commit (9d675be) that pins the limiter clock, because bcrypt under -race could refill buckets mid-test.

## Verification evidence

- go vet ./... (backend and benchmarks): clean.
- go test -race -count=1 ./... on go1.26.9: all packages ok (cmd/server, auth, crypto, files, httpapi, storage).
- govulncheck ./... on go1.26.9: no reachable vulnerabilities. One finding in a required module is reported as not called by this code. It was 12 reachable standard-library findings on go1.26.4 (V21).
- gosec ./...: 15 issues remain. Each is accepted below. Baseline was 23.
- staticcheck ./...: 4 findings, all SA1019 for CFB and OFB (see accepted list). Baseline had 6 findings including unused fields and an unused variable, all fixed.
- npm audit (frontend): 0 vulnerabilities. Frontend dependencies did not change.
- npm run build: passes.
- Live smoke test (backend/cmd/smoke against the built binary on port 8097, public origin matching): register with Origin header 201; reload restores session 200 with a usable CSRF token; upload 201 with 6 variants; recipient downloads all six variants byte-identical (SHA-256 match); owner revokes; revoked recipient gets 404; cross-site login 403; cross-site listing change 403. Passed.

## Accepted scanner findings (justified, not suppressed)

- gosec G405, G502, G503 and staticcheck SA1019 (DES, RC4, CFB, OFB): required by the comparison registry in ADR 002. Every variant is wrapped in HMAC-SHA256 encrypt-then-MAC. DES and RC4 are labelled educational in the UI and report.
- gosec G115 in crypto/envelope.go (header length to uint32): Seal refuses headers above MaxHeaderLength (4096) before this conversion.
- gosec G115 in crypto/padding.go (PKCS#7 pad length to byte): PKCS7Pad and PKCS7Unpad reject block sizes above 255.
- gosec G115 in auth/password.go (legacy Argon2id parameter and key length): values are parsed with explicit bit sizes; only hashes stored by this application are verified.
- gosec G124 in httpapi/handlers_auth.go (cookie Secure attribute): Secure is set from the -secure-cookies flag by design. HttpOnly and SameSite=Strict are always set.
- gosec G705 in httpapi/handlers_files.go (download body): responses are application/octet-stream attachments with nosniff, a restrictive CSP, and no-store.
- gosec G706 in httpapi/errors.go and cmd/server/main.go (log lines): values are quoted with %q, and the request ID is validated first (V17).

## Limits that remain

- Rate limits and the login-timing equalizer are per process. A restart clears limiter state.
- The Origin check trusts the Host header for same-origin matching. Deploy behind the configured public origin only.
- Development keys in data/dev-keys.json are for local use. Losing that file makes development data unrecoverable (ADR 013).
- Only go1.26.9 was verified. The toolchain download came through a module proxy because the default proxy was unreachable from this machine.
- The CFB and OFB modes are kept for the assignment comparison (see the staticcheck note above). gofmt -w was applied across backend/internal and backend/cmd; the whitespace-insensitive diff shows only import ordering and one signature spacing change.




# Agent handoff: security audit (14 October 2026)

- Baseline version and commit/branch: codex/security-hardening, baseline 061aa68; final code commit 23942c4; this handoff is committed after it.
- Task goal and requirement IDs: find and fix the security findings V1 to V23 (docs/security-audit.md). Touches AUTH-01, AUTH-02, PROF-01, FILE-01, FILE-02, SHARE-01, CRYPTO-01, PRIV-01, UX-01, QUAL-01.
- Canonical documents read: AGENTS.md, README.md, docs/01-product.md, docs/02-permissions.md, docs/05-cryptography.md, docs/06-privacy-security.md, docs/08-verification.md, docs/10-decisions.md, contracts/openapi.json.
- Files and modules changed: backend/internal/{httpapi, auth, users, files, sharing, storage, crypto, apperr}, backend/cmd/server (new flags -public-origin and -secure-cookies; loadKeys in devkeys.go), backend/cmd/smoke (new live smoke client), backend/go.mod and go.work (go1.26.9), benchmarks/go.mod, .gitignore, docs, contracts/openapi.json.
- Decisions made: ADRs 011 to 014 in docs/10-decisions.md. Authority: user decisions recorded in the session for bcrypt with a 72-byte limit, the trimmed allowlist, and generated dev keys. The rest follows the approved plan.
- Actual implementation status: V1 to V23 fixed or verified (V22 was already safe; the static root is now served through fs.FS). The ledger lists each commit.
- Verification: go vet ./... clean; go test -race -count=1 ./... passes on go1.26.9; govulncheck reports no reachable vulnerabilities; gosec 15 accepted findings (listed in the ledger); staticcheck 4 accepted SA1019 findings; npm audit 0; npm run build passes; live smoke test passes.
- Failing or skipped checks: none. gofmt -l reports CRLF-only differences in files this work did not change.
- Security and data-loss considerations: the secure cookie name, HSTS, and Origin checks need -secure-cookies and -public-origin set for production. Deleting data/dev-keys.json makes development data unrecoverable.
- Contract and schema changes: contracts/openapi.json gained 413 responses on login and registration, a 429 on registration and login, a 72-byte password limit description, a single-file upload note, and an UNKNOWN_VARIANT note. Schema migration: none. The new session purge removes expired rows at startup and hourly.
- Remaining work and next concrete task: decide whether the accepted CFB and OFB deprecation notices are acceptable for the assignment report, and merge the branch after review.
- Blockers requiring user or instructor input: none for the code. Merging to main or pushing is not done; the branch stays local.

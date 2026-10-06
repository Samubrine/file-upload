# Delivery boundaries and proposed milestones

This is a roadmap for design review, not a detailed implementation plan or completed work. No deadline supplied, so no invented dates. Four contributors are suggested by the assignment, not assumed to be present.

1. Review documented scope/security model, then produce concrete implementation plan, commands and pinned toolchain.
2. Persistence/crypto foundation: migrations, registry, envelope, isolated vectors and transaction tests.
3. Authentication/profile: sessions, Argon2id, encrypted profile/index, CSRF, self export/deletion.
4. File ownership: upload validation/limits, fourteen copies, authorized downloads, rename/replace/delete.
5. Sharing/discovery: visibility grants, download grants, authenticated homepage, matrix integration tests.
6. React interface: token-based components, auth, owned/shared/home metadata pages, account and comparison states.
7. Integration/evidence: browser flows, races/fault injection, benchmark measurements, short report and assignment checklist.

## Suggested responsibilities
Backend/persistence; crypto/security/benchmarks; React/design/accessibility; QA/integration/report. Each role uses the same requirements and contracts. One person can perform multiple roles sequentially; parallel work needs file ownership and contract agreement.

## Environment contract
Required server config: database path, active key ID and root key map, identity index key, backup key when backups enabled, public origin, notice version, project contact, session cookie deployment profile. Defaults for quotas/limits from product doc. Validate at startup; never start with generated throwaway keys over an existing database. Keys generated through a documented secure local provisioning command at implementation time; .env.example contains names only.

## Runtime verification commands to establish
Backend tests/vet/race; frontend install from lockfile/typecheck/build; database migration test; authorization contract integration; browser E2E; synthetic benchmark harness. Agent must write exact executable commands once layout exists. Do not run fictional commands from this roadmap.

## Status
Complete: requirements/design/context documentation package.
Not started: application code, dependencies, database migrations, runtime tests, measurements, report findings, deployment.

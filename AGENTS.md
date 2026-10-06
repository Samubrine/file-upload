# Provider-independent agent instructions

Read README.md and its reading sequence before changing the application. These rules apply to every agent and contributor, including CLI, IDE, and orchestration tools. A provider-specific instruction file, if introduced, must only point here and must not duplicate project requirements.

## Invariants
- No content preview, thumbnails, inline document rendering, or video streaming. Metadata visibility never grants file content.
- Anonymous visitors access authentication pages only. Homepage metadata requires login.
- An owner manages only their own files. A registered recipient can receive metadata visibility and/or a download grant; download implies metadata visibility. No recipient editing or resharing.
- Every accepted file content, file metadata payload, and profile payload has exactly fourteen independent encrypted variants. Never layer algorithms over each other. Passwords are salted Argon2id hashes, never encrypted copies.
- Root keys are external secrets. Never commit keys, realistic ID cards, personal datasets, plaintext private fields, or session tokens.
- Server authorizes every operation. A hidden React button is not an authorization control.
- Authenticate envelopes before decrypting or emitting plaintext. Fail closed on corruption and unavailable keys.
- Replacement is atomic, creates a new revision, and resets listing and grants.
- SQLite persists encrypted BLOBs, not plaintext file content or external file paths.
- Benchmark client-perceived download time separately from server crypto time.

## Work procedure
1. Identify requirement IDs and source documents for the task.
2. Read relevant code and latest handoff; do not infer progress from a prior chat.
3. State affected modules and contracts; preserve existing user changes.
4. Implement the smallest cohesive task after design/implementation authorization. Before implementation, turn the reviewed design into a concrete plan.
5. Verify security-sensitive behavior with positive and negative cases; record exact commands, exit status, and evidence.
6. Update docs only when behavior or decisions change. Never label a failing check as passed.
7. End with docs/13-agent-handoff.md populated for the work completed. A task is not done if required checks are unavailable; state the blocker.

## Coordination
Assign file/module ownership before concurrent edits. Do not rewrite another agent's branch or documents without coordination. All agents use the same permission matrix, registry, and OpenAPI. Maintain one canonical contract; generated client types derive from contracts/openapi.json. Never copy summaries into competing PRDs.

## Scope changes
A new feature, preview capability, algorithm/mode, quota change, authentication flow, or permission rule requires a decision-log entry and updates to affected requirements/contracts/tests. Fixing an implementation to comply with these docs is not a scope expansion.

## Commands
No commands are presented as currently working: there is no application yet. During implementation, establish and document Go test/vet/race checks, frontend typecheck/build, authorization integration tests, browser end-to-end tests, and benchmark invocation in README. Pin actual resolved toolchain/dependency versions and commit lockfiles. Do not claim compatibility with an untested future version.

# CipherVault — project context v1.0

Documentation baseline: 6 October 2026. Working project name: CipherVault.
Status: design documented; application not implemented. This package is a reviewable specification, not proof that the application passes its requirements.

## Purpose
Build an educational encrypted personal-storage web application for a four-person assignment. Use Go, React with TypeScript, and SQLite. Compare independently encrypted copies of the same data using fourteen configurations. Preserve one coherent context across agents without depending on a provider's conversation memory.

## Read first
1. AGENTS.md — operating rules and handoffs.
2. docs/01-product.md — confirmed scope and requirement IDs.
3. docs/02-permissions.md — definitive authorization behavior.
4. docs/03-architecture.md and docs/04-data-model.md.
5. docs/05-cryptography.md and docs/06-privacy-security.md.
6. docs/07-design-system.md and contracts/design-tokens.json.
7. contracts/openapi.json — definitive HTTP contract.
8. docs/08-verification.md and docs/09-benchmarks.md.
9. docs/10-decisions.md, docs/11-delivery.md, docs/12-traceability.md.
10. docs/13-agent-handoff.md and docs/14-report-template.md.

## Authority
Direct user instructions supersede documents. Within this package: product determines scope; permissions determines authorization; cryptography determines encryption; OpenAPI determines HTTP shapes; data model determines persistence; design system determines interaction and visuals. Read docs/00-design-brief.md for the integrated review. Do not resolve conflicts by silently inventing behavior. Record the conflict, propose an amendment, and keep the corresponding requirement, contract, tests, and decision log synchronized.

## Repository layout when implemented
backend/cmd/server; backend/internal/{auth,users,files,sharing,crypto,storage,httpapi}; backend/migrations; frontend/src/{app,features,components,styles}; contracts; docs; benchmarks; scripts.

Use a single repository. No external project or deployment has been created. No dependencies, product code, or database have been installed by this documentation task.

## Completion rule
Every requirement has executable evidence where applicable. No promise of literal bug freedom; report actual checks and remaining limitations. Report analysis values only after measurements. See docs/11-delivery.md for the proposed milestone order.

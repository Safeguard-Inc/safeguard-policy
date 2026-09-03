# Release process

How `safeguard-policy` ships versions and artifacts, and what is expected
of a release. This is the operational companion to
[`versioning.md`](versioning.md), which describes the version *axes*; this
document describes the *process*.

## Version model

The repository uses [semantic versioning](https://semver.org/):

```text
v0.1.0
v0.2.0
...
v1.0.0
```

A release is a tag of the form `v<major>.<minor>.<patch>` pushed to
`main`. The tag drives the release pipeline (`.github/workflows/release.yml`);
there is no manual artifact upload.

Four things are versioned together by the tag but are conceptually
independent (see `docs/versioning.md`):

| Artifact | Version source | Notes |
| -------- | -------------- | ----- |
| Contract wasm | Cargo package version | `safeguard-contract` |
| Rust crate(s) | Cargo package version | `safeguard-core`, `safeguard-sdk`, `safeguard-cli` |
| TypeScript SDK | `sdk/typescript/package.json` | `@safeguard/policy-sdk` |
| Policy schemas | `$id` query string | `policy-schema/*.schema.json` |

Before tagging, bump all of them together so the tag, the crates and the
package agree (see [Checklist](#release-checklist)).

## What a release must contain

1. **A passing full gate.** The release workflow runs `./scripts/ci.sh all`
   plus `cargo-deny check` on the exact tagged tree. A tag that fails the
   gate fails the release; there is no override.
2. **Artifacts for every consumer** of the polyrepo interface:
   - `safeguard_contract.wasm` — the deployed policy contract
     (built for `wasm32v1-none`, release profile).
   - `safeguard-cli` — the operator CLI binary.
   - `safeguard-policy-schemas.tar.gz` — `policy-schema/` + `policies/`,
     the machine-readable interface `safeguard-hooks` and `safeguard-audit`
     consume.
   - `safeguard-sdk-typescript.tar.gz` — the TypeScript SDK package.
3. **Release notes.** The workflow drafts them from `CHANGELOG.md`; the
   maintainer editing the release should keep the notes focused on
   interface-relevant changes (new entrypoints, schema additions, code
   changes, decision/status code additions).

## Compatibility rules that gate a release

These are hard rules; violating any of them requires a major version bump
and an announced migration:

- Decision, reason, rule type/action and status/region codes are **never
  renumbered**. Additions append.
- The policy schema is **additive-only**: new optional properties and enum
  extensions are fine; removals, renames and renumberings are breaking.
- `schema_version` (contract entrypoint) and the schema `$id` versions must
  agree on the release.
- A breaking change ships with the migration/rollback documented in
  `docs/versioning.md` and rehearsed on testnet before tagging.

## Release checklist

1. Update `CHANGELOG.md` under `## [Unreleased]` — then move the entries to
   a dated `## [0.x.y] - YYYY-MM-DD` section.
2. Bump the crate versions in `crates/*/Cargo.toml` (workspace crates use
   `version.workspace = true`; bump once in `Cargo.toml`) and
   `sdk/typescript/package.json`.
3. Bump the schema version **only** if the schemas changed in a breaking
   way (see `policy-schema/README.md`); additive changes keep the version.
4. Run the full local gate: `./scripts/ci.sh all` and
   `./scripts/ci.sh security`.
5. Tag and push:

   ```bash
   git tag -a v0.1.0 -m "safeguard-policy v0.1.0"
   git push origin v0.1.0
   ```

   The release workflow runs the gate, builds the artifacts and creates the
   GitHub release. If the gate fails, fix forward and re-tag (delete the
   failed tag locally and on the remote).

## Publishing crates and packages

The release workflow produces and attaches artifacts but does **not** push
to crates.io or npm — the repository is not yet registered on either.
Before that step is enabled:

- `crates/safeguard-core` must stay dependency-free and `no_std` on crates.io
  (it currently is; that is a published-surface guarantee).
- The TypeScript SDK must be unpublished (`"private": true` today) until its
  API is stabilized.

Publishing to registries is tracked on the roadmap as part of the release
automation phase.

## Rollback

A release is immutable once tagged. If a deployed contract misbehaves:

- **Policy-level** problems roll back by activating a previous policy
  version — no new release needed.
- **Contract-level** problems roll back by re-pointing `safeguard-hooks` at
  the previous contract instance (and migrating state back if the new
  layout was written), per `docs/versioning.md`.
- **Schema-level** problems cannot be rolled back silently: consumers must
  support the previous schema version (additive compatibility) or migrate.

## See also

- [`versioning.md`](versioning.md) — the four version axes
- `policy-schema/README.md` — schema compatibility contract
- `CHANGELOG.md` — per-release changes
- `.github/workflows/release.yml` — the release pipeline
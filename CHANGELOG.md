# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial repository structure for the `safeguard-policy` polyrepo:
  - `crates/safeguard-core`: `no_std` policy engine (decision model, rule
    primitives, versioning, deterministic evaluation).
  - `crates/safeguard-contract`: Soroban policy contract with role-based
    administration, policy lifecycle, token registry binding and an on-chain
    `evaluate` entrypoint.
  - `policy-schema`: JSON Schema definitions for policies, rules, decision
    documents, jurisdiction configuration and normalized sanctions data.
  - `policies`: default, example and fixture policy documents.
  - `scripts`: policy validation and fixture cross-reference checking.
  - Reference documentation (architecture, policy model, rule engine,
    security model) and CI.

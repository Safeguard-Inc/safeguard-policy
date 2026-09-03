//! Off-chain adapters: the integration boundary between external compliance
//! data and Safeguard's normalized registry datasets.
//!
//! `docs/adapters.md` describes the pipeline; this crate implements it:
//!
//! ```text
//! External Source
//!       │
//!       ▼
//! Source Adapter     (one per provider; fetch, parse, map)
//!       │
//!       ▼
//! Normalizer         (canonical field mapping, hashing, validation)
//!       │
//!       ▼
//! Safeguard Dataset  (validated against policy-schema via the SDK models)
//! ```
//!
//! Design rules that shape this crate (see `docs/adapters.md`):
//!
//! - **Never in the Soroban execution path.** Adapters run off-chain and
//!   publish datasets; the contract only ever reads what was pushed into its
//!   registries.
//! - **Deterministic.** The same provider snapshot must produce the same
//!   normalized entries, so hashing, mapping and ordering are pure.
//! - **No PII.** Sanctions subjects are reduced to a SHA-256 hash of a
//!   normalized identifier; identity records carry attestation references,
//!   never personal data.
//! - **Never guess.** A source field that cannot be normalized surfaces for
//!   operator review rather than being invented.
//! - **Validate before publish.** Output is validated against the SDK's
//!   schema-mirroring models before it can reach a registry.

pub mod dataset;
pub mod identity;
pub mod jurisdiction;
pub mod sanctions;

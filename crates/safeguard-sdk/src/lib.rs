//! # safeguard-sdk
//!
//! Off-chain Rust SDK for Safeguard policy work: parse and validate policy
//! documents, classify regions, and run the **exact same engine** used
//! on-chain ([`safeguard_core`]) offline.
//!
//! The SDK deliberately does **not** duplicate the decision engine: it calls
//! [`safeguard_core::evaluator`], the same code compiled into the wasm
//! contract, so offline results cannot drift from on-chain results.
//!
//! On-chain interaction (deploying, registering, calling `evaluate` against
//! a live contract) is done through the generated contract client from
//! `safeguard-contract`; see `docs/sdk.md`.

pub mod model;
pub mod validation;

pub use safeguard_core::decision::{Decision, PolicyDecision, ReasonCode};
pub use safeguard_core::evaluation::EvaluationRequest;
pub use safeguard_core::rule::{Rule, RuleAction, RuleId, RuleType};
pub use safeguard_core::rules::account_status::AccountStatus;
pub use safeguard_core::rules::jurisdiction::RegionStatus;

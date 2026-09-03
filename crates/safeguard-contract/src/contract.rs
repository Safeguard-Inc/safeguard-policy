//! The exported [`PolicyContract`] entrypoints.
//!
//! Every public function is a thin, authorization-checked bridge to the
//! functional modules. No policy logic lives here.
//!
//! # Entrypoint inventory
//!
//! * `schema_version` — the decision/serialization schema this contract speaks
//! * `initialize` / role management — see [`crate::admin`]
//! * policy lifecycle — see [`crate::lifecycle`]
//! * token registry — see [`crate::registry`]
//! * `evaluate` — see [`crate::registry`] for request assembly and
//!   [`safeguard-core::evaluator`] for the decision itself

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct PolicyContract;

#[contractimpl]
impl PolicyContract {
    /// The version of the policy schema and decision serialization this
    /// contract speaks. Bumped independently of the contract itself (see
    /// `docs/versioning.md`); consumers should gate on it.
    pub fn schema_version(_env: Env) -> u32 {
        1
    }
}

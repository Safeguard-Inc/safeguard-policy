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

use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

use crate::admin;
use crate::error::ContractError;

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

    // ----------------------------------------------------------- bootstrap

    /// Initialize the contract with an administrator. Callable once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        admin::initialize(&env, &admin)
    }

    // ---------------------------------------------------------------- admin

    /// The current administrator (public read).
    pub fn admin(env: Env) -> Result<Address, ContractError> {
        admin::get_admin(&env)
    }

    /// Replace the administrator. Requires the current admin's auth.
    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), ContractError> {
        admin::set_admin(&env, &new_admin)
    }

    /// The current registry authorities (public read).
    pub fn authorities(env: Env) -> Vec<Address> {
        admin::get_authorities(&env)
    }

    /// Add a registry authority. Requires the admin's auth.
    pub fn add_authority(env: Env, authority: Address) -> Result<(), ContractError> {
        admin::add_authority(&env, &authority)
    }

    /// Remove a registry authority. Requires the admin's auth.
    pub fn remove_authority(env: Env, authority: Address) -> Result<(), ContractError> {
        admin::remove_authority(&env, &authority)
    }
}

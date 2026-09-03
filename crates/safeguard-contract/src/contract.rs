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
use crate::lifecycle;
use crate::registry;
use crate::storage::{Id, PolicyVersionRecord, RuleRecord};

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

    // ------------------------------------------------------------- lifecycle

    /// Register a new draft version of a policy. Admin only; append-only.
    pub fn register_version(
        env: Env,
        policy_id: Id,
        version: u32,
        config_hash: Id,
        rules: Vec<RuleRecord>,
    ) -> Result<(), ContractError> {
        lifecycle::register_version(&env, &policy_id, version, &config_hash, &rules)
    }

    /// Activate a draft version, superseding the previous active version.
    /// Admin only.
    pub fn activate_version(env: Env, policy_id: Id, version: u32) -> Result<(), ContractError> {
        lifecycle::activate_version(&env, &policy_id, version)
    }

    /// Deactivate the active version of a policy. Admin only.
    pub fn deactivate_version(env: Env, policy_id: Id, version: u32) -> Result<(), ContractError> {
        lifecycle::deactivate_version(&env, &policy_id, version)
    }

    /// The record of a specific policy version (public read).
    pub fn get_version(
        env: Env,
        policy_id: Id,
        version: u32,
    ) -> Result<PolicyVersionRecord, ContractError> {
        lifecycle::get_version(&env, &policy_id, version)
    }

    /// The record of the active version of a policy (public read).
    pub fn get_active_version(
        env: Env,
        policy_id: Id,
    ) -> Result<PolicyVersionRecord, ContractError> {
        lifecycle::get_active_version(&env, &policy_id)
    }

    // ---------------------------------------------------------------- tokens

    /// Bind a token to a policy. Admin or registry authority. Idempotent.
    pub fn bind_token(
        env: Env,
        operator: Address,
        policy_id: Id,
        token: Address,
    ) -> Result<(), ContractError> {
        registry::bind_token(&env, &operator, &policy_id, &token)
    }

    /// Unbind a token from a policy. Admin or registry authority. Idempotent.
    pub fn unbind_token(
        env: Env,
        operator: Address,
        policy_id: Id,
        token: Address,
    ) -> Result<(), ContractError> {
        registry::unbind_token(&env, &operator, &policy_id, &token)
    }

    /// The tokens bound to a policy (public read).
    pub fn bound_tokens(env: Env, policy_id: Id) -> Vec<Address> {
        registry::bound_tokens(&env, &policy_id)
    }
}

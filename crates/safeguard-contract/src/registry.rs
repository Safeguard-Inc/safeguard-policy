//! Policy↔token registry.
//!
//! A compliance policy applies only to the Confidential Tokens it has been
//! explicitly bound to. This prevents one policy from accidentally governing
//! unrelated assets and lets `evaluate` reject subjects whose token is not
//! covered:
//!
//! ```text
//! Policy A ──▶ Token X
//! Policy A ──▶ Token Y
//! Policy B ──▶ Token Z
//! ```
//!
//! Binding management requires the admin or a registry authority. Reads are
//! public so hooks and audit tooling can resolve coverage.

use soroban_sdk::{Address, Env, Vec};

use crate::admin;
use crate::error::ContractError;
use crate::storage::{self, Id};

/// Bind a token to a policy. Admin or registry authority. Idempotent.
///
/// Publishes a [`crate::events::TokenBound`] event on a real change, so
/// audit can prove which tokens a policy governed at any point in time;
/// re-binding an already-bound token is a no-op that emits nothing.
pub fn bind_token(
    env: &Env,
    operator: &Address,
    policy_id: &Id,
    token: &Address,
) -> Result<(), ContractError> {
    admin::require_admin_or_authority(env, operator)?;

    let mut tokens = storage::token_bindings(env, policy_id);
    if !tokens.contains(token) {
        tokens.push_back(token.clone());
        storage::set_token_bindings(env, policy_id, &tokens);
        crate::events::token_bound(env, policy_id, token);
    }
    Ok(())
}

/// Unbind a token from a policy. Admin or registry authority. Idempotent.
///
/// Publishes a [`crate::events::TokenUnbound`] event when a token was
/// actually removed; unbinding a token outside the policy's scope is a
/// no-op that emits nothing.
pub fn unbind_token(
    env: &Env,
    operator: &Address,
    policy_id: &Id,
    token: &Address,
) -> Result<(), ContractError> {
    admin::require_admin_or_authority(env, operator)?;

    let tokens = storage::token_bindings(env, policy_id);
    let mut remaining: Vec<Address> = Vec::new(env);
    let mut removed = false;
    for entry in tokens.iter() {
        if &entry != token {
            remaining.push_back(entry);
        } else {
            removed = true;
        }
    }
    if removed {
        storage::set_token_bindings(env, policy_id, &remaining);
        crate::events::token_unbound(env, policy_id, token);
    }
    Ok(())
}

/// The tokens currently bound to a policy (public read).
pub fn bound_tokens(env: &Env, policy_id: &Id) -> Vec<Address> {
    storage::token_bindings(env, policy_id)
}

/// Whether a token is bound to a policy.
pub fn is_bound(env: &Env, policy_id: &Id, token: &Address) -> bool {
    storage::token_bindings(env, policy_id).contains(token)
}

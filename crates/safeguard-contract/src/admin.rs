//! Role-based administration of the policy contract.
//!
//! Roles follow `docs/security.md`:
//!
//! * **Admin** — bootstrap, change the admin, manage authorities, and drive
//!   the policy lifecycle (create/activate/deactivate versions).
//! * **Registry authority** — manages the policy↔token registry; added and
//!   removed only by the admin.
//! * **Everyone else** — read-only (queries) or subject to evaluation.
//!
//! Every state-changing function authenticates the acting address with
//! `require_auth`; no operation is callable by an anonymous caller.

use soroban_sdk::{vec, Address, Env, Vec};

use crate::error::ContractError;
use crate::storage;

/// Initialize the contract with an admin. Fails if already initialized.
pub fn initialize(env: &Env, admin: &Address) -> Result<(), ContractError> {
    if storage::is_initialized(env) {
        return Err(ContractError::AlreadyInitialized);
    }
    admin.require_auth();
    storage::set_admin(env, admin);
    storage::set_authorities(env, &vec![env]);
    Ok(())
}

/// Read the current admin (public read; auditors may query state).
pub fn get_admin(env: &Env) -> Result<Address, ContractError> {
    storage::admin(env)
}

/// Replace the admin. Only the current admin may do this.
pub fn set_admin(env: &Env, new_admin: &Address) -> Result<(), ContractError> {
    let current = storage::admin(env)?;
    current.require_auth();
    new_admin.require_auth();
    storage::set_admin(env, new_admin);
    Ok(())
}

/// The current registry authorities.
pub fn get_authorities(env: &Env) -> Vec<Address> {
    storage::authorities(env)
}

/// Add a registry authority. Only the admin may do this.
pub fn add_authority(env: &Env, authority: &Address) -> Result<(), ContractError> {
    let current = storage::admin(env)?;
    current.require_auth();

    let mut list = storage::authorities(env);
    if !list.contains(authority) {
        list.push_back(authority.clone());
        storage::set_authorities(env, &list);
    }
    Ok(())
}

/// Remove a registry authority. Only the admin may do this.
pub fn remove_authority(env: &Env, authority: &Address) -> Result<(), ContractError> {
    let current = storage::admin(env)?;
    current.require_auth();

    let list = storage::authorities(env);
    let mut filtered: Vec<Address> = vec![env];
    for entry in list.iter() {
        if &entry != authority {
            filtered.push_back(entry);
        }
    }
    storage::set_authorities(env, &filtered);
    Ok(())
}

/// Whether an address is the admin.
pub fn is_admin(env: &Env, address: &Address) -> bool {
    storage::admin(env)
        .map(|admin| &admin == address)
        .unwrap_or(false)
}

/// Whether an address is the admin or a registry authority.
pub fn is_admin_or_authority(env: &Env, address: &Address) -> bool {
    if is_admin(env, address) {
        return true;
    }
    storage::authorities(env).contains(address)
}

/// Authenticate an address that must be the admin.
pub fn require_admin(env: &Env) -> Result<Address, ContractError> {
    let current = storage::admin(env)?;
    current.require_auth();
    Ok(current)
}

/// Authenticate an address that must be the admin or a registry authority.
///
/// The caller declares who they are; the contract verifies membership and
/// requires that the declared address authorized the call.
pub fn require_admin_or_authority(env: &Env, declared: &Address) -> Result<Address, ContractError> {
    if !is_admin_or_authority(env, declared) {
        return Err(ContractError::Unauthorized);
    }
    declared.require_auth();
    Ok(declared.clone())
}

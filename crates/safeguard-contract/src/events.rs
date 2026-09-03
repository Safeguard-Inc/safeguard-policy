//! Typed policy lifecycle events.
//!
//! These events make changes to the compliance configuration itself auditable
//! — they are the difference between "the policy changed" and "we can prove
//! which policy version was active when". `safeguard-audit` consumes them;
//! the event names are part of the stable interface between the polyrepos.
//!
//! Note the boundary: **transfer-level** events (`transfer_approved`,
//! `transfer_blocked`) belong to `safeguard-hooks`, not here.

use soroban_sdk::{contractevent, Address, Env};

use crate::storage::Id;

/// A new draft version of a policy was registered.
#[contractevent]
pub struct PolicyCreated {
    #[topic]
    pub policy_id: Id,
    pub version: u32,
    pub config_hash: Id,
}

/// A draft version was activated (any previously active version is
/// superseded).
#[contractevent]
pub struct PolicyActivated {
    #[topic]
    pub policy_id: Id,
    pub version: u32,
    pub config_hash: Id,
}

/// The active version of a policy was deactivated (policy now has no active
/// version until a new one is activated).
#[contractevent]
pub struct PolicyDeactivated {
    #[topic]
    pub policy_id: Id,
    pub version: u32,
}

/// An account's identity verification record was written or replaced.
///
/// Part of the `registry_updated` event family: audit consumes these to
/// prove compliance data changes. `status` is an
/// [`safeguard_core::registries::identity::IdentityStatus`] code.
#[contractevent]
pub struct IdentityUpdated {
    #[topic]
    pub account: Address,
    pub status: u32,
    pub attestation_ref: Id,
    pub expires_at: u64,
}

/// An account's identity verification record was removed.
#[contractevent]
pub struct IdentityRemoved {
    #[topic]
    pub account: Address,
}

/// Publish an identity record write/replacement.
pub fn identity_updated(env: &Env, account: &Address, record: &crate::storage::IdentityRecord) {
    IdentityUpdated {
        account: account.clone(),
        status: record.status,
        attestation_ref: record.attestation_ref.clone(),
        expires_at: record.expires_at,
    }
    .publish(env);
}

/// Publish an identity record removal.
pub fn identity_removed(env: &Env, account: &Address) {
    IdentityRemoved {
        account: account.clone(),
    }
    .publish(env);
}

/// A subject's sanctions entry was written, replaced or retired.
/// `status` is a [`safeguard_core::registries::sanctions::SanctionsStatus`]
/// code; retirement is an update to `inactive`, never a deletion.
#[contractevent]
pub struct SanctionsEntryUpdated {
    #[topic]
    pub subject_hash: Id,
    pub status: u32,
    pub dataset_version: u32,
}

/// Publish a sanctions entry write/replace/retire.
pub fn sanctions_entry_updated(
    env: &Env,
    subject_hash: &Id,
    record: &crate::storage::SanctionsEntryRecord,
) {
    SanctionsEntryUpdated {
        subject_hash: subject_hash.clone(),
        status: record.status,
        dataset_version: record.dataset_version,
    }
    .publish(env);
}

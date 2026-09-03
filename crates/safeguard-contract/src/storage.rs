//! Contract storage: data keys, persisted records and typed accessors.
//!
//! # Layout
//!
//! **Instance storage** (lives with the contract instance):
//!
//! ```text
//! Admin          → Address
//! Authorities    → Vec<Address>
//! ```
//!
//! **Persistent storage** (ledger entries with explicit TTL extension):
//!
//! ```text
//! Version(VersionKey)   → PolicyVersionRecord
//! ActiveVersion(policy) → u32
//! TokenBindings(policy) → Vec<Address>
//! ```
//!
//! All multi-byte ids cross the boundary as [`BytesN::<32>`] so arbitrary
//! (non-UTF-8) ids are representable and serialize deterministically.
//!
//! Accessors are the only code that touches storage, keeping the key layout
//! reviewable in one place.

use soroban_sdk::{contracttype, vec, Address, BytesN, Env, IntoVal, TryFromVal, Val, Vec};

use crate::error::ContractError;

/// How many ledgers ahead persistent entries are extended on write/read.
/// 5_000_000 ledgers ≈ 9.5 months at the ~5s Soroban ledger cadence.
pub const TTL_EXTEND_TO: u32 = 5_000_000;
/// Entries are only extended when their remaining TTL is below this.
pub const TTL_THRESHOLD: u32 = 500_000;

/// A policy id or rule id as fixed 32 bytes.
pub type Id = BytesN<32>;

/// Composite key for one policy version's record.
#[contracttype]
#[derive(Clone)]
pub struct VersionKey {
    pub policy_id: Id,
    pub version: u32,
}

/// Storage key namespace.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// instance: the administrator [`Address`].
    Admin,
    /// instance: additional registry authorities.
    Authorities,
    /// persistent: configuration record of a policy version.
    Version(VersionKey),
    /// persistent: the active version number of a policy.
    ActiveVersion(Id),
    /// persistent: tokens covered by a policy.
    TokenBindings(Id),
}

/// On-chain rule record (category/action stored by stable core code).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleRecord {
    pub rule_id: Id,
    pub rule_type: u32,
    pub action: u32,
}

/// On-chain record of one policy version.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyVersionRecord {
    pub policy_id: Id,
    pub version: u32,
    /// [`safeguard_core::version::VersionStatus`] code.
    pub status: u32,
    /// Config hash (sha-256 of the serialized rule set).
    pub config_hash: Id,
    pub rules: Vec<RuleRecord>,
}

/// Extend the TTL of a persistent key past the next read/write.
fn extend(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
}

// ---------------------------------------------------------------- instance

/// Whether the contract has been initialized (an admin is set).
pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::Admin)
}

pub fn admin(env: &Env) -> Result<Address, ContractError> {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(ContractError::NotInitialized)
}

pub fn set_admin(env: &Env, address: &Address) {
    env.storage().instance().set(&DataKey::Admin, address);
}

pub fn authorities(env: &Env) -> Vec<Address> {
    env.storage()
        .instance()
        .get(&DataKey::Authorities)
        .unwrap_or_else(|| vec![env])
}

pub fn set_authorities(env: &Env, addresses: &Vec<Address>) {
    env.storage()
        .instance()
        .set(&DataKey::Authorities, addresses);
}

// -------------------------------------------------------------- persistent

/// Set a persistent value, extending its TTL in the same call.
fn set_persistent<T: IntoVal<Env, Val>>(env: &Env, key: &DataKey, value: &T) {
    env.storage().persistent().set(key, value);
    extend(env, key);
}

/// Read a persistent value, extending its TTL when present.
fn get_persistent<T: TryFromVal<Env, Val>>(env: &Env, key: &DataKey) -> Option<T> {
    let value: Option<T> = env.storage().persistent().get(key);
    if value.is_some() {
        extend(env, key);
    }
    value
}

pub fn version_record(env: &Env, policy_id: &Id, version: u32) -> Option<PolicyVersionRecord> {
    get_persistent(
        env,
        &DataKey::Version(VersionKey {
            policy_id: policy_id.clone(),
            version,
        }),
    )
}

pub fn set_version_record(env: &Env, record: &PolicyVersionRecord) {
    set_persistent(
        env,
        &DataKey::Version(VersionKey {
            policy_id: record.policy_id.clone(),
            version: record.version,
        }),
        record,
    );
}

pub fn active_version(env: &Env, policy_id: &Id) -> Option<u32> {
    get_persistent(env, &DataKey::ActiveVersion(policy_id.clone()))
}

pub fn set_active_version(env: &Env, policy_id: &Id, version: u32) {
    set_persistent(env, &DataKey::ActiveVersion(policy_id.clone()), &version);
}

pub fn token_bindings(env: &Env, policy_id: &Id) -> Vec<Address> {
    get_persistent(env, &DataKey::TokenBindings(policy_id.clone())).unwrap_or_else(|| vec![env])
}

pub fn set_token_bindings(env: &Env, policy_id: &Id, tokens: &Vec<Address>) {
    set_persistent(env, &DataKey::TokenBindings(policy_id.clone()), tokens);
}

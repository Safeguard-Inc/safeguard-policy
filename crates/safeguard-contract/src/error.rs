//! On-chain error codes returned (or panicked with) by the contract.
//!
//! Codes are **stable public API** in the same way as
//! [`safeguard-core`](safeguard_core) reason codes: `safeguard-hooks` and
//! `safeguard-audit` may observe them, so new errors are appended and never
//! renumbered.

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    /// The caller is not authorized for the operation.
    Unauthorized = 1,
    /// The contract was already initialized.
    AlreadyInitialized = 2,
    /// The contract has not been initialized.
    NotInitialized = 3,
    /// No policy with this id exists.
    PolicyNotFound = 4,
    /// No version of this policy exists.
    VersionNotFound = 5,
    /// The version is not a draft and cannot be activated.
    VersionNotDraft = 6,
    /// The supplied rule set is invalid (duplicate category or id).
    InvalidRuleSet = 7,
    /// The policy has no active version.
    PolicyNotActive = 8,
    /// The token is not bound to the policy.
    TokenNotBound = 9,
    /// The policy id is reserved or otherwise invalid.
    InvalidPolicyId = 10,
}

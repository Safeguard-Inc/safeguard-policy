//! Identity adapter: external KYC/attestation providers → normalized
//! verification outcomes.
//!
//! The policy layer consumes exactly five outcomes
//! ([`safeguard_sdk::IdentityStatus`]) plus the attestation expiry; it never
//! sees provider-specific shapes. Adapters map provider state onto those
//! outcomes, and the engine's fail-closed rules handle anything but
//! `Verified` (flag, never approve) — see `docs/adapters.md` and
//! `docs/security.md`.
//!
//! This module defines:
//!
//! - [`AttestationRecord`]: the normalized record an adapter produces for
//!   one account (identity status, expiry, attestation reference, derived
//!   jurisdiction) — PII-free and matching the on-chain identity registry.
//! - [`IdentitySource`]: the trait concrete provider adapters implement.
//! - [`resolve_status`]: the expiry rule every adapter should use, factored
//!   out so it cannot be implemented differently per provider.

use std::time::{SystemTime, UNIX_EPOCH};

use safeguard_sdk::IdentityStatus;

/// One normalized identity record for an account.
///
/// Mirrors the on-chain `set_identity` surface (`docs/registries.md`):
/// attestation references only, never personal data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRecord {
    /// Stellar-style account address the attestation applies to.
    pub account: String,
    /// The normalized verification outcome.
    pub status: IdentityStatus,
    /// Reference to the off-chain attestation (provider record id).
    pub attestation_ref: String,
    /// Unix epoch seconds when verification expires; `0` = never.
    pub expires_at: u64,
    /// Optional normalized jurisdiction for the account (region code from
    /// the jurisdiction universe, or `XX` for unknown).
    pub jurisdiction: Option<String>,
}

/// Errors resolving an identity from a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The provider returned no record for the account.
    NoRecord(String),
    /// The provider's response could not be mapped (malformed shape).
    Unmappable(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRecord(account) => write!(f, "no provider record for account {account}"),
            Self::Unmappable(detail) => write!(f, "unmappable provider response: {detail}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// An identity/KYC/attestation provider.
///
/// Implementations wrap one provider. The single method returns the
/// provider's raw facts for an account; [`resolve_record`] maps them to the
/// normalized [`AttestationRecord`], applying the shared expiry rule.
pub trait IdentitySource {
    /// Stable provider identifier (e.g. `veriff`, `persona`).
    fn provider_id(&self) -> &'static str;

    /// The provider's raw facts for an account.
    ///
    /// The concrete shape is provider-specific (this trait is deliberately
    /// provider-neutral); adapters return the fields the normalizer needs.
    fn fetch_facts(&self, account: &str) -> Result<ProviderFacts, IdentityError>;
}

/// Provider-neutral facts about an identity, as returned by a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFacts {
    /// Whether the provider considers the identity verified right now.
    pub verified: bool,
    /// Provider record/attestation identifier.
    pub attestation_ref: String,
    /// Unix epoch seconds when the provider's verification expires.
    pub expires_at: u64,
    /// Raw jurisdiction/region the provider reports, if any.
    pub jurisdiction: Option<String>,
}

/// Resolve the normalized identity status for a set of provider facts.
///
/// The shared rule:
///
/// - provider says not verified → [`IdentityStatus::Unverified`];
/// - verified but already expired → [`IdentityStatus::Expired`];
/// - otherwise → [`IdentityStatus::Verified`].
///
/// `now` is injected so tests and replay are deterministic; production
/// callers pass [`now_epoch_seconds`].
pub fn resolve_status(facts: &ProviderFacts, now: u64) -> IdentityStatus {
    if !facts.verified {
        return IdentityStatus::Unverified;
    }
    if facts.expires_at != 0 && facts.expires_at < now {
        return IdentityStatus::Expired;
    }
    IdentityStatus::Verified
}

/// The current Unix epoch in seconds (production [`resolve_status`] input).
#[must_use]
pub fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Map provider facts to a normalized [`AttestationRecord`] for an account.
///
/// Deterministic given `now`; records carry no personal data — only the
/// attestation reference and the derived status/expiry/jurisdiction.
pub fn resolve_record(
    account: &str,
    facts: &ProviderFacts,
    now: u64,
) -> Result<AttestationRecord, IdentityError> {
    if account.trim().is_empty() {
        return Err(IdentityError::Unmappable("empty account".to_owned()));
    }
    if facts.attestation_ref.trim().is_empty() {
        return Err(IdentityError::Unmappable(
            "empty attestation reference".to_owned(),
        ));
    }
    Ok(AttestationRecord {
        account: account.to_owned(),
        status: resolve_status(facts, now),
        attestation_ref: facts.attestation_ref.clone(),
        expires_at: facts.expires_at,
        jurisdiction: facts.jurisdiction.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(verified: bool, expires_at: u64) -> ProviderFacts {
        ProviderFacts {
            verified,
            attestation_ref: "ATT-1".to_owned(),
            expires_at,
            jurisdiction: None,
        }
    }

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn unverified_is_never_verified() {
        assert_eq!(
            resolve_status(&facts(false, 0), NOW),
            IdentityStatus::Unverified
        );
        // Even an unexpired, otherwise-current attestation must not verify.
        assert_eq!(
            resolve_status(&facts(false, NOW + 10_000), NOW),
            IdentityStatus::Unverified
        );
    }

    #[test]
    fn verified_but_expired_is_expired() {
        assert_eq!(
            resolve_status(&facts(true, NOW - 1), NOW),
            IdentityStatus::Expired
        );
    }

    #[test]
    fn verified_and_current_is_verified() {
        assert_eq!(
            resolve_status(&facts(true, NOW + 1), NOW),
            IdentityStatus::Verified
        );
        assert_eq!(
            resolve_status(&facts(true, 0), NOW),
            IdentityStatus::Verified
        );
    }

    #[test]
    fn resolve_record_is_deterministic_and_pii_free() {
        let record = resolve_record(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            &facts(true, NOW + 100),
            NOW,
        )
        .expect("record resolves");
        assert_eq!(record.status, IdentityStatus::Verified);
        assert_eq!(record.attestation_ref, "ATT-1");
        assert_eq!(record.expires_at, NOW + 100);
    }

    #[test]
    fn rejects_empty_accounts_and_references() {
        assert!(resolve_record("", &facts(true, 0), NOW).is_err());
        let empty_ref = ProviderFacts {
            attestation_ref: "".to_owned(),
            ..facts(true, 0)
        };
        assert!(resolve_record("G…", &empty_ref, NOW).is_err());
    }
}

//! Rule model: identifiers, rule categories and rule definitions.
//!
//! A *rule* is a named, typed check that a policy version can enable. Rules
//! reference external state (allowlist membership, denylist entries, sanctions
//! datasets, jurisdiction status) by category; the engine evaluates enabled
//! rules in a fixed precedence order (see [`crate::evaluator`]).

/// Length of a rule (or policy) identifier in bytes.
///
/// Identifiers are fixed-width so they serialize deterministically to on-chain
/// storage and events without heap allocation. `"SANCTIONS-001"`-style
/// identifiers fit comfortably; longer identifiers are truncated.
pub const ID_LEN: usize = 32;

/// A fixed-width identifier for rules and policies.
///
/// [`RuleId`] compares byte-for-byte and never allocates. Construction from a
/// string pads with `0x00` and truncates at [`ID_LEN`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleId([u8; ID_LEN]);

impl RuleId {
    /// Wrap the raw fixed-width bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Build an identifier from a string, truncating to [`ID_LEN`] bytes.
    ///
    /// Bytes beyond the first [`ID_LEN`] are dropped; shorter inputs are
    /// zero-padded.
    #[must_use]
    pub fn from_str(input: &str) -> Self {
        let mut bytes = [0u8; ID_LEN];
        for (slot, byte) in bytes.iter_mut().zip(input.as_bytes()) {
            *slot = *byte;
        }
        Self(bytes)
    }

    /// Borrow the raw fixed-width bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    /// The identifier as a byte slice trimmed of trailing zero padding.
    #[must_use]
    pub fn as_trimmed_bytes(&self) -> &[u8] {
        let mut end = self.0.len();
        while end > 0 && self.0[end - 1] == 0 {
            end -= 1;
        }
        &self.0[..end]
    }

    /// Whether the identifier is all zeros (unset).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        let mut i = 0;
        while i < ID_LEN {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl From<&str> for RuleId {
    fn from(value: &str) -> Self {
        Self::from_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{RuleId, ID_LEN};

    #[test]
    fn ids_are_truncated_and_padded_deterministically() {
        let short = RuleId::from_str("SANCTIONS-001");
        assert_eq!(
            short.as_trimmed_bytes(),
            b"SANCTIONS-001",
            "short ids keep their bytes"
        );
        assert_eq!(short.as_bytes().len(), ID_LEN);

        let exact = RuleId::from_str("12345678901234567890123456789012");
        assert_eq!(
            exact.as_trimmed_bytes(),
            b"12345678901234567890123456789012"
        );

        let long = RuleId::from_str("this-identifier-is-much-longer-than-thirty-two-bytes");
        assert_eq!(long.as_trimmed_bytes().len(), ID_LEN);
    }

    #[test]
    fn ids_compare_byte_for_byte() {
        assert_eq!(RuleId::from_str("a"), RuleId::from_str("a"));
        assert_ne!(RuleId::from_str("a"), RuleId::from_str("b"));
        // An all-zero id is the unset id and compares unequal to everything else.
        assert!(RuleId::from_str("").is_empty());
        assert!(RuleId::from_bytes([0u8; ID_LEN]).is_empty());
        assert!(!RuleId::from_str("a").is_empty());
    }

    #[test]
    fn from_str_impl_matches_from_str_helper() {
        assert_eq!(
            RuleId::from("ALLOWLIST-01"),
            RuleId::from_str("ALLOWLIST-01")
        );
    }
}

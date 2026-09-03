//! Registry dataset models.
//!
//! The normalized JSON shapes that cross the adapter boundary (see
//! `docs/adapters.md` and `docs/registries.md`). These mirror
//! `policy-schema/` exactly — field names, enum labels and the strict
//! `deny_unknown_fields` posture — so adapter output validates before it is
//! ever pushed on-chain.
//!
//! The SDK stays Soroban-free, so conversion stops at the **pure** mapping:
//! [`decode_subject_hash`] produces the 32-byte subject id a caller hands to
//! the contract's `set_sanctions_entry`. `effective_at` keeps its schema
//! RFC 3339 form here; converting it to the on-chain epoch-seconds
//! representation happens at the call site that owns the Soroban value.

use serde::{Deserialize, Serialize};

/// Sanctions entry status, matching `sanctions.schema.json` and the core
/// [`safeguard_core::registries::sanctions::SanctionsStatus`] codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SanctionsStatusLabel {
    /// The entry actively screens subjects.
    Active,
    /// The entry no longer screens subjects (retired, reviewed).
    Inactive,
}

impl SanctionsStatusLabel {
    /// The stable numeric code used by the on-chain registry.
    #[must_use]
    pub const fn to_code(self) -> u32 {
        match self {
            Self::Active => 0,
            Self::Inactive => 1,
        }
    }

    /// Parse from a numeric code.
    #[must_use]
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Active),
            1 => Some(Self::Inactive),
            _ => None,
        }
    }
}

/// One normalized sanctions record as produced by a source adapter,
/// matching `policy-schema/sanctions.schema.json` exactly.
///
/// Keyed by a 32-byte subject hash so no personal data is stored on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanctionsDatasetEntry {
    /// SHA-256 (hex) of the subject identifier as normalized by the adapter.
    pub subject_hash: String,
    /// Source list identifier (e.g. `OFAC-SDN`), ASCII, at most 32 bytes.
    pub list_id: String,
    pub status: SanctionsStatusLabel,
    /// Monotonic dataset version; >= 1.
    pub dataset_version: u32,
    /// RFC 3339 time the listing became effective.
    pub effective_at: String,
    /// Source identifier (adapter/authority), e.g. `ofac`.
    pub source: String,
}

/// Decode a 64-hex-char subject hash into its 32 bytes.
#[must_use]
pub fn decode_subject_hash(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, slot) in bytes.iter_mut().enumerate() {
        let hi = decode_hex_digit(hex.as_bytes()[i * 2])?;
        let lo = decode_hex_digit(hex.as_bytes()[i * 2 + 1])?;
        *slot = hi << 4 | lo;
    }
    Some(bytes)
}

fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_convert_to_codes() {
        assert_eq!(SanctionsStatusLabel::Active.to_code(), 0);
        assert_eq!(SanctionsStatusLabel::Inactive.to_code(), 1);
        assert_eq!(
            SanctionsStatusLabel::from_code(0),
            Some(SanctionsStatusLabel::Active)
        );
        assert_eq!(
            SanctionsStatusLabel::from_code(1),
            Some(SanctionsStatusLabel::Inactive)
        );
        assert_eq!(SanctionsStatusLabel::from_code(2), None);
    }

    #[test]
    fn statuses_serialize_lowercase() {
        assert_eq!(
            serde_json::to_string(&SanctionsStatusLabel::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&SanctionsStatusLabel::Inactive).unwrap(),
            "\"inactive\""
        );
    }

    #[test]
    fn entries_parse_with_stable_labels_and_reject_unknown_fields() {
        let base = r#"{
            "subject_hash": "c0ffee0000000000000000000000000000000000000000000000000000000000",
            "list_id": "OFAC-SDN",
            "status": "active",
            "dataset_version": 3,
            "effective_at": "2024-01-15T00:00:00Z",
            "source": "ofac"
        }"#;
        let entry: SanctionsDatasetEntry = serde_json::from_str(base).unwrap();
        assert_eq!(entry.list_id, "OFAC-SDN");
        assert_eq!(entry.status, SanctionsStatusLabel::Active);
        assert_eq!(entry.dataset_version, 3);

        // The model is lenient on subject_hash content; the schema's hex
        // pattern is enforced by decode_subject_hash (see the decode test).
        // What the model does enforce: enum labels and no unknown fields.
        let bad_status = base.replace("\"active\"", "\"bogus\"");
        assert!(serde_json::from_str::<SanctionsDatasetEntry>(&bad_status).is_err());

        // Unknown fields are rejected like the schema's additionalProperties.
        let with_extra = base.replace(
            "\"source\": \"ofac\"",
            "\"source\": \"ofac\", \"extra\": true",
        );
        assert!(serde_json::from_str::<SanctionsDatasetEntry>(&with_extra).is_err());
    }

    #[test]
    fn subject_hash_decodes_to_thirty_two_bytes() {
        let hex = "c0ffee0000000000000000000000000000000000000000000000000000000000";
        let bytes = decode_subject_hash(hex).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0xc0);
        assert_eq!(bytes[1], 0xff);
        assert_eq!(bytes[2], 0xee);

        assert!(decode_subject_hash("zz").is_none());
        assert!(decode_subject_hash("abc").is_none());
        assert!(decode_subject_hash(hex.to_uppercase().as_str()).is_some());
    }
}

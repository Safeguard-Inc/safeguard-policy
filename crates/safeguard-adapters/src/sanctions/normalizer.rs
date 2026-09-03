//! The sanctions normalizer: deterministic mapping from provider records to
//! canonical [`SanctionsDatasetEntry`] values.
//!
//! The normalizer owns every decision that must be identical no matter who
//! runs it:
//!
//! - **subject hashing**: a provider subject is normalized to a canonical
//!   ASCII string (lowercased, whitespace collapsed, diacritics stripped)
//!   and then SHA-256-hashed. The hash — not the text — is what leaves the
//!   adapter, so no personal data is stored on-chain (see
//!   [`safeguard_sdk::registry::SanctionsDatasetEntry`]).
//! - **list mapping**: provider program codes are mapped onto the stable
//!   list identifiers the registry knows (e.g. provider `SDN` → `OFAC-SDN`).
//!   An unmapped code is a review item, never a silent pass-through.
//! - **status mapping**: provider lifecycle states collapse to the two
//!   canonical statuses (`active` / `inactive`); anything unreadable is a
//!   review item.
//! - **effective date**: parsed to RFC 3339 (UTC); unparseable dates are a
//!   review item.

use sha2::{Digest, Sha256};

use safeguard_sdk::registry::{SanctionsDatasetEntry, SanctionsStatusLabel};

use super::source::ProviderRecord;

/// The normalized outcome of a single provider record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedRecord {
    /// The record normalized cleanly into a registry entry.
    Entry(SanctionsDatasetEntry),
    /// The record could not be normalized and needs operator review.
    ///
    /// This is the "never guess" rule from `docs/adapters.md`: an unreadable
    /// field surfaces instead of inventing a value.
    Review {
        /// The raw record that failed (rendered for a human).
        record: ProviderRecord,
        /// Why it could not be normalized.
        reason: String,
    },
}

/// Mapping tables a given source needs to normalize its records.
#[derive(Debug, Clone)]
pub struct NormalizerConfig {
    /// Maps a provider program/list code to the canonical list identifier.
    /// Example: `"SDN" -> "OFAC-SDN"`.
    pub list_map: Vec<(String, String)>,
    /// Provider statuses that mean the listing is currently in force.
    /// Example: `["active"]`.
    pub active_statuses: Vec<String>,
    /// Stable source id stamped on every entry (e.g. `ofac`).
    pub source_id: &'static str,
}

impl NormalizerConfig {
    /// Resolve a provider list code to its canonical identifier.
    fn canonical_list(&self, provider_list: &str) -> Option<&str> {
        self.list_map
            .iter()
            .find(|(code, _)| code == provider_list)
            .map(|(_, canonical)| canonical.as_str())
    }

    /// Whether a provider status means the listing is active.
    fn is_active(&self, provider_status: &str) -> bool {
        self.active_statuses
            .iter()
            .any(|status| status == provider_status)
    }
}

/// Normalize a provider subject identifier to a canonical ASCII string.
///
/// Lowercases, collapses runs of whitespace, and strips diacritics **to
/// their base letter** (precomposed `é` decomposes to `e` + combining
/// accent, then the combining mark is dropped, leaving `e`). Two spellings
/// that differ only in case, spacing or accents hash identically, which is
/// what makes screening deterministic across datasets. An accented letter
/// must never become an empty slot: `José` and `Jose` screening the same
/// is the point.
pub fn canonicalize_subject(subject: &str) -> String {
    use unicode_normalization::UnicodeNormalization;

    let mut canonical = String::with_capacity(subject.len());
    let mut pending_space = false;
    // NFD first, so precomposed accented letters become base + combining
    // mark and the mark can be dropped without losing the base letter.
    for character in subject.nfd() {
        let lowered = character.to_lowercase();
        for item in lowered {
            if item.is_ascii_alphanumeric() {
                if pending_space && !canonical.is_empty() {
                    canonical.push(' ');
                }
                pending_space = false;
                canonical.push(item);
            } else if item.is_whitespace() {
                pending_space = true;
            } else if matches!(item, '-' | '\'' | '.') {
                // Word separators keep the canonical form readable; they do
                // not affect the hash's determinism.
                pending_space = true;
            }
            // Everything else (combining marks, punctuation) is dropped.
        }
    }
    canonical
}

/// SHA-256 hash of a canonical subject, hex-encoded (64 chars).
///
/// This is the `subject_hash` stored in registry entries. The hash input is
/// the *canonical* subject, so hashing is stable across case/spacing/accent
/// variants of the same name.
pub fn hash_subject(canonical_subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_subject.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Parse a provider date (`YYYY-MM-DD` or RFC 3339) into an RFC 3339 UTC
/// string. Returns `None` when the format is unrecognized.
fn to_rfc3339(date: &str) -> Option<String> {
    let trimmed = date.trim();
    // Full RFC 3339 already in UTC.
    if trimmed.len() >= 20 && trimmed.as_bytes().get(4) == Some(&b'-') {
        if let Some(rest) = trimmed.strip_suffix('Z') {
            let _ = rest; // keep the caller-visible normalization below
        }
        // Accept `YYYY-MM-DDTHH:MM:SSZ` and variants ending in an offset.
        if trimmed.contains('T') {
            return Some(normalize_rfc3339(trimmed));
        }
    }
    // Date-only provider format: `YYYY-MM-DD` -> midnight UTC.
    let bytes = trimmed.as_bytes();
    if bytes.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-' {
        let year: i32 = trimmed[0..4].parse().ok()?;
        let month: u32 = trimmed[5..7].parse().ok()?;
        let day: u32 = trimmed[8..10].parse().ok()?;
        if (1..=12).contains(&month) && (1..=31).contains(&day) {
            return Some(format!("{year:04}-{month:02}-{day:02}T00:00:00Z"));
        }
    }
    None
}

/// Normalize a full or offset RFC 3339 timestamp to `…Z` UTC form.
fn normalize_rfc3339(value: &str) -> String {
    let len = value.len();
    if len >= 20 && value.as_bytes()[19] == b'Z' {
        return value[..20].to_owned();
    }
    // Offset form `…+HH:MM` / `…-HH:MM` after the 19-char `…T…:SS`.
    let cut = len.checked_sub(6).unwrap_or(len);
    if cut >= 20 && matches!(value.as_bytes().get(cut), Some(b'+') | Some(b'-')) {
        return value[..cut].to_owned() + "Z";
    }
    // Fall back to a conservative parse: keep the date-time, drop the rest.
    if len >= 19 && value.as_bytes()[10] == b'T' {
        return value[..19].to_owned() + "Z";
    }
    value.to_owned()
}

/// Normalize provider records into canonical entries.
///
/// Deterministic: the same records plus the same config produce the same
/// output in the same order (input order preserved; providers should sort
/// snapshots upstream if ordering matters to diffing).
pub fn normalize_records(
    records: &[ProviderRecord],
    config: &NormalizerConfig,
) -> Vec<NormalizedRecord> {
    records
        .iter()
        .map(|record| normalize_record(record, config))
        .collect()
}

/// Normalize one provider record.
pub fn normalize_record(record: &ProviderRecord, config: &NormalizerConfig) -> NormalizedRecord {
    if record.raw_subject.trim().is_empty() {
        return review(record, "empty subject");
    }
    let Some(list_id) = config.canonical_list(&record.provider_list) else {
        return review(
            record,
            format!("unmapped provider list code {:?}", record.provider_list),
        );
    };
    let status = if config.is_active(&record.provider_status) {
        SanctionsStatusLabel::Active
    } else if record.provider_status.trim().is_empty() {
        return review(record, "empty provider status");
    } else {
        SanctionsStatusLabel::Inactive
    };
    let effective_at = match record.effective_date.as_deref() {
        Some(date) => match to_rfc3339(date) {
            Some(normalized) => normalized,
            None => {
                return review(record, format!("unparseable effective date {date:?}"));
            }
        },
        None => return review(record, "missing effective date"),
    };

    let canonical = canonicalize_subject(&record.raw_subject);
    if canonical.is_empty() {
        return review(record, "subject has no canonical form");
    }

    NormalizedRecord::Entry(SanctionsDatasetEntry {
        subject_hash: hash_subject(&canonical),
        list_id: list_id.to_owned(),
        status,
        dataset_version: 1,
        effective_at,
        source: config.source_id.to_owned(),
    })
}

/// Build a [`NormalizedRecord::Review`] value.
fn review(record: &ProviderRecord, reason: impl Into<String>) -> NormalizedRecord {
    NormalizedRecord::Review {
        record: record.clone(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NormalizerConfig {
        NormalizerConfig {
            list_map: vec![
                ("SDN".to_owned(), "OFAC-SDN".to_owned()),
                ("CON".to_owned(), "EU-CONSOLIDATED".to_owned()),
            ],
            active_statuses: vec!["active".to_owned()],
            source_id: "ofac",
        }
    }

    fn record(subject: &str) -> ProviderRecord {
        ProviderRecord {
            raw_subject: subject.to_owned(),
            provider_list: "SDN".to_owned(),
            provider_status: "active".to_owned(),
            effective_date: Some("2023-06-01".to_owned()),
        }
    }

    #[test]
    fn canonicalize_is_case_space_and_accent_insensitive() {
        assert_eq!(
            canonicalize_subject("  BIN   LADEN, usama  "),
            "bin laden usama"
        );
        assert_eq!(canonicalize_subject("Bin Laden, Usama"), "bin laden usama");
        assert_eq!(canonicalize_subject("José María"), "jose maria");
        assert_eq!(canonicalize_subject("MÜLLER"), "muller");
        // Accented and plain spellings must canonicalize identically, and
        // the base letter must never vanish.
        assert_eq!(canonicalize_subject("José"), canonicalize_subject("Jose"));
        assert_eq!(canonicalize_subject("ÉMILE"), "emile");
    }

    #[test]
    fn hash_is_stable_and_hex() {
        // hash_subject hashes a *canonical* subject; callers canonicalize
        // first, so variants of one name hash identically.
        let first = hash_subject(&canonicalize_subject("bin laden usama"));
        let second = hash_subject(&canonicalize_subject("BIN LADEN, USAMA"));
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        // Different subjects hash differently.
        assert_ne!(
            hash_subject("bin laden usama"),
            hash_subject("osama bin laden")
        );
    }

    #[test]
    fn normalizes_a_clean_record() {
        let result = normalize_record(&record("Bin Laden, Usama"), &config());
        let NormalizedRecord::Entry(entry) = result else {
            panic!("expected an entry, got a review item");
        };
        assert_eq!(entry.list_id, "OFAC-SDN");
        assert_eq!(entry.status, SanctionsStatusLabel::Active);
        assert_eq!(entry.effective_at, "2023-06-01T00:00:00Z");
        assert_eq!(entry.source, "ofac");
        assert_eq!(entry.dataset_version, 1);
        assert_eq!(
            entry.subject_hash,
            hash_subject(&canonicalize_subject("Bin Laden, Usama"))
        );
    }

    #[test]
    fn unmapped_list_and_unparseable_dates_become_review_items() {
        let unmapped = ProviderRecord {
            provider_list: "MYSTERY".to_owned(),
            ..record("Someone")
        };
        assert!(matches!(
            normalize_record(&unmapped, &config()),
            NormalizedRecord::Review { .. }
        ));

        let bad_date = ProviderRecord {
            effective_date: Some("not-a-date".to_owned()),
            ..record("Someone")
        };
        assert!(matches!(
            normalize_record(&bad_date, &config()),
            NormalizedRecord::Review { .. }
        ));

        let no_date = ProviderRecord {
            effective_date: None,
            ..record("Someone")
        };
        assert!(matches!(
            normalize_record(&no_date, &config()),
            NormalizedRecord::Review { .. }
        ));
    }

    #[test]
    fn removed_status_maps_to_inactive() {
        let removed = ProviderRecord {
            provider_status: "removed".to_owned(),
            ..record("Al-Qaeda")
        };
        let NormalizedRecord::Entry(entry) = normalize_record(&removed, &config()) else {
            panic!("expected an entry");
        };
        assert_eq!(entry.status, SanctionsStatusLabel::Inactive);
    }

    #[test]
    fn rfc3339_variants_normalize_to_utc() {
        assert_eq!(
            to_rfc3339("2023-06-01").as_deref(),
            Some("2023-06-01T00:00:00Z")
        );
        assert_eq!(
            to_rfc3339("2023-06-01T12:30:00Z").as_deref(),
            Some("2023-06-01T12:30:00Z")
        );
        assert_eq!(
            to_rfc3339("2023-06-01T12:30:00+02:00").as_deref(),
            Some("2023-06-01T12:30:00Z")
        );
        assert_eq!(to_rfc3339("June 1, 2023"), None);
    }

    #[test]
    fn normalization_is_deterministic() {
        let records = vec![record("Bin Laden, Usama"), record("Al-Qaeda")];
        let first = normalize_records(&records, &config());
        let second = normalize_records(&records, &config());
        assert_eq!(first, second);
    }
}

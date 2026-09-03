//! End-to-end golden test for the sanctions pipeline: a provider snapshot
//! enters through the source boundary, records flow through the normalizer,
//! and the resulting entries must (a) match a committed golden expectation
//! and (b) round-trip through the SDK's schema-mirroring model — the same
//! validation `scripts/check-fixtures.py` applies to shipped fixtures.

use safeguard_adapters::sanctions::{
    hash_subject, normalize_records, NormalizedRecord, NormalizerConfig, PipeDelimitedSource,
    SanctionsSource,
};
use safeguard_sdk::registry::SanctionsDatasetEntry;

/// The reference config for the golden test's OFAC-style source.
fn ofac_config() -> NormalizerConfig {
    NormalizerConfig {
        list_map: vec![
            ("SDN".to_owned(), "OFAC-SDN".to_owned()),
            ("SSI".to_owned(), "OFAC-SSI".to_owned()),
        ],
        active_statuses: vec!["active".to_owned()],
        source_id: "ofac",
    }
}

const SNAPSHOT: &str = "\
# Golden-test snapshot (OFAC-style)
bin laden, usama|SDN|active|2023-06-01
north korea, pyongyang bank|SDN|active|2022-11-20
qods force|SSI|active|2021-04-15
retired entity|SDN|removed|2019-03-15
";

#[test]
fn golden_pipeline_produces_schema_valid_entries() {
    let source = PipeDelimitedSource;
    let records = source.parse(SNAPSHOT).expect("snapshot parses");
    let normalized = normalize_records(&records, &ofac_config());

    let entries: Vec<&SanctionsDatasetEntry> = normalized
        .iter()
        .filter_map(|result| match result {
            NormalizedRecord::Entry(entry) => Some(entry),
            NormalizedRecord::Review { .. } => None,
        })
        .collect();

    // Four records, one of which is a removed (inactive) listing; the
    // "removed" status still normalizes to an entry (status inactive).
    assert_eq!(entries.len(), 4);

    let usama = &entries[0];
    assert_eq!(usama.list_id, "OFAC-SDN");
    assert_eq!(usama.effective_at, "2023-06-01T00:00:00Z");
    assert_eq!(usama.source, "ofac");
    // Golden subject hash: recompute from the canonical subject so the test
    // documents the exact identifier being screened.
    assert_eq!(
        usama.subject_hash,
        hash_subject("bin laden usama"),
        "subject_hash must be the hash of the canonical subject"
    );

    // The removed listing is inactive, never active.
    let retired = entries
        .iter()
        .find(|entry| entry.list_id == "OFAC-SDN" && entry.effective_at == "2019-03-15T00:00:00Z")
        .expect("removed entry present");
    assert_eq!(retired.status.to_code(), 1, "removed maps to inactive");

    // Every entry round-trips through the SDK model (deny_unknown_fields,
    // exact field set) — the same shape check-fixtures.py runs.
    for entry in &entries {
        let json = serde_json::to_value(entry).expect("entry serializes");
        let reparsed: SanctionsDatasetEntry =
            serde_json::from_value(json).expect("entry matches the SDK model exactly");
        assert_eq!(reparsed, **entry);
    }
}

const SNAPSHOT_WITH_JUNK: &str = "\
good subject|SDN|active|2023-06-01
unmapped list|MYSTERY|active|2023-06-01
no date|SDN|active
";

#[test]
fn junk_records_surface_for_review_not_invention() {
    let source = PipeDelimitedSource;
    let records = source.parse(SNAPSHOT_WITH_JUNK).expect("snapshot parses");
    let normalized = normalize_records(&records, &ofac_config());

    let entries = normalized
        .iter()
        .filter(|result| matches!(result, NormalizedRecord::Entry(_)))
        .count();
    let reviews = normalized
        .iter()
        .filter_map(|result| match result {
            NormalizedRecord::Review { record, reason } => Some((record, reason)),
            NormalizedRecord::Entry(_) => None,
        })
        .collect::<Vec<_>>();

    // Only the clean record becomes an entry; the unmapped list and the
    // missing date become review items naming why.
    assert_eq!(entries, 1);
    assert_eq!(reviews.len(), 2);
    assert!(reviews.iter().any(|(_, reason)| reason.contains("MYSTERY")));
    assert!(reviews
        .iter()
        .any(|(_, reason)| reason.contains("missing effective date")));
}

#[test]
fn pipeline_is_deterministic_across_runs() {
    let source = PipeDelimitedSource;
    let records = source.parse(SNAPSHOT).expect("parses");
    let first = normalize_records(&records, &ofac_config());
    let second = normalize_records(&records, &ofac_config());
    assert_eq!(first, second);
}

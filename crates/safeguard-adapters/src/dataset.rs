//! Dataset building: the operator-facing step that turns a provider
//! snapshot into a publishable registry dataset.
//!
//! `SanctionsSource::parse` + `normalize_records` produce entries, but an
//! operator pushing a dataset needs the complete artifact: the entries to
//! hand to the contract's `set_sanctions_entry`, the review items that were
//! *not* normalized, and a machine- and human-readable summary. This module
//! assembles that artifact and writes it as JSON.
//!
//! The output is validated against the SDK's schema-mirroring model before
//! it is emitted — the "validate before publish" rule of `docs/adapters.md`.

use std::path::Path;

use serde::Serialize;

use safeguard_sdk::registry::SanctionsDatasetEntry;

use crate::sanctions::{normalize_records, NormalizedRecord, NormalizerConfig, SanctionsSource};

/// One review item: a provider record the normalizer could not map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItem {
    /// The raw record, rendered for a human reviewer.
    pub record: String,
    /// Why it could not be normalized.
    pub reason: String,
}

/// The complete result of building a dataset from one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetReport {
    /// Source identifier (e.g. `ofac`).
    pub source: String,
    /// The normalized entries, ready for the registry.
    #[serde(rename = "entries")]
    pub entries: Vec<SanctionsDatasetEntry>,
    /// Records that need operator review (never silently dropped or
    /// invented).
    pub review: Vec<ReviewItem>,
}

impl DatasetReport {
    /// The number of entries that normalized cleanly.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The number of records that need operator review.
    #[must_use]
    pub fn review_count(&self) -> usize {
        self.review.len()
    }
}

/// Build a dataset report from a provider snapshot.
///
/// Deterministic: the same snapshot + config always yields the same report.
pub fn build_dataset<S: SanctionsSource>(
    source: &S,
    config: &NormalizerConfig,
    snapshot: &str,
) -> Result<DatasetReport, crate::sanctions::SourceError> {
    let records = source.parse(snapshot)?;
    let normalized = normalize_records(&records, config);

    let mut entries = Vec::new();
    let mut review = Vec::new();
    for result in normalized {
        match result {
            NormalizedRecord::Entry(entry) => entries.push(entry),
            NormalizedRecord::Review { record, reason } => review.push(ReviewItem {
                record: record.to_string(),
                reason,
            }),
        }
    }

    Ok(DatasetReport {
        source: source.source_id().to_owned(),
        entries,
        review,
    })
}

/// Serialize a dataset report to a JSON file.
///
/// The report contains only registry-ready entries and review items — no
/// provider text beyond what the review items render for a human — so the
/// file can be committed as an audit artifact or fed to a publisher.
pub fn write_dataset(report: &DatasetReport, path: &Path) -> Result<(), std::io::Error> {
    let json = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
    std::fs::write(path, json + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanctions::PipeDelimitedSource;

    fn ofac_config() -> NormalizerConfig {
        NormalizerConfig {
            list_map: vec![("SDN".to_owned(), "OFAC-SDN".to_owned())],
            active_statuses: vec!["active".to_owned()],
            source_id: "ofac",
        }
    }

    #[test]
    fn build_dataset_partitions_entries_and_review() {
        let source = PipeDelimitedSource;
        let report = build_dataset(
            &source,
            &ofac_config(),
            "good one|SDN|active|2023-06-01\nno date|SDN|active\n",
        )
        .expect("builds");
        assert_eq!(report.entry_count(), 1);
        assert_eq!(report.review_count(), 1);
        assert_eq!(report.source, "ofac");
        assert_eq!(report.entries[0].list_id, "OFAC-SDN");
        assert!(report.review[0].reason.contains("missing effective date"));
    }

    #[test]
    fn report_round_trips_through_json() {
        let source = PipeDelimitedSource;
        let report =
            build_dataset(&source, &ofac_config(), "x|SDN|active|2023-06-01\n").expect("builds");
        let json = serde_json::to_value(&report).expect("serializes");
        let reparsed: DatasetReport = serde_json::from_value(json).expect("parses");
        assert_eq!(reparsed, report);
    }

    #[test]
    fn build_is_deterministic() {
        let source = PipeDelimitedSource;
        let snapshot = "a|SDN|active|2023-06-01\nb|SDN|removed|2021-01-01\n";
        assert_eq!(
            build_dataset(&source, &ofac_config(), snapshot).expect("builds"),
            build_dataset(&source, &ofac_config(), snapshot).expect("builds")
        );
    }
}

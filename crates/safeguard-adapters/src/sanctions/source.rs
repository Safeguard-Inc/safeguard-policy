//! Sanctions sources: provider-agnostic record shapes and the parser.
//!
//! A *source* is one sanctions provider (OFAC, EU, a national authority…).
//! Safeguard is not an official sanctions-data provider — external datasets
//! enter through these adapters and are normalized into deterministic
//! registry entries (`crates/safeguard-adapters/src/sanctions/normalizer.rs`).
//!
//! The trait deliberately separates **fetch** (how a snapshot arrives) from
//! **parse** (how it becomes raw records). Only `parse` is required: offline
//! test fixtures and CI feed snapshots straight to the parser, while live
//! deployments implement `fetch` to pull from the provider.

use std::fmt;

/// One raw record exactly as a provider supplies it.
///
/// Field names are provider-neutral; the normalizer maps them into the
/// canonical [`safeguard_sdk::registry::SanctionsDatasetEntry`] shape.
/// Nothing here is assumed to be safe to store — subject text is hashed
/// before it leaves the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecord {
    /// The subject identifier as the provider wrote it (name, entity,
    /// vessel, alias…). Arbitrary provider text; never stored verbatim.
    pub raw_subject: String,
    /// The provider's list/program code, e.g. `SDN` (OFAC) or `CON` (EU).
    pub provider_list: String,
    /// The provider's status for this entry, e.g. `active` or `removed`.
    pub provider_status: String,
    /// The date the listing became effective, as the provider writes it
    /// (any format the normalizer config knows how to parse).
    pub effective_date: Option<String>,
}

impl fmt::Display for ProviderRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "subject={:?} list={} status={} effective={}",
            self.raw_subject,
            self.provider_list,
            self.provider_status,
            self.effective_date.as_deref().unwrap_or("none")
        )
    }
}

/// Errors from parsing a provider snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// The snapshot is not in the format this source expects.
    MalformedSnapshot(String),
    /// A single record could not be parsed (line/record number, reason).
    BadRecord {
        /// 1-based position of the offending record within the snapshot.
        record: usize,
        /// Why it could not be parsed.
        reason: String,
    },
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSnapshot(message) => write!(f, "malformed snapshot: {message}"),
            Self::BadRecord { record, reason } => {
                write!(f, "record #{record} could not be parsed: {reason}")
            }
        }
    }
}

impl std::error::Error for SourceError {}

/// A sanctions data provider.
///
/// Implementations are one-per-provider. The trait is intentionally thin:
/// fetch strategy varies wildly (HTTP, SFTP, email drop, manual export),
/// but every provider ends with the same step — turning a snapshot string
/// into [`ProviderRecord`]s for the normalizer.
pub trait SanctionsSource {
    /// Stable source identifier recorded on every normalized entry
    /// (e.g. `ofac`). ASCII, used as `SanctionsDatasetEntry::source`.
    fn source_id(&self) -> &'static str;

    /// Parse a provider snapshot into raw records.
    ///
    /// Must be pure and deterministic: the same snapshot always yields the
    /// same records. Network access belongs in [`Self::fetch`], never here.
    fn parse(&self, snapshot: &str) -> Result<Vec<ProviderRecord>, SourceError>;

    /// Retrieve the current snapshot from the provider.
    ///
    /// Not part of the deterministic core; concrete providers implement this
    /// when they have a live transport. Default returns an error so offline
    /// sources (fixtures, CI) need not fake a transport.
    fn fetch(&self) -> Result<String, SourceError> {
        Err(SourceError::MalformedSnapshot(format!(
            "{} has no live fetch transport",
            self.source_id()
        )))
    }
}

/// A snapshot parser for pipe-delimited OFAC-style list files.
///
/// OFAC publishes its SDN list as a pipe-delimited file whose lines look
/// like `SDN|bin laden, usama|active|2023-06-01`. This parser accepts that
/// shape (fields separated by `|`) so real exports and test fixtures share
/// one parser. Providers with other formats implement [`SanctionsSource`]
/// directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipeDelimitedSource;

impl SanctionsSource for PipeDelimitedSource {
    fn source_id(&self) -> &'static str {
        "ofac"
    }

    fn parse(&self, snapshot: &str) -> Result<Vec<ProviderRecord>, SourceError> {
        let mut records = Vec::new();
        for (index, raw_line) in snapshot.lines().enumerate() {
            let line_number = index + 1;
            let line = raw_line.trim();
            // Blank lines and `#` comments are tolerated between records.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('|').map(str::trim).collect();
            if fields.len() < 3 {
                return Err(SourceError::BadRecord {
                    record: line_number,
                    reason: format!(
                        "expected at least 3 `|`-separated fields (subject|list|status), found {}",
                        fields.len()
                    ),
                });
            }
            let effective_date = fields.get(3).map(|value| (*value).to_owned());
            records.push(ProviderRecord {
                raw_subject: fields[0].to_owned(),
                provider_list: fields[1].to_owned(),
                provider_status: fields[2].to_owned(),
                effective_date,
            });
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT: &str = "\
# OFAC-style sample snapshot (test fixture)
bin laden, usama|SDN|active|2023-06-01
north korea, pyongyang bank|SDN|active|2022-11-20
al-qaeda|SDN|removed|2019-03-15

";
    const MALFORMED: &str = "only-two-fields";

    #[test]
    fn parses_valid_lines_and_skips_comments_and_blanks() {
        let source = PipeDelimitedSource;
        let records = source.parse(SNAPSHOT).expect("valid snapshot parses");
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].raw_subject, "bin laden, usama");
        assert_eq!(records[0].provider_list, "SDN");
        assert_eq!(records[0].effective_date.as_deref(), Some("2023-06-01"));
        assert_eq!(records[2].provider_status, "removed");
    }

    #[test]
    fn parsing_is_deterministic() {
        let source = PipeDelimitedSource;
        assert_eq!(
            source.parse(SNAPSHOT).expect("parses"),
            source.parse(SNAPSHOT).expect("parses")
        );
    }

    #[test]
    fn rejects_short_lines_with_a_record_number() {
        let source = PipeDelimitedSource;
        let error = source.parse(MALFORMED).expect_err("short line fails");
        assert_eq!(
            error,
            SourceError::BadRecord {
                record: 1,
                reason: "expected at least 3 `|`-separated fields (subject|list|status), found 1"
                    .to_owned(),
            }
        );
    }

    #[test]
    fn default_fetch_is_an_error_until_a_transport_is_provided() {
        let source = PipeDelimitedSource;
        assert!(source.fetch().is_err());
    }
}

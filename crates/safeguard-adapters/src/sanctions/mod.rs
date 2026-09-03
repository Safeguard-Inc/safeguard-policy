//! Sanctions adapter: external sanctions lists → canonical registry entries.
//!
//! Implements the pipeline documented in `docs/adapters.md`:
//!
//! ```text
//! Provider snapshot
//!      │  SanctionsSource::parse
//!      ▼
//! ProviderRecord[]
//!      │  normalizer::normalize_records
//!      ▼
//! NormalizedRecord::Entry(SanctionsDatasetEntry)  |  Review { record, reason }
//! ```
//!
//! Entries are keyed by the SHA-256 hash of a canonical subject so no
//! personal data leaves the adapter; records that cannot be normalized
//! surface as review items instead of being invented (see the module docs
//! of [`normalizer`]).

pub mod normalizer;
pub mod source;

pub use normalizer::{
    canonicalize_subject, hash_subject, normalize_record, normalize_records, NormalizedRecord,
    NormalizerConfig,
};
pub use source::{PipeDelimitedSource, ProviderRecord, SanctionsSource, SourceError};

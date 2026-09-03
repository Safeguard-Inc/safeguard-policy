//! `safeguard dataset build <snapshot> -o <report.json>` — run a sanctions
//! provider snapshot through the adapter pipeline and write the dataset
//! report an operator reviews before pushing entries on-chain.
//!
//! The snapshot is parsed with the OFAC-style pipe-delimited source and
//! normalized with a configurable list/status mapping. Entries that
//! normalize cleanly are reported; unmappable records are listed as review
//! items — never silently dropped or invented.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;

use safeguard_adapters::dataset::{build_dataset, write_dataset, DatasetReport};
use safeguard_adapters::sanctions::{NormalizerConfig, PipeDelimitedSource};

/// Arguments for `safeguard dataset build`.
#[derive(Args)]
pub struct DatasetArgs {
    /// Path to a provider snapshot (pipe-delimited OFAC-style file).
    pub snapshot: PathBuf,
    /// Where to write the dataset report JSON.
    #[arg(short, long, default_value = "dataset-report.json")]
    pub output: PathBuf,
    /// Additional list mappings `PROVIDER_CODE=LIST_ID` (repeatable).
    #[arg(long = "list", value_parser = parse_list_mapping)]
    pub list_mappings: Vec<(String, String)>,
}

/// Parse a `PROVIDER_CODE=LIST_ID` list mapping argument.
pub fn parse_list_mapping(value: &str) -> Result<(String, String)> {
    let (provider, canonical) = value
        .split_once('=')
        .with_context(|| format!("list mapping must be PROVIDER_CODE=LIST_ID, got {value:?}"))?;
    if provider.is_empty() || canonical.is_empty() {
        anyhow::bail!("list mapping must be PROVIDER_CODE=LIST_ID, got {value:?}");
    }
    Ok((provider.to_owned(), canonical.to_owned()))
}

/// The default list mapping: OFAC program codes → canonical list ids.
fn default_list_mappings() -> Vec<(String, String)> {
    vec![
        ("SDN".to_owned(), "OFAC-SDN".to_owned()),
        ("SSI".to_owned(), "OFAC-SSI".to_owned()),
        ("CAPTA".to_owned(), "OFAC-CAPTA".to_owned()),
        ("NS-MACRO".to_owned(), "OFAC-NS-MACRO".to_owned()),
        ("NS-ISA".to_owned(), "OFAC-NS-ISA".to_owned()),
        ("NS-PLC".to_owned(), "OFAC-NS-PLC".to_owned()),
        ("NS-SDN".to_owned(), "OFAC-NS-SDN".to_owned()),
        ("NS-CMIC".to_owned(), "OFAC-NS-CMIC".to_owned()),
    ]
}

/// Statuses the default config treats as in-force listings.
fn default_active_statuses() -> Vec<String> {
    vec!["active".to_owned()]
}

pub fn run(args: DatasetArgs) -> Result<()> {
    let mut mappings = default_list_mappings();
    mappings.extend(args.list_mappings);
    let config = NormalizerConfig {
        list_map: mappings,
        active_statuses: default_active_statuses(),
        source_id: "ofac",
    };

    let snapshot = fs::read_to_string(&args.snapshot)
        .with_context(|| format!("reading snapshot {}", args.snapshot.display()))?;

    let source = PipeDelimitedSource;
    let report = build_dataset(&source, &config, &snapshot)
        .with_context(|| format!("building dataset from {}", args.snapshot.display()))?;

    write_dataset(&report, &args.output)
        .with_context(|| format!("writing {}", args.output.display()))?;

    print_summary(&report, &args.output);
    Ok(())
}

fn print_summary(report: &DatasetReport, output: &Path) {
    println!(
        "source {}: {} entries normalized, {} review items",
        report.source,
        report.entry_count(),
        report.review_count()
    );
    if report.review_count() > 0 {
        println!("review items (operator decision required):");
        for item in &report.review {
            println!("  - {}\n      reason: {}", item.record, item.reason);
        }
    }
    println!("report written to {}", output.display());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_mapping_parser_accepts_valid_pairs() {
        assert_eq!(
            parse_list_mapping("SDN=OFAC-SDN").expect("parses"),
            ("SDN".to_owned(), "OFAC-SDN".to_owned())
        );
    }

    #[test]
    fn list_mapping_parser_rejects_junk() {
        assert!(parse_list_mapping("SDN").is_err());
        assert!(parse_list_mapping("=OFAC-SDN").is_err());
        assert!(parse_list_mapping("SDN=").is_err());
    }
}

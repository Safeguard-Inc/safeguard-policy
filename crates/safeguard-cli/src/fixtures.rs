//! Fixture dataset loading and validation for the CLI.
//!
//! The fixtures under `policies/fixtures/` are the reference datasets the
//! docs and tests use. This module loads them and enforces the same rules as
//! `scripts/check-fixtures.py`, so operators can validate locally with the
//! same binary they use for everything else. Sanctions entries go through
//! the SDK's schema-mirroring model; account and jurisdiction shapes are
//! fixture-local (they are not schema-backed surfaces).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use safeguard_sdk::registry::{decode_subject_hash, SanctionsDatasetEntry};

/// One account fixture: a subject plus its resolved facts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountFixture {
    /// Stellar-style G address.
    pub account: String,
    /// Core `AccountStatus` label.
    pub status: String,
    /// Region code (must exist in the universe) or `XX` for unknown.
    pub jurisdiction: String,
    pub allowlisted: bool,
    pub denylisted: bool,
}

/// The region universe: every code a policy or account may reference.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct JurisdictionUniverse {
    pub permitted: Vec<String>,
    pub restricted: Vec<String>,
    pub prohibited: Vec<String>,
}

impl JurisdictionUniverse {
    /// Every known region code across all three lists.
    pub fn all_codes(&self) -> std::collections::BTreeSet<String> {
        self.permitted
            .iter()
            .chain(&self.restricted)
            .chain(&self.prohibited)
            .cloned()
            .collect()
    }
}

/// The on-disk wrapper shape of accounts.json (`{ "accounts": [...] }`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsFile {
    accounts: Vec<AccountFixture>,
}

/// All fixture datasets for a fixtures directory.
#[derive(Debug, Clone, Default)]
pub struct FixtureSets {
    pub accounts: Vec<AccountFixture>,
    pub universe: JurisdictionUniverse,
    pub sanctions: Vec<SanctionsDatasetEntry>,
}

/// The reserved sentinel for an unknown jurisdiction.
pub const UNKNOWN_JURISDICTION: &str = "XX";

/// Load and parse the three fixture datasets (missing sanctions file is not
/// an error: deployments may have no screening dataset).
pub fn load(dir: &Path) -> Result<FixtureSets> {
    let read = |name: &str| -> Result<String> {
        fs::read_to_string(dir.join(name))
            .with_context(|| format!("reading {}/{}", dir.display(), name))
    };

    let accounts: Vec<AccountFixture> =
        serde_json::from_str::<AccountsFile>(&read("accounts.json")?)
            .context("parsing accounts.json")?
            .accounts;

    let universe: JurisdictionUniverse =
        serde_json::from_str(&read("jurisdictions.json")?).context("parsing jurisdictions.json")?;

    let sanctions_path = dir.join("sanctions.json");
    let sanctions = if sanctions_path.exists() {
        serde_json::from_str(
            &fs::read_to_string(&sanctions_path)
                .with_context(|| format!("reading {}", sanctions_path.display()))?,
        )
        .context("parsing sanctions.json")?
    } else {
        Vec::new()
    };

    Ok(FixtureSets {
        accounts,
        universe,
        sanctions,
    })
}

/// Validate every fixture dataset; returns a list of problems (empty = ok).
pub fn validate(sets: &FixtureSets) -> Vec<String> {
    let mut problems = Vec::new();

    // Region universe: uppercase alpha-2, no duplicates, no cross-list
    // classification.
    let lists: [(&str, &Vec<String>); 3] = [
        ("permitted", &sets.universe.permitted),
        ("restricted", &sets.universe.restricted),
        ("prohibited", &sets.universe.prohibited),
    ];
    let mut classified: std::collections::BTreeMap<String, &str> = Default::default();
    for (list_name, codes) in lists {
        let mut seen = std::collections::BTreeSet::new();
        for code in codes {
            if !is_region_code(code) {
                problems.push(format!(
                    "jurisdictions: {code:?} is not an uppercase ISO alpha-2 code"
                ));
            }
            if !seen.insert(code) {
                problems.push(format!(
                    "jurisdictions: duplicate region {code:?} in {list_name}"
                ));
            }
            if let Some(previous) = classified.insert(code.clone(), list_name) {
                if previous != list_name {
                    problems.push(format!(
                        "jurisdictions: {code:?} classified as both {previous} and {list_name}"
                    ));
                }
            }
        }
    }
    let universe_codes = sets.universe.all_codes();

    // Account fixtures: well-formed address, known status, jurisdiction in
    // the universe (or the unknown sentinel), boolean flags.
    for account in &sets.accounts {
        if !is_stellar_address(&account.account) {
            problems.push(format!(
                "accounts: {:?} is not a well-formed G address",
                account.account
            ));
        }
        if !matches!(
            account.status.as_str(),
            "active" | "restricted" | "frozen" | "suspended" | "unknown"
        ) {
            problems.push(format!(
                "accounts: {:?} has unknown status {:?}",
                account.account, account.status
            ));
        }
        if account.jurisdiction != UNKNOWN_JURISDICTION
            && !universe_codes.contains(&account.jurisdiction)
        {
            problems.push(format!(
                "accounts: {:?} jurisdiction {:?} not in jurisdictions.json",
                account.account, account.jurisdiction
            ));
        }
    }

    // Sanctions entries: schema shape via the SDK model plus the pure
    // subject-hash and version checks.
    for entry in &sets.sanctions {
        if decode_subject_hash(&entry.subject_hash).is_none() {
            problems.push(format!(
                "sanctions: {:?} is not a 64-hex subject hash",
                entry.subject_hash
            ));
        }
        if entry.dataset_version == 0 {
            problems.push(format!(
                "sanctions: {} has dataset_version 0 (must be >= 1)",
                entry.subject_hash
            ));
        }
    }

    problems
}

/// An uppercase ISO 3166-1 alpha-2 region code.
fn is_region_code(code: &str) -> bool {
    code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase())
}

/// A Stellar-style public key: `G` followed by 55 base-32 characters
/// (A-Z and 2-7; the digits 0, 1, 8, 9 are not part of the alphabet).
fn is_stellar_address(address: &str) -> bool {
    let bytes = address.as_bytes();
    bytes.len() == 56
        && bytes[0] == b'G'
        && bytes[1..]
            .iter()
            .all(|byte| matches!(*byte, b'A'..=b'Z') || matches!(*byte, b'2'..=b'7'))
}

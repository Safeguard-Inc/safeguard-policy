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

use safeguard_sdk::composition::{PolicySet, PolicySource};
use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::registry::{decode_subject_hash, SanctionsDatasetEntry};
use safeguard_sdk::IdentityStatus;

/// Core `IdentityStatus` labels, mirrored from
/// `safeguard_core::registries::identity`.
const IDENTITY_STATUSES: [IdentityStatus; 5] = [
    IdentityStatus::Verified,
    IdentityStatus::Unverified,
    IdentityStatus::Revoked,
    IdentityStatus::Expired,
    IdentityStatus::Unknown,
];

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

/// One identity verification record, mirroring `set_identity` on-chain:
/// attestation reference only, no PII.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFixture {
    /// Stellar-style G address.
    pub account: String,
    /// Core `IdentityStatus` label.
    pub status: String,
    /// Reference to an off-chain attestation (KYC/verification provider).
    pub attestation_ref: String,
    /// Unix epoch seconds when the verification expires; 0 = never.
    pub expires_at: i64,
}

/// One policy -> token registry binding.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBindingFixture {
    /// The policy the token is bound to (must exist as a shipped policy).
    pub policy_id: String,
    /// Stellar-style token contract address.
    pub token: String,
    /// Human-readable annotation; informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)] // consumed by tools that read the raw file, not by validate
    pub note: Option<String>,
}

/// The on-disk wrapper shape of accounts.json (`{ "accounts": [...] }`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsFile {
    accounts: Vec<AccountFixture>,
}

/// The on-disk wrapper shape of identity.json (`{ "accounts": [...] }`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    accounts: Vec<IdentityFixture>,
}

/// The on-disk wrapper shape of tokens.json (`{ "bindings": [...] }`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokensFile {
    bindings: Vec<TokenBindingFixture>,
}

/// All fixture datasets for a fixtures directory.
#[derive(Debug, Clone, Default)]
pub struct FixtureSets {
    pub accounts: Vec<AccountFixture>,
    pub universe: JurisdictionUniverse,
    pub sanctions: Vec<SanctionsDatasetEntry>,
    pub identity: Vec<IdentityFixture>,
    pub tokens: Vec<TokenBindingFixture>,
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

    // Identity and token fixtures are optional datasets: deployments may
    // have no verification records or token bindings yet.
    let identity = load_optional::<IdentityFile>(dir, "identity.json")?
        .map(|f| f.accounts)
        .unwrap_or_default();
    let tokens = load_optional::<TokensFile>(dir, "tokens.json")?
        .map(|f| f.bindings)
        .unwrap_or_default();

    Ok(FixtureSets {
        accounts,
        universe,
        sanctions,
        identity,
        tokens,
    })
}

/// Load a JSON file if it exists; `None` when absent.
fn load_optional<T: serde::de::DeserializeOwned>(dir: &Path, name: &str) -> Result<Option<T>> {
    let path = dir.join(name);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parsing {name}"))
        .map(Some)
}

/// Validate every fixture dataset; returns a list of problems (empty = ok).
pub fn validate(dir: &Path, sets: &FixtureSets) -> Vec<String> {
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

    // Identity records: well-formed address, known status, non-empty
    // attestation reference, integer epoch expiry.
    for record in &sets.identity {
        if !is_stellar_address(&record.account) {
            problems.push(format!(
                "identity: {:?} is not a well-formed G address",
                record.account
            ));
        }
        if !IDENTITY_STATUSES
            .iter()
            .any(|status| status.as_str() == record.status)
        {
            problems.push(format!(
                "identity: {:?} has unknown status {:?}",
                record.account, record.status
            ));
        }
        if record.attestation_ref.is_empty() {
            problems.push(format!(
                "identity: {:?} must carry an attestation_ref",
                record.account
            ));
        }
        if record.expires_at < 0 {
            problems.push(format!(
                "identity: {:?} expires_at must be a non-negative epoch",
                record.account
            ));
        }
    }

    // Token bindings: well-formed address, non-empty policy id, and the
    // policy must exist among the shipped reference policies (same rule as
    // scripts/check-fixtures.py, so the two gates cannot disagree).
    let shipped = shipped_policies(dir);
    if let Some(shipped) = &shipped {
        problems.extend(shipped.problems.iter().cloned());
    }
    for binding in &sets.tokens {
        if binding.policy_id.is_empty() {
            problems.push("tokens: binding with an empty policy_id".to_owned());
        }
        if !is_stellar_address(&binding.token) {
            problems.push(format!(
                "tokens: {:?} is not a well-formed Stellar address",
                binding.token
            ));
        }
        if let Some(shipped) = &shipped {
            if !shipped.ids.contains(&binding.policy_id) {
                problems.push(format!(
                    "tokens: policy {:?} has no shipped policy document",
                    binding.policy_id
                ));
            }
        }
    }

    problems
}

/// The reference policies shipped next to the fixtures directory, loaded as
/// a **composed set** rather than a bag of ids.
struct ShippedPolicies {
    /// Every declared `policy_id`, for the token-binding cross-check.
    ids: std::collections::BTreeSet<String>,
    /// Identity collisions and unreadable documents, phrased as fixture
    /// problems.
    problems: Vec<String>,
}

/// Loads the reference policies shipped next to the fixtures directory
/// (`../default` and `../examples`).
///
/// `None` when the fixtures directory is not inside a repository checkout
/// (e.g. a temp dir), in which case the existence cross-check is skipped.
///
/// Composing them instead of collecting ids is the point: a second file
/// declaring an identity that already exists is a collision to report, not
/// a duplicate for a set to swallow. The earlier version collected
/// `policy_id`s into a `BTreeSet`, so a colliding identity vanished silently
/// and the cross-check passed — after which a token bound to that id
/// resolved to whichever file the directory listing happened to yield last.
fn shipped_policies(dir: &Path) -> Option<ShippedPolicies> {
    let mut sources = Vec::new();
    let mut problems = Vec::new();
    for relative in ["../default", "../examples"] {
        let directory = dir.join(relative);
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        // Sorted so collision reports do not depend on readdir order, which
        // is exactly the nondeterminism this check exists to remove.
        let mut paths: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect();
        paths.sort();
        for path in paths {
            let raw = match std::fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(error) => {
                    problems.push(format!(
                        "policies: {} cannot be read: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            match serde_json::from_str::<PolicyDocument>(&raw) {
                Ok(document) => {
                    sources.push(PolicySource::new(path.display().to_string(), document));
                }
                Err(error) => problems.push(format!(
                    "policies: {} is not a policy document: {error}",
                    path.display()
                )),
            }
        }
    }
    if sources.is_empty() {
        return None;
    }
    let ids = sources
        .iter()
        .map(|source| source.document.policy_id.clone())
        .collect();
    if let Err(errors) = PolicySet::compose(sources) {
        problems.extend(errors.iter().map(|error| format!("policies: {error}")));
    }
    Some(ShippedPolicies { ids, problems })
}

/// An uppercase ISO 3166-1 alpha-2 region code.
fn is_region_code(code: &str) -> bool {
    code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase())
}

/// A Stellar-style public key: `G` followed by 55 base-32 characters
/// (A-Z and 2-7; the digits 0, 1, 8, 9 are not part of the alphabet).
fn is_stellar_address(address: &str) -> bool {
    address.len() == 56
        && address.as_bytes()[0] == b'G'
        && address.as_bytes()[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(byte))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A scratch layout with `policies/{default,examples}` and an empty
    /// `policies/fixtures`, which is the shape `shipped_policies` walks.
    fn layout(name: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "safeguard-fixtures-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        for directory in ["default", "examples", "fixtures"] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
        }
        root
    }

    fn policy_json(policy_id: &str, version: u32) -> String {
        format!(
            r#"{{"policy_id":"{policy_id}","version":{version},"rules":[
                {{"id":"ALLOW-1","type":"allowlist","action":"block"}}]}}"#
        )
    }

    fn sets_bound_to(policy_id: &str) -> FixtureSets {
        FixtureSets {
            accounts: Vec::new(),
            universe: JurisdictionUniverse::default(),
            sanctions: Vec::new(),
            identity: Vec::new(),
            tokens: vec![TokenBindingFixture {
                policy_id: policy_id.to_owned(),
                token: format!("G{}", "A".repeat(55)),
                note: None,
            }],
        }
    }

    #[test]
    fn a_colliding_shipped_policy_identity_is_reported() {
        // The regression: two files declaring the same identity. Collecting
        // ids into a set used to deduplicate them silently, so the gate
        // passed and a token bound to this id had no well-defined rules.
        let root = layout("collision");
        std::fs::write(
            root.join("default/policy.json"),
            policy_json("institutional-default", 1),
        )
        .unwrap();
        std::fs::write(
            root.join("examples/override.json"),
            policy_json("institutional-default", 1),
        )
        .unwrap();

        let problems = validate(
            &root.join("fixtures"),
            &sets_bound_to("institutional-default"),
        );
        assert!(
            problems.iter().any(
                |problem| problem.contains("duplicate policy version institutional-default v1")
            ),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("examples/override.json")),
            "the collision must name the origin: {problems:?}"
        );
    }

    #[test]
    fn a_new_version_of_a_shipped_policy_is_not_a_collision() {
        let root = layout("versioned");
        std::fs::write(
            root.join("default/policy.json"),
            policy_json("institutional-default", 1),
        )
        .unwrap();
        std::fs::write(
            root.join("examples/v2.json"),
            policy_json("institutional-default", 2),
        )
        .unwrap();

        let problems = validate(
            &root.join("fixtures"),
            &sets_bound_to("institutional-default"),
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn a_binding_to_an_unshipped_policy_is_still_reported() {
        let root = layout("unshipped");
        std::fs::write(
            root.join("default/policy.json"),
            policy_json("institutional-default", 1),
        )
        .unwrap();

        let problems = validate(&root.join("fixtures"), &sets_bound_to("typo-policy"));
        assert!(
            problems
                .iter()
                .any(|problem| problem
                    .contains("policy \"typo-policy\" has no shipped policy document")),
            "{problems:?}"
        );
    }

    #[test]
    fn an_unreadable_shipped_policy_is_reported_rather_than_skipped() {
        // The old code silently `continue`d past anything it could not parse,
        // which is the same class of bug: a malformed shipped policy reduced
        // the set the cross-check ran against without saying so.
        let root = layout("malformed");
        std::fs::write(root.join("default/policy.json"), "{ not json").unwrap();
        std::fs::write(
            root.join("examples/ok.json"),
            policy_json("institutional-default", 1),
        )
        .unwrap();

        let problems = validate(
            &root.join("fixtures"),
            &sets_bound_to("institutional-default"),
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("default/policy.json is not a policy document")),
            "{problems:?}"
        );
    }

    #[test]
    fn an_invalid_shipped_policy_is_rejected_by_composition() {
        let root = layout("invalid");
        // Duplicate rule ids: valid JSON, invalid policy.
        std::fs::write(
            root.join("default/policy.json"),
            r#"{"policy_id":"institutional-default","version":1,"rules":[
                {"id":"A-1","type":"allowlist","action":"block"},
                {"id":"A-1","type":"denylist","action":"block"}]}"#,
        )
        .unwrap();

        let problems = validate(
            &root.join("fixtures"),
            &sets_bound_to("institutional-default"),
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("invalid policy document")
                    && problem.contains("duplicate rule id")),
            "{problems:?}"
        );
    }
}

//! `safeguard evaluate <policy.json> <facts.json>` — decide a subject
//! offline using the same engine as the contract.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::{AccountStatus, RegionStatus};
use serde::Deserialize;

/// Facts file shape: core labels plus a region code or classification.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactsFile {
    /// `active` | `restricted` | `frozen` | `suspended` | `unknown`.
    account_status: String,
    allowlist_member: bool,
    denylist_matched: bool,
    sanctions_matched: bool,
    /// A region code (e.g. "US") or a classification
    /// (`permitted` | `restricted` | `prohibited` | `unknown`).
    jurisdiction: String,
}

fn parse_status(label: &str) -> Result<AccountStatus> {
    let status = match label {
        "active" => AccountStatus::Active,
        "restricted" => AccountStatus::Restricted,
        "frozen" => AccountStatus::Frozen,
        "suspended" => AccountStatus::Suspended,
        "unknown" => AccountStatus::Unknown,
        _ => bail!(
            "unknown account_status {label:?} (use active|restricted|frozen|suspended|unknown)"
        ),
    };
    Ok(status)
}

fn parse_classification(label: &str) -> Option<RegionStatus> {
    match label {
        "permitted" => Some(RegionStatus::Permitted),
        "restricted" => Some(RegionStatus::Restricted),
        "prohibited" => Some(RegionStatus::Prohibited),
        "unknown" => Some(RegionStatus::Unknown),
        _ => None,
    }
}

/// Evaluate a subject offline. `jurisdiction` in the facts file is a region
/// code (classified against the policy) or an explicit classification.
pub fn run(policy_path: &Path, facts_path: &Path) -> Result<()> {
    let policy: PolicyDocument = serde_json::from_str(
        &fs::read_to_string(policy_path)
            .with_context(|| format!("reading {}", policy_path.display()))?,
    )
    .with_context(|| format!("parsing {}", policy_path.display()))?;

    let facts: FactsFile = serde_json::from_str(
        &fs::read_to_string(facts_path)
            .with_context(|| format!("reading {}", facts_path.display()))?,
    )
    .with_context(|| format!("parsing {}", facts_path.display()))?;

    let account_status = parse_status(&facts.account_status)?;

    // Validate before deciding: the SDK refuses to evaluate invalid docs.
    let problems = safeguard_sdk::validation::validate_policy_document(&policy);
    if !problems.is_empty() {
        eprintln!("invalid policy document:");
        for problem in &problems {
            eprintln!("  - {problem}");
        }
        bail!("refusing to evaluate an invalid policy document");
    }

    let jurisdiction = match parse_classification(&facts.jurisdiction) {
        Some(classification) => classification,
        None => safeguard_sdk::evaluate::classify_region(&policy, &facts.jurisdiction),
    };

    let decision = safeguard_sdk::evaluate::evaluate(
        &policy,
        &safeguard_sdk::EvaluationFacts {
            account_status,
            allowlist_member: facts.allowlist_member,
            denylist_matched: facts.denylist_matched,
            sanctions_matched: facts.sanctions_matched,
            jurisdiction,
        },
    );

    let rule = decision
        .rule
        .map(|id| format!(" rule={}", String::from_utf8_lossy(id.as_trimmed_bytes())))
        .unwrap_or_default();
    println!(
        "{} ({}) policy={} v{}{}",
        decision.decision.as_str(),
        decision.reason_code.as_str(),
        policy.policy_id,
        policy.version,
        rule
    );
    Ok(())
}

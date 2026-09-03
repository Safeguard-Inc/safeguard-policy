//! `safeguard evaluate <policy.json> <facts.json>` — decide a subject
//! offline using the same engine as the contract.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::FactsFile;

/// Evaluate a subject offline. The facts file shape is the SDK's
/// [`FactsFile`] (see `docs/cli.md`).
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

    // Validate before deciding: the SDK refuses to evaluate invalid docs.
    let problems = safeguard_sdk::validation::validate_policy_document(&policy);
    if !problems.is_empty() {
        eprintln!("invalid policy document:");
        for problem in &problems {
            eprintln!("  - {problem}");
        }
        bail!("refusing to evaluate an invalid policy document");
    }

    let evaluation_facts = facts
        .to_evaluation_facts(&policy)
        .map_err(|message| anyhow::anyhow!("resolving {}: {message}", facts_path.display()))?;
    let decision = safeguard_sdk::evaluate::evaluate(&policy, &evaluation_facts);

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

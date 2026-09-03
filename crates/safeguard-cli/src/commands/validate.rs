//! `safeguard validate <policy.json>` — validate a policy document.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::validation::validate_policy_document;

/// Validate one policy document. Exits non-zero when invalid.
pub fn run(path: &Path) -> Result<()> {
    let json = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let document: PolicyDocument = serde_json::from_str(&json)
        .with_context(|| format!("parsing {} (schema conformance)", path.display()))?;

    let problems = validate_policy_document(&document);
    if problems.is_empty() {
        println!(
            "OK   {} — {} rules, version {}",
            path.display(),
            document.rules.len(),
            document.version
        );
        return Ok(());
    }

    eprintln!("FAIL {}", path.display());
    for problem in &problems {
        eprintln!("  - {problem}");
    }
    anyhow::bail!("validation failed for {}", path.display());
}

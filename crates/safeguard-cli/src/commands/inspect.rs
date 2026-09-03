//! `safeguard inspect <policy.json>` — summarize a policy document.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use safeguard_sdk::model::PolicyDocument;

/// Print a human-readable summary of a policy document.
pub fn run(path: &Path) -> Result<()> {
    let json = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let document: PolicyDocument =
        serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display()))?;

    println!("policy_id    {}", document.policy_id);
    println!("version      {}", document.version);
    if let Some(title) = &document.title {
        println!("title        {title}");
    }
    if let Some(description) = &document.description {
        println!("description  {description}");
    }
    println!("rules        {} (evaluation order: account status, allowlist, denylist, sanctions, jurisdiction)",
        document.rules.len());

    for rule in &document.rules {
        let regions = match (&rule.regions, rule.rule_type.as_core()) {
            (Some(regions), safeguard_sdk::RuleType::Jurisdiction) => format!(
                " | permitted {} | restricted {} | prohibited {}",
                regions.permitted.len(),
                regions.restricted.len(),
                regions.prohibited.len()
            ),
            _ => String::new(),
        };
        println!(
            "  {:32} {:<12} {:<6}{}",
            rule.id,
            rule.rule_type.as_core().as_str(),
            rule.action.as_core().as_str(),
            regions
        );
    }

    println!("decides      offline evaluation uses the same engine as the contract");
    Ok(())
}

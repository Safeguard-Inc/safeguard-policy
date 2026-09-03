//! `safeguard policy test <policy.json> [fixtures_dir]` — evaluate every
//! fixture subject through a policy offline.
//!
//! This is the policy author's acceptance run: register nothing on-chain,
//! just prove that the subjects in the fixture dataset resolve to the
//! intended decisions under the proposed policy. `--strict` turns any
//! BLOCK into a non-zero exit, so the command composes with CI gates.
//!
//! Note: the account fixtures carry no sanctions-screening claim (they are
//! the spec's account dataset), so `sanctions_matched` is false for every
//! subject; the sanctions dataset can be checked separately with
//! `registry inspect`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::{Decision, FactsFile};

use crate::commands::fixture::DEFAULT_FIXTURES_DIR;
use crate::fixtures;

#[derive(Parser)]
pub struct PolicyTestArgs {
    /// Path to a policy JSON document.
    pub policy: PathBuf,
    /// Fixtures directory (defaults to policies/fixtures).
    #[arg(long, default_value = DEFAULT_FIXTURES_DIR)]
    pub fixtures_dir: PathBuf,
    /// Exit non-zero if any subject evaluates to BLOCK.
    #[arg(long)]
    pub strict: bool,
}

pub fn run(policy_path: &Path, fixtures_dir: &Path, strict: bool) -> Result<()> {
    let json = std::fs::read_to_string(policy_path)
        .with_context(|| format!("reading {}", policy_path.display()))?;
    let policy: PolicyDocument = serde_json::from_str(&json)
        .with_context(|| format!("parsing {}", policy_path.display()))?;

    let problems = safeguard_sdk::validation::validate_policy_document(&policy);
    if !problems.is_empty() {
        eprintln!("invalid policy document:");
        for problem in &problems {
            eprintln!("  - {problem}");
        }
        anyhow::bail!("refusing to test an invalid policy document");
    }

    let sets = fixtures::load(fixtures_dir)
        .with_context(|| format!("loading fixtures from {}", fixtures_dir.display()))?;
    if sets.accounts.is_empty() {
        anyhow::bail!("no account fixtures found in {}", fixtures_dir.display());
    }

    println!(
        "policy {} v{} — {} fixture subjects",
        policy.policy_id,
        policy.version,
        sets.accounts.len()
    );
    println!(
        "{:<16} {:<10} {:<4} {:<8} {}",
        "account", "status", "region", "decision", "reason"
    );

    let mut counts = [0usize; 3]; // approve, block, flag
    let mut blocked = Vec::new();
    for account in &sets.accounts {
        let facts = FactsFile {
            account_status: account.status.clone(),
            allowlist_member: account.allowlisted,
            denylist_matched: account.denylisted,
            sanctions_matched: false,
            jurisdiction: account.jurisdiction.clone(),
        };
        let resolved = facts.to_evaluation_facts(&policy).map_err(|message| {
            anyhow::anyhow!("resolving facts for {}: {message}", account.account)
        })?;
        let decision = safeguard_sdk::evaluate::evaluate(&policy, &resolved);

        counts[decision.decision.to_code() as usize] += 1;
        if decision.decision == Decision::Block {
            blocked.push(account.account.clone());
        }

        // Fixture addresses share a long prefix, so show head…tail.
        let short = if account.account.len() > 14 {
            format!(
                "{}…{}",
                &account.account[..6],
                &account.account[account.account.len() - 6..]
            )
        } else {
            account.account.clone()
        };
        println!(
            "{short:<16} {:<10} {:<4} {:<8} {}",
            account.status,
            account.jurisdiction,
            decision.decision.as_str(),
            decision.reason_code.as_str()
        );
    }

    println!(
        "summary: {} approve, {} block, {} flag",
        counts[0], counts[1], counts[2]
    );

    if strict && !blocked.is_empty() {
        anyhow::bail!("strict: {} subject(s) evaluated to BLOCK", blocked.len());
    }
    Ok(())
}

//! `safeguard fixture validate [dir]` — validate the fixture datasets.
//!
//! Mirrors the rules of `scripts/check-fixtures.py` using the same SDK
//! models the rest of the CLI uses, so operators can validate locally
//! without the Python toolchain. Defaults to `policies/fixtures`.

use std::path::Path;

use anyhow::{Context, Result};

use crate::fixtures;

/// Default fixtures directory relative to the current directory.
pub const DEFAULT_FIXTURES_DIR: &str = "policies/fixtures";

pub fn run(path: Option<&Path>) -> Result<()> {
    let dir = path.unwrap_or_else(|| Path::new(DEFAULT_FIXTURES_DIR));

    let sets =
        fixtures::load(dir).with_context(|| format!("loading fixtures from {}", dir.display()))?;
    let problems = fixtures::validate(dir, &sets);

    if problems.is_empty() {
        println!(
            "OK: {} accounts, {} sanctions entries, {} identity records, {} token bindings, {} region codes",
            sets.accounts.len(),
            sets.sanctions.len(),
            sets.identity.len(),
            sets.tokens.len(),
            sets.universe.all_codes().len()
        );
        return Ok(());
    }

    eprintln!("FAIL: {} problem(s) in {}", problems.len(), dir.display());
    for problem in &problems {
        eprintln!("  - {problem}");
    }
    anyhow::bail!("fixture validation failed");
}

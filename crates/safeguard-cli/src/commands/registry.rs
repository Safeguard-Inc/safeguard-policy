//! `safeguard registry inspect <dataset.json>` — summarize a normalized
//! registry dataset before it is pushed on-chain.
//!
//! Auto-detects the dataset kind from its JSON shape:
//!
//! * an array of `SanctionsDatasetEntry` (sanctions.schema.json shape);
//! * an object with an `accounts` array (identity verification records);
//! * an object with a `bindings` array (policy -> token registry bindings);
//! * an object with permitted/restricted/prohibited lists (the region
//!   universe fixture);
//! * a `safeguard dataset build` report (`{source, entries, review}`),
//!   summarized with its review items before the entries are pushed.
//!
//! The output is a summary an operator can eyeball before handing the data
//! to the contract's registry entrypoints.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub fn run(path: &Path) -> Result<()> {
    let json = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: Value =
        serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display()))?;

    if let Some(entries) = value.as_array() {
        return inspect_sanctions(entries);
    }
    let object = value.as_object().with_context(|| {
        format!(
            "{} is neither a dataset array nor an object",
            path.display()
        )
    })?;
    if object.contains_key("accounts") {
        return inspect_identity(&object["accounts"]);
    }
    if object.contains_key("bindings") {
        return inspect_token_bindings(&object["bindings"]);
    }
    if object.contains_key("permitted") {
        return inspect_jurisdiction(object);
    }
    if object.contains_key("entries") && object.contains_key("review") {
        return inspect_dataset_report(object);
    }
    bail!(
        "{}: unrecognized dataset shape (expected sanctions entries, an accounts list, token bindings, region lists, or a dataset report)",
        path.display()
    )
}

/// Summarize a `safeguard dataset build` report: the entries that would be
/// pushed plus the review items requiring an operator decision.
fn inspect_dataset_report(object: &serde_json::Map<String, Value>) -> Result<()> {
    let source = object
        .get("source")
        .and_then(Value::as_str)
        .with_context(|| "dataset report missing source")?;
    let entries = object
        .get("entries")
        .and_then(Value::as_array)
        .with_context(|| "dataset report `entries` must be an array")?;
    let review = object
        .get("review")
        .and_then(Value::as_array)
        .with_context(|| "dataset report `review` must be an array")?;

    let mut active = 0usize;
    let mut inactive = 0usize;
    let mut lists = std::collections::BTreeMap::new();
    for entry in entries {
        match entry.get("status").and_then(Value::as_str) {
            Some("active") => active += 1,
            Some("inactive") => inactive += 1,
            _ => bail!("dataset entry missing a known status"),
        }
        if let Some(list) = entry.get("list_id").and_then(Value::as_str) {
            *lists.entry(list.to_owned()).or_insert(0usize) += 1;
        }
    }

    println!(
        "dataset report (source {source}): {} entries ({active} active, {inactive} inactive), {} review items",
        entries.len(),
        review.len()
    );
    let lists_summary = lists
        .iter()
        .map(|(list, count)| format!("{list} ({count})"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("  lists: {lists_summary}");
    if !review.is_empty() {
        println!("  review items (operator decision required before pushing):");
        for item in review {
            let reason = item
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            println!("    - {reason}");
        }
    }
    Ok(())
}

fn inspect_sanctions(entries: &[Value]) -> Result<()> {
    use std::collections::BTreeMap;

    let mut active = 0usize;
    let mut inactive = 0usize;
    let mut lists: BTreeMap<String, usize> = BTreeMap::new();
    let mut versions: BTreeMap<u32, usize> = BTreeMap::new();

    for entry in entries {
        let status = entry
            .get("status")
            .and_then(Value::as_str)
            .with_context(|| "sanctions entry missing status")?;
        match status {
            "active" => active += 1,
            "inactive" => inactive += 1,
            other => bail!("sanctions entry has unknown status {other:?}"),
        }
        if let Some(list) = entry.get("list_id").and_then(Value::as_str) {
            *lists.entry(list.to_owned()).or_default() += 1;
        }
        if let Some(version) = entry.get("dataset_version").and_then(Value::as_u64) {
            *versions
                .entry(u32::try_from(version).unwrap_or(u32::MAX))
                .or_default() += 1;
        }
    }

    println!(
        "sanctions dataset: {} entries ({active} active, {inactive} inactive)",
        entries.len()
    );
    let lists_summary = lists
        .iter()
        .map(|(list, count)| format!("{list} ({count})"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("  lists: {lists_summary}");
    let versions_summary = versions
        .iter()
        .map(|(version, count)| format!("v{version} x{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("  dataset versions: {versions_summary}");
    Ok(())
}

fn inspect_identity(accounts: &Value) -> Result<()> {
    use std::collections::BTreeMap;

    let accounts = accounts
        .as_array()
        .with_context(|| "identity dataset `accounts` must be an array")?;
    let mut statuses: BTreeMap<String, usize> = BTreeMap::new();
    for account in accounts {
        let status = account
            .get("status")
            .and_then(Value::as_str)
            .with_context(|| "identity record missing status")?;
        *statuses.entry(status.to_owned()).or_default() += 1;
    }

    println!("identity dataset: {} records", accounts.len());
    for (status, count) in &statuses {
        println!("  {status}: {count}");
    }
    Ok(())
}

fn inspect_token_bindings(bindings: &Value) -> Result<()> {
    use std::collections::BTreeMap;

    let bindings = bindings
        .as_array()
        .with_context(|| "token dataset `bindings` must be an array")?;
    let mut policies: BTreeMap<String, usize> = BTreeMap::new();
    for binding in bindings {
        let policy_id = binding
            .get("policy_id")
            .and_then(Value::as_str)
            .with_context(|| "token binding missing policy_id")?;
        if binding.get("token").and_then(Value::as_str).is_none() {
            bail!("token binding for {policy_id:?} missing token address");
        }
        *policies.entry(policy_id.to_owned()).or_default() += 1;
    }

    println!("token registry: {} bindings", bindings.len());
    for (policy_id, count) in &policies {
        println!("  {policy_id}: {count} token(s)");
    }
    Ok(())
}

fn inspect_jurisdiction(object: &serde_json::Map<String, Value>) -> Result<()> {
    let mut total = 0usize;
    for list in ["permitted", "restricted", "prohibited"] {
        let codes = object
            .get(list)
            .and_then(Value::as_array)
            .with_context(|| format!("jurisdiction universe missing {list} list"))?;
        total += codes.len();
        println!("  {list}: {}", codes.len());
    }
    println!("jurisdiction universe: {total} region codes");
    Ok(())
}

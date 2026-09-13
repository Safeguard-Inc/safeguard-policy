//! `safeguard policy compose <policy.json>…` — assemble policy documents
//! from multiple sources into one set and report identity collisions.
//!
//! A policy author's policies usually live in more than one place: the
//! reference documents in `policies/default` and `policies/examples`, a
//! vendor bundle, a deployment's override directory. `validate` checks one
//! document at a time, so nothing there can see that two *different* files
//! declare the same `policy_id` at the same `version` — and an identity with
//! two owners has no well-defined rules.
//!
//! This command is the load-time gate for that: it composes every source
//! through [`safeguard_sdk::composition::PolicySet`], which validates each
//! document and rejects any contested `(policy_id, version)` with the
//! origins that disagree. Exit code is non-zero when anything is rejected,
//! so it composes with CI.
//!
//! A *new version* under an existing `policy_id` is not a collision — it is
//! the version history the contract's append-only registry is built around
//! (`docs/versioning.md`), and it composes cleanly.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use safeguard_sdk::composition::{PolicySet, PolicySource};
use safeguard_sdk::model::PolicyDocument;

/// Loads one policy document as a named source.
fn load_source(path: &Path) -> Result<PolicySource> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let document: PolicyDocument = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as a policy document", path.display()))?;
    Ok(PolicySource::new(path.display().to_string(), document))
}

/// Expands a `--dir` argument into its top-level `*.json` documents, sorted.
///
/// Sorted because the collision report has to be reproducible: the whole
/// point of the check is that "which source wins" must never depend on
/// directory order.
fn expand_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    paths.sort();
    Ok(paths)
}

/// Composes `paths` (plus every `*.json` in each `dirs` entry) and reports
/// the result. Returns the composed set so callers can act on it.
pub fn run(paths: &[PathBuf], dirs: &[PathBuf], quiet: bool) -> Result<PolicySet> {
    let mut all: Vec<PathBuf> = paths.to_vec();
    for dir in dirs {
        all.extend(expand_dir(dir)?);
    }
    if all.is_empty() {
        anyhow::bail!("no policy documents given: pass files, --dir, or both");
    }

    let mut sources = Vec::with_capacity(all.len());
    for path in &all {
        sources.push(load_source(path)?);
    }

    match PolicySet::compose(sources) {
        Ok(set) => {
            if !quiet {
                println!("composed {} policy version(s)", set.len());
                for (key, entry) in set.iter() {
                    println!("  {key:<40} {}", entry.origin);
                }
                // A version series is worth surfacing: a binding that names
                // only a policy id resolves to the highest version, so the
                // author should see which one that is.
                for policy_id in set.policy_ids() {
                    let versions = set.versions_of(policy_id);
                    if versions.len() > 1 {
                        println!(
                            "  {policy_id}: versions {} — a binding by id resolves to v{}",
                            versions
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                            versions.iter().copied().max().unwrap_or(1)
                        );
                    }
                }
            }
            Ok(set)
        }
        Err(errors) => {
            eprintln!("{} composition error(s):", errors.len());
            for error in &errors {
                eprintln!("  - {error}");
            }
            anyhow::bail!("refusing a policy set with contested identities")
        }
    }
}

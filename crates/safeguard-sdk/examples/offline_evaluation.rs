//! Offline policy evaluation with the Safeguard SDK.
//!
//! A complete, runnable example of the SDK flow: load a policy document,
//! validate it, and evaluate a subject against it using the exact same
//! engine compiled into the wasm contract.
//!
//! Run from the repository root:
//!
//! ```bash
//! cargo run -p safeguard-sdk --example offline_evaluation \
//!     -- policies/default/policy.json
//! ```
//!
//! The subject facts are hard-coded below as two demonstrative cases
//! (everything passing vs a sanctions match) so the example is
//! self-contained. Real callers resolve facts from adapters/registries as
//! described in docs/how-to-evaluate.md.

use std::env;
use std::fs;
use std::path::Path;

use safeguard_sdk::evaluate::{evaluate, EvaluationFacts};
use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::validation::validate_policy_document;
use safeguard_sdk::{AccountStatus, RegionStatus};

fn main() {
    // `cargo run` passes the manifest dir as the working directory, so the
    // policy path resolves relative to the repository root.
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "policies/default/policy.json".to_owned());
    let doc = load_policy(Path::new(&path));

    // 1. Validate: the schema + invariant checks that guard on-chain
    //    registration (32-byte ASCII ids, unique rule ids, one rule per
    //    type, well-formed region lists, ...).
    let problems = validate_policy_document(&doc);
    if !problems.is_empty() {
        eprintln!("{} does not validate:", path);
        for problem in &problems {
            eprintln!("  - {problem}");
        }
        std::process::exit(1);
    }
    println!(
        "valid: {} v{} ({} rules)",
        doc.policy_id,
        doc.version,
        doc.rules.len()
    );

    // 2. Evaluate two subjects. Facts are caller-resolved: the hook (or a
    //    backend service) owns the identity/sanctions/jurisdiction lookups
    //    and hands the engine a normalized snapshot.
    let passing = EvaluationFacts {
        account_status: AccountStatus::Active,
        allowlist_member: true,
        denylist_matched: false,
        sanctions_matched: false,
        jurisdiction: RegionStatus::Permitted,
    };
    let matched = EvaluationFacts {
        sanctions_matched: true,
        ..passing
    };

    for (label, facts) in [("passing", passing), ("sanctions match", matched)] {
        let decision = evaluate(&doc, &facts);
        println!(
            "{label:>15}: {:?} (reason={:?}, rule={:?})",
            decision.decision,
            decision.reason_code,
            decision
                .rule
                .map(|id| String::from_utf8_lossy(id.as_trimmed_bytes()).into_owned())
        );
    }
}

fn load_policy(path: &Path) -> PolicyDocument {
    let json = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("error: cannot read {}: {e}", path.display());
        std::process::exit(1);
    });
    serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("error: cannot parse {}: {e}", path.display());
        std::process::exit(1);
    })
}

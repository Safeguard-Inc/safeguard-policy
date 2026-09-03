//! Golden decision documents for audit tooling.
//!
//! Audit consumes decision documents matching `decision.schema.json`. This
//! suite proves the engine actually produces the committed golden fixtures
//! (`tests/fixtures/decisions.json`) for the documented worked cases — so a
//! decision serialization or reason-code drift breaks here, and audit can
//! trust the fixture file as a stable cross-repo contract.

use std::fs;
use std::path::{Path, PathBuf};

use safeguard_sdk::evaluate::{evaluate, evaluate_with_region_code, EvaluationFacts};
use safeguard_sdk::model::{DecisionDoc, PolicyDocument};
use safeguard_sdk::{AccountStatus, RegionStatus};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn combined_policy() -> PolicyDocument {
    let json = fs::read_to_string(repo_root().join("policies/examples/combined-policy.json"))
        .expect("read combined policy");
    serde_json::from_str(&json).expect("parse combined policy")
}

fn fixed_timestamp() -> Option<String> {
    Some("2026-09-03T00:00:00.000Z".to_owned())
}

fn golden_decisions() -> Vec<DecisionDoc> {
    let json =
        fs::read_to_string(repo_root().join("crates/safeguard-sdk/tests/fixtures/decisions.json"))
            .expect("read golden decisions");
    serde_json::from_str(&json).expect("parse golden decisions")
}

/// Build the decision document an audit service would store for each of the
/// documented worked cases, then compare against the committed fixtures.
#[test]
fn engine_decisions_match_the_golden_documents() {
    let policy = combined_policy();
    let passing = EvaluationFacts {
        account_status: AccountStatus::Active,
        allowlist_member: true,
        denylist_matched: false,
        sanctions_matched: false,
        jurisdiction: RegionStatus::Permitted,
    };

    let cases = [
        // Case 1 — everything passes.
        evaluate(&policy, &passing),
        // Case 2 — non-member.
        evaluate(
            &policy,
            &EvaluationFacts {
                allowlist_member: false,
                ..passing
            },
        ),
        // Case 3 — sanctions match (flag under this policy).
        evaluate(
            &policy,
            &EvaluationFacts {
                sanctions_matched: true,
                ..passing
            },
        ),
        // Case 4 — frozen account (structural, no rule).
        evaluate(
            &policy,
            &EvaluationFacts {
                account_status: AccountStatus::Frozen,
                ..passing
            },
        ),
        // Case 5 — prohibited region.
        evaluate_with_region_code(&policy, passing, "IR"),
        // Case 6 — unknown region (fail-closed).
        evaluate_with_region_code(&policy, passing, "XX"),
    ];
    let cases = cases.as_slice();

    let expected = golden_decisions();
    assert_eq!(
        cases.len(),
        expected.len(),
        "golden fixture must cover every case"
    );

    for (index, decision) in cases.iter().enumerate() {
        let doc = DecisionDoc::from_parts(decision, "example-combined", 1, fixed_timestamp())
            .unwrap_or_else(|| {
                panic!(
                    "case {index}: reason {:?} has no decision-doc label",
                    decision.reason_code
                )
            });
        assert_eq!(
            &doc, &expected[index],
            "case {index}: engine decision document drifted from the golden fixture"
        );
    }

    // Guard against accidental reason-code reuse that would make cases
    // indistinguishable to audit.
    let reasons: Vec<u32> = cases.iter().map(|d| d.reason_code.to_code()).collect();
    let unique: std::collections::BTreeSet<u32> = reasons.iter().copied().collect();
    assert_eq!(
        unique.len(),
        cases.len(),
        "each case must carry a distinct reason code"
    );
}

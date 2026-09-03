//! Integration tests that run every **shipped** policy through the SDK.
//!
//! These are the drift guards between `policies/`, `policy-schema/` and the
//! engine: if a reference policy stops validating, or the documented worked
//! cases stop producing their documented outcomes, this suite fails.
//!
//! The expected outcomes below are the same cases documented in
//! `docs/how-to-evaluate.md`, pinned here so the docs and the engine cannot
//! silently disagree.

use std::fs;
use std::path::{Path, PathBuf};

use safeguard_sdk::evaluate::{evaluate, evaluate_with_region_code, EvaluationFacts};
use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::validation::validate_policy_document;
use safeguard_sdk::{AccountStatus, Decision, ReasonCode};

/// Root of the repository (the crate manifest sits two levels under it).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn policies_dir() -> PathBuf {
    repo_root().join("policies")
}

fn load_policy(path: &Path) -> PolicyDocument {
    let json = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Every shipped policy must parse and validate.
#[test]
fn all_shipped_policies_validate() {
    let mut paths = vec![policies_dir().join("default").join("policy.json")];
    let examples = fs::read_dir(policies_dir().join("examples"))
        .expect("examples dir exists")
        .map(|entry| entry.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect::<Vec<_>>();
    paths.extend(examples);

    assert!(
        paths.len() >= 6,
        "expected default + 5 example policies, found {}",
        paths.len()
    );

    for path in paths {
        let doc = load_policy(&path);
        let problems = validate_policy_document(&doc);
        assert!(
            problems.is_empty(),
            "{} must validate, problems: {problems:?}",
            path.display()
        );
    }
}

/// The default policy blocks sanctions matches (its sanctions rule is
/// `block`), unlike the combined example policy where the same data only
/// flags. Per-rule severity must be policy-owned, not data-owned.
#[test]
fn default_policy_blocks_sanctions_matches() {
    let doc = load_policy(&policies_dir().join("default").join("policy.json"));
    let facts = EvaluationFacts {
        sanctions_matched: true,
        ..EvaluationFacts::default()
    };
    let decision = evaluate(&doc, &facts);
    assert_eq!(decision.decision, Decision::Block);
    assert_eq!(decision.reason_code, ReasonCode::SanctionsMatch);
}

/// The documented worked cases from docs/how-to-evaluate.md, pinned against
/// the combined example policy.
#[test]
fn documented_worked_cases_hold() {
    let doc = load_policy(&policies_dir().join("examples").join("combined-policy.json"));

    // Case 1 — everything passes → APPROVE (no_reason).
    let approved = evaluate(&doc, &EvaluationFacts::default());
    assert_eq!(approved.decision, Decision::Approve);
    assert_eq!(approved.reason_code, ReasonCode::NoReason);

    // Case 2 — non-member → BLOCK (allowlist_required, rule ALLOWLIST-001).
    let non_member = evaluate(
        &doc,
        &EvaluationFacts {
            allowlist_member: false,
            ..EvaluationFacts::default()
        },
    );
    assert_eq!(non_member.decision, Decision::Block);
    assert_eq!(non_member.reason_code, ReasonCode::AllowlistRequired);
    assert_eq!(
        non_member.rule.map(|id| id.as_trimmed_bytes().to_vec()),
        Some(b"ALLOWLIST-001".to_vec())
    );

    // Case 3 — sanctions match → FLAG (sanctions_match, rule SANCTIONS-001),
    // because the combined policy flags instead of blocking.
    let flagged = evaluate(
        &doc,
        &EvaluationFacts {
            sanctions_matched: true,
            ..EvaluationFacts::default()
        },
    );
    assert_eq!(flagged.decision, Decision::Flag);
    assert_eq!(flagged.reason_code, ReasonCode::SanctionsMatch);
    assert_eq!(
        flagged.rule.map(|id| id.as_trimmed_bytes().to_vec()),
        Some(b"SANCTIONS-001".to_vec())
    );

    // Case 4 — frozen account → structural BLOCK (account_frozen), no rule.
    let frozen = evaluate(
        &doc,
        &EvaluationFacts {
            account_status: AccountStatus::Frozen,
            ..EvaluationFacts::default()
        },
    );
    assert_eq!(frozen.decision, Decision::Block);
    assert_eq!(frozen.reason_code, ReasonCode::AccountFrozen);
    assert_eq!(frozen.rule, None);

    // Case 5 — prohibited region → BLOCK (jurisdiction_prohibited,
    // rule JURISDICTION-001).
    let prohibited = evaluate_with_region_code(&doc, EvaluationFacts::default(), "IR");
    assert_eq!(prohibited.decision, Decision::Block);
    assert_eq!(prohibited.reason_code, ReasonCode::JurisdictionProhibited);
    assert_eq!(
        prohibited.rule.map(|id| id.as_trimmed_bytes().to_vec()),
        Some(b"JURISDICTION-001".to_vec())
    );

    // Case 6 — unknown region → fail-closed BLOCK (jurisdiction_unknown).
    let unknown_region = evaluate_with_region_code(&doc, EvaluationFacts::default(), "XX");
    assert_eq!(unknown_region.decision, Decision::Block);
    assert_eq!(unknown_region.reason_code, ReasonCode::JurisdictionUnknown);
}

/// Case 7 (partial): unknown account status never approves — it flags with
/// account_status_unknown, fail-closed.
#[test]
fn unknown_account_status_flags_fail_closed() {
    let doc = load_policy(&policies_dir().join("examples").join("combined-policy.json"));
    let unknown = evaluate(
        &doc,
        &EvaluationFacts {
            account_status: AccountStatus::Unknown,
            ..EvaluationFacts::default()
        },
    );
    assert_eq!(unknown.decision, Decision::Flag);
    assert_eq!(unknown.reason_code, ReasonCode::AccountStatusUnknown);
    assert_eq!(unknown.rule, None);
}

/// Every example policy must be evaluable end to end (valid document +
/// engine run) under default facts — a policy that cannot be evaluated is a
/// policy that cannot be deployed.
#[test]
fn every_example_policy_evaluates_under_default_facts() {
    let examples = fs::read_dir(policies_dir().join("examples"))
        .expect("examples dir exists")
        .map(|entry| entry.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect::<Vec<_>>();
    assert_eq!(examples.len(), 5);

    for path in examples {
        let doc = load_policy(&path);
        let decision = evaluate(&doc, &EvaluationFacts::default());
        assert!(
            matches!(
                decision.decision,
                Decision::Approve | Decision::Block | Decision::Flag
            ),
            "{} produced no decision",
            path.display()
        );
    }
}

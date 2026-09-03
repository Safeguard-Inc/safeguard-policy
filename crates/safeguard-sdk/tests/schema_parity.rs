//! Parity tests between `policy-schema/` and the SDK label enums.
//!
//! docs/sdk.md promises the three surfaces (JSON Schema, Rust SDK, TypeScript
//! SDK) stay in lockstep. This suite machine-checks the Rust half: every
//! label the SDK can serialize must be accepted by the schema, and every
//! value the schema accepts must be a label the SDK can produce — in both
//! directions, for every enum that crosses the boundary.
//!
//! The TypeScript half is guarded by its own mirror tests in sdk/typescript;
//! scripts/test-schema.py guards the schemas themselves.

use std::fs;
use std::path::{Path, PathBuf};

use safeguard_sdk::model::{DecisionLabel, ReasonLabel, RuleActionLabel, RuleTypeLabel};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn schema(path: &str) -> serde_json::Value {
    let json = fs::read_to_string(repo_root().join("policy-schema").join(path))
        .unwrap_or_else(|e| panic!("read policy-schema/{path}: {e}"));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("parse policy-schema/{path}: {e}"))
}

/// Assert an SDK label enum exactly mirrors a schema enum: the serialized
/// form of every variant appears in the schema list, and the schema list
/// contains nothing the SDK cannot produce.
fn assert_parity<T>(labels: &[T], schema_path: &str, schema_pointer: &[&str]) -> Vec<String>
where
    T: serde::Serialize,
{
    let mut pointer_value = &schema(schema_path);
    for part in schema_pointer {
        pointer_value = &pointer_value[part];
    }
    let schema_values = pointer_value
        .as_array()
        .expect("schema enum must be an array")
        .iter()
        .map(|v| v.as_str().expect("enum values are strings").to_owned())
        .collect::<Vec<_>>();

    let sdk_values = labels
        .iter()
        .map(|label| serde_json::to_string(label).expect("label serializes"))
        .map(|json| serde_json::from_str::<String>(&json).expect("label is a string"))
        .collect::<Vec<_>>();

    let mut problems = Vec::new();
    for sdk in &sdk_values {
        if !schema_values.contains(sdk) {
            problems.push(format!("SDK label {sdk:?} is not accepted by the schema"));
        }
    }
    for schema in &schema_values {
        if !sdk_values.contains(schema) {
            problems.push(format!("schema value {schema:?} has no SDK label"));
        }
    }
    problems
}

#[test]
fn rule_type_labels_match_policy_schema() {
    let problems = assert_parity(
        &[
            RuleTypeLabel::Allowlist,
            RuleTypeLabel::Denylist,
            RuleTypeLabel::Sanctions,
            RuleTypeLabel::Jurisdiction,
        ],
        "policy.schema.json",
        &["$defs", "rule", "properties", "type", "enum"],
    );
    assert!(problems.is_empty(), "rule type drift: {problems:?}");
}

#[test]
fn rule_action_labels_match_policy_schema() {
    let problems = assert_parity(
        &[RuleActionLabel::Block, RuleActionLabel::Flag],
        "policy.schema.json",
        &["$defs", "rule", "properties", "action", "enum"],
    );
    assert!(problems.is_empty(), "rule action drift: {problems:?}");
}

#[test]
fn decision_labels_match_decision_schema() {
    let problems = assert_parity(
        &[
            DecisionLabel::Approve,
            DecisionLabel::Block,
            DecisionLabel::Flag,
        ],
        "decision.schema.json",
        &["properties", "decision", "enum"],
    );
    assert!(problems.is_empty(), "decision drift: {problems:?}");
}

#[test]
fn reason_labels_match_decision_schema() {
    let problems = assert_parity(
        &[
            ReasonLabel::NoReason,
            ReasonLabel::AccountFrozen,
            ReasonLabel::AccountSuspended,
            ReasonLabel::AccountRestricted,
            ReasonLabel::AccountStatusUnknown,
            ReasonLabel::AllowlistRequired,
            ReasonLabel::DenylistMatch,
            ReasonLabel::SanctionsMatch,
            ReasonLabel::JurisdictionProhibited,
            ReasonLabel::JurisdictionRestricted,
            ReasonLabel::JurisdictionUnknown,
        ],
        "decision.schema.json",
        &["properties", "reason_code", "enum"],
    );
    assert!(problems.is_empty(), "reason code drift: {problems:?}");
}

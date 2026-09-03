//! Property tests: arbitrary resolved facts against every **shipped**
//! policy.
//!
//! The unit tests cover hand-picked cases; these properties sample the
//! unbounded facts space and pin the properties operators rely on:
//!
//! * evaluating any facts against any shipped policy never panics and
//!   always yields a valid decision;
//! * unknown account status or jurisdiction never approves under any
//!   shipped policy (fail-closed);
//! * a sanctions match never approves under the default policy, whose
//!   sanctions rule blocks.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use proptest::prelude::*;

use safeguard_sdk::evaluate::{evaluate, evaluate_with_region_code, EvaluationFacts};
use safeguard_sdk::model::PolicyDocument;
use safeguard_sdk::{AccountStatus, Decision, RegionStatus};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The shipped policies under test (default + examples), loaded once.
fn shipped_policies() -> &'static Vec<PolicyDocument> {
    static POLICIES: OnceLock<Vec<PolicyDocument>> = OnceLock::new();
    POLICIES.get_or_init(|| {
        let mut paths = vec![repo_root()
            .join("policies")
            .join("default")
            .join("policy.json")];
        let examples = fs::read_dir(repo_root().join("policies").join("examples"))
            .expect("examples dir exists")
            .map(|entry| entry.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect::<Vec<_>>();
        paths.extend(examples);

        paths
            .iter()
            .map(|path| {
                let json = fs::read_to_string(path).expect("read policy");
                serde_json::from_str(&json).expect("parse policy")
            })
            .collect()
    })
}

fn any_status() -> impl Strategy<Value = AccountStatus> {
    prop_oneof![
        Just(AccountStatus::Active),
        Just(AccountStatus::Restricted),
        Just(AccountStatus::Frozen),
        Just(AccountStatus::Suspended),
        Just(AccountStatus::Unknown),
    ]
}

fn any_region() -> impl Strategy<Value = RegionStatus> {
    prop_oneof![
        Just(RegionStatus::Permitted),
        Just(RegionStatus::Restricted),
        Just(RegionStatus::Prohibited),
        Just(RegionStatus::Unknown),
    ]
}

fn any_facts() -> impl Strategy<Value = EvaluationFacts> {
    (
        any_status(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any_region(),
    )
        .prop_map(
            |(
                account_status,
                allowlist_member,
                denylist_matched,
                sanctions_matched,
                jurisdiction,
            )| {
                EvaluationFacts {
                    account_status,
                    allowlist_member,
                    denylist_matched,
                    sanctions_matched,
                    jurisdiction,
                }
            },
        )
}

proptest! {
    /// Evaluation never panics for arbitrary facts against any shipped
    /// policy and always yields one of the three decisions.
    #[test]
    fn any_facts_against_any_shipped_policy_evaluate_cleanly(
        facts in any_facts(),
    ) {
        for policy in shipped_policies() {
            let decision = evaluate(policy, &facts);
            prop_assert!(
                matches!(decision.decision, Decision::Approve | Decision::Block | Decision::Flag),
                "policy {} produced no decision",
                policy.policy_id
            );
        }
    }

    /// Unknown account status never approves under any shipped policy —
    /// the core maps it to a structural flag, and no policy overrides that.
    #[test]
    fn unknown_account_status_never_approves(
        allowlist_member: bool,
        denylist_matched: bool,
        sanctions_matched: bool,
        region in any_region(),
    ) {
        let facts = EvaluationFacts {
            account_status: AccountStatus::Unknown,
            allowlist_member,
            denylist_matched,
            sanctions_matched,
            jurisdiction: region,
        };
        for policy in shipped_policies() {
            let decision = evaluate(policy, &facts);
            prop_assert_ne!(
                decision.decision,
                Decision::Approve,
                "policy {} approved an unknown-status subject",
                policy.policy_id
            );
        }
    }

    /// Under the default policy — whose sanctions rule blocks — a sanctions
    /// match can never approve, regardless of every other fact.
    #[test]
    fn default_policy_never_approves_a_sanctions_match(facts in any_facts()) {
        let policy = &shipped_policies()[0];
        prop_assert_eq!(policy.policy_id.as_str(), "institutional-default");
        let facts = EvaluationFacts {
            sanctions_matched: true,
            ..facts
        };
        let decision = evaluate(policy, &facts);
        prop_assert_ne!(
            decision.decision,
            Decision::Approve,
            "default policy approved a sanctions match"
        );
    }

    /// Any shipped policy with an enabled jurisdiction rule never approves
    /// an unknown region (its action fires, fail-closed).
    #[test]
    fn jurisdiction_policies_never_approve_an_unknown_region(facts in any_facts()) {
        for policy in shipped_policies() {
            let has_jurisdiction = policy
                .rules
                .iter()
                .any(|rule| rule.rule_type.as_core() == safeguard_sdk::RuleType::Jurisdiction);
            if !has_jurisdiction {
                continue;
            }
            let decision = evaluate_with_region_code(policy, facts, "XX");
            prop_assert_ne!(
                decision.decision,
                Decision::Approve,
                "policy {} approved an unknown region",
                policy.policy_id
            );
        }
    }
}

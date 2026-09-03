//! Offline evaluation: run the core engine against a policy document.
//!
//! The SDK does not reimplement the engine — it builds a
//! [`EvaluationRequest`] from the policy document and calls
//! [`safeguard_core::evaluator`], the same code compiled into the wasm
//! contract. Offline results therefore cannot drift from on-chain results.
//!
//! Also provides region-code classification against a policy's jurisdiction
//! rule, so callers can think in region codes ("US") while the engine
//! consumes classifications (permitted/restricted/prohibited/unknown).

use crate::model::PolicyDocument;
use crate::{AccountStatus, PolicyDecision, RegionStatus, RuleId, RuleType};
use safeguard_core::evaluation::{
    EvaluationRequest, JurisdictionCheck, MatchCheck, MembershipCheck,
};

/// The subject facts an evaluation needs, resolved by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationFacts {
    /// Structural account status.
    pub account_status: AccountStatus,
    /// Whether the subject is an allowlist member.
    pub allowlist_member: bool,
    /// Whether the subject matched the denylist.
    pub denylist_matched: bool,
    /// Whether the subject matched sanctions screening.
    pub sanctions_matched: bool,
    /// The subject's jurisdiction classification.
    pub jurisdiction: RegionStatus,
}

impl Default for EvaluationFacts {
    fn default() -> Self {
        Self {
            account_status: AccountStatus::Active,
            allowlist_member: true,
            denylist_matched: false,
            sanctions_matched: false,
            jurisdiction: RegionStatus::Permitted,
        }
    }
}

/// Classify a region code against a policy's jurisdiction rule.
///
/// Returns `Unknown` when the policy has no jurisdiction rule or the code is
/// not listed (fail-closed: the engine triggers the rule action for unknown
/// regions).
#[must_use]
pub fn classify_region(policy: &PolicyDocument, code: &str) -> RegionStatus {
    for rule in &policy.rules {
        if rule.rule_type.as_core() != RuleType::Jurisdiction {
            continue;
        }
        let Some(regions) = &rule.regions else {
            continue;
        };
        if regions.permitted.iter().any(|c| c == code) {
            return RegionStatus::Permitted;
        }
        if regions.restricted.iter().any(|c| c == code) {
            return RegionStatus::Restricted;
        }
        if regions.prohibited.iter().any(|c| c == code) {
            return RegionStatus::Prohibited;
        }
        return RegionStatus::Unknown;
    }
    RegionStatus::Unknown
}

/// Evaluate facts against a policy document using the core engine.
///
/// Panics if the document is invalid (run
/// [`crate::validation::validate_policy_document`] first, or use
/// [`try_evaluate`]).
#[must_use]
pub fn evaluate(policy: &PolicyDocument, facts: &EvaluationFacts) -> PolicyDecision {
    try_evaluate(policy, facts).expect("policy document must be valid")
}

/// Fallible variant of [`evaluate`]: validates the document first and
/// returns the validation problems on failure.
pub fn try_evaluate(
    policy: &PolicyDocument,
    facts: &EvaluationFacts,
) -> Result<PolicyDecision, Vec<String>> {
    let problems = crate::validation::validate_policy_document(policy);
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(evaluate_unchecked(policy, facts))
}

/// Build the request and run the engine (document assumed valid).
fn evaluate_unchecked(policy: &PolicyDocument, facts: &EvaluationFacts) -> PolicyDecision {
    let mut request = EvaluationRequest {
        account_status: facts.account_status,
        ..EvaluationRequest::default()
    };

    for rule in &policy.rules {
        let rule_id = RuleId::from_str(&rule.id);
        let action = rule.action.as_core();
        match rule.rule_type.as_core() {
            RuleType::Allowlist => {
                request.allowlist = Some(MembershipCheck {
                    rule_id,
                    action,
                    member: facts.allowlist_member,
                });
            }
            RuleType::Denylist => {
                request.denylist = Some(MatchCheck {
                    rule_id,
                    action,
                    matched: facts.denylist_matched,
                });
            }
            RuleType::Sanctions => {
                request.sanctions = Some(MatchCheck {
                    rule_id,
                    action,
                    matched: facts.sanctions_matched,
                });
            }
            RuleType::Jurisdiction => {
                request.jurisdiction = Some(JurisdictionCheck {
                    rule_id,
                    action,
                    region: facts.jurisdiction,
                });
            }
        }
    }

    safeguard_core::evaluator::evaluate(&request)
}

/// Convenience: evaluate with a region code instead of a classification.
///
/// The code is classified against the policy's jurisdiction rule; codes not
/// listed classify as unknown (fail-closed).
#[must_use]
pub fn evaluate_with_region_code(
    policy: &PolicyDocument,
    mut facts: EvaluationFacts,
    region_code: &str,
) -> PolicyDecision {
    facts.jurisdiction = classify_region(policy, region_code);
    evaluate(policy, &facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RegionLists, RuleActionLabel, RuleDoc, RuleTypeLabel};
    use crate::{Decision, ReasonCode};

    fn rule(id: &str, rule_type: RuleTypeLabel, action: RuleActionLabel) -> RuleDoc {
        RuleDoc {
            id: id.to_owned(),
            rule_type,
            action,
            regions: None,
        }
    }

    fn jurisdiction_rule(id: &str, action: RuleActionLabel) -> RuleDoc {
        RuleDoc {
            id: id.to_owned(),
            rule_type: RuleTypeLabel::Jurisdiction,
            action,
            regions: Some(RegionLists {
                permitted: vec!["US".into(), "GB".into()],
                restricted: vec!["RU".into()],
                prohibited: vec!["IR".into()],
            }),
        }
    }

    fn policy() -> PolicyDocument {
        PolicyDocument {
            policy_id: "example-combined".into(),
            version: 1,
            title: None,
            description: None,
            rules: vec![
                rule(
                    "ALLOWLIST-001",
                    RuleTypeLabel::Allowlist,
                    RuleActionLabel::Block,
                ),
                rule(
                    "DENYLIST-001",
                    RuleTypeLabel::Denylist,
                    RuleActionLabel::Block,
                ),
                rule(
                    "SANCTIONS-001",
                    RuleTypeLabel::Sanctions,
                    RuleActionLabel::Flag,
                ),
                jurisdiction_rule("JURISDICTION-001", RuleActionLabel::Block),
            ],
            metadata: None,
        }
    }

    #[test]
    fn approve_when_everything_passes() {
        let decision = evaluate(&policy(), &EvaluationFacts::default());
        assert_eq!(decision.decision, Decision::Approve);
        assert_eq!(decision.reason_code, ReasonCode::NoReason);
    }

    #[test]
    fn allowlist_denies_non_members() {
        let facts = EvaluationFacts {
            allowlist_member: false,
            ..EvaluationFacts::default()
        };
        let decision = evaluate(&policy(), &facts);
        assert_eq!(decision.decision, Decision::Block);
        assert_eq!(decision.reason_code, ReasonCode::AllowlistRequired);
        assert_eq!(
            decision.rule.map(|id| id.as_trimmed_bytes().to_vec()),
            Some(b"ALLOWLIST-001".to_vec())
        );
    }

    #[test]
    fn sanctions_match_flags_under_a_flag_action() {
        let facts = EvaluationFacts {
            sanctions_matched: true,
            ..EvaluationFacts::default()
        };
        let decision = evaluate(&policy(), &facts);
        assert_eq!(decision.decision, Decision::Flag);
        assert_eq!(decision.reason_code, ReasonCode::SanctionsMatch);
    }

    #[test]
    fn frozen_accounts_block_structurally() {
        let facts = EvaluationFacts {
            account_status: AccountStatus::Frozen,
            ..EvaluationFacts::default()
        };
        let decision = evaluate(&policy(), &facts);
        assert_eq!(decision.decision, Decision::Block);
        assert_eq!(decision.reason_code, ReasonCode::AccountFrozen);
        assert_eq!(decision.rule, None);
    }

    #[test]
    fn region_codes_classify_against_the_policy() {
        assert_eq!(classify_region(&policy(), "US"), RegionStatus::Permitted);
        assert_eq!(classify_region(&policy(), "RU"), RegionStatus::Restricted);
        assert_eq!(classify_region(&policy(), "IR"), RegionStatus::Prohibited);
        assert_eq!(classify_region(&policy(), "XX"), RegionStatus::Unknown);
    }

    #[test]
    fn prohibited_region_blocks_under_a_blocking_jurisdiction_rule() {
        let decision = evaluate_with_region_code(&policy(), EvaluationFacts::default(), "IR");
        assert_eq!(decision.decision, Decision::Block);
        assert_eq!(decision.reason_code, ReasonCode::JurisdictionProhibited);
    }

    #[test]
    fn unknown_region_fails_closed_to_the_rule_action() {
        let decision = evaluate_with_region_code(&policy(), EvaluationFacts::default(), "XX");
        assert_eq!(decision.decision, Decision::Block);
        assert_eq!(decision.reason_code, ReasonCode::JurisdictionUnknown);
    }

    #[test]
    fn invalid_documents_are_rejected_by_try_evaluate() {
        let mut broken = policy();
        broken.rules.push(rule(
            "ALLOWLIST-002",
            RuleTypeLabel::Allowlist,
            RuleActionLabel::Flag,
        ));
        assert!(try_evaluate(&broken, &EvaluationFacts::default()).is_err());
    }
}

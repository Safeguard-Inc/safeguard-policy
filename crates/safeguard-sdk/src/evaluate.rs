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

/// A facts **file** as documented for the CLI and fixture tooling.
///
/// Labels mirror the JSON surfaces (`docs/cli.md`): account status and
/// region use the stable core labels (plus region **codes** like `US`),
/// membership/matches are booleans. Strict `deny_unknown_fields` posture
/// matches the JSON schemas.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactsFile {
    /// `active` | `restricted` | `frozen` | `suspended` | `unknown`.
    pub account_status: String,
    pub allowlist_member: bool,
    pub denylist_matched: bool,
    pub sanctions_matched: bool,
    /// A region code (e.g. `US`) or a classification
    /// (`permitted` | `restricted` | `prohibited` | `unknown`).
    pub jurisdiction: String,
}

/// Parse an [`AccountStatus`] from its stable lowercase label.
pub fn parse_status_label(label: &str) -> Result<AccountStatus, String> {
    match label {
        "active" => Ok(AccountStatus::Active),
        "restricted" => Ok(AccountStatus::Restricted),
        "frozen" => Ok(AccountStatus::Frozen),
        "suspended" => Ok(AccountStatus::Suspended),
        "unknown" => Ok(AccountStatus::Unknown),
        _ => Err(format!(
            "unknown account_status {label:?} (use active|restricted|frozen|suspended|unknown)"
        )),
    }
}

/// Parse a [`RegionStatus`] from its stable lowercase classification label.
#[must_use]
pub fn parse_region_label(label: &str) -> Option<RegionStatus> {
    match label {
        "permitted" => Some(RegionStatus::Permitted),
        "restricted" => Some(RegionStatus::Restricted),
        "prohibited" => Some(RegionStatus::Prohibited),
        "unknown" => Some(RegionStatus::Unknown),
        _ => None,
    }
}

impl FactsFile {
    /// Resolve this facts file against a policy into [`EvaluationFacts`].
    ///
    /// The region field is an explicit classification when it parses as one,
    /// otherwise it is a region code classified against the policy's
    /// jurisdiction rule (unknown codes classify as `Unknown`, fail-closed).
    pub fn to_evaluation_facts(&self, policy: &PolicyDocument) -> Result<EvaluationFacts, String> {
        let jurisdiction = match parse_region_label(&self.jurisdiction) {
            Some(classification) => classification,
            None => classify_region(policy, &self.jurisdiction),
        };
        Ok(EvaluationFacts {
            account_status: parse_status_label(&self.account_status)?,
            allowlist_member: self.allowlist_member,
            denylist_matched: self.denylist_matched,
            sanctions_matched: self.sanctions_matched,
            jurisdiction,
        })
    }
}

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

    #[test]
    fn facts_file_resolves_labels_and_region_codes() {
        let policy = policy();
        let json = r#"{
            "account_status": "active",
            "allowlist_member": true,
            "denylist_matched": false,
            "sanctions_matched": false,
            "jurisdiction": "US"
        }"#;
        let facts: FactsFile = serde_json::from_str(json).expect("parses");
        let resolved = facts.to_evaluation_facts(&policy).expect("resolves");
        assert_eq!(resolved.account_status, AccountStatus::Active);
        assert_eq!(resolved.jurisdiction, RegionStatus::Permitted);

        // An explicit classification wins over code classification.
        let classified = serde_json::from_str::<FactsFile>(
            r#"{
                "account_status": "active",
                "allowlist_member": true,
                "denylist_matched": false,
                "sanctions_matched": false,
                "jurisdiction": "prohibited"
            }"#,
        )
        .expect("parses");
        let resolved = classified.to_evaluation_facts(&policy).expect("resolves");
        assert_eq!(resolved.jurisdiction, RegionStatus::Prohibited);

        // Unknown labels are rejected, unknown region codes fail closed.
        let bad = serde_json::from_str::<FactsFile>(
            r#"{
                "account_status": "bogus",
                "allowlist_member": true,
                "denylist_matched": false,
                "sanctions_matched": false,
                "jurisdiction": "US"
            }"#,
        )
        .expect("parses");
        assert!(bad.to_evaluation_facts(&policy).is_err());

        // Unknown fields are rejected like the schemas.
        assert!(serde_json::from_str::<FactsFile>(
            r#"{
                "account_status": "active",
                "allowlist_member": true,
                "denylist_matched": false,
                "sanctions_matched": false,
                "jurisdiction": "US",
                "extra": true
            }"#
        )
        .is_err());
    }
}

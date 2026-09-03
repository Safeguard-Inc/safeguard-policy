//! On-chain evaluation: assemble a core request from contract state.
//!
//! `evaluate` is the read path `safeguard-hooks` calls. It is deliberately
//! side-effect free (no storage writes, no events) and deterministic:
//!
//! 1. Resolve the policy's **active version** record (fail: no active policy).
//! 2. Check the token is **bound** to the policy (fail: not covered).
//! 3. Translate the caller's facts (`EvaluationInput`) plus the active
//!    version's rules into a [`safeguard_core::evaluation::EvaluationRequest`].
//! 4. Run the core engine and map its decision back into Soroban values.
//!
//! The contract never interprets rule semantics itself — the core engine
//! decides. The contract only owns state, scope and translation.
//!
//! # Input codes
//!
//! [`EvaluationInput`] carries core codes (status/region) or booleans
//! (membership/matches). Unknown status or region codes map to the core
//! `Unknown` variants, whose fail-closed semantics flag rather than approve,
//! so a misbehaving caller cannot widen the outcome by sending junk codes.

use soroban_sdk::{contracttype, Address, BytesN, Env};

use crate::error::ContractError;
use crate::registry;
use crate::storage::{self, Id, PolicyVersionRecord};

use safeguard_core::decision::PolicyDecision;
use safeguard_core::evaluation::{
    EvaluationRequest, JurisdictionCheck, MatchCheck, MembershipCheck,
};
use safeguard_core::rule::{RuleAction, RuleId, RuleType};
use safeguard_core::rules::account_status::AccountStatus;
use safeguard_core::rules::jurisdiction::RegionStatus;

/// Caller-supplied facts about the subject of an evaluation.
///
/// Codes follow the stable core enums (`AccountStatus`, `RegionStatus`);
/// flags are raw booleans for membership/matches. Rule configuration (which
/// categories are enabled, with which actions) comes from the active policy
/// version, never from the caller.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationInput {
    /// [`safeguard_core::rules::account_status::AccountStatus`] code.
    pub account_status: u32,
    /// Whether the subject is an allowlist member (only read when the policy
    /// enables an allowlist rule).
    pub allowlist_member: bool,
    /// Whether the subject matched the denylist.
    pub denylist_matched: bool,
    /// Whether the subject matched sanctions screening.
    pub sanctions_matched: bool,
    /// [`safeguard_core::rules::jurisdiction::RegionStatus`] code.
    pub jurisdiction: u32,
}

/// The on-chain result of an evaluation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationResult {
    /// The active policy version that produced this decision.
    pub policy_version: u32,
    /// [`safeguard_core::decision::Decision`] code.
    pub decision: u32,
    /// [`safeguard_core::decision::ReasonCode`] code.
    pub reason_code: u32,
    /// The rule that triggered the outcome, when a rule produced it.
    pub rule_id: Option<Id>,
}

/// Decode an account status code, fail-closed on unknown values.
fn decode_status(code: u32) -> AccountStatus {
    AccountStatus::from_code(code).unwrap_or(AccountStatus::Unknown)
}

/// Decode a region code, fail-closed on unknown values.
fn decode_region(code: u32) -> RegionStatus {
    RegionStatus::from_code(code).unwrap_or(RegionStatus::Unknown)
}

/// Decode a rule action (records are validated at registration).
fn decode_action(code: u32) -> Result<RuleAction, ContractError> {
    RuleAction::from_code(code).ok_or(ContractError::InvalidRuleSet)
}

/// Decode a stored rule record into its core representation.
fn decode_rule(
    record: &storage::RuleRecord,
) -> Result<(RuleId, RuleType, RuleAction), ContractError> {
    let rule_id = RuleId::from_bytes(record.rule_id.to_array());
    let rule_type = RuleType::from_code(record.rule_type).ok_or(ContractError::InvalidRuleSet)?;
    let action = decode_action(record.action)?;
    Ok((rule_id, rule_type, action))
}

/// Assemble the core evaluation request from the active version's rules and
/// the caller's facts.
fn assemble(
    record: &PolicyVersionRecord,
    input: &EvaluationInput,
) -> Result<EvaluationRequest, ContractError> {
    let mut request = EvaluationRequest {
        account_status: decode_status(input.account_status),
        ..EvaluationRequest::default()
    };

    for stored in record.rules.iter() {
        let (rule_id, rule_type, action) = decode_rule(&stored)?;
        match rule_type {
            RuleType::Allowlist => {
                request.allowlist = Some(MembershipCheck {
                    rule_id,
                    action,
                    member: input.allowlist_member,
                });
            }
            RuleType::Denylist => {
                request.denylist = Some(MatchCheck {
                    rule_id,
                    action,
                    matched: input.denylist_matched,
                });
            }
            RuleType::Sanctions => {
                request.sanctions = Some(MatchCheck {
                    rule_id,
                    action,
                    matched: input.sanctions_matched,
                });
            }
            RuleType::Jurisdiction => {
                request.jurisdiction = Some(JurisdictionCheck {
                    rule_id,
                    action,
                    region: decode_region(input.jurisdiction),
                });
            }
        }
    }
    Ok(request)
}

/// Map a core decision into its on-chain representation.
fn to_result(env: &Env, policy_version: u32, decision: PolicyDecision) -> EvaluationResult {
    EvaluationResult {
        policy_version,
        decision: decision.decision.to_code(),
        reason_code: decision.reason_code.to_code(),
        rule_id: decision
            .rule
            .map(|id| BytesN::from_array(env, id.as_bytes())),
    }
}

/// Evaluate a subject against the active version of a policy for a token.
///
/// Public read; deterministic; never writes state. Errors only on scope or
/// configuration problems (`PolicyNotActive`, `TokenNotBound`,
/// `InvalidRuleSet`), never on the subject's compliance state — that is what
/// the returned decision expresses.
pub fn evaluate(
    env: &Env,
    policy_id: &Id,
    token: &Address,
    input: &EvaluationInput,
) -> Result<EvaluationResult, ContractError> {
    // Scope checks first: no active policy, or an unbound token, means we
    // cannot (and must not) evaluate.
    let active = storage::active_version(env, policy_id).ok_or(ContractError::PolicyNotActive)?;
    if !registry::is_bound(env, policy_id, token) {
        return Err(ContractError::TokenNotBound);
    }
    let record =
        storage::version_record(env, policy_id, active).ok_or(ContractError::VersionNotFound)?;

    let request = assemble(&record, input)?;
    let decision = safeguard_core::evaluator::evaluate(&request);
    Ok(to_result(env, active, decision))
}

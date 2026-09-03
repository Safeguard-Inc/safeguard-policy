//! Integration tests: the full lifecycle and evaluation paths through the
//! generated contract client against the Soroban test host.

#![cfg(test)]

extern crate std;

use std::path::Path;

use crate::error::ContractError;
use crate::evaluate::{EvaluationInput, EvaluationResult};
use crate::storage::{Id, RuleRecord};
use crate::{PolicyContract, PolicyContractClient};

use safeguard_sdk::model::PolicyDocument;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Events as _;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, Vec};

use safeguard_core::decision::{Decision, ReasonCode};
use safeguard_core::rule::{RuleAction, RuleId, RuleType};
use safeguard_core::version::VersionStatus;

/// Encode an id from an ASCII string using the core id rules.
fn rid(env: &Env, text: &str) -> Id {
    let core = RuleId::from_str(text);
    BytesN::from_array(env, core.as_bytes())
}

fn config_hash(env: &Env, fill: u8) -> Id {
    BytesN::from_array(env, &[fill; 32])
}

/// The contract error carried by a failed client call: the client surfaces
/// contract-level errors as `Ok(ContractError)` inside the invocation error.
type ClientError = Result<ContractError, soroban_sdk::InvokeError>;

fn contract_err(error: ContractError) -> ClientError {
    Ok(error)
}

/// Deploy and initialize the contract; return the actors and a client.
fn setup(
    env: &Env,
) -> (
    Address,
    Address,
    Address,
    Address,
    Id,
    PolicyContractClient<'_>,
) {
    env.mock_all_auths();

    let admin = Address::generate(env);
    let authority = Address::generate(env);
    let stranger = Address::generate(env);
    let token = Address::generate(env);
    let policy = rid(env, "institutional-default");

    let contract_id = env.register(PolicyContract, ());
    let client = PolicyContractClient::new(env, &contract_id);
    client.initialize(&admin);
    client.add_authority(&authority);

    (admin, authority, stranger, token, policy, client)
}

/// Register the default policy: allowlist + sanctions rules (both block).
fn register_default_policy(env: &Env, client: &PolicyContractClient, policy: &Id, version: u32) {
    let rules = vec![
        env,
        RuleRecord {
            rule_id: rid(env, "ALLOWLIST-001"),
            rule_type: RuleType::Allowlist.to_code(),
            action: RuleAction::Block.to_code(),
        },
        RuleRecord {
            rule_id: rid(env, "SANCTIONS-001"),
            rule_type: RuleType::Sanctions.to_code(),
            action: RuleAction::Block.to_code(),
        },
    ];
    client.register_version(policy, &version, &config_hash(env, 1), &rules);
}

/// Register + activate version 1 and bind the token.
fn bound_and_active(
    env: &Env,
    client: &PolicyContractClient,
    admin: &Address,
    policy: &Id,
    token: &Address,
) {
    register_default_policy(env, client, policy, 1);
    client.activate_version(policy, &1);
    client.bind_token(admin, policy, token);
}

fn active_input(env: &Env, account: &Address) -> EvaluationInput {
    EvaluationInput {
        account_status: 0, // active
        allowlist_member: true,
        denylist_matched: false,
        sanctions_matched: false,
        jurisdiction: 0, // permitted
        subject: BytesN::from_array(env, &[1; 32]),
        account: account.clone(),
    }
}

fn assert_approve(result: &EvaluationResult) {
    assert_eq!(result.decision, Decision::Approve.to_code());
    assert_eq!(result.reason_code, ReasonCode::NoReason.to_code());
    assert_eq!(result.rule_id, None);
}

// ------------------------------------------------------------------ admin

#[test]
fn initializes_once_and_guards_reinitialization() {
    let env = Env::default();
    let (admin, authority, _, _, _, client) = setup(&env);

    let err = client.try_initialize(&admin).unwrap_err();
    assert_eq!(err, contract_err(ContractError::AlreadyInitialized));
    assert_eq!(client.admin(), admin);
    assert_eq!(client.authorities(), vec![&env, authority.clone()]);
}

#[test]
fn registry_operations_require_an_authorized_operator() {
    let env = Env::default();
    let (_, _, stranger, token, policy, client) = setup(&env);

    let err = client
        .try_bind_token(&stranger, &policy, &token)
        .unwrap_err();
    assert_eq!(err, contract_err(ContractError::Unauthorized));
}

// --------------------------------------------------------------- lifecycle

#[test]
fn register_activate_and_query_the_lifecycle() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);
    register_default_policy(&env, &client, &policy, 1);

    let record = client.get_version(&policy, &1);
    assert_eq!(record.version, 1);
    assert_eq!(record.status, VersionStatus::Draft.to_code());
    assert_eq!(record.rules.len(), 2); // The activation invocation published one typed lifecycle event; events
                                       // are scoped to the invocation that emitted them, so query immediately.
    client.activate_version(&policy, &1);
    let all_events = env.events().all();
    assert_eq!(
        all_events.events().len(),
        1,
        "activation published one event"
    );

    let active = client.get_active_version(&policy);
    assert_eq!(active.version, 1);
    assert_eq!(active.status, VersionStatus::Active.to_code());

    client.bind_token(&admin, &policy, &token);
    assert_eq!(client.bound_tokens(&policy), vec![&env, token.clone()]);
}

#[test]
fn duplicate_registration_is_rejected() {
    let env = Env::default();
    let (_, _, _, _, policy, client) = setup(&env);
    register_default_policy(&env, &client, &policy, 1);

    let rules = vec![&env];
    let err = client
        .try_register_version(&policy, &1, &config_hash(&env, 2), &rules)
        .unwrap_err();
    assert_eq!(err, contract_err(ContractError::VersionExists));
}

#[test]
fn invalid_rule_sets_are_rejected_before_persisting() {
    let env = Env::default();
    let (_, _, _, _, policy, client) = setup(&env);

    // Two allowlist rules: duplicate category.
    let rules = vec![
        &env,
        RuleRecord {
            rule_id: rid(&env, "ALLOWLIST-001"),
            rule_type: RuleType::Allowlist.to_code(),
            action: RuleAction::Block.to_code(),
        },
        RuleRecord {
            rule_id: rid(&env, "ALLOWLIST-002"),
            rule_type: RuleType::Allowlist.to_code(),
            action: RuleAction::Flag.to_code(),
        },
    ];
    let err = client
        .try_register_version(&policy, &1, &config_hash(&env, 1), &rules)
        .unwrap_err();
    assert_eq!(err, contract_err(ContractError::InvalidRuleSet));
    // Nothing persisted.
    assert_eq!(
        client.try_get_version(&policy, &1).unwrap_err(),
        contract_err(ContractError::VersionNotFound)
    );
}

#[test]
fn activation_requires_a_draft_version() {
    let env = Env::default();
    let (_, _, _, _, policy, client) = setup(&env);
    register_default_policy(&env, &client, &policy, 1);
    client.activate_version(&policy, &1);

    // Re-activating the active version is not allowed.
    let err = client.try_activate_version(&policy, &1).unwrap_err();
    assert_eq!(err, contract_err(ContractError::VersionNotDraft));

    // Activating a version that does not exist fails cleanly.
    let err = client.try_activate_version(&policy, &99).unwrap_err();
    assert_eq!(err, contract_err(ContractError::VersionNotFound));
}

#[test]
fn activating_a_new_version_supersedes_the_old_one() {
    let env = Env::default();
    let (_, _, _, _, policy, client) = setup(&env);
    register_default_policy(&env, &client, &policy, 1);
    client.activate_version(&policy, &1);

    let rules = vec![
        &env,
        RuleRecord {
            rule_id: rid(&env, "SANCTIONS-001"),
            rule_type: RuleType::Sanctions.to_code(),
            action: RuleAction::Flag.to_code(),
        },
    ];
    client.register_version(&policy, &2, &config_hash(&env, 2), &rules);
    client.activate_version(&policy, &2);

    assert_eq!(
        client.get_version(&policy, &1).status,
        VersionStatus::Superseded.to_code()
    );
    assert_eq!(client.get_active_version(&policy).version, 2);
}

#[test]
fn deactivation_removes_the_active_version() {
    let env = Env::default();
    let (_, _, _, _, policy, client) = setup(&env);
    register_default_policy(&env, &client, &policy, 1);
    client.activate_version(&policy, &1);
    client.deactivate_version(&policy, &1);

    assert_eq!(
        client.get_version(&policy, &1).status,
        VersionStatus::Disabled.to_code()
    );
    // Only the active version may be deactivated.
    let err = client.try_deactivate_version(&policy, &1).unwrap_err();
    assert_eq!(err, contract_err(ContractError::VersionNotActive));
    // The policy has no active version anymore.
    assert_eq!(
        client.try_get_active_version(&policy).unwrap_err(),
        contract_err(ContractError::PolicyNotActive)
    );
}

// -------------------------------------------------------------- evaluation

#[test]
fn approve_when_every_check_passes() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);
    bound_and_active(&env, &client, &admin, &policy, &token);

    let result = client.evaluate(&policy, &token, &active_input(&env, &admin));
    assert_eq!(result.policy_version, 1);
    assert_approve(&result);
}

#[test]
fn allowlist_denies_non_members_with_the_rule_id() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);
    bound_and_active(&env, &client, &admin, &policy, &token);

    let mut facts = active_input(&env, &admin);
    facts.allowlist_member = false;
    let result = client.evaluate(&policy, &token, &facts);
    assert_eq!(result.decision, Decision::Block.to_code());
    assert_eq!(result.reason_code, ReasonCode::AllowlistRequired.to_code());
    assert_eq!(result.rule_id, Some(rid(&env, "ALLOWLIST-001")));
}

#[test]
fn sanctions_matches_block_under_a_blocking_policy() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);
    bound_and_active(&env, &client, &admin, &policy, &token);

    let mut facts = active_input(&env, &admin);
    facts.sanctions_matched = true;
    let result = client.evaluate(&policy, &token, &facts);
    assert_eq!(result.decision, Decision::Block.to_code());
    assert_eq!(result.reason_code, ReasonCode::SanctionsMatch.to_code());
    assert_eq!(result.rule_id, Some(rid(&env, "SANCTIONS-001")));
}

#[test]
fn flag_actions_flag_instead_of_blocking() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);

    let rules = vec![
        &env,
        RuleRecord {
            rule_id: rid(&env, "SANCTIONS-001"),
            rule_type: RuleType::Sanctions.to_code(),
            action: RuleAction::Flag.to_code(),
        },
    ];
    client.register_version(&policy, &1, &config_hash(&env, 1), &rules);
    client.activate_version(&policy, &1);
    client.bind_token(&admin, &policy, &token);

    let mut facts = active_input(&env, &admin);
    facts.sanctions_matched = true;
    let result = client.evaluate(&policy, &token, &facts);
    assert_eq!(result.decision, Decision::Flag.to_code());
    assert_eq!(result.reason_code, ReasonCode::SanctionsMatch.to_code());
}

#[test]
fn frozen_accounts_block_even_when_rules_would_pass() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);
    bound_and_active(&env, &client, &admin, &policy, &token);

    let mut facts = active_input(&env, &admin);
    facts.account_status = 2; // frozen
    let result = client.evaluate(&policy, &token, &facts);
    assert_eq!(result.decision, Decision::Block.to_code());
    assert_eq!(result.reason_code, ReasonCode::AccountFrozen.to_code());
    assert_eq!(result.rule_id, None);
}

#[test]
fn unknown_status_codes_fail_closed_to_flag() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);
    bound_and_active(&env, &client, &admin, &policy, &token);

    let mut facts = active_input(&env, &admin);
    facts.account_status = 99; // invalid account status code
    let result = client.evaluate(&policy, &token, &facts);
    assert_eq!(result.decision, Decision::Flag.to_code());
    assert_eq!(
        result.reason_code,
        ReasonCode::AccountStatusUnknown.to_code()
    );
}

#[test]
fn evaluation_is_deterministic() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);
    bound_and_active(&env, &client, &admin, &policy, &token);

    let mut facts = active_input(&env, &admin);
    facts.denylist_matched = true;
    let first = client.evaluate(&policy, &token, &facts);
    for _ in 0..16 {
        assert_eq!(client.evaluate(&policy, &token, &facts), first);
    }
}

#[test]
fn scope_guards_refuse_evaluation_outside_the_policy() {
    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);

    // No active version yet.
    client.bind_token(&admin, &policy, &token);
    assert_eq!(
        client
            .try_evaluate(&policy, &token, &active_input(&env, &admin))
            .unwrap_err(),
        contract_err(ContractError::PolicyNotActive)
    );

    // Active version but the token is not bound.
    register_default_policy(&env, &client, &policy, 1);
    client.activate_version(&policy, &1);
    let other_token = Address::generate(&env);
    assert_eq!(
        client
            .try_evaluate(&policy, &other_token, &active_input(&env, &admin))
            .unwrap_err(),
        contract_err(ContractError::TokenNotBound)
    );

    // After binding, evaluation succeeds.
    client.bind_token(&admin, &policy, &token);
    assert_approve(&client.evaluate(&policy, &token, &active_input(&env, &admin)));
}

// -------------------------------------------------------------- registries

/// Register + activate a version with a blocking jurisdiction rule and bind
/// the token, for registry-resolution tests.
fn jurisdiction_active(
    env: &Env,
    client: &PolicyContractClient,
    admin: &Address,
    policy: &Id,
    token: &Address,
) {
    let rules = vec![
        env,
        RuleRecord {
            rule_id: rid(env, "JURISDICTION-001"),
            rule_type: RuleType::Jurisdiction.to_code(),
            action: RuleAction::Block.to_code(),
        },
    ];
    client.register_version(policy, &1, &config_hash(env, 3), &rules);
    client.activate_version(policy, &1);
    client.bind_token(admin, policy, token);
}

fn subject_hash(env: &Env) -> Id {
    BytesN::from_array(env, &[1; 32])
}

/// The identity registry accepts writes from a registry authority and
/// publishes one typed event; reads return the record.
#[test]
fn identity_registry_lifecycle_and_events() {
    let env = Env::default();
    let (admin, authority, _, _, _, client) = setup(&env);
    let account = Address::generate(&env);

    // Authority writes a verified record with an attestation reference.
    client.set_identity(
        &authority,
        &account,
        &0,
        &rid(&env, "ATT-1"),
        &1_800_000_000,
    );
    let all_events = env.events().all();
    assert_eq!(
        all_events.events().len(),
        1,
        "set_identity published one event"
    );

    let record = client.identity(&account).unwrap();
    assert_eq!(record.status, 0); // verified
    assert_eq!(record.attestation_ref, rid(&env, "ATT-1"));
    assert_eq!(record.expires_at, 1_800_000_000);

    // Replacing the record works (same account, new status).
    client.set_identity(
        &authority,
        &account,
        &2,
        &rid(&env, "ATT-1"),
        &1_800_000_000,
    ); // revoked
    let updated = client.identity(&account).unwrap();
    assert_eq!(updated.status, 2);

    // Removal clears the record; no event when there is nothing to remove.
    client.remove_identity(&admin, &account);
    assert!(client.identity(&account).is_none());

    // Unknown status codes are rejected before persisting.
    let err = client
        .try_set_identity(&authority, &account, &99, &rid(&env, "ATT-1"), &0)
        .unwrap_err();
    assert_eq!(err, contract_err(ContractError::InvalidRegistryData));

    // A stranger cannot write.
    let stranger = Address::generate(&env);
    let err = client
        .try_set_identity(&stranger, &account, &0, &rid(&env, "ATT-1"), &0)
        .unwrap_err();
    assert_eq!(err, contract_err(ContractError::Unauthorized));
}

/// An active sanctions entry makes evaluate block even when the caller
/// claims no match; retiring the entry restores the caller-claim behavior.
#[test]
fn sanctions_registry_is_authoritative_in_evaluate() {
    let env = Env::default();
    let (admin, authority, _, token, policy, client) = setup(&env);
    bound_and_active(&env, &client, &admin, &policy, &token);

    let mut facts = active_input(&env, &admin);
    facts.sanctions_matched = false; // caller claims a clean screen

    // No entry: the caller's claim stands and evaluation approves.
    assert_approve(&client.evaluate(&policy, &token, &facts));

    // Authority lists the subject hash as active on the OFAC-SDN list.
    client.set_sanctions_entry(
        &authority,
        &subject_hash(&env),
        &rid(&env, "OFAC-SDN"),
        &0, // active
        &1, // dataset version
        &1_700_000_000,
        &Bytes::from_slice(&env, b"ofac"),
    );
    assert_eq!(env.events().all().events().len(), 1);

    // Registry is authoritative: the caller's clean-screen claim no longer
    // stands and the blocking sanctions rule fires.
    let result = client.evaluate(&policy, &token, &facts);
    assert_eq!(result.decision, Decision::Block.to_code());
    assert_eq!(result.reason_code, ReasonCode::SanctionsMatch.to_code());

    // Retiring the entry (never deleting) lifts the block for this subject.
    client.retire_sanctions_entry(&authority, &subject_hash(&env));
    assert_approve(&client.evaluate(&policy, &token, &facts));

    // Invalid status code and version zero are rejected.
    let err = client
        .try_set_sanctions_entry(
            &authority,
            &subject_hash(&env),
            &rid(&env, "OFAC-SDN"),
            &99,
            &1,
            &0,
            &Bytes::from_slice(&env, b"ofac"),
        )
        .unwrap_err();
    assert_eq!(err, contract_err(ContractError::InvalidRegistryData));
}

/// A stored jurisdiction classification is authoritative in evaluate; a
/// stored prohibited region blocks even when the caller claims permitted.
#[test]
fn jurisdiction_registry_is_authoritative_in_evaluate() {
    let env = Env::default();
    let (admin, authority, _, token, policy, client) = setup(&env);
    jurisdiction_active(&env, &client, &admin, &policy, &token);
    let account = Address::generate(&env);

    let mut facts = active_input(&env, &account);
    facts.jurisdiction = 0; // caller claims permitted

    // No classification stored: caller claim stands.
    assert_approve(&client.evaluate(&policy, &token, &facts));

    // Authority classifies the account as prohibited (region code 2).
    client.set_jurisdiction(&authority, &account, &2);
    assert_eq!(env.events().all().events().len(), 1);

    // Registry is authoritative: prohibited blocks despite the claim.
    let result = client.evaluate(&policy, &token, &facts);
    assert_eq!(result.decision, Decision::Block.to_code());
    assert_eq!(
        result.reason_code,
        ReasonCode::JurisdictionProhibited.to_code()
    );

    // Clearing drops back to the caller's claim.
    client.clear_jurisdiction(&authority, &account);
    assert_approve(&client.evaluate(&policy, &token, &facts));

    // Unknown region codes are rejected.
    let err = client
        .try_set_jurisdiction(&authority, &account, &99)
        .unwrap_err();
    assert_eq!(err, contract_err(ContractError::InvalidRegistryData));
}

/// Arbitrary u32 input codes never panic or error: unknown codes decode
/// fail-closed to `Unknown`, and unknown status/region codes never approve.
/// The contract boundary is the last place junk codes could enter, so the
/// whole u32 space is fuzzed (proptest samples it and shrinks failures).
#[test]
fn arbitrary_input_codes_never_error_or_fail_open() {
    use proptest::prelude::*;

    use safeguard_core::rules::account_status::AccountStatus as CoreStatus;
    use safeguard_core::rules::jurisdiction::RegionStatus as CoreRegion;

    let env = Env::default();
    let (admin, _, _, token, policy, client) = setup(&env);
    bound_and_active(&env, &client, &admin, &policy, &token);

    // A second policy with a jurisdiction rule, bound to a second token, so
    // the region decode path is exercised too.
    let policy2 = rid(&env, "jurisdiction-only");
    let token2 = Address::generate(&env);
    let rules = vec![
        &env,
        RuleRecord {
            rule_id: rid(&env, "JURISDICTION-001"),
            rule_type: RuleType::Jurisdiction.to_code(),
            action: RuleAction::Block.to_code(),
        },
    ];
    client.register_version(&policy2, &1, &config_hash(&env, 4), &rules);
    client.activate_version(&policy2, &1);
    client.bind_token(&admin, &policy2, &token2);

    let account = Address::generate(&env);
    let subject = BytesN::from_array(&env, &[1; 32]);

    proptest!(|(
        status_code in any::<u32>(),
        region_code in any::<u32>(),
        allowlist_member in any::<bool>(),
        denylist_matched in any::<bool>(),
        sanctions_matched in any::<bool>(),
    )| {
        let input = EvaluationInput {
            account_status: status_code,
            allowlist_member,
            denylist_matched,
            sanctions_matched,
            jurisdiction: region_code,
            subject: subject.clone(),
            account: account.clone(),
        };

        // Any code is decodable (fail-closed): evaluation must never error
        // under either policy.
        let result = client.try_evaluate(&policy, &token, &input);
        prop_assert!(
            result.is_ok(),
            "evaluate errored on codes {} / {}",
            status_code,
            region_code
        );
        let regional = client.try_evaluate(&policy2, &token2, &input);
        prop_assert!(regional.is_ok(), "jurisdiction policy errored on region code {}", region_code);

        // An unrecognized account status maps to Unknown, which never approves.
        if CoreStatus::from_code(status_code).is_none() {
            let decision = result
                .expect("invocation succeeded")
                .expect("evaluation succeeded");
            prop_assert_ne!(
                decision.decision,
                Decision::Approve.to_code(),
                "unknown status code {} approved",
                status_code
            );
        }

        // An unrecognized region code maps to Unknown, and under the blocking
        // jurisdiction policy Unknown triggers the rule action: never approve.
        if CoreRegion::from_code(region_code).is_none() {
            let decision = regional
                .expect("invocation succeeded")
                .expect("evaluation succeeded");
            prop_assert_ne!(
                decision.decision,
                Decision::Approve.to_code(),
                "unknown region code {} approved",
                region_code
            );
        }
    });
}

// -------------------------------------------- shipped-policy compatibility

/// Load a policy document from the repository's policies/ directory.
fn load_shipped_policy(relative: &str) -> PolicyDocument {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let json =
        std::fs::read_to_string(root.join("policies").join(relative)).expect("read shipped policy");
    serde_json::from_str(&json).expect("parse shipped policy")
}

/// Register a shipped policy document on-chain: its rule set becomes the
/// version's records, so what the JSON says and what the contract enforces
/// are the same thing.
fn register_shipped(
    env: &Env,
    client: &PolicyContractClient,
    admin: &Address,
    policy_id: &Id,
    token: &Address,
    doc: &PolicyDocument,
) {
    let mut records: Vec<RuleRecord> = Vec::new(env);
    for rule in &doc.rules {
        let rule_id = safeguard_core::rule::RuleId::from_str(&rule.id);
        records.push_back(RuleRecord {
            rule_id: BytesN::from_array(env, rule_id.as_bytes()),
            rule_type: rule.rule_type.as_core().to_code(),
            action: rule.action.as_core().to_code(),
        });
    }
    client.register_version(policy_id, &1, &config_hash(env, 9), &records);
    client.activate_version(policy_id, &1);
    client.bind_token(admin, policy_id, token);
}

/// Register the shipped combined policy and run the worked cases from
/// docs/how-to-evaluate.md at the **contract** level: the same JSON document
/// that ships in policies/ is what the contract enforces.
#[test]
fn shipped_combined_policy_enforces_the_documented_cases() {
    let env = Env::default();
    let (admin, _, _, _, _, client) = setup(&env);

    let doc = load_shipped_policy("examples/combined-policy.json");
    assert_eq!(doc.policy_id, "example-combined");
    let policy = rid(&env, &doc.policy_id);
    let token = Address::generate(&env);
    register_shipped(&env, &client, &admin, &policy, &token, &doc);

    let subject = BytesN::from_array(&env, &[7; 32]);
    let input = |status: u32,
                 allowlist: bool,
                 deny: bool,
                 sanctions: bool,
                 region: u32|
     -> EvaluationInput {
        EvaluationInput {
            account_status: status,
            allowlist_member: allowlist,
            denylist_matched: deny,
            sanctions_matched: sanctions,
            jurisdiction: region,
            subject: subject.clone(),
            account: admin.clone(),
        }
    };

    // Case 1 — everything passes → APPROVE (no_reason).
    let ok = client.evaluate(&policy, &token, &input(0, true, false, false, 0));
    assert_eq!(ok.decision, Decision::Approve.to_code());
    assert_eq!(ok.reason_code, ReasonCode::NoReason.to_code());
    assert_eq!(ok.policy_version, 1);

    // Case 2 — non-member → BLOCK by allowlist, rule attributed.
    let blocked = client.evaluate(&policy, &token, &input(0, false, false, false, 0));
    assert_eq!(blocked.decision, Decision::Block.to_code());
    assert_eq!(blocked.reason_code, ReasonCode::AllowlistRequired.to_code());
    assert_eq!(blocked.rule_id, Some(rid(&env, "ALLOWLIST-001")));

    // Case 3 — sanctions match → FLAG (not BLOCK) under the combined policy.
    let flagged = client.evaluate(&policy, &token, &input(0, true, false, true, 0));
    assert_eq!(flagged.decision, Decision::Flag.to_code());
    assert_eq!(flagged.reason_code, ReasonCode::SanctionsMatch.to_code());
    assert_eq!(flagged.rule_id, Some(rid(&env, "SANCTIONS-001")));

    // Case 4 — frozen account → structural BLOCK, no rule.
    let frozen = client.evaluate(&policy, &token, &input(2, true, false, false, 0));
    assert_eq!(frozen.decision, Decision::Block.to_code());
    assert_eq!(frozen.reason_code, ReasonCode::AccountFrozen.to_code());
    assert_eq!(frozen.rule_id, None);

    // Case 5 — prohibited region (IR) → BLOCK by jurisdiction.
    let prohibited = client.evaluate(&policy, &token, &input(0, true, false, false, 2));
    assert_eq!(prohibited.decision, Decision::Block.to_code());
    assert_eq!(
        prohibited.reason_code,
        ReasonCode::JurisdictionProhibited.to_code()
    );
    assert_eq!(prohibited.rule_id, Some(rid(&env, "JURISDICTION-001")));

    // Case 6 — unknown region → fail-closed BLOCK.
    let unknown = client.evaluate(&policy, &token, &input(0, true, false, false, 3));
    assert_eq!(unknown.decision, Decision::Block.to_code());
    assert_eq!(
        unknown.reason_code,
        ReasonCode::JurisdictionUnknown.to_code()
    );
}

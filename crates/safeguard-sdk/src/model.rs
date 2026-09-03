//! Serde models for policy documents and decision documents.
//!
//! These mirror `policy-schema/` exactly: field names, enum labels
//! (serde `rename_all`) and the strict `deny_unknown_fields` posture of the
//! JSON schemas. Labels convert losslessly to and from the core enums via
//! their stable `as_str`/`from_code` serialization.

use serde::{Deserialize, Serialize};

use crate::{Decision, PolicyDecision, ReasonCode, RuleAction, RuleId, RuleType};

/// A rule type label, matching `policy-schema` enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleTypeLabel {
    Allowlist,
    Denylist,
    Sanctions,
    Jurisdiction,
}

impl RuleTypeLabel {
    /// Convert to the core rule type (stable `as_str` labels align).
    #[must_use]
    pub fn as_core(self) -> RuleType {
        match self {
            Self::Allowlist => RuleType::Allowlist,
            Self::Denylist => RuleType::Denylist,
            Self::Sanctions => RuleType::Sanctions,
            Self::Jurisdiction => RuleType::Jurisdiction,
        }
    }

    /// Parse from a core rule type.
    #[must_use]
    pub fn from_core(rule_type: RuleType) -> Self {
        match rule_type {
            RuleType::Allowlist => Self::Allowlist,
            RuleType::Denylist => Self::Denylist,
            RuleType::Sanctions => Self::Sanctions,
            RuleType::Jurisdiction => Self::Jurisdiction,
        }
    }
}

/// A rule action label, matching `policy-schema` enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleActionLabel {
    Block,
    Flag,
}

impl RuleActionLabel {
    #[must_use]
    pub fn as_core(self) -> RuleAction {
        match self {
            Self::Block => RuleAction::Block,
            Self::Flag => RuleAction::Flag,
        }
    }

    #[must_use]
    pub fn from_core(action: RuleAction) -> Self {
        match action {
            RuleAction::Block => Self::Block,
            RuleAction::Flag => Self::Flag,
        }
    }
}

/// Region classification lists of a jurisdiction rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionLists {
    pub permitted: Vec<String>,
    pub restricted: Vec<String>,
    pub prohibited: Vec<String>,
}

/// A single rule inside a policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDoc {
    pub id: String,
    #[serde(rename = "type")]
    pub rule_type: RuleTypeLabel,
    pub action: RuleActionLabel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regions: Option<RegionLists>,
}

impl RuleDoc {
    /// Convert to the core rule, truncating the id to the engine's
    /// fixed-width identifier (validators reject over-long ids first).
    #[must_use]
    pub fn as_core(&self) -> crate::Rule {
        crate::Rule {
            id: RuleId::from_str(&self.id),
            rule_type: self.rule_type.as_core(),
            action: self.action.as_core(),
        }
    }
}

/// A policy document, matching `policy.schema.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub policy_id: String,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub rules: Vec<RuleDoc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// A decision label, matching `decision.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DecisionLabel {
    Approve,
    Block,
    Flag,
}

impl DecisionLabel {
    #[must_use]
    pub fn as_core(self) -> Decision {
        match self {
            Self::Approve => Decision::Approve,
            Self::Block => Decision::Block,
            Self::Flag => Decision::Flag,
        }
    }

    #[must_use]
    pub fn from_core(decision: Decision) -> Self {
        match decision {
            Decision::Approve => Self::Approve,
            Decision::Block => Self::Block,
            Decision::Flag => Self::Flag,
        }
    }
}

/// A reason code label, matching `decision.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonLabel {
    NoReason,
    AccountFrozen,
    AccountSuspended,
    AccountRestricted,
    AccountStatusUnknown,
    AllowlistRequired,
    DenylistMatch,
    SanctionsMatch,
    JurisdictionProhibited,
    JurisdictionRestricted,
    JurisdictionUnknown,
}

impl ReasonLabel {
    #[must_use]
    pub fn as_core(self) -> ReasonCode {
        match self {
            Self::NoReason => ReasonCode::NoReason,
            Self::AccountFrozen => ReasonCode::AccountFrozen,
            Self::AccountSuspended => ReasonCode::AccountSuspended,
            Self::AccountRestricted => ReasonCode::AccountRestricted,
            Self::AccountStatusUnknown => ReasonCode::AccountStatusUnknown,
            Self::AllowlistRequired => ReasonCode::AllowlistRequired,
            Self::DenylistMatch => ReasonCode::DenylistMatch,
            Self::SanctionsMatch => ReasonCode::SanctionsMatch,
            Self::JurisdictionProhibited => ReasonCode::JurisdictionProhibited,
            Self::JurisdictionRestricted => ReasonCode::JurisdictionRestricted,
            Self::JurisdictionUnknown => ReasonCode::JurisdictionUnknown,
        }
    }

    /// Parse from a core reason code; `None` for codes the SDK does not
    /// serialize yet (new reasons must be added to the schema in lockstep).
    #[must_use]
    pub fn from_core(reason: ReasonCode) -> Option<Self> {
        match reason {
            ReasonCode::NoReason => Some(Self::NoReason),
            ReasonCode::AccountFrozen => Some(Self::AccountFrozen),
            ReasonCode::AccountSuspended => Some(Self::AccountSuspended),
            ReasonCode::AccountRestricted => Some(Self::AccountRestricted),
            ReasonCode::AccountStatusUnknown => Some(Self::AccountStatusUnknown),
            ReasonCode::AllowlistRequired => Some(Self::AllowlistRequired),
            ReasonCode::DenylistMatch => Some(Self::DenylistMatch),
            ReasonCode::SanctionsMatch => Some(Self::SanctionsMatch),
            ReasonCode::JurisdictionProhibited => Some(Self::JurisdictionProhibited),
            ReasonCode::JurisdictionRestricted => Some(Self::JurisdictionRestricted),
            ReasonCode::JurisdictionUnknown => Some(Self::JurisdictionUnknown),
        }
    }
}

/// A decision document, matching `decision.schema.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionDoc {
    pub decision: DecisionLabel,
    pub policy_id: String,
    pub policy_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub reason_code: ReasonLabel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

impl DecisionDoc {
    /// Build a decision document from an engine decision plus the policy
    /// context that produced it.
    #[must_use]
    pub fn from_parts(
        decision: &PolicyDecision,
        policy_id: &str,
        policy_version: u32,
        timestamp: Option<String>,
    ) -> Option<Self> {
        Some(Self {
            decision: DecisionLabel::from_core(decision.decision),
            policy_id: policy_id.to_owned(),
            policy_version,
            rule_id: decision
                .rule
                .map(|id| String::from_utf8_lossy(id.as_trimmed_bytes()).into_owned()),
            reason_code: ReasonLabel::from_core(decision.reason_code)?,
            timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_document_round_trips_with_stable_labels() {
        let json = r#"{
            "policy_id": "institutional-default",
            "version": 1,
            "rules": [
                { "id": "ALLOWLIST-001", "type": "allowlist", "action": "block" },
                {
                    "id": "JURISDICTION-001",
                    "type": "jurisdiction",
                    "action": "flag",
                    "regions": {
                        "permitted": ["US"],
                        "restricted": ["RU"],
                        "prohibited": ["IR"]
                    }
                }
            ]
        }"#;
        let doc: PolicyDocument = serde_json::from_str(json).expect("parses");
        assert_eq!(doc.policy_id, "institutional-default");
        assert_eq!(doc.rules.len(), 2);
        assert_eq!(doc.rules[0].rule_type, RuleTypeLabel::Allowlist);
        assert_eq!(doc.rules[1].action, RuleActionLabel::Flag);
        assert_eq!(doc.rules[1].regions.as_ref().unwrap().permitted, vec!["US"]);

        let reserialized = serde_json::to_string(&doc).expect("serializes");
        let reparsed: PolicyDocument = serde_json::from_str(&reserialized).expect("reparses");
        assert_eq!(doc, reparsed);
    }

    #[test]
    fn unknown_fields_are_rejected_like_the_schema() {
        let json = r#"{ "policy_id": "p", "version": 1, "rules": [],
                         "unexpected": true }"#;
        assert!(serde_json::from_str::<PolicyDocument>(json).is_err());
    }

    #[test]
    fn rule_converts_to_core_with_truncation_semantics() {
        let rule = RuleDoc {
            id: "SANCTIONS-001".into(),
            rule_type: RuleTypeLabel::Sanctions,
            action: RuleActionLabel::Block,
            regions: None,
        };
        let core = rule.as_core();
        assert_eq!(core.rule_type, RuleType::Sanctions);
        assert_eq!(core.action, RuleAction::Block);
        assert_eq!(core.id.as_trimmed_bytes(), b"SANCTIONS-001");
    }

    #[test]
    fn decision_doc_builds_from_an_engine_decision() {
        let decision = PolicyDecision::from_rule(
            Decision::Block,
            ReasonCode::SanctionsMatch,
            RuleId::from_str("SANCTIONS-001"),
        );
        let doc = DecisionDoc::from_parts(&decision, "example-combined", 1, None).unwrap();
        assert_eq!(doc.decision, DecisionLabel::Block);
        assert_eq!(doc.reason_code, ReasonLabel::SanctionsMatch);
        assert_eq!(doc.rule_id.as_deref(), Some("SANCTIONS-001"));
        assert_eq!(doc.policy_version, 1);
    }
}

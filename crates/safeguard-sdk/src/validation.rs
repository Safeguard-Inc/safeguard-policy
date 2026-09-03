//! Cross-item validation of policy documents.
//!
//! Mirrors `scripts/validate_policy.py` (which validates against the JSON
//! Schema) plus the invariants JSON Schema cannot express. Keeping the same
//! checks in the SDK means every Rust consumer — the CLI, integrations,
//! test harnesses — rejects the same invalid documents the schemas and the
//! contract registration path reject.
//!
//! The checks:
//!
//! * policy id and rule ids: non-empty ASCII, at most 32 bytes (the engine's
//!   fixed-width identifier; longer ids would silently truncate on-chain);
//! * rule ids unique, at most one rule per type;
//! * at least one rule;
//! * `version >= 1`;
//! * jurisdiction rules carry region lists; non-jurisdiction rules do not;
//! * region codes are uppercase ISO 3166-1 alpha-2.

use crate::model::{PolicyDocument, RegionLists, RuleTypeLabel};

/// Validate a policy document, returning human-readable problems (empty =
/// valid).
#[must_use]
pub fn validate_policy_document(document: &PolicyDocument) -> Vec<String> {
    let mut problems = Vec::new();

    if document.policy_id.is_empty() {
        problems.push("policy_id: must not be empty".to_owned());
    } else {
        check_id(&document.policy_id, "policy_id", &mut problems);
    }

    if document.version == 0 {
        problems.push("version: must be >= 1".to_owned());
    }

    if document.rules.is_empty() {
        problems.push("rules: at least one rule is required".to_owned());
    }

    let mut seen_ids = std::collections::HashSet::new();
    let mut seen_types = std::collections::HashSet::new();
    for rule in &document.rules {
        if rule.id.is_empty() {
            problems.push("rule: id must not be empty".to_owned());
        } else {
            check_id(&rule.id, &format!("rule {:?}", rule.id), &mut problems);
            if !seen_ids.insert(rule.id.clone()) {
                problems.push(format!("rule {:?}: duplicate rule id", rule.id));
            }
        }
        if !seen_types.insert(rule.rule_type) {
            problems.push(format!(
                "rule {:?}: at most one rule per type ({} already enabled)",
                rule.id,
                rule.rule_type.as_core().as_str()
            ));
        }
        match rule.rule_type {
            RuleTypeLabel::Jurisdiction => match &rule.regions {
                Some(regions) => check_regions(regions, &rule.id, &mut problems),
                None => problems.push(format!(
                    "rule {:?}: jurisdiction rules must carry regions",
                    rule.id
                )),
            },
            _ => {
                if rule.regions.is_some() {
                    problems.push(format!(
                        "rule {:?}: regions are only valid on jurisdiction rules",
                        rule.id
                    ));
                }
            }
        }
    }

    problems
}

/// Check an identifier: non-empty ASCII, at most 32 bytes.
fn check_id(id: &str, label: &str, problems: &mut Vec<String>) {
    if id.len() > 32 {
        problems.push(format!(
            "{label}: identifier longer than 32 bytes (would truncate on-chain)"
        ));
    }
    if !id.is_ascii() {
        problems.push(format!("{label}: identifier must be ASCII"));
    }
}

/// Check region lists: uppercase ISO alpha-2 codes, no duplicates within a
/// list, and no code classified in two lists.
fn check_regions(regions: &RegionLists, rule_id: &str, problems: &mut Vec<String>) {
    for (list_name, codes) in [
        ("permitted", &regions.permitted),
        ("restricted", &regions.restricted),
        ("prohibited", &regions.prohibited),
    ] {
        let mut seen = std::collections::HashSet::new();
        for code in codes {
            if code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()) {
                problems.push(format!(
                    "rule {rule_id:?}: region {code:?} in {list_name} is not an uppercase ISO alpha-2 code"
                ));
            }
            if !seen.insert(code.clone()) {
                problems.push(format!(
                    "rule {rule_id:?}: duplicate region {code:?} in {list_name}"
                ));
            }
        }
    }

    // A code may appear in at most one list.
    let mut classified = std::collections::HashMap::<String, &str>::new();
    for (list_name, codes) in [
        ("permitted", &regions.permitted),
        ("restricted", &regions.restricted),
        ("prohibited", &regions.prohibited),
    ] {
        for code in codes {
            if let Some(previous) = classified.insert(code.clone(), list_name) {
                problems.push(format!(
                    "rule {rule_id:?}: region {code:?} is classified as both {previous} and {list_name}"
                ));
            }
        }
    }
}

/// Convenience: parse then validate a JSON policy document.
pub fn validate_json(json: &str) -> Result<Vec<String>, serde_json::Error> {
    let document: PolicyDocument = serde_json::from_str(json)?;
    Ok(validate_policy_document(&document))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RegionLists, RuleActionLabel, RuleDoc, RuleTypeLabel};

    fn rule(id: &str, rule_type: RuleTypeLabel, action: RuleActionLabel) -> RuleDoc {
        RuleDoc {
            id: id.to_owned(),
            rule_type,
            action,
            regions: None,
        }
    }

    fn regions() -> RegionLists {
        RegionLists {
            permitted: vec!["US".into(), "GB".into()],
            restricted: vec!["RU".into()],
            prohibited: vec!["IR".into()],
        }
    }

    fn doc(rules: Vec<RuleDoc>) -> PolicyDocument {
        PolicyDocument {
            policy_id: "test-policy".into(),
            version: 1,
            title: None,
            description: None,
            rules,
            metadata: None,
        }
    }

    #[test]
    fn valid_document_has_no_problems() {
        let mut d = doc(vec![
            rule(
                "ALLOWLIST-001",
                RuleTypeLabel::Allowlist,
                RuleActionLabel::Block,
            ),
            RuleDoc {
                id: "JURISDICTION-001".into(),
                rule_type: RuleTypeLabel::Jurisdiction,
                action: RuleActionLabel::Flag,
                regions: Some(regions()),
            },
        ]);
        assert!(validate_policy_document(&d).is_empty());
        d.version = 0;
        assert!(!validate_policy_document(&d).is_empty());
    }

    #[test]
    fn duplicate_ids_and_types_are_rejected() {
        let d = doc(vec![
            rule("A-1", RuleTypeLabel::Allowlist, RuleActionLabel::Block),
            rule("A-1", RuleTypeLabel::Denylist, RuleActionLabel::Block),
            rule("A-2", RuleTypeLabel::Allowlist, RuleActionLabel::Flag),
        ]);
        let problems = validate_policy_document(&d);
        assert!(
            problems.iter().any(|p| p.contains("duplicate rule id")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("at most one rule per type")),
            "{problems:?}"
        );
    }

    #[test]
    fn jurisdiction_region_rules_are_enforced() {
        // Missing regions.
        let d = doc(vec![rule(
            "J-1",
            RuleTypeLabel::Jurisdiction,
            RuleActionLabel::Flag,
        )]);
        let problems = validate_policy_document(&d);
        assert!(problems.iter().any(|p| p.contains("must carry regions")));

        // Regions on a non-jurisdiction rule.
        let d = doc(vec![RuleDoc {
            id: "A-1".into(),
            rule_type: RuleTypeLabel::Allowlist,
            action: RuleActionLabel::Block,
            regions: Some(regions()),
        }]);
        let problems = validate_policy_document(&d);
        assert!(problems
            .iter()
            .any(|p| p.contains("only valid on jurisdiction")));

        // Bad codes and cross-list classification ("US" in two lists).
        let bad = RegionLists {
            permitted: vec!["us".into(), "USA".into(), "US".into()],
            restricted: vec!["US".into()],
            prohibited: vec![],
        };
        let d = doc(vec![RuleDoc {
            id: "J-1".into(),
            rule_type: RuleTypeLabel::Jurisdiction,
            action: RuleActionLabel::Flag,
            regions: Some(bad),
        }]);
        let problems = validate_policy_document(&d);
        assert!(
            problems.iter().any(|p| p.contains("ISO alpha-2")),
            "{problems:?}"
        );
        assert!(problems.iter().any(|p| p.contains("both")), "{problems:?}");
    }

    #[test]
    fn identifier_width_is_enforced() {
        let d = doc(vec![rule(
            &"X".repeat(33),
            RuleTypeLabel::Allowlist,
            RuleActionLabel::Block,
        )]);
        let problems = validate_policy_document(&d);
        assert!(problems.iter().any(|p| p.contains("longer than 32 bytes")));
    }

    #[test]
    fn parse_then_validate_json() {
        let json = r#"{
            "policy_id": "p",
            "version": 1,
            "rules": [
                { "id": "A-1", "type": "allowlist", "action": "block" },
                { "id": "A-1", "type": "denylist", "action": "block" }
            ]
        }"#;
        let problems = validate_json(json).expect("parses");
        assert!(problems.iter().any(|p| p.contains("duplicate rule id")));
    }
}

//! Composing policy documents from multiple sources.
//!
//! [`crate::validation`] checks **one** document. A real policy set is
//! assembled from many: the reference policies shipped in a repository, a
//! registry export, a vendor bundle, an operator's override directory. That
//! assembly step has a failure mode validation cannot see, because it is a
//! property of the *set* and not of any document:
//!
//! > Two sources can claim the same identity — the same `policy_id` at the
//! > same `version`.
//!
//! Nothing downstream can tell the two apart. A token bound to that
//! `policy_id` resolves to whichever document the loader happened to visit
//! last, so which rule parameters apply becomes an accident of read order.
//! [`PolicySet::compose`] makes that an error that names the policy id, the
//! version, and both origins — rather than a silent overwrite.
//!
//! A **different** version under the same `policy_id` is not a collision: it
//! is the version history the contract's append-only registry is built
//! around (`docs/versioning.md`). Only the `(policy_id, version)` pair is an
//! identity that two sources cannot both own.
//!
//! Composition also validates every document as it loads. A source that
//! cannot pass [`validate_policy_document`] is rejected rather than admitted
//! into a set whose lookup would then depend on it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::model::PolicyDocument;
use crate::validation::validate_policy_document;

/// A policy document together with the source it was loaded from.
///
/// The origin is carried for exactly one reason: a collision report is only
/// actionable if it says *which* files disagree. Use the path, the registry
/// key, or the bundle entry name — whatever an operator can open.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicySource {
    /// Where the document came from (a file path, registry key, …).
    pub origin: String,
    /// The parsed document.
    pub document: PolicyDocument,
}

impl PolicySource {
    /// Pair a document with its origin.
    #[must_use]
    pub fn new(origin: impl Into<String>, document: PolicyDocument) -> Self {
        Self {
            origin: origin.into(),
            document,
        }
    }
}

/// The identity of one policy version: the key a composed set is indexed by.
///
/// Ordered so iteration and collision reports are deterministic regardless
/// of the order sources were read in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersionKey {
    /// The policy this version belongs to.
    pub policy_id: String,
    /// The version number within the policy.
    pub version: u32,
}

impl fmt::Display for PolicyVersionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{}", self.policy_id, self.version)
    }
}

/// Why a source could not join a composed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionError {
    /// The document fails the same invariants a single document gets, so it
    /// is rejected at load time instead of becoming a silently unusable
    /// member of the set.
    InvalidDocument {
        /// Where the rejected document came from.
        origin: String,
        /// The validator's problems, verbatim.
        problems: Vec<String>,
    },
    /// Two sources claim the same `(policy_id, version)`.
    DuplicateVersion {
        /// The contested policy id.
        policy_id: String,
        /// The contested version.
        version: u32,
        /// The origins that claim it, in the order they were composed. The
        /// first entry is the source that already owned the identity; later
        /// entries were refused.
        origins: Vec<String>,
    },
}

impl CompositionError {
    /// The contested identity, when the error is a collision.
    #[must_use]
    pub fn key(&self) -> Option<PolicyVersionKey> {
        match self {
            CompositionError::DuplicateVersion {
                policy_id, version, ..
            } => Some(PolicyVersionKey {
                policy_id: policy_id.clone(),
                version: *version,
            }),
            CompositionError::InvalidDocument { .. } => None,
        }
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompositionError::InvalidDocument { origin, problems } => {
                write!(
                    f,
                    "invalid policy document at {origin}: {}",
                    problems.join("; ")
                )
            }
            CompositionError::DuplicateVersion {
                policy_id,
                version,
                origins,
            } => {
                write!(
                    f,
                    "duplicate policy version {policy_id} v{version} declared by {}",
                    origins
                        .iter()
                        .map(|origin| format!("{origin:?}"))
                        .collect::<Vec<_>>()
                        .join(" and ")
                )?;
                write!(
                    f,
                    " — an identity must have exactly one source, or which rules apply \
                     depends on load order"
                )
            }
        }
    }
}

impl std::error::Error for CompositionError {}

/// One composed entry: a document and the origin that supplied it.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyEntry {
    /// Where the document came from.
    pub origin: String,
    /// The document itself.
    pub document: PolicyDocument,
}

/// A set of policy documents assembled from many sources, indexed by
/// identity so that lookup never depends on assembly order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicySet {
    entries: BTreeMap<PolicyVersionKey, PolicyEntry>,
}

impl PolicySet {
    /// Compose `sources` into a set, validating each document and rejecting
    /// any two sources that claim the same `(policy_id, version)`.
    ///
    /// Returns **every** problem rather than the first, so a bundle with
    /// several bad files is fixed in one pass. The first source to claim an
    /// identity keeps it; the rest are reported, which means the set is
    /// never partially applied — on `Err` nothing is returned.
    pub fn compose<I>(sources: I) -> Result<Self, Vec<CompositionError>>
    where
        I: IntoIterator<Item = PolicySource>,
    {
        let mut entries: BTreeMap<PolicyVersionKey, PolicyEntry> = BTreeMap::new();
        let mut errors = Vec::new();
        for source in sources {
            let problems = validate_policy_document(&source.document);
            if !problems.is_empty() {
                errors.push(CompositionError::InvalidDocument {
                    origin: source.origin,
                    problems,
                });
                continue;
            }
            let key = PolicyVersionKey {
                policy_id: source.document.policy_id.clone(),
                version: source.document.version,
            };
            match entries.get(&key) {
                Some(existing) => errors.push(CompositionError::DuplicateVersion {
                    policy_id: key.policy_id,
                    version: key.version,
                    origins: vec![existing.origin.clone(), source.origin],
                }),
                None => {
                    entries.insert(
                        key,
                        PolicyEntry {
                            origin: source.origin,
                            document: source.document,
                        },
                    );
                }
            }
        }
        if errors.is_empty() {
            Ok(Self { entries })
        } else {
            Err(errors)
        }
    }

    /// The document for one identity, if composed.
    #[must_use]
    pub fn get(&self, policy_id: &str, version: u32) -> Option<&PolicyDocument> {
        self.entry(policy_id, version).map(|entry| &entry.document)
    }

    /// The entry (document plus origin) for one identity, if composed.
    #[must_use]
    pub fn entry(&self, policy_id: &str, version: u32) -> Option<&PolicyEntry> {
        self.entries.get(&PolicyVersionKey {
            policy_id: policy_id.to_owned(),
            version,
        })
    }

    /// Iterate entries in identity order (policy id, then version).
    pub fn iter(&self) -> impl Iterator<Item = (&PolicyVersionKey, &PolicyEntry)> {
        self.entries.iter()
    }

    /// Number of composed policy versions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every distinct policy id in the set, version-independent.
    #[must_use]
    pub fn policy_ids(&self) -> BTreeSet<&str> {
        self.entries
            .keys()
            .map(|key| key.policy_id.as_str())
            .collect()
    }

    /// The composed versions of `policy_id`, ascending.
    #[must_use]
    pub fn versions_of(&self, policy_id: &str) -> Vec<u32> {
        self.entries
            .keys()
            .filter(|key| key.policy_id == policy_id)
            .map(|key| key.version)
            .collect()
    }

    /// The highest composed version of `policy_id` — the one a binding that
    /// names only a policy id resolves to (`docs/versioning.md`).
    #[must_use]
    pub fn latest(&self, policy_id: &str) -> Option<&PolicyEntry> {
        self.versions_of(policy_id)
            .into_iter()
            .max()
            .and_then(|version| self.entry(policy_id, version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RegionLists, RuleActionLabel, RuleDoc, RuleTypeLabel};

    fn document(policy_id: &str, version: u32) -> PolicyDocument {
        PolicyDocument {
            policy_id: policy_id.to_owned(),
            version,
            title: None,
            description: None,
            rules: vec![RuleDoc {
                id: format!("{policy_id}-ALLOW"),
                rule_type: RuleTypeLabel::Allowlist,
                action: RuleActionLabel::Block,
                regions: None,
            }],
            metadata: None,
        }
    }

    fn source(origin: &str, policy_id: &str, version: u32) -> PolicySource {
        PolicySource::new(origin, document(policy_id, version))
    }

    #[test]
    fn distinct_identities_compose_and_lookup_independently_of_order() {
        let forward =
            PolicySet::compose([source("a.json", "alpha", 1), source("b.json", "beta", 1)])
                .unwrap();
        let reversed =
            PolicySet::compose([source("b.json", "beta", 1), source("a.json", "alpha", 1)])
                .unwrap();

        assert_eq!(forward, reversed, "assembly order must not change the set");
        assert_eq!(forward.len(), 2);
        assert_eq!(forward.policy_ids(), ["alpha", "beta"].into());
        assert_eq!(
            forward.entry("alpha", 1).map(|e| e.origin.as_str()),
            Some("a.json")
        );
        assert_eq!(forward.get("alpha", 2), None);
    }

    #[test]
    fn a_colliding_identity_is_reported_with_both_origins() {
        let errors = PolicySet::compose([
            source("default/policy.json", "institutional-default", 1),
            source("examples/override.json", "institutional-default", 1),
        ])
        .unwrap_err();

        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].key(),
            Some(PolicyVersionKey {
                policy_id: "institutional-default".into(),
                version: 1,
            })
        );
        match &errors[0] {
            CompositionError::DuplicateVersion { origins, .. } => {
                assert_eq!(origins, &["default/policy.json", "examples/override.json"])
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // The message an operator sees must name the identity and both files.
        let rendered = errors[0].to_string();
        assert!(rendered.contains("institutional-default v1"), "{rendered}");
        assert!(rendered.contains("default/policy.json"), "{rendered}");
        assert!(rendered.contains("examples/override.json"), "{rendered}");
    }

    #[test]
    fn a_second_version_under_the_same_id_is_history_not_a_collision() {
        let set = PolicySet::compose([
            source("v1.json", "institutional-default", 1),
            source("v2.json", "institutional-default", 2),
        ])
        .expect("a new version is the versioning feature, not a conflict");

        assert_eq!(set.policy_ids(), ["institutional-default"].into());
        assert_eq!(set.versions_of("institutional-default"), [1, 2]);
        assert_eq!(
            set.latest("institutional-default")
                .map(|e| e.origin.as_str()),
            Some("v2.json")
        );
    }

    #[test]
    fn an_invalid_document_is_rejected_at_load_time() {
        let mut empty_rules = document("alpha", 1);
        empty_rules.rules.clear();
        let errors = PolicySet::compose([
            source("good.json", "alpha", 1),
            PolicySource::new("bad.json", empty_rules),
        ])
        .unwrap_err();

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].key(), None);
        match &errors[0] {
            CompositionError::InvalidDocument { origin, problems } => {
                assert_eq!(origin, "bad.json");
                assert!(
                    problems.iter().any(|p| p.contains("at least one rule")),
                    "{problems:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn every_problem_is_reported_in_one_pass() {
        let mut empty_rules = document("alpha", 1);
        empty_rules.rules.clear();
        let errors = PolicySet::compose([
            source("a.json", "alpha", 1),
            source("b.json", "alpha", 1),
            PolicySource::new("c.json", empty_rules),
        ])
        .unwrap_err();
        assert_eq!(errors.len(), 2, "{errors:?}");
    }

    #[test]
    fn a_three_way_collision_names_the_contested_identity() {
        let errors = PolicySet::compose([
            source("a.json", "alpha", 7),
            source("b.json", "alpha", 7),
            source("c.json", "alpha", 7),
        ])
        .unwrap_err();
        assert_eq!(errors.len(), 2);
        for error in &errors {
            assert_eq!(
                error.key(),
                Some(PolicyVersionKey {
                    policy_id: "alpha".into(),
                    version: 7,
                })
            );
        }
    }

    #[test]
    fn an_empty_composition_is_an_empty_set() {
        let set = PolicySet::compose(std::iter::empty()).unwrap();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(set.policy_ids().is_empty());
        assert_eq!(set.latest("anything"), None);
    }

    #[test]
    fn region_rules_keep_their_regions_through_composition() {
        // Regions are only valid on jurisdiction rules, so the composition
        // has to carry a well-formed one to be admitted at all.
        let mut regional = document("regional", 3);
        regional.rules[0].rule_type = RuleTypeLabel::Jurisdiction;
        regional.rules[0].regions = Some(RegionLists {
            permitted: vec!["US".into()],
            restricted: vec!["RU".into()],
            prohibited: vec!["IR".into()],
        });
        let set = PolicySet::compose([PolicySource::new("regional.json", regional)]).unwrap();
        let composed = set.get("regional", 3).unwrap();
        assert_eq!(
            composed.rules[0].regions.as_ref().map(|r| &r.prohibited),
            Some(&vec!["IR".to_string()])
        );
    }
}

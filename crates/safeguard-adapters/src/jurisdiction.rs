//! Jurisdiction adapter: external geo/identity-provider data → normalized
//! region classification.
//!
//! The engine consumes region codes classified as `permitted`, `restricted`
//! or `prohibited` (plus the reserved `XX` unknown sentinel) — see
//! `policy-schema/jurisdiction.schema.json` and `docs/registries.md`.
//! Providers report country codes, IP geolocation, residence fields, etc.;
//! adapters map those onto the classification universe a policy defines.
//!
//! The [`RegionClassifier`] below is the reusable piece: given the policy's
//! universe (permitted/restricted/prohibited lists) it classifies any
//! two-letter region code, mapping anything outside the universe to
//! [`RegionClass::Unknown`] so the engine fails closed.

/// How a region code relates to a policy's jurisdiction configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionClass {
    /// In the policy's `permitted` list.
    Permitted,
    /// In the policy's `restricted` list.
    Restricted,
    /// In the policy's `prohibited` list.
    Prohibited,
    /// Not classified by this policy (unknown → engine fails closed).
    Unknown,
}

impl RegionClass {
    /// The stable lowercase label used in JSON documents.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permitted => "permitted",
            Self::Restricted => "restricted",
            Self::Prohibited => "prohibited",
            Self::Unknown => "unknown",
        }
    }
}

/// The classification universe a policy defines for a jurisdiction rule.
///
/// Mirrors the shape of `jurisdiction.schema.json`:
/// `{"permitted": ["US"], "restricted": ["RU"], "prohibited": ["IR"]}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegionUniverse {
    pub permitted: Vec<String>,
    pub restricted: Vec<String>,
    pub prohibited: Vec<String>,
}

impl RegionUniverse {
    /// Classify a region code against this universe.
    ///
    /// Codes are compared case-insensitively and normalized to uppercase,
    /// so a provider sending `us` and a policy listing `US` agree. Anything
    /// not in the universe is [`RegionClass::Unknown`] — never guessed.
    #[must_use]
    pub fn classify(&self, region: &str) -> RegionClass {
        let normalized = region.trim().to_ascii_uppercase();
        if self.permitted.iter().any(|code| code == &normalized) {
            RegionClass::Permitted
        } else if self.restricted.iter().any(|code| code == &normalized) {
            RegionClass::Restricted
        } else if self.prohibited.iter().any(|code| code == &normalized) {
            RegionClass::Prohibited
        } else {
            RegionClass::Unknown
        }
    }
}

/// Normalize a provider-supplied region to the canonical uppercase form.
///
/// Providers report regions in mixed shapes (`us`, `US`, `usa`, ISO
/// numeric `840`, full names). This maps the common variants onto the
/// ISO 3166-1 alpha-2 codes the policy universe uses. Anything unrecognized
/// returns `None` — the caller turns that into [`RegionClass::Unknown`].
#[must_use]
pub fn normalize_region(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let upper = trimmed.to_ascii_uppercase();
    // Exact alpha-2 already.
    if upper.len() == 2 && upper.chars().all(|c| c.is_ascii_alphabetic()) {
        return Some(upper);
    }
    // Alpha-3 and numeric aliases for common cases.
    let alias: Option<&str> = match upper.as_str() {
        "USA" | "840" => Some("US"),
        "CAN" | "124" => Some("CA"),
        "GBR" | "826" => Some("GB"),
        "DEU" | "276" => Some("DE"),
        "FRA" | "250" => Some("FR"),
        "ITA" | "380" => Some("IT"),
        "ESP" | "724" => Some("ES"),
        "NLD" | "528" => Some("NL"),
        "RUS" | "643" => Some("RU"),
        "CHN" | "156" => Some("CN"),
        "IRN" | "364" => Some("IR"),
        "PRK" | "408" => Some("KP"),
        _ => None,
    };
    alias.map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn universe() -> RegionUniverse {
        RegionUniverse {
            permitted: vec!["US".to_owned(), "CA".to_owned()],
            restricted: vec!["RU".to_owned()],
            prohibited: vec!["IR".to_owned(), "KP".to_owned()],
        }
    }

    #[test]
    fn classifies_against_the_universe() {
        let universe = universe();
        assert_eq!(universe.classify("US"), RegionClass::Permitted);
        assert_eq!(universe.classify("RU"), RegionClass::Restricted);
        assert_eq!(universe.classify("IR"), RegionClass::Prohibited);
        assert_eq!(universe.classify("DE"), RegionClass::Unknown);
    }

    #[test]
    fn classification_is_case_insensitive() {
        let universe = universe();
        assert_eq!(universe.classify("us"), RegionClass::Permitted);
        assert_eq!(universe.classify(" ru "), RegionClass::Restricted);
    }

    #[test]
    fn unknown_regions_fail_closed_not_guessed() {
        let universe = universe();
        assert_eq!(universe.classify("ZZ"), RegionClass::Unknown);
        assert_eq!(universe.classify(""), RegionClass::Unknown);
    }

    #[test]
    fn normalizes_common_aliases() {
        assert_eq!(normalize_region("us"), Some("US".to_owned()));
        assert_eq!(normalize_region("usa"), Some("US".to_owned()));
        assert_eq!(normalize_region("840"), Some("US".to_owned()));
        assert_eq!(normalize_region("DEU"), Some("DE".to_owned()));
        assert_eq!(normalize_region("not-a-country"), None);
        assert_eq!(normalize_region(""), None);
    }

    #[test]
    fn determinism() {
        let universe = universe();
        assert_eq!(universe.classify("us"), universe.classify("US"));
        assert_eq!(universe.classify("GBR"), RegionClass::Unknown); // alias not in universe
    }
}

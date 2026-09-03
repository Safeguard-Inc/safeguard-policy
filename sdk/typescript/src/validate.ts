import type { PolicyDocument, RegionLists, Rule, RuleType } from "./types";

const ID_RE = /^[\x20-\x7E]*$/;
const REGION_RE = /^[A-Z]{2}$/;
const MAX_ID_BYTES = 32;

/** UTF-8 byte length, browser-safe (no Buffer dependency). */
function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function checkId(id: string, label: string, problems: string[]): void {
  if (utf8Length(id) > MAX_ID_BYTES) {
    problems.push(`${label}: identifier longer than 32 bytes (would truncate on-chain)`);
  }
  if (!ID_RE.test(id)) {
    problems.push(`${label}: identifier must be ASCII`);
  }
}

function checkRegions(regions: RegionLists, ruleId: string, problems: string[]): void {
  const lists: Array<[string, string[]]> = [
    ["permitted", regions.permitted],
    ["restricted", regions.restricted],
    ["prohibited", regions.prohibited],
  ];
  const classified = new Map<string, string>();

  for (const [listName, codes] of lists) {
    const seen = new Set<string>();
    for (const code of codes) {
      if (!REGION_RE.test(code)) {
        problems.push(
          `rule "${ruleId}": region "${code}" in ${listName} is not an uppercase ISO alpha-2 code`
        );
      }
      if (seen.has(code)) {
        problems.push(`rule "${ruleId}": duplicate region "${code}" in ${listName}`);
      }
      seen.add(code);

      const previous = classified.get(code);
      if (previous !== undefined && previous !== listName) {
        problems.push(
          `rule "${ruleId}": region "${code}" is classified as both ${previous} and ${listName}`
        );
      }
      classified.set(code, listName);
    }
  }
}

/**
 * Validate a policy document, returning human-readable problems
 * (empty array = valid). Mirrors the Rust SDK validator and
 * scripts/validate_policy.py.
 */
export function validatePolicyDocument(document: PolicyDocument): string[] {
  const problems: string[] = [];

  if (document.policy_id.length === 0) {
    problems.push("policy_id: must not be empty");
  } else {
    checkId(document.policy_id, "policy_id", problems);
  }

  if (!Number.isInteger(document.version) || document.version < 1) {
    problems.push("version: must be an integer >= 1");
  }

  if (document.rules.length === 0) {
    problems.push("rules: at least one rule is required");
  }

  const seenIds = new Set<string>();
  const seenTypes = new Set<RuleType>();
  for (const rule of document.rules) {
    if (rule.id.length === 0) {
      problems.push("rule: id must not be empty");
    } else {
      checkId(rule.id, `rule "${rule.id}"`, problems);
      if (seenIds.has(rule.id)) {
        problems.push(`rule "${rule.id}": duplicate rule id`);
      }
      seenIds.add(rule.id);
    }

    if (seenTypes.has(rule.type)) {
      problems.push(`rule "${rule.id}": at most one rule per type (${rule.type} already enabled)`);
    }
    seenTypes.add(rule.type);

    if (rule.type === "jurisdiction") {
      if (rule.regions === undefined) {
        problems.push(`rule "${rule.id}": jurisdiction rules must carry regions`);
      } else {
        checkRegions(rule.regions, rule.id, problems);
      }
    } else if (rule.regions !== undefined) {
      problems.push(`rule "${rule.id}": regions are only valid on jurisdiction rules`);
    }
  }

  return problems;
}

/** Parse JSON then validate; throws on invalid JSON. */
export function validatePolicyJson(json: string): string[] {
  return validatePolicyDocument(JSON.parse(json) as PolicyDocument);
}

/** A minimal structural check useful before trusting a rule object. */
export function isRule(value: unknown): value is Rule {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const rule = value as Partial<Rule>;
  return (
    typeof rule.id === "string" &&
    (rule.type === "allowlist" ||
      rule.type === "denylist" ||
      rule.type === "sanctions" ||
      rule.type === "jurisdiction") &&
    (rule.action === "block" || rule.action === "flag")
  );
}
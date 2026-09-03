/**
 * Type definitions mirroring `policy-schema/` and the core serialization.
 * Literal unions match the JSON Schema enums exactly; do not add values here
 * without updating the schemas in lockstep (see docs/versioning.md).
 */

/** Rule category, matching policy.schema.json `type` and core RuleType labels. */
export type RuleType = "allowlist" | "denylist" | "sanctions" | "jurisdiction";

/** Rule severity, matching policy.schema.json `action` and core RuleAction. */
export type RuleAction = "block" | "flag";

/** Region classification, matching core RegionStatus labels. */
export type RegionStatus = "permitted" | "restricted" | "prohibited" | "unknown";

/** Account status, matching core AccountStatus labels. */
export type AccountStatus = "active" | "restricted" | "frozen" | "suspended" | "unknown";

/** Decision outcome, matching decision.schema.json and core Decision labels. */
export type Decision = "APPROVE" | "BLOCK" | "FLAG";

/** Reason codes, matching decision.schema.json and core ReasonCode labels. */
export type ReasonCode =
  | "no_reason"
  | "account_frozen"
  | "account_suspended"
  | "account_restricted"
  | "account_status_unknown"
  | "allowlist_required"
  | "denylist_match"
  | "sanctions_match"
  | "jurisdiction_prohibited"
  | "jurisdiction_restricted"
  | "jurisdiction_unknown";

/** Region classification lists of a jurisdiction rule. */
export interface RegionLists {
  permitted: string[];
  restricted: string[];
  prohibited: string[];
}

/** A single rule inside a policy document. */
export interface Rule {
  /** Unique within the policy version; ASCII, at most 32 bytes. */
  id: string;
  type: RuleType;
  action: RuleAction;
  /** Required for jurisdiction rules, forbidden for other types. */
  regions?: RegionLists;
}

/** A policy document, matching policy.schema.json. */
export interface PolicyDocument {
  /** ASCII, at most 32 bytes (the on-chain id width). */
  policy_id: string;
  version: number;
  title?: string;
  description?: string;
  rules: Rule[];
  metadata?: Record<string, unknown>;
}

/** A decision document, matching decision.schema.json. */
export interface DecisionDoc {
  decision: Decision;
  policy_id: string;
  policy_version: number;
  /** Present when a rule produced the outcome. */
  rule_id?: string;
  reason_code: ReasonCode;
  /** RFC 3339 timestamp recorded by the emitting service. */
  timestamp?: string;
}

/** All valid rule types (for round-trip checks). */
export const RULE_TYPES: readonly RuleType[] = [
  "allowlist",
  "denylist",
  "sanctions",
  "jurisdiction",
];

/** All valid rule actions. */
export const RULE_ACTIONS: readonly RuleAction[] = ["block", "flag"];

/** All valid decisions. */
export const DECISIONS: readonly Decision[] = ["APPROVE", "BLOCK", "FLAG"];

/** All valid reason codes. */
export const REASON_CODES: readonly ReasonCode[] = [
  "no_reason",
  "account_frozen",
  "account_suspended",
  "account_restricted",
  "account_status_unknown",
  "allowlist_required",
  "denylist_match",
  "sanctions_match",
  "jurisdiction_prohibited",
  "jurisdiction_restricted",
  "jurisdiction_unknown",
];
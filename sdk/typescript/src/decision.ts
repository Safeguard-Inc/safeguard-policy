import type { Decision, DecisionDoc, ReasonCode } from "./types";

/**
 * Build a decision document for audit tooling, matching
 * decision.schema.json. Timestamps are RFC 3339; pass your own or omit.
 */
export function buildDecisionDoc(params: {
  decision: Decision;
  policy_id: string;
  policy_version: number;
  rule_id?: string;
  reason_code: ReasonCode;
  timestamp?: string;
}): DecisionDoc {
  const doc: DecisionDoc = {
    decision: params.decision,
    policy_id: params.policy_id,
    policy_version: params.policy_version,
    reason_code: params.reason_code,
  };
  if (params.rule_id !== undefined) {
    doc.rule_id = params.rule_id;
  }
  if (params.timestamp !== undefined) {
    doc.timestamp = params.timestamp;
  }
  return doc;
}

/** RFC 3339 timestamp helper (UTC, millisecond precision). */
export function nowTimestamp(date: Date = new Date()): string {
  return date.toISOString();
}
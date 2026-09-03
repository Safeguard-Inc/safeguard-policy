import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { buildDecisionDoc, nowTimestamp } from "../decision";

describe("buildDecisionDoc", () => {
  it("builds a minimal decision document", () => {
    const doc = buildDecisionDoc({
      decision: "APPROVE",
      policy_id: "institutional-default",
      policy_version: 1,
      reason_code: "no_reason",
    });
    assert.deepEqual(doc, {
      decision: "APPROVE",
      policy_id: "institutional-default",
      policy_version: 1,
      reason_code: "no_reason",
    });
  });

  it("includes rule and timestamp when provided", () => {
    const doc = buildDecisionDoc({
      decision: "BLOCK",
      policy_id: "example-combined",
      policy_version: 1,
      rule_id: "SANCTIONS-001",
      reason_code: "sanctions_match",
      timestamp: "2026-09-03T00:00:00.000Z",
    });
    assert.equal(doc.rule_id, "SANCTIONS-001");
    assert.equal(doc.timestamp, "2026-09-03T00:00:00.000Z");

    // Serializes with stable keys for audit storage.
    const json = JSON.stringify(doc);
    assert.ok(json.includes('"decision":"BLOCK"'));
    assert.ok(json.includes('"reason_code":"sanctions_match"'));
  });
});

describe("nowTimestamp", () => {
  it("produces an RFC 3339 timestamp", () => {
    const ts = nowTimestamp();
    assert.match(ts, /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/);
  });
});
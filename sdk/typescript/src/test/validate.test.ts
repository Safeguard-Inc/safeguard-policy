import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { validatePolicyDocument, isRule } from "../validate";
import type { PolicyDocument, RegionLists, Rule } from "../types";

function rule(id: string, type: Rule["type"], action: Rule["action"]): Rule {
  return { id, type, action };
}

function regions(): RegionLists {
  return { permitted: ["US", "GB"], restricted: ["RU"], prohibited: ["IR"] };
}

function doc(rules: Rule[]): PolicyDocument {
  return { policy_id: "test-policy", version: 1, rules };
}

describe("validatePolicyDocument", () => {
  it("accepts a valid document", () => {
    const problems = validatePolicyDocument(
      doc([
        rule("ALLOWLIST-001", "allowlist", "block"),
        { ...rule("JURISDICTION-001", "jurisdiction", "flag"), regions: regions() },
      ])
    );
    assert.deepEqual(problems, []);
  });

  it("rejects duplicate ids and duplicate types", () => {
    const problems = validatePolicyDocument(
      doc([
        rule("A-1", "allowlist", "block"),
        rule("A-1", "denylist", "block"),
        rule("A-2", "allowlist", "flag"),
      ])
    );
    assert.ok(problems.some((p) => p.includes("duplicate rule id")));
    assert.ok(problems.some((p) => p.includes("at most one rule per type")));
  });

  it("rejects ids longer than 32 bytes and non-ascii ids", () => {
    const long = validatePolicyDocument(doc([rule("X".repeat(33), "allowlist", "block")]));
    assert.ok(long.some((p) => p.includes("longer than 32 bytes")));

    const nonAscii = validatePolicyDocument(doc([rule("héllo-001", "allowlist", "block")]));
    assert.ok(nonAscii.some((p) => p.includes("must be ASCII")));
  });

  it("rejects jurisdiction rules without regions and regions on other types", () => {
    const missing = validatePolicyDocument(doc([rule("J-1", "jurisdiction", "flag")]));
    assert.ok(missing.some((p) => p.includes("must carry regions")));

    const stray = validatePolicyDocument(
      doc([{ ...rule("A-1", "allowlist", "block"), regions: regions() }])
    );
    assert.ok(stray.some((p) => p.includes("only valid on jurisdiction")));
  });

  it("rejects malformed and cross-classified region codes", () => {
    const bad = doc([
      {
        id: "J-1",
        type: "jurisdiction",
        action: "flag",
        regions: {
          permitted: ["us", "US"],
          restricted: ["US"],
          prohibited: [],
        },
      },
    ]);
    const problems = validatePolicyDocument(bad);
    assert.ok(problems.some((p) => p.includes("ISO alpha-2")));
    assert.ok(problems.some((p) => p.includes("both")));
  });

  it("rejects version zero and empty rule sets", () => {
    assert.ok(validatePolicyDocument({ policy_id: "p", version: 0, rules: [] }).length > 0);
  });
});

describe("isRule", () => {
  it("accepts well-formed rules and rejects junk", () => {
    assert.equal(isRule({ id: "A-1", type: "allowlist", action: "block" }), true);
    assert.equal(isRule({ id: "A-1", type: "kyc", action: "block" }), false);
    assert.equal(isRule(null), false);
    assert.equal(isRule("nope"), false);
  });
});
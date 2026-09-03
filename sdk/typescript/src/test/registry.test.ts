import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { decodeSubjectHash, isSanctionsEntry } from "../registry";
import type { SanctionsDatasetEntry } from "../registry";

const VALID: SanctionsDatasetEntry = {
  subject_hash: "c0ffee0000000000000000000000000000000000000000000000000000000000",
  list_id: "OFAC-SDN",
  status: "active",
  dataset_version: 3,
  effective_at: "2024-01-15T00:00:00Z",
  source: "ofac",
};

describe("isSanctionsEntry", () => {
  it("accepts a well-formed entry", () => {
    assert.equal(isSanctionsEntry(VALID), true);
  });

  it("rejects malformed hashes, statuses and versions", () => {
    assert.equal(isSanctionsEntry({ ...VALID, subject_hash: "ab" }), false);
    assert.equal(isSanctionsEntry({ ...VALID, status: "bogus" }), false);
    assert.equal(isSanctionsEntry({ ...VALID, dataset_version: 0 }), false);
    assert.equal(isSanctionsEntry({ ...VALID, dataset_version: 1.5 }), false);
    assert.equal(isSanctionsEntry({ ...VALID, source: "" }), false);
    assert.equal(isSanctionsEntry(null), false);
  });
});

describe("decodeSubjectHash", () => {
  it("decodes 64 hex chars into 32 bytes", () => {
    const bytes = decodeSubjectHash(VALID.subject_hash);
    assert.ok(bytes);
    assert.equal(bytes!.length, 32);
    assert.equal(bytes![0], 0xc0);
    assert.equal(bytes![1], 0xff);
    assert.equal(bytes![2], 0xee);
  });

  it("rejects non-hex and wrong-length input", () => {
    assert.equal(decodeSubjectHash("zz"), null);
    assert.equal(decodeSubjectHash("abc"), null);
    assert.equal(decodeSubjectHash(""), null);
  });
});

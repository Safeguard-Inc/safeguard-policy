import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  decodeSubjectHash,
  isDatasetReport,
  isIdentityRecord,
  isSanctionsEntry,
} from "../registry";
import type { DatasetReport, IdentityRecord, SanctionsDatasetEntry } from "../registry";

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

const IDENTITY_VALID: IdentityRecord = {
  account: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
  status: "verified",
  attestation_ref: "ATT-0001",
  expires_at: 1893456000,
};

const REPORT_VALID: DatasetReport = {
  source: "ofac",
  entries: [VALID],
  review: [{ record: "junk|XYZ|active", reason: "unmapped provider list code \"XYZ\"" }],
};

describe("isDatasetReport", () => {
  it("accepts a well-formed report", () => {
    assert.equal(isDatasetReport(REPORT_VALID), true);
  });

  it("accepts an empty review list", () => {
    assert.equal(isDatasetReport({ ...REPORT_VALID, review: [] }), true);
  });

  it("rejects malformed reports", () => {
    assert.equal(isDatasetReport({ ...REPORT_VALID, source: "" }), false);
    assert.equal(isDatasetReport({ ...REPORT_VALID, entries: ["nope"] }), false);
    assert.equal(
      isDatasetReport({ ...REPORT_VALID, review: [{ record: "x" }] }),
      false
    );
    assert.equal(isDatasetReport(null), false);
  });
});

describe("isIdentityRecord", () => {
  it("accepts a well-formed record", () => {
    assert.equal(isIdentityRecord(IDENTITY_VALID), true);
  });

  it("accepts every identity status", () => {
    for (const status of ["verified", "unverified", "revoked", "expired", "unknown"]) {
      assert.equal(isIdentityRecord({ ...IDENTITY_VALID, status }), true);
    }
  });

  it("rejects malformed accounts, statuses and expiry", () => {
    assert.equal(isIdentityRecord({ ...IDENTITY_VALID, account: "not-an-address" }), false);
    assert.equal(isIdentityRecord({ ...IDENTITY_VALID, status: "bogus" }), false);
    assert.equal(isIdentityRecord({ ...IDENTITY_VALID, attestation_ref: "" }), false);
    assert.equal(isIdentityRecord({ ...IDENTITY_VALID, expires_at: -1 }), false);
    assert.equal(isIdentityRecord({ ...IDENTITY_VALID, expires_at: 1.5 }), false);
    assert.equal(isIdentityRecord(null), false);
  });
});

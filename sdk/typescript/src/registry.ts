/**
 * Registry dataset types, mirroring `policy-schema/sanctions.schema.json`.
 *
 * Adapters normalize external sanctions data into these shapes (see
 * docs/adapters.md); dashboards and backend services use the types to build
 * and validate entries before they are pushed on-chain. The subject hash
 * stays a 64-hex-char string in JSON; `decodeSubjectHash` gives the raw 32
 * bytes for building the on-chain id.
 */

/** Entry status, matching sanctions.schema.json `status`. */
export type SanctionsStatus = "active" | "inactive";

/** One normalized sanctions record as produced by a source adapter. */
export interface SanctionsDatasetEntry {
  /** SHA-256 (hex) of the normalized subject identifier; 64 hex chars. */
  subject_hash: string;
  /** Source list identifier (e.g. "OFAC-SDN"), ASCII, at most 32 bytes. */
  list_id: string;
  status: SanctionsStatus;
  /** Monotonic dataset version; >= 1. */
  dataset_version: number;
  /** RFC 3339 time the listing became effective. */
  effective_at: string;
  /** Source identifier (adapter/authority), e.g. "ofac". */
  source: string;
}

/** All valid sanctions entry statuses. */
export const SANCTIONS_STATUSES: readonly SanctionsStatus[] = ["active", "inactive"];

/**
 * Identity verification status, matching the on-chain `IdentityStatus`
 * codes (safeguard_core::registries::identity). `verified` is the only
 * status hooks may treat as verified; everything else fails closed.
 */
export type IdentityStatus = "verified" | "unverified" | "revoked" | "expired" | "unknown";

/** All valid identity statuses. */
export const IDENTITY_STATUSES: readonly IdentityStatus[] = [
  "verified",
  "unverified",
  "revoked",
  "expired",
  "unknown",
];

/**
 * One identity verification record, mirroring `set_identity` on-chain and
 * `policies/fixtures/identity.json`. Attestation references only — no PII
 * is stored on-chain.
 */
export interface IdentityRecord {
  /** Stellar-style account address (G...). */
  account: string;
  status: IdentityStatus;
  /** Reference to an off-chain attestation (KYC/verification provider). */
  attestation_ref: string;
  /** Unix epoch seconds when the verification expires; 0 = never. */
  expires_at: number;
}

const G_ADDRESS = /^G[A-Z2-7]{55}$/;

/**
 * The operator-facing artifact of `safeguard dataset build` (and the Rust
 * `safeguard_adapters::dataset::DatasetReport`): registry-ready entries
 * plus the review items an operator must decide on before anything is
 * pushed on-chain.
 */
export interface DatasetReport {
  /** Source identifier, e.g. "ofac". */
  source: string;
  /** The normalized entries, ready for the registry. */
  entries: SanctionsDatasetEntry[];
  /** Records that could not be normalized; require operator review. */
  review: ReviewItem[];
}

/** One record the normalizer could not map; rendered for a human. */
export interface ReviewItem {
  /** The raw provider record. */
  record: string;
  /** Why it could not be normalized. */
  reason: string;
}

/** Structural check that a value is a well-formed dataset report. */
export function isDatasetReport(value: unknown): value is DatasetReport {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const report = value as Partial<DatasetReport>;
  return (
    typeof report.source === "string" &&
    report.source.length > 0 &&
    Array.isArray(report.entries) &&
    report.entries.every((entry) => isSanctionsEntry(entry)) &&
    Array.isArray(report.review) &&
    report.review.every(
      (item) =>
        typeof item === "object" &&
        item !== null &&
        typeof (item as Partial<ReviewItem>).record === "string" &&
        typeof (item as Partial<ReviewItem>).reason === "string"
    )
  );
}

/** Structural check that a value is a well-formed identity record. */
export function isIdentityRecord(value: unknown): value is IdentityRecord {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Partial<IdentityRecord>;
  return (
    typeof record.account === "string" &&
    G_ADDRESS.test(record.account) &&
    typeof record.status === "string" &&
    (IDENTITY_STATUSES as readonly string[]).includes(record.status) &&
    typeof record.attestation_ref === "string" &&
    record.attestation_ref.length > 0 &&
    typeof record.expires_at === "number" &&
    Number.isInteger(record.expires_at) &&
    record.expires_at >= 0
  );
}

const HEX_64 = /^[0-9a-fA-F]{64}$/;

/** Decode a 64-hex-char subject hash into its 32 bytes (browser-safe). */
export function decodeSubjectHash(hex: string): Uint8Array | null {
  if (!HEX_64.test(hex)) {
    return null;
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Structural check that a value is a well-formed sanctions entry. */
export function isSanctionsEntry(value: unknown): value is SanctionsDatasetEntry {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const entry = value as Partial<SanctionsDatasetEntry>;
  return (
    typeof entry.subject_hash === "string" &&
    HEX_64.test(entry.subject_hash) &&
    typeof entry.list_id === "string" &&
    entry.list_id.length > 0 &&
    entry.list_id.length <= 32 &&
    (entry.status === "active" || entry.status === "inactive") &&
    typeof entry.dataset_version === "number" &&
    Number.isInteger(entry.dataset_version) &&
    entry.dataset_version >= 1 &&
    typeof entry.effective_at === "string" &&
    typeof entry.source === "string" &&
    entry.source.length > 0
  );
}
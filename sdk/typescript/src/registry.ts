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
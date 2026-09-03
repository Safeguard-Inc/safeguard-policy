/**
 * @safeguard/policy-sdk — TypeScript SDK for Safeguard policy documents.
 *
 * Provides the machine-readable policy surface for web applications,
 * compliance dashboards and backend services: type definitions mirroring
 * policy-schema/, invariant validation matching the Rust SDK, and
 * decision-document helpers for audit tooling.
 *
 * This SDK does not reimplement the decision engine. Decisions come from the
 * contract (or the offline CLI/Rust SDK), which run the same
 * safeguard_core::evaluator compiled into the wasm artifact.
 */

export * from "./types";
export * from "./validate";
export * from "./decision";
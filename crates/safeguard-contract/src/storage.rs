//! Contract storage: data keys and typed accessors.
//!
//! Filled in by the storage commit; layout is documented here so deployment
//! tooling can reason about state without reading code.

// Data-key layout (instance):
//   Admin                  → Address
//   Authorities            → Vec<Address>
// Data-key layout (persistent):
//   PolicyVersions(id, ver)  → PolicyVersionRecord
//   ActiveVersion(id)        → u32
//   TokenBindings(id)        → Vec<Address>

//! `safeguard version` — print version information.

use anyhow::Result;

/// Print CLI, SDK and schema versions.
pub fn run() -> Result<()> {
    println!("safeguard-cli  {}", env!("CARGO_PKG_VERSION"));
    println!("safeguard-sdk  {}", safeguard_sdk::VERSION);
    println!("policy schema  {}", crate::SCHEMA_VERSION);
    Ok(())
}

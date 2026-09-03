//! The Safeguard operator CLI.
//!
//! Offline tooling for policy authors and operators. It reuses the same SDK
//! (and through it the same core engine) as everything else in this
//! repository, so what the CLI decides is exactly what the contract decides.
//!
//! The CLI is a developer/operator tool, not a replacement for on-chain
//! enforcement: activating a policy or evaluating live subjects happens
//! against the contract, never through this binary.

use clap::{Parser, Subcommand};

mod commands;

/// The policy-schema version the CLI understands (mirrors the contract's
/// `schema_version` entrypoint).
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Parser)]
#[command(
    name = "safeguard",
    version,
    about = "Safeguard policy tooling: validate, inspect and evaluate policy documents offline",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print version information.
    Version,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Version => commands::version::run(),
    };
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

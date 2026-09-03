//! The Safeguard operator CLI.
//!
//! Offline tooling for policy authors and operators. It reuses the same SDK
//! (and through it the same core engine) as everything else in this
//! repository, so what the CLI decides is exactly what the contract decides.
//!
//! The CLI is a developer/operator tool, not a replacement for on-chain
//! enforcement: activating a policy or evaluating live subjects happens
//! against the contract, never through this binary.

use std::path::PathBuf;

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
    /// Validate a policy document (schema + invariants).
    Validate {
        /// Path to a policy JSON document.
        path: PathBuf,
    },
    /// Print a summary of a policy document.
    Inspect {
        /// Path to a policy JSON document.
        path: PathBuf,
    },
    /// Evaluate a subject offline (same engine as the contract).
    Evaluate {
        /// Path to a policy JSON document.
        policy: PathBuf,
        /// Path to a facts JSON document.
        facts: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Version => commands::version::run(),
        Command::Validate { path } => commands::validate::run(&path),
        Command::Inspect { path } => commands::inspect::run(&path),
        Command::Evaluate { policy, facts } => commands::evaluate::run(&policy, &facts),
    };
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

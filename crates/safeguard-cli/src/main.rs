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
mod fixtures;

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
    /// Validate the fixture datasets (accounts, jurisdictions, sanctions).
    Fixture {
        #[command(subcommand)]
        command: FixtureCommand,
    },
    /// Inspect a normalized registry dataset before pushing it on-chain.
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Test a policy against the fixture subjects offline.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Run a provider snapshot through an adapter pipeline.
    Dataset {
        #[command(subcommand)]
        command: DatasetCommand,
    },
}

#[derive(Subcommand)]
enum DatasetCommand {
    /// Normalize a sanctions snapshot into a dataset report.
    Build(commands::dataset::DatasetArgs),
}

#[derive(Subcommand)]
enum FixtureCommand {
    /// Validate the fixture datasets.
    Validate {
        /// Fixtures directory (defaults to policies/fixtures).
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum RegistryCommand {
    /// Summarize a sanctions, identity or jurisdiction dataset.
    Inspect {
        /// Path to a registry dataset JSON document.
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Evaluate every fixture subject through a policy offline.
    Test {
        /// Path to a policy JSON document.
        policy: PathBuf,
        /// Fixtures directory (defaults to policies/fixtures).
        #[arg(long, default_value = "policies/fixtures")]
        fixtures_dir: PathBuf,
        /// Exit non-zero if any subject evaluates to BLOCK.
        #[arg(long)]
        strict: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Version => commands::version::run(),
        Command::Validate { path } => commands::validate::run(&path),
        Command::Inspect { path } => commands::inspect::run(&path),
        Command::Evaluate { policy, facts } => commands::evaluate::run(&policy, &facts),
        Command::Fixture {
            command: FixtureCommand::Validate { path },
        } => commands::fixture::run(path.as_deref()),
        Command::Registry {
            command: RegistryCommand::Inspect { path },
        } => commands::registry::run(&path),
        Command::Policy {
            command:
                PolicyCommand::Test {
                    policy,
                    fixtures_dir,
                    strict,
                },
        } => commands::policy::run(&policy, &fixtures_dir, strict),
        Command::Dataset {
            command: DatasetCommand::Build(args),
        } => commands::dataset::run(args),
    };
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

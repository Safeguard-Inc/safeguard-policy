//! Integration tests exercising the built binary end to end.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_safeguard-cli");

const VALID_POLICY: &str = r#"{
  "policy_id": "test-policy",
  "version": 1,
  "rules": [
    { "id": "ALLOWLIST-001", "type": "allowlist", "action": "block" },
    { "id": "SANCTIONS-001", "type": "sanctions", "action": "flag" },
    {
      "id": "JURISDICTION-001",
      "type": "jurisdiction",
      "action": "block",
      "regions": {
        "permitted": ["US"],
        "restricted": ["RU"],
        "prohibited": ["IR"]
      }
    }
  ]
}"#;

const INVALID_POLICY: &str = r#"{
  "policy_id": "test-policy",
  "version": 1,
  "rules": [
    { "id": "A-1", "type": "allowlist", "action": "block" },
    { "id": "A-1", "type": "denylist", "action": "block" }
  ]
}"#;

const UNKNOWN_FIELD_POLICY: &str = r#"{
  "policy_id": "test-policy",
  "version": 1,
  "rules": [],
  "unexpected": true
}"#;

/// Write `content` to a unique temp file and return its path.
fn temp_file(name: &str, content: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("safeguard-cli-test-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join(name);
    fs::write(&path, content).expect("write temp file");
    path
}

fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(BIN).args(args).output().expect("run binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn version_reports_cli_sdk_and_schema() {
    let (ok, stdout, _) = run(&["version"]);
    assert!(ok);
    assert!(stdout.contains("safeguard-cli"));
    assert!(stdout.contains("safeguard-sdk"));
    assert!(stdout.contains("policy schema  1"));
}

#[test]
fn validate_accepts_a_valid_policy_and_rejects_invalid_ones() {
    let valid = temp_file("valid.json", VALID_POLICY);
    let (ok, stdout, _) = run(&["validate", valid.to_str().unwrap()]);
    assert!(ok, "valid policy must validate");
    assert!(stdout.contains("OK"));

    let invalid = temp_file("invalid.json", INVALID_POLICY);
    let (ok, _, stderr) = run(&["validate", invalid.to_str().unwrap()]);
    assert!(!ok, "duplicate ids must fail");
    assert!(stderr.contains("duplicate rule id"));

    let unknown = temp_file("unknown.json", UNKNOWN_FIELD_POLICY);
    let (ok, _, _) = run(&["validate", unknown.to_str().unwrap()]);
    assert!(!ok, "unknown fields must be rejected like the schema");
}

#[test]
fn inspect_summarizes_the_policy() {
    let valid = temp_file("valid.json", VALID_POLICY);
    let (ok, stdout, _) = run(&["inspect", valid.to_str().unwrap()]);
    assert!(ok);
    assert!(stdout.contains("policy_id    test-policy"));
    assert!(stdout.contains("ALLOWLIST-001"));
    assert!(stdout.contains("jurisdiction"));
}

#[test]
fn evaluate_decides_offline_with_the_core_engine() {
    let policy = temp_file("policy.json", VALID_POLICY);

    // Sanctions match under a flag action → FLAG with rule attribution.
    let facts = temp_file(
        "facts-flag.json",
        r#"{
          "account_status": "active",
          "allowlist_member": true,
          "denylist_matched": false,
          "sanctions_matched": true,
          "jurisdiction": "US"
        }"#,
    );
    let (ok, stdout, _) = run(&[
        "evaluate",
        policy.to_str().unwrap(),
        facts.to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("FLAG (sanctions_match)"));
    assert!(stdout.contains("rule=SANCTIONS-001"));

    // Frozen account → structural BLOCK, no rule attribution.
    let frozen = temp_file(
        "facts-frozen.json",
        r#"{
          "account_status": "frozen",
          "allowlist_member": true,
          "denylist_matched": false,
          "sanctions_matched": false,
          "jurisdiction": "US"
        }"#,
    );
    let (ok, stdout, _) = run(&[
        "evaluate",
        policy.to_str().unwrap(),
        frozen.to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("BLOCK (account_frozen)"));
    assert!(
        !stdout.contains("rule="),
        "structural outcomes carry no rule"
    );

    // Prohibited region code → classified against the policy → BLOCK.
    let prohibited = temp_file(
        "facts-prohibited.json",
        r#"{
          "account_status": "active",
          "allowlist_member": true,
          "denylist_matched": false,
          "sanctions_matched": false,
          "jurisdiction": "IR"
        }"#,
    );
    let (ok, stdout, _) = run(&[
        "evaluate",
        policy.to_str().unwrap(),
        prohibited.to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("BLOCK (jurisdiction_prohibited)"));

    // Invalid facts label → clean error, non-zero exit.
    let bad_facts = temp_file(
        "facts-bad.json",
        r#"{
          "account_status": "bogus",
          "allowlist_member": true,
          "denylist_matched": false,
          "sanctions_matched": false,
          "jurisdiction": "US"
        }"#,
    );
    let (ok, _, stderr) = run(&[
        "evaluate",
        policy.to_str().unwrap(),
        bad_facts.to_str().unwrap(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("unknown account_status"));
}

#[test]
fn missing_files_fail_cleanly() {
    let (ok, _, stderr) = run(&["validate", "/nonexistent/policy.json"]);
    assert!(!ok);
    assert!(stderr.contains("reading"));
}

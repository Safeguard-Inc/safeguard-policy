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

const SNAPSHOT: &str = "\
bin laden, usama|SDN|active|2023-06-01
qods force|SSI|active|2021-04-15
unmapped entity|XYZ|active|2023-01-01
";

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

/// The fixtures directory of the repository (three levels up from the test
/// binary's manifest dir).
fn repo_fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policies/fixtures")
}

#[test]
fn fixture_validate_accepts_the_shipped_fixtures() {
    let (ok, stdout, stderr) = run(&["fixture", "validate", repo_fixtures_dir().to_str().unwrap()]);
    assert!(ok, "shipped fixtures must validate: {stderr}");
    assert!(stdout.contains("OK:"));
    assert!(stdout.contains("accounts"));
    assert!(stdout.contains("sanctions entries"));
    assert!(stdout.contains("identity records"));
    assert!(stdout.contains("token bindings"));
}

#[test]
fn fixture_validate_rejects_a_token_binding_for_an_unknown_policy() {
    // Same rule as scripts/check-fixtures.py: a token binding must reference
    // a shipped reference policy. The temp dir has no ../default or
    // ../examples siblings, so the cross-check is skipped there; run against
    // a copy of the shipped fixtures plus a bogus binding instead.
    let dir = temp_dir_with(
        "fixture-unknown-policy",
        &[
            ("accounts.json", r#"{"accounts": []}"#),
            (
                "jurisdictions.json",
                r#"{"permitted": ["US"], "restricted": [], "prohibited": []}"#,
            ),
            (
                "tokens.json",
                r#"{"bindings": [{
                    "policy_id": "no-such-policy",
                    "token": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
                }]}"#,
            ),
        ],
    );
    // In a bare temp dir the shipped-policy cross-check is skipped, so the
    // dataset must still validate (shape is fine).
    let (ok, _, stderr) = run(&["fixture", "validate", dir.to_str().unwrap()]);
    assert!(ok, "bare temp dir must validate: {stderr}");

    // The shipped fixtures directory is inside the repo, so a bogus binding
    // added there would fail the cross-check. Exercise the check against the
    // real repo layout via a sibling-directory probe: point the command at a
    // fixtures dir that has ../default and ../examples.
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let probe = repo_root.join("target/fixture-probe");
    let _ = std::fs::remove_dir_all(&probe);
    std::fs::create_dir_all(probe.join("fixtures")).unwrap();
    std::fs::write(probe.join("fixtures/accounts.json"), r#"{"accounts": []}"#).unwrap();
    std::fs::write(
        probe.join("fixtures/jurisdictions.json"),
        r#"{"permitted": ["US"], "restricted": [], "prohibited": []}"#,
    )
    .unwrap();
    std::fs::write(
        probe.join("fixtures/tokens.json"),
        r#"{"bindings": [{
            "policy_id": "no-such-policy",
            "token": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        }]}"#,
    )
    .unwrap();
    std::fs::create_dir_all(probe.join("default")).unwrap();
    std::fs::create_dir_all(probe.join("examples")).unwrap();
    std::fs::write(probe.join("default/policy.json"), VALID_POLICY).unwrap();
    std::fs::write(probe.join("examples/example.json"), VALID_POLICY).unwrap();

    let (ok, _, stderr) = run(&[
        "fixture",
        "validate",
        probe.join("fixtures").to_str().unwrap(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("no shipped policy document"));
    let _ = std::fs::remove_dir_all(&probe);
}

#[test]
fn fixture_validate_rejects_a_corrupt_dataset() {
    // A jurisdiction code outside the universe must be flagged.
    let dir = temp_dir_with(
        "fixture-corrupt",
        &[
            (
                "accounts.json",
                r#"{"accounts": [{
                    "account": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "status": "active",
                    "jurisdiction": "ZZ",
                    "allowlisted": true,
                    "denylisted": false
                }]}"#,
            ),
            (
                "jurisdictions.json",
                r#"{"permitted": ["US"], "restricted": [], "prohibited": []}"#,
            ),
        ],
    );
    let (ok, _, stderr) = run(&["fixture", "validate", dir.to_str().unwrap()]);
    assert!(!ok);
    assert!(stderr.contains("not in jurisdictions.json"));
}

#[test]
fn registry_inspect_summarizes_each_dataset_kind() {
    let dir = repo_fixtures_dir();
    let (ok, stdout, _) = run(&[
        "registry",
        "inspect",
        dir.join("sanctions.json").to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("sanctions dataset"));
    assert!(stdout.contains("active"));
    assert!(stdout.contains("OFAC-SDN"));

    let (ok, stdout, _) = run(&[
        "registry",
        "inspect",
        dir.join("jurisdictions.json").to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("jurisdiction universe"));

    let (ok, stdout, _) = run(&[
        "registry",
        "inspect",
        dir.join("identity.json").to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("identity dataset"));
    assert!(stdout.contains("verified"));

    let (ok, stdout, _) = run(&[
        "registry",
        "inspect",
        dir.join("tokens.json").to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("token registry"));
    assert!(stdout.contains("institutional-default"));

    // A `dataset build` report summarizes entries + review items.
    let report = temp_file(
        "report.json",
        r#"{"source":"ofac","entries":[{
            "subject_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            "list_id": "OFAC-SDN",
            "status": "active",
            "dataset_version": 1,
            "effective_at": "2023-06-01T00:00:00Z",
            "source": "ofac"
        }],"review":[{
            "record": "junk|XYZ|active|2023-01-01",
            "reason": "unmapped provider list code \"XYZ\""
        }]}"#,
    );
    let (ok, stdout, _) = run(&["registry", "inspect", report.to_str().unwrap()]);
    assert!(ok);
    assert!(stdout.contains("dataset report"));
    assert!(stdout.contains("1 entries (1 active"));
    assert!(stdout.contains("1 review items"));
    assert!(stdout.contains("unmapped provider list code"));
}

#[test]
fn dataset_build_normalizes_a_snapshot_and_reports_review_items() {
    let snapshot = temp_file("snapshot.txt", SNAPSHOT);
    let report = temp_file("report.json", "");
    let (ok, stdout, stderr) = run(&[
        "dataset",
        "build",
        snapshot.to_str().unwrap(),
        "-o",
        report.to_str().unwrap(),
    ]);
    assert!(ok, "dataset build must succeed: {stderr}");
    assert!(stdout.contains("2 entries normalized"));
    assert!(stdout.contains("1 review items"));
    assert!(stdout.contains("unmapped provider list code"));

    let written = fs::read_to_string(&report).expect("report written");
    let value: serde_json::Value = serde_json::from_str(&written).expect("report is JSON");
    assert_eq!(value["source"], "ofac");
    assert_eq!(value["entries"].as_array().expect("entries array").len(), 2);
    assert_eq!(value["review"].as_array().expect("review array").len(), 1);
}

#[test]
fn registry_inspect_rejects_unknown_shapes() {
    let dir = temp_dir_with("registry-junk", &[("junk.json", "{\"nope\": true}")]);
    let (ok, _, stderr) = run(&[
        "registry",
        "inspect",
        dir.join("junk.json").to_str().unwrap(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("unrecognized dataset shape"));
}

#[test]
fn policy_test_reports_the_expected_decisions() {
    let dir = repo_fixtures_dir();
    let policy = temp_file("combined.json", VALID_POLICY);
    let (ok, stdout, _) = run(&[
        "policy",
        "test",
        policy.to_str().unwrap(),
        "--fixtures-dir",
        dir.to_str().unwrap(),
    ]);
    assert!(ok);
    assert!(stdout.contains("summary:"));
    assert!(stdout.contains("APPROVE"));
    assert!(stdout.contains("BLOCK"));

    // Strict mode turns the blocked subjects into a non-zero exit.
    let (strict_ok, _, stderr) = run(&[
        "policy",
        "test",
        policy.to_str().unwrap(),
        "--fixtures-dir",
        dir.to_str().unwrap(),
        "--strict",
    ]);
    assert!(!strict_ok);
    assert!(stderr.contains("evaluated to BLOCK"));
}

/// Create a temporary fixtures dir containing the given files.
fn temp_dir_with(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("safeguard-cli-test-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    for (file, content) in files {
        fs::write(dir.join(file), content).expect("write temp fixture");
    }
    dir
}

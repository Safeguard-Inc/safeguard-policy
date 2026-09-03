#!/usr/bin/env python3
"""Automated test battery for the policy schemas and reference policies.

Runs the checks CI depends on:

1. Every schema file validates against the JSON Schema 2020-12 meta-schema.
2. The rule definition in policy.schema.json is byte-identical to the one in
   rule.schema.json (parity, so the two copies cannot drift).
3. Every reference policy (policies/default and policies/examples) validates.
4. Negative cases: documents that must be rejected are rejected — this keeps
   the validator honest and prevents the schema from silently accepting junk.
5. Jurisdiction rule configs validate standalone against
   jurisdiction.schema.json, and the embedded config shape matches.

Exits non-zero on any failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

# Ensure sibling modules are importable even with PYTHONSAFEPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "policy-schema"
POLICIES_DIR = REPO_ROOT / "policies"

SCHEMA_FILES = [
    "policy.schema.json",
    "rule.schema.json",
    "decision.schema.json",
    "jurisdiction.schema.json",
    "sanctions.schema.json",
]

failures: list[str] = []
checks = 0


def check(condition: bool, label: str) -> None:
    global checks
    checks += 1
    if not condition:
        failures.append(label)


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def base_policy(rules: list[dict]) -> dict:
    return {
        "policy_id": "test-policy",
        "version": 1,
        "rules": rules,
    }


def main() -> int:
    # 1. Schemas are valid against the meta-schema.
    for name in SCHEMA_FILES:
        schema = load(SCHEMA_DIR / name)
        try:
            Draft202012Validator.check_schema(schema)
            check(True, f"meta-schema: {name}")
        except Exception as exc:  # noqa: BLE001 - report any schema error
            check(False, f"meta-schema: {name}: {exc}")

    # 2. Rule definition parity between policy.schema.json and rule.schema.json.
    policy_schema = load(SCHEMA_DIR / "policy.schema.json")
    rule_schema = load(SCHEMA_DIR / "rule.schema.json")
    check(
        policy_schema["$defs"]["rule"] == rule_schema["$defs"]["rule"],
        "parity: $defs.rule identical in policy.schema.json and rule.schema.json",
    )

    # 3. Every reference policy validates.
    policy_paths = sorted((POLICIES_DIR / "default").glob("*.json")) + sorted(
        (POLICIES_DIR / "examples").glob("*.json")
    )
    for path in policy_paths:
        problems = validate_policy.validate_policy_document(load(path))
        check(not problems, f"reference policy {path.name}: {'; '.join(problems)}")

    # 4. Negative cases: each must be rejected by schema or invariants.
    negative_cases: list[tuple[str, dict]] = [
        (
            "duplicate rule ids",
            base_policy(
                [
                    {"id": "A-1", "type": "allowlist", "action": "block"},
                    {"id": "A-1", "type": "denylist", "action": "block"},
                ]
            ),
        ),
        (
            "two rules of the same type",
            base_policy(
                [
                    {"id": "A-1", "type": "allowlist", "action": "block"},
                    {"id": "A-2", "type": "allowlist", "action": "flag"},
                ]
            ),
        ),
        (
            "rule id longer than 32 bytes",
            base_policy(
                [{"id": "X" * 33, "type": "allowlist", "action": "block"}]
            ),
        ),
        (
            "non-ascii rule id",
            base_policy([{"id": "h\u00e9llo-001", "type": "allowlist", "action": "block"}]),
        ),
        (
            "unknown rule type",
            base_policy([{"id": "KYC-001", "type": "kyc", "action": "block"}]),
        ),
        (
            "unknown action",
            base_policy([{"id": "A-1", "type": "allowlist", "action": "review"}]),
        ),
        (
            "jurisdiction rule without regions",
            base_policy([{"id": "J-1", "type": "jurisdiction", "action": "flag"}]),
        ),
        (
            "regions on a non-jurisdiction rule",
            base_policy(
                [
                    {
                        "id": "A-1",
                        "type": "allowlist",
                        "action": "block",
                        "regions": {
                            "permitted": ["US"],
                            "restricted": [],
                            "prohibited": [],
                        },
                    }
                ]
            ),
        ),
        (
            "version zero",
            {"policy_id": "p", "version": 0, "rules": []},
        ),
        (
            "empty rules array",
            base_policy([]),
        ),
        (
            "lowercase region code",
            base_policy(
                [
                    {
                        "id": "J-1",
                        "type": "jurisdiction",
                        "action": "flag",
                        "regions": {
                            "permitted": ["us"],
                            "restricted": [],
                            "prohibited": [],
                        },
                    }
                ]
            ),
        ),
        (
            "missing policy_id",
            {"version": 1, "rules": [{"id": "A-1", "type": "allowlist", "action": "block"}]},
        ),
    ]
    for label, document in negative_cases:
        problems = validate_policy.validate_policy_document(document)
        check(bool(problems), f"negative: {label} must be rejected (got no problems)")

    # 5. Standalone jurisdiction config validation.
    jurisdiction_schema = load(SCHEMA_DIR / "jurisdiction.schema.json")
    validator = Draft202012Validator(jurisdiction_schema)
    good_config = {
        "action": "flag",
        "regions": {"permitted": ["US"], "restricted": [], "prohibited": ["IR"]},
    }
    check(
        validator.is_valid(good_config),
        "jurisdiction: a well-formed config validates",
    )
    check(
        not validator.is_valid({"regions": {"permitted": [], "restricted": [], "prohibited": []}}),
        "jurisdiction: missing action is rejected",
    )

    if failures:
        print(f"FAIL: {len(failures)} of {checks} checks failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"OK: all {checks} schema checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
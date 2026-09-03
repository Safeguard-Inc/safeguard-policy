#!/usr/bin/env python3
"""Check that policy fixtures and reference policies stay consistent.

Enforces the rules documented in policies/fixtures/README.md:

1. Account fixtures are well-formed (Stellar-style G addresses), use known
   AccountStatus labels, and carry a jurisdiction that exists in
   jurisdictions.json (or the reserved ``XX`` unknown sentinel).
2. Sanctions fixtures validate against the normalized sanctions schema.
3. Every policy in policies/default and policies/examples validates
   (policy.schema.json + invariants via validate_policy.py).
4. Every region code in a policy's jurisdiction rule exists in
   jurisdictions.json, so example policies and the region universe cannot
   drift apart.

Exits non-zero on any inconsistency.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

# Ensure sibling modules are importable even when the interpreter runs with
# PYTHONSAFEPATH (script dir not on sys.path).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICIES_DIR = REPO_ROOT / "policies"
FIXTURES_DIR = POLICIES_DIR / "fixtures"

# Well-formed Stellar-style account: G followed by 55 base-32 chars.
ACCOUNT_RE = re.compile(r"^G[A-Z2-7]{55}$")
# Core AccountStatus labels (safeguard_core::rules::account_status).
ACCOUNT_STATUSES = {"active", "restricted", "frozen", "suspended", "unknown"}
# Reserved sentinel for an unknown jurisdiction (RegionStatus::Unknown).
UNKNOWN_JURISDICTION = "XX"
REGION_LISTS = ("permitted", "restricted", "prohibited")


def load_json(path: Path) -> dict | list:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    problems: list[str] = []

    jurisdictions = load_json(FIXTURES_DIR / "jurisdictions.json")
    universe: set[str] = set()
    for key in REGION_LISTS:
        universe.update(jurisdictions.get(key, []))

    # ---- account fixtures -------------------------------------------------
    accounts = load_json(FIXTURES_DIR / "accounts.json")["accounts"]
    for account in accounts:
        address = account["account"]
        if not ACCOUNT_RE.match(address):
            problems.append(f"accounts: {address!r} is not a well-formed G address")
        if account["status"] not in ACCOUNT_STATUSES:
            problems.append(f"accounts: {address!r} has unknown status {account['status']!r}")
        jurisdiction = account["jurisdiction"]
        if jurisdiction != UNKNOWN_JURISDICTION and jurisdiction not in universe:
            problems.append(
                f"accounts: {address!r} jurisdiction {jurisdiction!r} not in jurisdictions.json"
            )
        for flag in ("allowlisted", "denylisted"):
            if not isinstance(account.get(flag), bool):
                problems.append(f"accounts: {address!r} {flag} must be a boolean")

    # ---- sanctions fixtures ----------------------------------------------
    sanctions_schema = validate_policy.load_schema("sanctions.schema.json")
    validator = Draft202012Validator(sanctions_schema)
    for entry in load_json(FIXTURES_DIR / "sanctions.json"):
        for error in validator.iter_errors(entry):
            problems.append(
                f"sanctions: {'/'.join(str(p) for p in error.path) or '<entry>'}: {error.message}"
            )

    # ---- reference policies ----------------------------------------------
    for directory in ("default", "examples"):
        for path in sorted((POLICIES_DIR / directory).glob("*.json")):
            document = load_json(path)
            for problem in validate_policy.validate_policy_document(document):
                problems.append(f"{path.name}: {problem}")
            for rule in document.get("rules", []):
                if rule.get("type") != "jurisdiction":
                    continue
                for key in REGION_LISTS:
                    for code in rule["regions"].get(key, []):
                        if code not in universe:
                            problems.append(
                                f"{path.name}: region {code!r} ({key}) not in jurisdictions.json"
                            )

    if problems:
        print(f"FAIL: {len(problems)} problem(s) found")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("OK: fixtures and reference policies are consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""Validate policy documents against the Safeguard policy schema.

Checks both layers:

1. JSON Schema conformance (policy.schema.json, draft 2020-12), including the
   conditional rule constraints (jurisdiction rules must carry regions,
   non-jurisdiction rules must not).
2. Cross-item invariants that JSON Schema cannot express: unique rule ids and
   at most one rule per type (the engine evaluates at most one rule per
   category in fixed precedence order).

Jurisdiction rules are additionally validated against the standalone
jurisdiction.schema.json so the embedded config cannot drift from the
published shape.

Usage:
    python3 scripts/validate_policy.py policy1.json [policy2.json ...]

Exits non-zero if any document is invalid. Can also be imported; use
`validate_policy_document(doc) -> list[str]`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "policy-schema"

_SCHEMA_CACHE: dict[str, dict] = {}


def load_schema(name: str) -> dict:
    if name not in _SCHEMA_CACHE:
        with (SCHEMA_DIR / name).open(encoding="utf-8") as handle:
            _SCHEMA_CACHE[name] = json.load(handle)
    return _SCHEMA_CACHE[name]


def _schema_problems(schema: dict, document: dict, prefix: str) -> list[str]:
    problems: list[str] = []
    validator = Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(document), key=lambda e: list(e.path)):
        location = ".".join(str(part) for part in error.path) or "<root>"
        problems.append(f"{prefix} {location}: {error.message}")
    return problems


def validate_policy_document(document: dict) -> list[str]:
    """Return human-readable problems for a policy document (empty = valid)."""
    problems = _schema_problems(load_schema("policy.schema.json"), document, "schema")

    rules = [r for r in document.get("rules", []) if isinstance(r, dict)]

    ids = [r.get("id") for r in rules]
    if len(ids) != len(set(ids)):
        problems.append("invariant <rules>: rule ids must be unique within a policy")

    types = [r.get("type") for r in rules]
    if len(types) != len(set(types)):
        problems.append("invariant <rules>: at most one rule per type")

    for rule in rules:
        if rule.get("type") == "jurisdiction" and "regions" in rule:
            config = {"action": rule.get("action"), "regions": rule["regions"]}
            problems.extend(
                _schema_problems(
                    load_schema("jurisdiction.schema.json"),
                    config,
                    f"jurisdiction rule {rule.get('id')!r}:",
                )
            )

    return problems


def validate_file(path: Path) -> bool:
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL {path}: could not parse: {exc}")
        return False

    problems = validate_policy_document(document)
    if problems:
        print(f"FAIL {path}")
        for problem in problems:
            print(f"  - {problem}")
        return False
    print(f"OK   {path}")
    return True


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="policy JSON documents")
    args = parser.parse_args(argv)

    ok = all(validate_file(path) for path in args.paths)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
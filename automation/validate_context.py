#!/usr/bin/env python3
"""Validate the context files against the schema and for referential integrity.

Gate for PR1. Fails if:
  - the merged context does not match schemas/context.schema.json
  - an expected_admin_path references a host absent from asset_tiers
  - an approved_change references an identity absent from identity_roles
  - known_reachability references a host absent from asset_tiers

Silent defaulting is the bug this guards against: unknown identities/hosts should
surface as gaps, not be waved through.
"""
from __future__ import annotations

import json
import pathlib
import sys
import datetime as dt

import yaml

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
CTX = ROOT / "automation" / "context"
SCHEMA = ROOT / "schemas" / "context.schema.json"


def load_context() -> dict:
    def _load(name):
        with (CTX / name).open(encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {
        "asset_tiers": _load("asset_tiers.yml"),
        "identity_roles": _load("identity_roles.yml"),
        "expected_admin_paths": _load("expected_admin_paths.yml"),
        "approved_changes": _load("approved_changes.yml"),
        "known_reachability": _load("known_reachability.yml"),
    }


def main() -> int:
    ctx = load_context()
    errors: list[str] = []

    if jsonschema is not None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        try:
            jsonschema.validate(ctx, schema)
        except jsonschema.ValidationError as e:
            errors.append(f"schema: {e.message}")
    else:
        errors.append("jsonschema not installed; structural validation skipped")

    hosts = set(ctx["asset_tiers"].get("hosts", {}))
    identities = set(ctx["identity_roles"].get("identities", {}))

    for p in ctx["expected_admin_paths"].get("approved_paths", []):
        if p.get("via") not in hosts:
            errors.append(f"expected_admin_paths: host '{p.get('via')}' not in asset_tiers")
        if p.get("identity") not in identities:
            errors.append(f"expected_admin_paths: identity '{p.get('identity')}' not in identity_roles")

    policy_metadata = ctx["expected_admin_paths"].get("policy_metadata") or {}
    policy_dates = {}
    for key in ("valid_from", "valid_until"):
        try:
            policy_dates[key] = dt.date.fromisoformat(str(policy_metadata.get(key)))
        except ValueError:
            errors.append(f"expected_admin_paths: {key}={policy_metadata.get(key)!r} is not an ISO date")
    if (policy_dates.get("valid_from") and policy_dates.get("valid_until")
            and policy_dates["valid_from"] > policy_dates["valid_until"]):
        errors.append("expected_admin_paths: valid_from must not be after valid_until")
    for scope in policy_metadata.get("complete_for", []):
        if scope.get("identity") not in identities:
            errors.append(f"expected_admin_paths.complete_for: identity '{scope.get('identity')}' not in identity_roles")
        if not isinstance(scope.get("environment"), str) or not scope.get("environment"):
            errors.append("expected_admin_paths.complete_for: environment must be a non-empty string")
        if not isinstance(scope.get("target_tier"), int):
            errors.append("expected_admin_paths.complete_for: target_tier must be an integer")

    for c in ctx["approved_changes"].get("approved_changes", []):
        if c.get("identity") not in identities:
            errors.append(f"approved_changes: identity '{c.get('identity')}' not in identity_roles")
        if c.get("target_host") not in hosts:
            errors.append(f"approved_changes: host '{c.get('target_host')}' not in asset_tiers")
        # approval date/type validation
        for k in ("approved_from", "approved_until"):
            if k in c:
                try:
                    dt.date.fromisoformat(str(c[k]))
                except ValueError:
                    errors.append(f"approved_changes: {k}={c[k]!r} is not an ISO date")
        for k in ("via", "service", "ticket"):
            if k in c and not isinstance(c[k], str):
                errors.append(f"approved_changes: {k} must be a string, got {type(c[k]).__name__}")

    for ident, targets in ctx["known_reachability"].get("known_edges", {}).items():
        if ident not in identities:
            errors.append(f"known_reachability: identity '{ident}' not in identity_roles")
        for h in targets:
            if h not in hosts:
                errors.append(f"known_reachability: host '{h}' not in asset_tiers")

    if errors:
        print("[FAIL] context validation")
        for e in errors:
            print(f"       - {e}")
        return 1
    print("[ OK ] context: schema + referential integrity")
    return 0


if __name__ == "__main__":
    sys.exit(main())

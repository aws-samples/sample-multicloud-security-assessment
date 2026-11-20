#!/usr/bin/env python3
"""Verify ProwlerAdditionsPolicy covers upstream Prowler's additional permissions.

Prowler publishes the extra read-only permissions its AWS checks need (on top of
the SecurityAudit and ViewOnlyAccess managed policies) in
permissions/prowler-additions-policy.json, tagged per release. This script:

1. Reads the pinned ProwlerVersion default from the AWS scanner template.
2. Fetches the upstream additions policy at that exact release tag (or reads a
   local copy with --upstream-file).
3. Checks that ProwlerAdditionsPolicy in every AWS template grants every
   upstream action/resource pair, honoring IAM wildcards.
4. Checks that the policy copies in the templates are identical, that the
   required AWS managed policies are still attached, and that every documented
   exception is still needed.

Exit status is 0 when everything is covered, 1 on a coverage or consistency
failure, and 2 on a usage or fetch error. The script never edits templates:
IAM changes always go through human review.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNER_TEMPLATE = REPO_ROOT / "aws" / "2-codebuild-prowler-aws.yaml"
POLICY_TEMPLATES = (
    REPO_ROOT / "aws" / "1-member-roles-aws.yaml",
    REPO_ROOT / "aws" / "2-codebuild-prowler-aws.yaml",
)
EXCEPTIONS_FILE = REPO_ROOT / "aws" / "prowler-permissions-exceptions.json"
POLICY_RESOURCE = "ProwlerAdditionsPolicy"
REQUIRED_MANAGED_POLICIES = ("policy/SecurityAudit", "policy/job-function/ViewOnlyAccess")
UPSTREAM_URL = (
    "https://raw.githubusercontent.com/prowler-cloud/prowler/"
    "{version}/permissions/prowler-additions-policy.json"
)
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that keeps CloudFormation short-form intrinsics as {tag: value}."""


def _construct_intrinsic(loader: CfnLoader, tag_suffix: str, node: yaml.Node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {"!" + tag_suffix: value}


CfnLoader.add_multi_constructor("!", _construct_intrinsic)


def load_template(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=CfnLoader)  # noqa: S506  # nosec B506 - SafeLoader subclass


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def resource_to_pattern(value) -> str:
    """Render a template Resource as a comparable ARN pattern.

    ${AWS::Partition} and other pseudo parameters/references become '*' so a
    template ARN can be compared with upstream's partition-agnostic 'arn:*:'.
    """
    if isinstance(value, dict) and len(value) == 1:
        (tag, inner), = value.items()
        if tag in ("!Sub", "Fn::Sub"):
            text = inner[0] if isinstance(inner, list) else inner
            return re.sub(r"\$\{[^}]+\}", "*", str(text))
        raise ValueError(f"Unsupported intrinsic in Resource: {value!r}")
    return str(value)


def normalize_upstream_resource(resource: str) -> str:
    # Upstream uses 'arn:*:' for the partition; the template uses
    # ${AWS::Partition}, which renders as '*' too. Keep both consistent.
    return re.sub(r"^arn:aws[a-z-]*:", "arn:*:", resource)


@dataclass(frozen=True)
class Grant:
    action: str  # IAM action or action pattern, lower-cased
    resource: str  # ARN or ARN pattern
    conditional: bool = False


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def statement_grants(statements: list, *, template: bool) -> list[Grant]:
    grants = []
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        if "NotAction" in statement or "NotResource" in statement:
            raise ValueError("NotAction/NotResource statements are not supported")
        resources = as_list(statement.get("Resource"))
        rendered = [
            resource_to_pattern(r) if template else normalize_upstream_resource(str(r))
            for r in resources
        ]
        conditional = bool(statement.get("Condition"))
        for action in as_list(statement.get("Action")):
            for resource in rendered:
                grants.append(Grant(str(action).lower(), resource, conditional))
    return grants


def policy_statements(template: dict, path: Path) -> list:
    resource = template.get("Resources", {}).get(POLICY_RESOURCE)
    if not resource:
        raise ValueError(f"{path.name}: resource {POLICY_RESOURCE} not found")
    return as_list(resource["Properties"]["PolicyDocument"]["Statement"])


def grant_covers(local: Grant, needed: Grant) -> bool:
    # A Condition narrows the grant, so it never fully covers an
    # unconditional upstream permission; document it as an exception instead.
    if local.conditional and not needed.conditional:
        return False
    # IAM action names are case-insensitive; ARNs are matched case-sensitively.
    return fnmatch.fnmatchcase(needed.action, local.action) and fnmatch.fnmatchcase(
        needed.resource, local.resource
    )


def find_gaps(local: list[Grant], upstream: list[Grant]) -> list[Grant]:
    return [need for need in upstream if not any(grant_covers(g, need) for g in local)]


def canonical_policy(statements: list) -> str:
    """Order-insensitive representation used to detect drift between copies."""
    normalized = []
    for statement in statements:
        item = dict(statement)
        item["Action"] = sorted(str(a).lower() for a in as_list(item.get("Action")))
        item["Resource"] = sorted(resource_to_pattern(r) for r in as_list(item.get("Resource")))
        normalized.append(json.dumps(item, sort_keys=True, default=str))
    return json.dumps(sorted(normalized))


def prowler_version(template: dict) -> str:
    version = str(template["Parameters"]["ProwlerVersion"]["Default"])
    if not VERSION_RE.match(version):
        raise ValueError(
            f"ProwlerVersion default must be a pinned X.Y.Z release to verify permissions, got {version!r}"
        )
    return version


def fetch_upstream(version: str, timeout: int = 30) -> bytes:
    url = UPSTREAM_URL.format(version=version)
    request = urllib.request.Request(url, headers={"User-Agent": "prowler-permissions-check"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310 - fixed https URL
        return response.read()


def load_exceptions(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    exceptions = {}
    for entry in data.get("exceptions", []):
        action = str(entry["action"]).lower()
        reason = str(entry.get("reason", "")).strip()
        if not reason:
            raise ValueError(f"Exception for {action} in {path.name} needs a reason")
        exceptions[action] = reason
    return exceptions


def suggestion_lines(gaps: list[Grant], display: dict[str, str]) -> list[str]:
    lines = []
    star = sorted({display.get(g.action, g.action) for g in gaps if g.resource == "*"})
    scoped = sorted({(display.get(g.action, g.action), g.resource) for g in gaps if g.resource != "*"})
    if star:
        lines.append("Add to the Resource: \"*\" statement of ProwlerAdditionsPolicy in both templates:")
        lines += [f"              - {a}" for a in star]
    if scoped:
        lines.append("Add these resource-scoped grants (use !Sub arn:${AWS::Partition}:...):")
        lines += [f"  {a} on {r}" for a, r in scoped]
    return lines


def check(
    upstream_policy: dict,
    templates: dict[Path, dict],
    exceptions: dict[str, str],
) -> Report:
    report = Report()
    upstream = statement_grants(as_list(upstream_policy.get("Statement")), template=False)
    upstream_actions = {g.action for g in upstream}
    display = {
        str(a).lower(): str(a)
        for statement in as_list(upstream_policy.get("Statement"))
        for a in as_list(statement.get("Action"))
    }
    all_gaps: set[Grant] = set()

    canonical: dict[str, list[str]] = {}
    for path, template in templates.items():
        statements = policy_statements(template, path)
        canonical.setdefault(canonical_policy(statements), []).append(path.name)

        local = statement_grants(statements, template=True)
        gaps = [g for g in find_gaps(local, upstream) if g.action not in exceptions]
        if gaps:
            report.errors.append(
                f"{path.name}: {POLICY_RESOURCE} is missing {len(gaps)} upstream permission(s):\n"
                + "\n".join(f"  - {g.action} on {g.resource}" for g in gaps)
            )
            all_gaps.update(gaps)

        extras = sorted(
            {
                g.action
                for g in local
                if not any(fnmatch.fnmatchcase(u, g.action) for u in upstream_actions)
            }
        )
        if extras:
            report.notes.append(f"{path.name}: actions not in upstream (allowed): {', '.join(extras)}")

        role_policies = []
        for resource in template.get("Resources", {}).values():
            props = resource.get("Properties") or {}
            if resource.get("Type") == "AWS::IAM::Role" and props.get("RoleName") == "ProwlerMemberRole":
                role_policies = [resource_to_pattern(p) for p in as_list(props.get("ManagedPolicyArns"))]
        for required in REQUIRED_MANAGED_POLICIES:
            if not any(p.endswith(":iam::aws:" + required) for p in role_policies):
                report.errors.append(f"{path.name}: ProwlerMemberRole no longer attaches {required}")

    if all_gaps:
        report.notes.extend(suggestion_lines(sorted(all_gaps, key=lambda g: (g.action, g.resource)), display))

    if len(canonical) > 1:
        report.errors.append(
            f"{POLICY_RESOURCE} differs between templates; keep the copies identical: "
            + " vs ".join(", ".join(names) for names in canonical.values())
        )

    # Every exception must still matter: the action exists upstream and at
    # least one template would otherwise have a gap for it.
    for action in sorted(exceptions):
        if action not in upstream_actions:
            report.errors.append(f"Stale exception: {action} is no longer in the upstream policy")
            continue
        needed = [g for g in upstream if g.action == action]
        still_needed = any(
            find_gaps(statement_grants(policy_statements(t, p), template=True), needed)
            for p, t in templates.items()
        )
        if not still_needed:
            report.errors.append(f"Stale exception: {action} is fully granted; remove the exception")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", help="Prowler release to compare against (default: template ProwlerVersion)")
    parser.add_argument("--upstream-file", type=Path, help="Use a local copy of prowler-additions-policy.json")
    parser.add_argument("--exceptions-file", type=Path, default=EXCEPTIONS_FILE)
    args = parser.parse_args(argv)

    try:
        templates = {path: load_template(path) for path in POLICY_TEMPLATES}
        version = args.version or prowler_version(load_template(SCANNER_TEMPLATE))
        if args.upstream_file:
            raw = args.upstream_file.read_bytes()
            source = str(args.upstream_file)
        else:
            raw = fetch_upstream(version)
            source = UPSTREAM_URL.format(version=version)
        upstream_policy = json.loads(raw)
        exceptions = load_exceptions(args.exceptions_file)
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Prowler version: {version}")
    print(f"Upstream policy: {source} (sha256 {hashlib.sha256(raw).hexdigest()})")
    try:
        report = check(upstream_policy, templates, exceptions)
    except (ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    for note in report.notes:
        print(note)
    for error in report.errors:
        print(f"FAIL: {error}", file=sys.stderr)
    if report.ok:
        print(f"OK: {POLICY_RESOURCE} covers every upstream permission for Prowler {version}.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

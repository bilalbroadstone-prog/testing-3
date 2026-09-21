#!/usr/bin/env python3
"""
make_test_packet.py
-------------------
Generate a realistic AIBOM scan packet for end-to-end testing, without waiting
on CloudApps or RabbitMQ.

    python3 make_test_packet.py --out test-packet.json
    python3 run.py --file test-packet.json

Why this exists: the consumer reads vulnerabilities that are already embedded in
the CycloneDX report. If a report carries none, main_aibom() falls through to
its legacy branch and shells out to `grype`, which is not installed here (and
which the README says this service must not need) - so the run dies with
FileNotFoundError before anything reaches {ns}.ai_discovery.

Every vulnerability produced here therefore carries `_source: "grype"` and an
`affects[0].ref` pointing at a component that really exists in the same
document, which is what extract_embedded_package_vulns() looks for. The packet
takes the designed path and never touches the grype binary.

Standard library only. Deterministic for a given --seed.
"""

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timezone

# ── vocabulary the consumer accepts ──────────────────────────────────────────
# processing.py discards a packet whose source identity is blank or normalizes
# to "all", and ai_discovery.ASSETS is the closed set of assets.
ASSETS = ("aws", "azure", "gcp", "github", "manual")

# Real library names, so the generated inventory reads like a genuine scan.
PY_PACKAGES = [
    "aiohttp", "requests", "urllib3", "jinja2", "pyyaml", "cryptography",
    "pillow", "numpy", "pandas", "flask", "django", "sqlalchemy", "boto3",
    "certifi", "setuptools", "werkzeug", "lxml", "paramiko", "redis", "celery",
]
JS_PACKAGES = [
    "lodash", "axios", "express", "minimist", "node-fetch", "semver",
    "webpack", "moment", "handlebars", "tar",
]

# AI components, discovered by the AIBOM side of the scanner rather than syft.
# These drive the models / inventory sections of the discovery report.
AI_COMPONENTS = [
    ("gpt-4o",                  "model",      "OpenAI GPT-4o inference endpoint"),
    ("claude-3-5-sonnet",       "model",      "Anthropic Claude 3.5 Sonnet endpoint"),
    ("text-embedding-3-large",  "model",      "OpenAI embedding model"),
    ("langchain-agent-runner",  "agent",      "LangChain tool-calling agent"),
    ("support-triage-agent",    "agent",      "Internal ticket triage agent"),
    ("filesystem-mcp",          "mcp_server", "Filesystem MCP server"),
    ("github-mcp",              "mcp_server", "GitHub MCP server"),
    ("ide-mcp-client",          "mcp_client", "IDE-side MCP client"),
]

# severity -> inclusive CVSS band, so score and severity never disagree.
SEVERITY_BANDS = {
    "critical": (9.0, 10.0),
    "high":     (7.0, 8.9),
    "medium":   (4.0, 6.9),
    "low":      (0.1, 3.9),
}

CVSS_VECTORS = [
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
]

VULN_BLURBS = [
    "Improper input validation allows a remote attacker to cause a denial of service.",
    "A crafted request can bypass the authentication check in the request handler.",
    "Unbounded memory allocation when parsing untrusted input leads to resource exhaustion.",
    "Path traversal in the archive extraction routine permits writing outside the target directory.",
    "Incorrect certificate validation allows man-in-the-middle attackers to spoof endpoints.",
    "A deserialization flaw permits arbitrary code execution when loading untrusted data.",
]


def _hex_id(rnd, length=16):
    """syft-style package-id suffix."""
    return "".join(rnd.choice("0123456789abcdef") for _ in range(length))


def _version(rnd):
    return f"{rnd.randint(0, 9)}.{rnd.randint(0, 20)}.{rnd.randint(0, 9)}"


def build_components(rnd, count):
    """Library components (syft/sbom side) plus AI components (aibom side).

    Returns (components, library_refs). Only the library refs are handed to the
    vulnerability builder - a CVE hanging off an AI agent would not look like a
    real Grype finding.
    """
    components = []
    library_refs = []

    pool = [("pypi", n, "python") for n in PY_PACKAGES] + \
           [("npm", n, "javascript") for n in JS_PACKAGES]
    rnd.shuffle(pool)

    for ecosystem, name, language in pool[:count]:
        version = _version(rnd)
        purl = f"pkg:{ecosystem}/{name}@{version}"
        # bom-ref carries the package-id suffix; purl does not. Matches the
        # shape of a real captured packet (see aws-packet.json).
        bom_ref = f"{purl}?package-id={_hex_id(rnd)}"
        components.append({
            "_source": "sbom",
            "bom-ref": bom_ref,
            "name": name,
            "purl": purl,
            "type": "library",
            "version": version,
            "properties": [
                {"name": "syft:package:foundBy", "value": f"{language}-installed-package-cataloger"},
                {"name": "syft:package:language", "value": language},
                {"name": "syft:package:type", "value": ecosystem},
                {"name": "syft:cpe23", "value": f"cpe:2.3:a:{name}:{name}:{version}:*:*:*:*:*:*:*"},
            ],
        })
        library_refs.append(bom_ref)

    # AI components - grouped via the cisco-aibom:type property.
    for name, subtype, description in AI_COMPONENTS:
        components.append({
            "_source": "aibom",
            "bom-ref": f"aibom:{subtype}:{name}",
            "name": name,
            "type": "application",
            "description": description,
            "properties": [
                {"name": "cisco-aibom:type", "value": subtype},
                {"name": "cisco-aibom:discovered-by", "value": "static-analysis"},
            ],
        })

    return components, library_refs


def build_vulnerabilities(rnd, library_refs, count):
    """Grype-shaped findings embedded directly in the report.

    `_source` and `affects[0].ref` are the two fields the consumer keys on -
    see the module docstring.
    """
    vulns = []
    severities = list(SEVERITY_BANDS)

    for i in range(count):
        ref = rnd.choice(library_refs)
        severity = severities[i % len(severities)]  # even spread across bands
        low, high = SEVERITY_BANDS[severity]
        score = round(rnd.uniform(low, high), 1)

        if rnd.random() < 0.5:
            vuln_id = f"CVE-{rnd.randint(2021, 2025)}-{rnd.randint(1000, 99999)}"
        else:
            block = lambda: "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(4))
            vuln_id = f"GHSA-{block()}-{block()}-{block()}"

        vulns.append({
            "_source": "grype",
            "id": vuln_id,
            "bom-ref": f"urn:uuid:{uuid.UUID(int=rnd.getrandbits(128), version=4)}",
            "affects": [{"ref": ref}],
            "ratings": [{
                "method": "CVSSv31",
                "score": score,
                "severity": severity,
                "vector": rnd.choice(CVSS_VECTORS),
            }],
            "description": rnd.choice(VULN_BLURBS),
            "source": {"name": "github", "url": f"https://github.com/advisories/{vuln_id}"},
            "references": [{
                "id": vuln_id,
                "source": {"name": "nvd", "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}"},
            }],
            "advisories": [{"url": f"https://github.com/advisories/{vuln_id}"}],
        })

    return vulns


def build_report(rnd, args, now_iso):
    components, library_refs = build_components(rnd, args.components)
    vulnerabilities = build_vulnerabilities(rnd, library_refs, args.vulns)

    root_ref = f"{args.owner}/{args.repo}"
    severity_counts = {s: 0 for s in SEVERITY_BANDS}
    for v in vulnerabilities:
        severity_counts[v["ratings"][0]["severity"]] += 1

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.UUID(int=rnd.getrandbits(128), version=4)}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": [
                {"type": "application", "author": "anchore", "name": "syft", "version": "1.18.1"},
                {"type": "application", "author": "anchore", "name": "grype", "version": "0.85.0"},
                {"type": "application", "author": "cytex", "name": "aibom-scanner", "version": "1.4.0"},
            ],
            "component": {"type": "application", "name": root_ref, "bom-ref": root_ref},
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [c["bom-ref"] for c in components]},
        ],
        "vulnerabilities": vulnerabilities,
        "compliance": {"frameworks": [], "controls": []},
        "semgrep": {"results": [], "severityCounts": {"error": 0, "warning": 0}},
        "cytexScan": {
            "repository": root_ref,
            "branch": "main",
            "commitSha": _hex_id(rnd, 40),
            "scanType": "devops",
            "trigger": "manual",
            "timestampUtc": now_iso,
            "summary": {
                "components": len(components),
                "dependencies": len(components),
                "vulnerabilities": len(vulnerabilities),
                "sastFindings": 0,
                "severityCounts": severity_counts,
                "sastSeverityCounts": {"error": 0, "warning": 0},
            },
            "toolStatus": {"syft": "ok", "grype": "ok", "aibom": "ok", "semgrep": "ok"},
        },
    }


def build_packet(rnd, args, now_iso, now_epoch):
    report = build_report(rnd, args, now_iso)

    # Report entry keys differ per asset: _repo_label() reads owner+repo for
    # github and region+repo for aws, and names the SBOM from whichever it finds.
    entry = {"repo": args.repo, "report": report}
    if args.asset == "aws":
        entry["region"] = args.region
    else:
        entry["owner"] = args.owner

    return {
        "sbom_type": "aibom",
        "sbom_name": args.sbom_name,
        "organization": args.namespace,
        "asset": args.asset,
        "account_name": args.account_name,
        "type": args.type,
        "data_source": args.data_source,
        "description": f"AIBOM report generated from {args.asset} {args.type} scan.",
        "file": {
            "account_name": args.account_name,
            "scan_time": now_epoch,
            "reports": [entry],
        },
    }


def validate(packet):
    """Fail loudly here rather than silently producing a packet the consumer
    discards, or one that falls through to the missing grype binary."""
    errors = []

    for field in ("asset", "account_name", "type", "data_source"):
        value = (packet.get(field) or "").strip()
        if not value:
            errors.append(f"{field} is empty - the consumer discards the packet")
        elif value == "all":
            errors.append(f"{field} is \"all\" - that is the rollup identity, the consumer discards it")

    if packet.get("asset") not in ASSETS:
        errors.append(f"asset {packet.get('asset')!r} is not one of {sorted(ASSETS)}")

    report = packet["file"]["reports"][0]["report"]
    components = report.get("components") or []
    vulns = report.get("vulnerabilities") or []

    if not components:
        errors.append("report has no components")
    if not vulns:
        errors.append("report has no vulnerabilities - the run would fall through to grype")

    known_refs = {c.get("bom-ref") for c in components}
    for v in vulns:
        affects = v.get("affects") or []
        ref = affects[0].get("ref") if affects else None
        if not ref:
            errors.append(f"{v.get('id')}: no affects[0].ref")
        elif ref not in known_refs:
            errors.append(f"{v.get('id')}: affects ref {ref} matches no component")

    if not any((v.get("_source") or "").lower() == "grype" for v in vulns):
        errors.append('no vulnerability has _source == "grype"')

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="Generate a test AIBOM scan packet for `run.py --file`.")
    parser.add_argument("--namespace", default="semp6", help="Mongo namespace / organization")
    parser.add_argument("--asset", default="github", choices=ASSETS)
    parser.add_argument("--account-name", default="demo-latest")
    parser.add_argument("--type", default="devops", help="Scan type, e.g. devops or logs")
    parser.add_argument("--data-source", default="cloud", help="cloud or device")
    parser.add_argument("--owner", default="bilalbroadstone", help="Repo owner (github assets)")
    parser.add_argument("--repo", default="prog_testing", help="Repository name")
    parser.add_argument("--region", default="eu-north-1", help="Region (aws assets)")
    parser.add_argument("--sbom-name", default=None, help="Defaults to <asset>-<type>-scan-TEST0001")
    parser.add_argument("--components", type=int, default=25, help="Library components to generate")
    parser.add_argument("--vulns", type=int, default=20, help="Embedded vulnerabilities to generate")
    parser.add_argument("--seed", type=int, default=1337, help="Makes output deterministic")
    parser.add_argument("--out", default="test-packet.json")
    args = parser.parse_args()

    if args.sbom_name is None:
        args.sbom_name = f"{args.asset}-{args.type}-scan-TEST0001"

    max_libs = len(PY_PACKAGES) + len(JS_PACKAGES)
    if args.components > max_libs:
        parser.error(f"--components cannot exceed {max_libs} (the library name pool)")
    if args.components < 1 or args.vulns < 1:
        parser.error("--components and --vulns must both be at least 1")

    rnd = random.Random(args.seed)
    now = datetime.now(timezone.utc)
    packet = build_packet(rnd, args, now.isoformat(timespec="seconds"), int(now.timestamp()))

    errors = validate(packet)
    if errors:
        print("✗ generated packet failed validation:", file=sys.stderr)
        for e in errors:
            print(f"    - {e}", file=sys.stderr)
        return 1

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(packet, fh, indent=2)

    report = packet["file"]["reports"][0]["report"]
    counts = report["cytexScan"]["summary"]["severityCounts"]
    ai_count = sum(1 for c in report["components"] if c["_source"] == "aibom")

    print(f"✓ wrote {args.out}")
    print(f"    namespace/asset/account   {args.namespace} / {args.asset} / {args.account_name}")
    print(f"    sbom_name                 {args.sbom_name}")
    print(f"    components                {len(report['components'])} "
          f"({args.components} library + {ai_count} AI)")
    print(f"    vulnerabilities           {len(report['vulnerabilities'])}")
    print(f"    severity                  " +
          "  ".join(f"{s}={counts[s]}" for s in ("critical", "high", "medium", "low")))
    print()
    print(f"    next:  python3 run.py --file {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

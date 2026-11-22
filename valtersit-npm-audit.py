#!/usr/bin/env python3
# Copyright 2026 Valters Capital, SIA
# Licensed under the Apache License, Version 2.0.
# ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
# Maintained by Hugo Valters

"""
ValtersIT npm Audit Scanner

Takes the output of `npm audit --json` - run here for you, or a report you
saved earlier - and submits the affected packages, with the exact versions
installed in your project, to the ValtersIT API as a scan. That puts npm's
findings in the same place as every other ValtersIT scan, enriched with CVE
ids, CVSS, EPSS and exploit data, and tracked across runs.

Input, one of:
  - default: runs `npm audit --json` in --path (default: current dir).
    Needs npm and a package-lock.json.
  - --input FILE: a saved `npm audit --json` report ("-" for stdin), so CI
    can run npm audit once and hand the result over.
Both npm 7+ reports (auditReportVersion 2) and npm 6 reports (advisories)
are understood. npm 7+ reports do not include installed versions, so they
are read from package-lock.json (--path, or --lockfile with --input).

Note that `npm audit` itself sends your dependency tree to the npm registry's
audit endpoint - that is npm's own behaviour, and the same thing happens
whenever you run it by hand. This script adds exactly one more call: the
scan submission to ValtersIT, which carries package names + versions only.

--fail-on SEVERITY makes the exit code non-zero when npm audit reports a
finding at or above that severity (low, moderate, high, critical), for
gating CI pipelines.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import valtersit_client as vit  # noqa: E402

TOOL_NAME = "npm-audit-scanner"

SEVERITY_ORDER = {"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}


def run_npm_audit(root: Path, omit_dev: bool) -> dict:
    if shutil.which("npm") is None:
        print("[!] npm not found on PATH. Install Node.js/npm, or pass a saved report with --input.",
              file=sys.stderr)
        sys.exit(2)
    cmd = ["npm", "audit", "--json"]
    if omit_dev:
        cmd.append("--omit=dev")
    try:
        # npm audit exits 1 whenever it finds anything - that is not an error.
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("[!] npm audit failed to run: {}".format(exc), file=sys.stderr)
        sys.exit(2)
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        print("[!] npm audit did not return JSON:\n{}".format((proc.stderr or proc.stdout)[:1500]), file=sys.stderr)
        sys.exit(2)
    if isinstance(report, dict) and report.get("error"):
        err = report["error"]
        print("[!] npm audit reported an error: {}".format(err.get("summary") if isinstance(err, dict) else err),
              file=sys.stderr)
        sys.exit(2)
    return report


def load_report(path: str) -> dict:
    try:
        text = sys.stdin.read() if path == "-" else Path(path).expanduser().read_text(encoding="utf-8")
        return json.loads(text)
    except (OSError, ValueError) as exc:
        print("[!] Could not read npm audit report {}: {}".format(path, exc), file=sys.stderr)
        sys.exit(2)


def load_lock_versions(lock_path: Path | None) -> dict:
    """{'node_modules/a/node_modules/b': '1.2.3', ...} from lockfile v2/v3,
    or {'b': ['1.2.3', ...]} style best-effort data from lockfile v1."""
    if lock_path is None or not lock_path.is_file():
        return {}
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return {}
    versions = {}
    if isinstance(lock.get("packages"), dict):
        for node, meta in lock["packages"].items():
            if node and isinstance(meta, dict) and meta.get("version"):
                versions[node] = meta["version"]
        return versions

    def walk(deps, prefix):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                node = "{}node_modules/{}".format(prefix, name)
                versions[node] = meta["version"]
                walk(meta.get("dependencies"), node + "/")

    walk(lock.get("dependencies"), "")
    return versions


_GHSA = re.compile(r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", re.IGNORECASE)


def parse_v2(report: dict, lock_versions: dict) -> list[dict]:
    """npm 7+ (auditReportVersion 2). One finding per (package, installed
    version); advisories come from `via` entries that are objects (string
    entries just point at another vulnerable package in the chain)."""
    findings = []
    for name, vuln in (report.get("vulnerabilities") or {}).items():
        if not isinstance(vuln, dict):
            continue
        advisories, cvss = [], None
        for via in vuln.get("via") or []:
            if isinstance(via, dict):
                m = _GHSA.search(via.get("url") or "")
                advisories.append("GHSA-" + m.group(1)[5:].lower() if m else str(via.get("source", "")))
                score = (via.get("cvss") or {}).get("score")
                if isinstance(score, (int, float)) and score > (cvss or 0):
                    cvss = score
        fix = vuln.get("fixAvailable")
        if isinstance(fix, dict):
            fix_text = "{}@{}{}".format(fix.get("name"), fix.get("version"),
                                        " (major)" if fix.get("isSemVerMajor") else "")
        else:
            fix_text = "yes" if fix else "no"
        nodes = vuln.get("nodes") or []
        installed = sorted({lock_versions[n] for n in nodes if n in lock_versions}) or ["unknown"]
        for version in installed:
            findings.append({
                "name": vuln.get("name") or name,
                "version": version,
                "severity": vuln.get("severity", "unknown"),
                "advisories": ",".join(dict.fromkeys(a for a in advisories if a)) or "(via dependency)",
                "cvss": cvss,
                "fix": fix_text,
                "direct": bool(vuln.get("isDirect")),
            })
    return findings


def parse_v1(report: dict) -> list[dict]:
    """npm 6 ("advisories" keyed by advisory id, installed versions inside findings)."""
    merged = {}
    for adv in (report.get("advisories") or {}).values():
        if not isinstance(adv, dict):
            continue
        ident = (adv.get("github_advisory_id") or ",".join(adv.get("cves") or []) or str(adv.get("id", "")))
        for finding in adv.get("findings") or []:
            key = (adv.get("module_name"), finding.get("version"))
            row = merged.setdefault(key, {
                "name": key[0], "version": key[1] or "unknown", "severity": adv.get("severity", "unknown"),
                "advisories": [], "cvss": (adv.get("cvss") or {}).get("score"),
                "fix": "patched in {}".format(adv.get("patched_versions")) if adv.get("patched_versions") else "no",
                "direct": any(">" not in p for p in finding.get("paths") or []),
            })
            row["advisories"].append(ident)
            if SEVERITY_ORDER.get(adv.get("severity"), -1) > SEVERITY_ORDER.get(row["severity"], -1):
                row["severity"] = adv.get("severity")
    for row in merged.values():
        row["advisories"] = ",".join(sorted(set(row["advisories"])))
    return list(merged.values())


def parse_report(report: dict, lock_versions: dict) -> list[dict]:
    if "vulnerabilities" in report:
        return parse_v2(report, lock_versions)
    if "advisories" in report:
        return parse_v1(report)
    print("[!] Unrecognised npm audit report format (no `vulnerabilities` or `advisories` key).",
          file=sys.stderr)
    sys.exit(2)


def build_inventory(findings: list[dict]) -> list[dict]:
    seen = set()
    inventory = []
    for f in findings:
        key = (f["name"], f["version"])
        if key in seen or f["version"] == "unknown":
            continue
        seen.add(key)
        inventory.append({"vendor": "npm", "product": f["name"], "version": f["version"], "slug": f["name"]})
    return inventory


def main():
    parser = argparse.ArgumentParser(description="ValtersIT npm audit scanner (submits npm audit findings).")
    parser.add_argument("--path", default=".", help="Project directory to run `npm audit` in (default: .).")
    parser.add_argument("--input", help="Saved `npm audit --json` report instead of running npm ('-' for stdin).")
    parser.add_argument("--lockfile", help="package-lock.json for installed versions when using --input "
                                           "(default: <path>/package-lock.json).")
    parser.add_argument("--omit-dev", action="store_true", help="Pass --omit=dev to npm audit.")
    parser.add_argument("--fail-on", choices=["low", "moderate", "high", "critical"],
                        help="Exit with status 3 if npm audit reports a finding at or above this severity.")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive prompt (requires prior confirmation).")
    parser.add_argument("--json", action="store_true", help="Also print the submitted inventory as JSON.")
    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    if args.input is None and not root.is_dir():
        print("[!] --path {} is not a directory on this host.".format(root), file=sys.stderr)
        sys.exit(2)
    lock_path = Path(args.lockfile).expanduser() if args.lockfile else root / "package-lock.json"

    if not vit.require_consent(TOOL_NAME, non_interactive=args.yes):
        sys.exit(1)

    report = load_report(args.input) if args.input else run_npm_audit(root, args.omit_dev)
    findings = parse_report(report, load_lock_versions(lock_path))
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], -1), f["name"]))

    meta = (report.get("metadata") or {}).get("vulnerabilities") or {}
    deps_total = ((report.get("metadata") or {}).get("dependencies") or {})
    deps_total = deps_total.get("total") if isinstance(deps_total, dict) else deps_total
    print("\nValtersIT npm Audit Scanner - source: {}".format(args.input or "npm audit in {}".format(root)))
    if meta:
        print("npm audit summary: {} critical, {} high, {} moderate, {} low{}".format(
            meta.get("critical", 0), meta.get("high", 0), meta.get("moderate", 0), meta.get("low", 0),
            " (of {} dependencies)".format(deps_total) if deps_total else ""))

    def short(advisories: str) -> str:
        parts = advisories.split(",")
        return parts[0] + (" +{}".format(len(parts) - 1) if len(parts) > 1 else "")

    vit.print_inventory_table(
        "NPM AUDIT FINDINGS ({})".format(len(findings)),
        [dict(f, advisories=short(f["advisories"])) for f in findings],
        [("name", "Package", 22), ("version", "Installed", 11), ("severity", "Severity", 9),
         ("advisories", "Advisory", 23), ("fix", "Fix available", 24)],
    )
    unknown = [f["name"] for f in findings if f["version"] == "unknown"]
    if unknown:
        print("[i] No installed version found for {} package(s) (e.g. {}) - pass --lockfile so they can be "
              "submitted too.\n".format(len(unknown), unknown[0]))

    inventory = build_inventory(findings)
    if args.json:
        print(json.dumps(inventory, indent=2))

    exit_code = 0
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        worst = max((SEVERITY_ORDER.get(f["severity"], -1) for f in findings), default=-1)
        if worst >= threshold:
            print("[!] npm audit reports findings at or above '{}' - failing (--fail-on).".format(args.fail_on))
            exit_code = 3

    if not inventory:
        print("[+] Nothing to submit - npm audit reported no affected packages with a known installed version.")
        sys.exit(exit_code)

    result = vit.submit_scan(inventory)
    if result["available"]:
        print("[+] Scan submitted. {} affected package(s) sent for matching.".format(len(inventory)))
        print(json.dumps(result["body"], indent=2))
    elif result.get("reason") == "no_api_key":
        vit.print_no_api_key_notice()
    else:
        print("[!] " + vit.explain_status(result["status"], result["body"]))
        sys.exit(1)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

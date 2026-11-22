# npm Audit Scanner

Send the findings of `npm audit` to the ValtersIT API — enriched with CVE
ids, CVSS, EPSS and exploit data, tracked across runs, and with an exit
code your CI can gate on. Open source, auditable, privacy-first — powered
by the ValtersIT CVE API.

> Part of the ValtersIT platform — CVE & Threat-IP data you can query or run yourself.
> Explore both API and scanners: https://www.valtersit.com/platform/
> Scanner plans & pricing: https://www.valtersit.com/cve/pricing/#scanners

## What it does

Takes the output of `npm audit --json` — run for you in a project, or a
report you saved earlier — and:

1. prints every affected package with the **exact installed version**,
   severity, GitHub advisory id and whether a fix is available;
2. submits the affected packages (name + installed version) to the
   ValtersIT API as a scan, so they show up next to your other ValtersIT
   scans with full CVE detail;
3. optionally fails the run (`--fail-on high`) for CI gating.

Both npm 7+ reports (`auditReportVersion: 2`) and npm 6 reports
(`advisories`) are understood. npm 7+ reports do not include installed
versions, so they are looked up in `package-lock.json`.

Want every dependency matched, not only what npm audit flags? Use the
[`nodejs-cve-scanner`](https://gitlab.com/valtersit/nodejs-cve-scanner)
instead — it submits the full lockfile inventory.

## Your data stays yours

- **What we receive:** the name and installed version of each package npm
  audit flagged (e.g. `minimist 0.0.8`), plus an opaque system identifier —
  a one-way hash of local machine signals (machine-id, disk UUID, CPU count)
  that cannot be reversed to any of them — so repeat scans of the same
  machine are recognised as the same system.
- **What we never receive:** your server's IP address, hostname, MAC
  address, `.npmrc` tokens, `.env` files, your source code, the npm audit
  report itself, or the contents of any file. Nothing outside of `name` +
  `version` (+ that opaque identifier) ever leaves this script.
- **About `npm audit` itself:** npm sends your dependency tree to the npm
  registry's audit endpoint whenever `npm audit` runs — by hand or through
  this script. That is npm's behaviour, not ours; use `--input` with a
  report generated elsewhere if that matters to you.
- **What it does not do:** it never runs `npm audit fix`, never installs
  or modifies packages, and never changes `package.json` or the lockfile.
- **Audit it yourself.** This is open source — two files, ~750 lines total.
  Read `valtersit-npm-audit.py` and `valtersit_client.py`; there is nothing
  else running.

## Install

Clone the repository:

```bash
git clone https://gitlab.com/valtersit/npm-audit-scanner
cd npm-audit-scanner
```

Or, one-liner (no git required):

```bash
mkdir -p npm-audit-scanner && cd npm-audit-scanner
curl -fsSLO https://gitlab.com/valtersit/npm-audit-scanner/-/raw/main/valtersit-npm-audit.py
curl -fsSLO https://gitlab.com/valtersit/npm-audit-scanner/-/raw/main/valtersit_client.py
```

Set your API key — either method works:

```bash
# Method 1: environment variable (recommended)
export VALTERSIT_API_KEY="vit_v1_your_key_here"

# Method 2: edit one line directly in valtersit_client.py
#   API_KEY = "vit_v1_your_key_here"
```

Get a key at [valtersit.com/cve/pricing](https://www.valtersit.com/cve/pricing/#scanners).

Run it:

```bash
# Run npm audit in a project and submit the findings
python3 valtersit-npm-audit.py --path /srv/my-app

# Use a report produced earlier (or by another job)
npm audit --json > audit.json
python3 valtersit-npm-audit.py --input audit.json --lockfile package-lock.json

# Pipe it straight in
npm audit --json | python3 valtersit-npm-audit.py --input - --lockfile package-lock.json
```

| Option | What it does |
|---|---|
| `--path DIR` | Project to run `npm audit` in (default: current directory) |
| `--input FILE` | Saved `npm audit --json` report instead (`-` for stdin) |
| `--lockfile FILE` | Where to read installed versions from with `--input` |
| `--omit-dev` | Production dependencies only (`npm audit --omit=dev`) |
| `--fail-on LEVEL` | Exit 3 if a finding is at or above `low`/`moderate`/`high`/`critical` |
| `--json` | Print the submitted inventory as JSON |
| `--yes` | Non-interactive (after confirming once) |

Requires a stock Python 3 interpreter (3.7+); npm is needed only when the
script runs `npm audit` for you. No `pip install`.

## Sample output

```
ValtersIT npm Audit Scanner - source: npm audit in /srv/my-app
npm audit summary: 1 critical, 5 high, 0 moderate, 3 low (of 52 dependencies)

==============================================================================
 NPM AUDIT FINDINGS (9)
==============================================================================
Package                 Installed    Severity   Advisory                 Fix available
--------------------------------------------------------------------------------------------------
minimist                0.0.8        critical   GHSA-vh95-rmgr-6w4m +1   minimist@1.2.8 (major)
body-parser             1.19.0       high       GHSA-qwcr-r2fm-qrc7 +1   yes
express                 4.17.1       high       GHSA-qw6h-vgh9-j6wx +1   yes
lodash                  4.17.15      high       GHSA-35jh-r3h4-6jhm +4   yes
...

 9 item(s) detected. No IP address, hostname, MAC address, file
 contents, or credentials were read or transmitted by this scan.
==============================================================================

[!] npm audit reports findings at or above 'high' - failing (--fail-on).
[+] Scan submitted. 9 affected package(s) sent for matching.
{
  "matched_cves": 11,
  "results": [
    {"slug": "minimist", "version": "0.0.8", "cve_id": "CVE-2021-44906", "cvss": 9.8, "patched_in": "1.2.6"},
    ...
  ]
}
```

**What to do next:** cross-reference any `cve_id` above against
`https://www.valtersit.com/cve/CVE-XXXX-XXXXX/` for the full write-up (CVSS,
EPSS, exploit availability, patch guidance). EPSS in particular helps
decide which of npm audit's many "high" findings to fix first.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Done (findings, if any, were below the `--fail-on` threshold) |
| `1` | Authorised-use not confirmed, or the ValtersIT API rejected the scan |
| `2` | npm / report / path problem — nothing was scanned |
| `3` | `--fail-on` threshold reached (the scan was still submitted) |

## Schedule it

Cron, daily at 04:45, non-interactive (requires you to have already
confirmed the authorised-use prompt once interactively):

```
45 4 * * * cd /opt/npm-audit-scanner && VALTERSIT_API_KEY=vit_v1_xxx /usr/bin/python3 valtersit-npm-audit.py --path /srv/my-app --omit-dev --yes >> /var/log/valtersit-npm-audit.log 2>&1
```

GitLab CI job:

```yaml
npm-audit:
  image: node:20
  script:
    - npm ci --ignore-scripts
    - curl -fsSLO https://gitlab.com/valtersit/npm-audit-scanner/-/raw/main/valtersit-npm-audit.py
    - curl -fsSLO https://gitlab.com/valtersit/npm-audit-scanner/-/raw/main/valtersit_client.py
    - python3 valtersit-npm-audit.py --path . --fail-on high --yes
```

Non-interactive runs (`--yes`) need a prior confirmation stored in
`VALTERSIT_STATE_DIR` (default `~/.valtersit`) — in CI, confirm once
locally and provide that `consent.json` to the job, as the
[`gitlab-ci-template`](https://gitlab.com/valtersit/gitlab-ci-template)
README describes.

## Authorised use only

Run this tool only against systems you own, or for which you have explicit
written authorisation to assess.

Before its first scan, this tool shows exactly this and requires you to type
`YES` to continue — no confirmation, no scan:

```
------------------------------------------------------------------------------
 ValtersIT Scanner — Authorised Use Confirmation
------------------------------------------------------------------------------
 Run this tool ONLY against systems you own, or for which you have explicit
 written authorisation to assess.

 This scan sends only component name + version, plus an opaque system
 identifier (a one-way hash of local machine signals such as machine-id
 and disk UUID, so repeat scans are recognised as the same system), to
 the ValtersIT API — no IP address, hostname, MAC address, or file
 contents. See the Privacy Policy: https://www.valtersit.com/privacy

 Type YES to confirm you are authorised to scan this system and continue.
 Anything else aborts without scanning.
------------------------------------------------------------------------------
```

See `valtersit_client.py` (`require_consent`) for that gate.

Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`); provided without
warranty of any kind. "ValtersIT" and the ValtersIT logo are trademarks of
Valters Capital, SIA and are not licensed for use. npm is a trademark of
npm, Inc.; this project is not affiliated with or endorsed by it.

## Questions or a bug?

Please **don't** open GitHub/GitLab issues — I don't monitor them.
Reach me through the contact form instead: https://www.valtersit.com/contacts/

Maintained by Hugo Valters

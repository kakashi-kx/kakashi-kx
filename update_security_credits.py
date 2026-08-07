#!/usr/bin/env python3
"""
Pulls live data for every GHSA ID listed in data/security_credits.json
from GitHub's public Security Advisory REST API, and rewrites the
section of README.md between:

    <!--SECURITY-CREDITS:START-->
    ...
    <!--SECURITY-CREDITS:END-->

Run manually:  python3 scripts/update_security_credits.py
Run in CI:     see .github/workflows/update-readme.yml

To add a new credit later: append its GHSA ID to
data/security_credits.json — nothing else needs editing.
"""

import json
import os
import sys
import urllib.request
import urllib.error

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDITS_FILE = os.path.join(REPO_ROOT, "data", "security_credits.json")
README_FILE = os.path.join(REPO_ROOT, "README.md")

START_MARKER = "<!--SECURITY-CREDITS:START-->"
END_MARKER = "<!--SECURITY-CREDITS:END-->"
IMPACT_START = "<!--IMPACT:START-->"
IMPACT_END = "<!--IMPACT:END-->"

SEVERITY_COLOR = {
    "critical": "8B0000",
    "high": "FF2E9A",
    "medium": "9333EA",
    "low": "6A0DAD",
}

API_BASE = "https://api.github.com/advisories/{}"
UA = "portfolio-readme-updater"


def fetch_advisory(ghsa_id: str) -> dict:
    req = urllib.request.Request(
        API_BASE.format(ghsa_id),
        headers={"Accept": "application/vnd.github+json", "User-Agent": UA},
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"warning: failed to fetch {ghsa_id}: {e}", file=sys.stderr)
        return {}


def render_row(advisory: dict, ghsa_id: str) -> str:
    if not advisory:
        return f"| `{ghsa_id}` | _fetch failed — see logs_ | | |"

    summary = advisory.get("summary", "").replace("|", "-")
    severity = (advisory.get("severity") or "unknown").lower()
    cve = advisory.get("cve_id") or "—"
    html_url = advisory.get("html_url", "#")
    package = ""
    vulns = advisory.get("vulnerabilities") or []
    if vulns:
        pkg = vulns[0].get("package") or {}
        package = pkg.get("name", "")

    color = SEVERITY_COLOR.get(severity, "555555")
    badge = (
        f"![{severity}](https://img.shields.io/badge/{severity.upper()}-{color}"
        f"?style=flat-square)"
    )

    title = f"[{summary}]({html_url})" if summary else f"[{ghsa_id}]({html_url})"
    return f"| {title} | {badge} | `{package}` | {cve} |"


def build_table(advisories: list) -> str:
    header = (
        "| Advisory | Severity | Package | CVE |\n"
        "|---|---|---|---|\n"
    )
    rows = [render_row(a, g) for a, g in advisories]
    return header + "\n".join(rows)


def build_impact_badges(advisories: list) -> str:
    total = len(advisories)
    cve_count = sum(1 for a, _ in advisories if a.get("cve_id"))
    ecosystems = sorted({
        (v.get("package") or {}).get("ecosystem", "")
        for a, _ in advisories
        for v in (a.get("vulnerabilities") or [])
        if (v.get("package") or {}).get("ecosystem")
    })
    eco_label = "%2C_".join(e for e in ecosystems) if ecosystems else "—"

    def badge(label, value, color):
        return (
            f'<img src="https://img.shields.io/badge/{label}-{value}-{color}'
            f'?style=for-the-badge&labelColor=0D0D0D" />'
        )

    return "\n".join([
        badge("Advisories_Credited", total, "9333EA"),
        badge("CVEs_Assigned", cve_count, "FF2E9A"),
        badge("Ecosystems", eco_label, "6A0DAD"),
    ])


def replace_section(content: str, start: str, end: str, body: str) -> str:
    if start not in content or end not in content:
        print(f"error: markers {start}/{end} not found in README.md", file=sys.stderr)
        return content
    pre, rest = content.split(start, 1)
    _, post = rest.split(end, 1)
    return f"{pre}{start}\n{body}\n{end}{post}"


def main() -> int:
    with open(CREDITS_FILE) as f:
        ghsa_ids = json.load(f)["ghsa_ids"]

    advisories = [(fetch_advisory(g), g) for g in ghsa_ids]

    with open(README_FILE) as f:
        content = f.read()

    new_content = replace_section(
        content, START_MARKER, END_MARKER, build_table(advisories)
    )
    new_content = replace_section(
        new_content, IMPACT_START, IMPACT_END, build_impact_badges(advisories)
    )

    if new_content != content:
        with open(README_FILE, "w") as f:
            f.write(new_content)
        print("README.md updated.")
    else:
        print("No changes.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import json
import sys
from collections import Counter
from pathlib import Path


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def semgrep(out):
    data = load(out / "semgrep.json")
    if data is None:
        return ["semgrep: no report"]
    results = data.get("results", [])
    by_rule = Counter(r["check_id"].split(".")[-1] for r in results)
    xss_pages = Counter(
        Path(r["path"]).name for r in results if Path(r["path"]).name.startswith("xss_")
    )
    lines = [f"semgrep: {len(results)} findings, {len(xss_pages)} xss_* files affected"]
    lines += [f"  {n:4}  {rule}" for rule, n in by_rule.most_common()]
    return lines


def gitleaks(out):
    data = load(out / "gitleaks.json")
    if data is None:
        return ["gitleaks: no report"]
    by_rule = Counter(f["RuleID"] for f in data)
    lines = [f"gitleaks: {len(data)} findings"]
    lines += [f"  {n:4}  {rule}" for rule, n in by_rule.most_common()]
    return lines


def trivy(out):
    data = load(out / "trivy.json")
    if data is None:
        return ["trivy: no report"]
    vulns = [v for r in data.get("Results", []) for v in r.get("Vulnerabilities") or []]
    by_sev = Counter(v["Severity"] for v in vulns)
    pkgs = len({v["PkgName"] for v in vulns})
    lines = [f"trivy: {len(vulns)} vulnerabilities in {pkgs} packages"]
    lines += [f"  {by_sev.get(s, 0):4}  {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")]
    return lines


def retire(out):
    data = load(out / "retire.json")
    if data is None:
        return ["retire: no report"]
    lines = ["retire:"]
    for entry in data.get("data", []):
        for res in entry.get("results", []):
            vulns = res.get("vulnerabilities", [])
            if vulns:
                cves = sorted({c for v in vulns for c in v.get("identifiers", {}).get("CVE", [])})
                lines.append(f"  {res['component']} {res['version']} ({Path(entry['file']).name}): {len(vulns)} vulns {', '.join(cves)}")
    return lines


def main():
    out = Path(sys.argv[1])
    report = semgrep(out) + gitleaks(out) + trivy(out) + retire(out)
    text = "\n".join(report) + "\n"
    (out / "summary.txt").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

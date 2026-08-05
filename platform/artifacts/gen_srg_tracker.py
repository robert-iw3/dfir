#!/usr/bin/env python3
"""
Build the Web Server SRG tracker from the benchmark and our determinations.

The benchmark (U_Web_Server_SRG_*.xml) states the requirement; `srg_status.yml` states what
this platform does about it. This merges the two, so the checklist is always the current
determination against the current benchmark and cannot drift from either.

  gen_srg_tracker.py           write WEB-SERVER-SRG-TRACKER.md + srg_tracker.json
                               + WEB-SERVER-SRG.ckl (opens in DISA STIG Viewer)
  gen_srg_tracker.py --check   exit 1 if any output is stale, or a control is unaccounted for

A control missing from the status file is a FAILURE, not a default: an unassessed requirement
that silently reads as "nothing to do" is the failure mode a checklist exists to prevent.

Statuses, in the order the assessment is meant to proceed:

  mitigated   Satisfied by a mechanism the platform already has. Needs `mechanism` and
              `evidence`; `verified` names the test that proves it, and stays false until one
              does — a claimed mitigation nobody checked is a claim, not a control.
  implement   Feasible on the current architecture: configuration or a bounded code change.
  redesign    Cannot be met without an architectural or web-tier redesign. Says what.
  na          Does not apply. Needs a justification that survives review.
  open        Not yet assessed.
"""
from __future__ import annotations

import json
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}
STATUS_FILE = HERE / "srg_status.yml"
OUT_MD = HERE / "WEB-SERVER-SRG-TRACKER.md"
OUT_JSON = HERE / "srg_tracker.json"
OUT_CKL = HERE / "WEB-SERVER-SRG.ckl"

# The determination each STIG Viewer status maps from. `implement` and `redesign` are both
# Open — a control with a plan is still a finding until the plan lands.
CKL_STATUS = {
    "mitigated": "NotAFinding",
    "implement": "Open",
    "redesign": "Open",
    "na": "Not_Applicable",
    "open": "Not_Reviewed",
}

ORDER = ["open", "redesign", "implement", "mitigated", "na"]
LABEL = {
    "mitigated": "Mitigated",
    "implement": "Implement",
    "redesign": "Redesign",
    "na": "Not applicable",
    "open": "Open",
}


def _text(el) -> str:
    """Flattened element text. `el or default` is not usable here: an Element with no
    children is falsy, so a populated node would be discarded."""
    return " ".join(((el.text if el is not None else "") or "").split())


def benchmark() -> tuple[Path, dict, list[dict]]:
    xmls = sorted(HERE.glob("U_Web_Server_SRG_*-xccdf.xml"))
    if len(xmls) != 1:
        sys.exit(f"expected exactly one Web Server SRG benchmark in {HERE}, found {len(xmls)}")
    root = ET.parse(xmls[0]).getroot()
    release = next((p.text for p in root.findall("x:plain-text", NS)
                    if p.get("id") == "release-info"), "")
    meta = {
        "stigid": root.get("id") or "Web_Server_SRG",
        "title": _text(root.find("x:title", NS)),
        "description": _text(root.find("x:description", NS)),
        "version": _text(root.find("x:version", NS)),
        "releaseinfo": (release or "").strip(),
        "filename": xmls[0].name,
    }
    controls = []
    for group in root.findall(".//x:Group", NS):
        rule = group.find("x:Rule", NS)
        desc = rule.find("x:description", NS).text or ""
        disc = re.search(r"<VulnDiscussion>(.*?)</VulnDiscussion>", desc, re.S)
        controls.append({
            "srg": (rule.find("x:version", NS).text or "").strip(),
            "vid": group.get("id"),
            "rid": rule.get("id"),
            "gtitle": _text(group.find("x:title", NS)),
            "severity": rule.get("severity"),
            "weight": rule.get("weight") or "10.0",
            "title": " ".join((rule.find("x:title", NS).text or "").split()),
            "discussion": " ".join((disc.group(1) if disc else "").split()),
            "check": _text(rule.find("x:check/x:check-content", NS)),
            "fix": _text(rule.find("x:fixtext", NS)),
            "ccis": [i.text for i in rule.findall("x:ident", NS) if "cci" in (i.get("system") or "")],
        })
    return xmls[0], meta, controls


def merge(controls: list[dict], status: dict) -> list[dict]:
    merged, missing = [], []
    for c in controls:
        s = status.get(c["srg"])
        if s is None:
            missing.append(c["srg"])
            s = {"status": "open"}
        if s.get("status") not in LABEL:
            sys.exit(f"{c['srg']}: unknown status {s.get('status')!r}")
        merged.append({**c, **s, "status": s.get("status", "open")})
    if missing:
        sys.exit("controls absent from srg_status.yml (assess them, do not leave them implicit):\n  "
                 + "\n  ".join(missing))
    return merged


def render(bench: Path, rows: list[dict]) -> str:
    counts = {k: sum(1 for r in rows if r["status"] == k) for k in ORDER}
    highs = [r for r in rows if r["severity"] == "high"]
    out = []
    a = out.append
    a("# Web Server SRG — implementation tracker")
    a("")
    a(f"`{bench.name}` · {len(rows)} controls · "
      f"{sum(1 for r in rows if r['severity'] == 'high')} CAT I (high), "
      f"{sum(1 for r in rows if r['severity'] == 'medium')} CAT II (medium)")
    a("")
    a("Generated by [`gen_srg_tracker.py`](gen_srg_tracker.py) from the benchmark plus")
    a("[`srg_status.yml`](srg_status.yml), which holds the determinations. Edit the status file,")
    a("never this one; `--check` fails when this file is stale or a control is unassessed.")
    a("")
    a("The web tier this applies to: **Traefik** (ingress, TLS termination), **oauth2-proxy**")
    a("(the SSO gate), **nginx** (serving the React application) and the **Django REST API**")
    a("behind it, with **Keycloak** as the identity provider.")
    a("")
    a("## Where it stands")
    a("")
    a("| Status | Count | Meaning |")
    a("|---|---:|---|")
    a(f"| Mitigated | {counts['mitigated']} | Satisfied by a mechanism the platform already has |")
    a(f"| Implement | {counts['implement']} | Feasible on the current architecture |")
    a(f"| Redesign | {counts['redesign']} | Needs an architectural or web-tier redesign |")
    a(f"| Not applicable | {counts['na']} | Does not apply, with justification |")
    a(f"| Open | {counts['open']} | Not yet assessed |")
    a("")
    verified = sum(1 for r in rows if r["status"] == "mitigated" and r.get("verified"))
    a(f"Of the {counts['mitigated']} mitigated, **{verified} are verified by a test** and "
      f"{counts['mitigated'] - verified} rest on inspection alone. A mitigation nobody checked "
      "is a claim; closing that gap is part of the work, not a footnote to it.")
    a("")
    a("### CAT I")
    a("")
    a("| Control | Status | Title |")
    a("|---|---|---|")
    for r in sorted(highs, key=lambda r: r["srg"]):
        a(f"| `{r['srg']}` | {LABEL[r['status']]} | {r['title']} |")
    a("")

    for st in ORDER:
        sel = [r for r in rows if r["status"] == st]
        if not sel:
            continue
        a(f"## {LABEL[st]} — {len(sel)}")
        a("")
        if st == "mitigated":
            a("| Control | V-ID | Sev | Title | Mechanism | Evidence | Verified by |")
            a("|---|---|---|---|---|---|---|")
            for r in sorted(sel, key=lambda r: r["srg"]):
                a(f"| `{r['srg']}` | {r['vid']} | {r['severity'][:3].upper()} | {r['title']} | "
                  f"{r.get('mechanism','—')} | {r.get('evidence','—')} | "
                  f"{r.get('verified') or '**not verified**'} |")
        elif st == "na":
            a("| Control | V-ID | Sev | Title | Justification |")
            a("|---|---|---|---|---|")
            for r in sorted(sel, key=lambda r: r["srg"]):
                a(f"| `{r['srg']}` | {r['vid']} | {r['severity'][:3].upper()} | {r['title']} | "
                  f"{r.get('note','—')} |")
        else:
            a("| Control | V-ID | Sev | Title | What it takes | Where |")
            a("|---|---|---|---|---|---|")
            for r in sorted(sel, key=lambda r: r["srg"]):
                a(f"| `{r['srg']}` | {r['vid']} | {r['severity'][:3].upper()} | {r['title']} | "
                  f"{r.get('note','—')} | {r.get('where','—')} |")
        a("")
    return "\n".join(out) + "\n"


def _finding_details(r: dict) -> str:
    """What an assessor reads first: the determination and what backs it."""
    if r["status"] == "mitigated":
        parts = [f"MITIGATED. {r.get('mechanism', '')}",
                 f"Evidence: {r.get('evidence', '')}"]
        parts.append(f"Verified by: {r['verified']}" if r.get("verified")
                     else "Not yet verified by a test — determination rests on inspection.")
        return "\n\n".join(p for p in parts if p.strip())
    if r["status"] == "na":
        return f"NOT APPLICABLE. {r.get('note', '')}"
    if r["status"] == "open":
        return "Not yet assessed."
    label = "PLANNED — feasible on the current architecture." if r["status"] == "implement" \
        else "PLANNED — requires an architectural or web-tier redesign."
    parts = [label, r.get("note", ""), f"Where: {r.get('where', '')}" if r.get("where") else ""]
    return "\n\n".join(p for p in parts if p.strip())


def render_ckl(meta: dict, rows: list[dict]) -> str:
    """A STIG Viewer checklist, one VULN per control.

    Deterministic output — the uuid is derived from the benchmark, not random — so --check
    can compare it byte-for-byte like the other artifacts."""
    root = ET.Element("CHECKLIST")
    asset = ET.SubElement(root, "ASSET")
    for tag, val in [("ROLE", "None"), ("ASSET_TYPE", "Computing"),
                     ("HOST_NAME", "ir-platform.local"), ("HOST_IP", ""), ("HOST_MAC", ""),
                     ("HOST_FQDN", "ir-platform.local"), ("TARGET_COMMENT",
                      "DFIR platform web tier: Traefik ingress, oauth2-proxy SSO gate, nginx, "
                      "Django REST API, Keycloak IdP"),
                     ("TECH_AREA", ""), ("TARGET_KEY", ""), ("WEB_OR_DATABASE", "true"),
                     ("WEB_DB_SITE", "ir-platform.local"), ("WEB_DB_INSTANCE", "")]:
        ET.SubElement(asset, tag).text = val

    istig = ET.SubElement(ET.SubElement(root, "STIGS"), "iSTIG")
    info = ET.SubElement(istig, "STIG_INFO")
    for name, val in [("version", meta["version"]), ("classification", "UNCLASSIFIED"),
                      ("customname", ""), ("stigid", meta["stigid"]),
                      ("description", meta["description"]), ("filename", meta["filename"]),
                      ("releaseinfo", meta["releaseinfo"]), ("title", meta["title"]),
                      ("uuid", str(uuid.uuid5(uuid.NAMESPACE_URL, meta["filename"]))),
                      ("notice", "terms-of-use"), ("source", "")]:
        si = ET.SubElement(info, "SI_DATA")
        ET.SubElement(si, "SID_NAME").text = name
        if val:
            ET.SubElement(si, "SID_DATA").text = val

    for r in sorted(rows, key=lambda r: r["srg"]):
        vuln = ET.SubElement(istig, "VULN")
        attrs = [("Vuln_Num", r["vid"]), ("Severity", r["severity"]),
                 ("Group_Title", r["gtitle"]), ("Rule_ID", r["rid"]),
                 ("Rule_Ver", r["srg"]), ("Rule_Title", r["title"]),
                 ("Vuln_Discuss", r["discussion"]), ("IA_Controls", ""),
                 ("Check_Content", r["check"]), ("Fix_Text", r["fix"]),
                 ("False_Positives", ""), ("False_Negatives", ""), ("Documentable", "false"),
                 ("Mitigations", ""), ("Potential_Impact", ""), ("Third_Party_Tools", ""),
                 ("Mitigation_Control", ""), ("Responsibility", ""), ("Security_Override_Guidance", ""),
                 ("Check_Content_Ref", "M"), ("Weight", r["weight"]), ("Class", "Unclass"),
                 ("STIGRef", f"{meta['title']} :: Version {meta['version']}, {meta['releaseinfo']}"),
                 ("TargetKey", ""), ("STIG_UUID", str(uuid.uuid5(uuid.NAMESPACE_URL, meta["filename"])))]
        attrs += [("CCI_REF", cci) for cci in r["ccis"]]
        for name, val in attrs:
            sd = ET.SubElement(vuln, "STIG_DATA")
            ET.SubElement(sd, "VULN_ATTRIBUTE").text = name
            ET.SubElement(sd, "ATTRIBUTE_DATA").text = val
        ET.SubElement(vuln, "STATUS").text = CKL_STATUS[r["status"]]
        ET.SubElement(vuln, "FINDING_DETAILS").text = _finding_details(r)
        ET.SubElement(vuln, "COMMENTS").text = \
            f"Determination: {LABEL[r['status']]}. Tracked in artifacts/srg_status.yml; " \
            "regenerate with gen_srg_tracker.py."
        ET.SubElement(vuln, "SEVERITY_OVERRIDE")
        ET.SubElement(vuln, "SEVERITY_JUSTIFICATION")

    ET.indent(root, space="\t")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 2.17-->\n'
            + ET.tostring(root, encoding="unicode") + "\n")


def main() -> int:
    bench, meta, controls = benchmark()
    status = yaml.safe_load(STATUS_FILE.read_text()) or {}
    rows = merge(controls, status)
    md = render(bench, rows)
    js = json.dumps({"benchmark": bench.name, "controls": rows}, indent=1, sort_keys=True) + "\n"
    ckl = render_ckl(meta, rows)

    if "--check" in sys.argv:
        stale = [p.name for p, new in ((OUT_MD, md), (OUT_JSON, js), (OUT_CKL, ckl))
                 if not p.exists() or p.read_text() != new]
        if stale:
            print(f"stale: {', '.join(stale)} — run gen_srg_tracker.py", file=sys.stderr)
            return 1
        print(f"tracker is current ({len(rows)} controls)")
        return 0

    OUT_MD.write_text(md)
    OUT_JSON.write_text(js)
    OUT_CKL.write_text(ckl)
    counts = {k: sum(1 for r in rows if r["status"] == k) for k in ORDER}
    print(f"wrote {OUT_MD.name} + {OUT_JSON.name} + {OUT_CKL.name}: {len(rows)} controls — "
          + ", ".join(f"{v} {k}" for k, v in counts.items() if v))
    return 0


if __name__ == "__main__":
    sys.exit(main())

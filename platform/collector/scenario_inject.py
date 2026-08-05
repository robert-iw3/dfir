#!/usr/bin/env python3
"""
Merge a corpus scenario into a real collection BEFORE the custody seal.

The collector's own hunts run first and their output stands; this adds the scenario's
findings, indicators and principals in the exact file shapes the ingest path consumes
(Combined_Findings_*.json, IOCs.json, Principals.json), and stamps the scenario's
machine id — every corpus run shares one container image, and without a distinct id the
enclave would join all 25 endpoints into a single host.

Sealing happens AFTER this runs, so custody verification downstream is real: the receiver
and puller verify the same manifest that covers this content.

Synthetic by declaration: the injected file names carry SCENARIO, and the scenario itself
is recorded beside them, so a bundle is never mistaken for real evidence.

  scenario_inject.py <scenario.json> <out_dir>
"""
import glob
import json
import os
import sys


def read(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def main(scenario_path, out_dir):
    with open(scenario_path) as fh:
        sc = json.load(fh)

    # The scenario REPLACES the toolkit's own output, it does not merge with it. The toolkit
    # runs against this container, not the endpoint being simulated, so its hunt findings are
    # environment noise — and on a synthetic capture the platform preserves collector verdicts
    # (the on-host adjudication is authoritative when memory is a placeholder), which would
    # carry that noise through as real detections. The scenario is the controlled finding set;
    # the toolkit's finding files are removed so ingest reads only it.
    for pat in ("Adjudication_*.json", "Combined_Findings_*.json", "*_Findings_*.json"):
        for stale in glob.glob(os.path.join(out_dir, pat)):
            os.remove(stale)
    with open(os.path.join(out_dir, "Combined_Findings_SCENARIO.json"), "w") as fh:
        json.dump(sc.get("findings", []), fh, indent=1)

    # IOCs and principals likewise come from the scenario alone — deterministic, and free of
    # whatever the container happened to contain.
    with open(os.path.join(out_dir, "IOCs.json"), "w") as fh:
        json.dump(sc.get("iocs") or {}, fh, indent=1)
    with open(os.path.join(out_dir, "Principals.json"), "w") as fh:
        json.dump(sc.get("principals") or [], fh, indent=1)

    # Host identity is NOT rewritten here. The collector already resolves it from
    # IR_MACHINE_ID / IR_HOSTNAME before any hunt runs (collect.sh resolve_machine_id), so the
    # corpus passes those two variables and the identity is native — not surgery on a file the
    # custody seal then has to cover. A distinct machine id per endpoint is what keeps the
    # enclave from merging all 25 into one host.

    # The scenario travels with the bundle — a corpus bundle states what it is.
    with open(os.path.join(out_dir, "_scenario.json"), "w") as fh:
        json.dump({"corpus": "v2", "hostname": sc["hostname"],
                   "incident_id": sc["incident_id"]}, fh, indent=1)

    print(f"[scenario] {sc['hostname']}: +{len(sc.get('findings', []))} findings, "
          f"{sum(len(v) for v in (sc.get('iocs') or {}).values())} indicators, "
          f"machine_id stamped")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))

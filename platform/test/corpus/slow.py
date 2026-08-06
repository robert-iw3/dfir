#!/usr/bin/env python3
"""
Corpus S — 20 endpoints, "Glass Heron". Eight months of dwell.

The fourth attack shape, and the one that tests the remaining factor. The first three
corpora all fit inside a day, so temporal coherence was 1.0 on every pair and never decided
anything. This one is built to make it decide.

  dwell        initial access to exfiltration spans 241 days. Adjacent hosts are weeks
               apart, the ends of the chain are seven months apart, and `WINDOW_DAYS` says
               anything beyond thirty days is not one intrusion.
  no movement  the operator returns over the corporate VPN each time rather than hopping,
               so five of the seven compromised hosts have no movement record.
  rotation     the C2 domain changes each quarter. Three domains, no overlap, so no
               indicator spans the campaign.
  aging        on the first host the delivery evidence has rotated out of the logs. The
               collector reports that it could not determine whether it was ever there —
               which is a third answer, not a clean result.

The benign baseline is planted EARLY on every endpoint, as it is in a real estate: patch
transactions, an inventory agent, a fleet-wide backup account. That matters, because a host's
"first activity" is then its baseline rather than its compromise, and any measure anchored to
first activity is reading the estate's schedule instead of the intrusion.

Two unrelated hosts carry the same unsanctioned remote-access tool, installed 190 days apart
by different people. They are shadow IT, not one campaign, and they are here to bound
whatever the temporal factor becomes: a window wide enough to hold Glass Heron together must
still keep these two apart.

  slow.py <outdir>     write <outdir>/<host>.json x20 + manifest.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone

DAY = datetime(2025, 11, 3, tzinfo=timezone.utc)

INC_S, INV_S = "INC-CORPUS-S", "Corpus - Glass Heron"

TP, LTP, IND = "True Positive", "Likely True Positive", "Indeterminate"


def at(day, hh=9, mm=0):
    return (DAY + timedelta(days=day, hours=hh, minutes=mm)).isoformat()


def sha(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


def machine_id(host):
    return hashlib.md5(f"corpus-slow:{host}".encode()).hexdigest()


# --- The fleet ------------------------------------------------------------------------
RD = [f"RD-WS-0{i}" for i in range(1, 8)]
HR = [f"HR-WS-0{i}" for i in range(1, 4)]
IT = ["IT-WS-01", "IT-WS-02"]
SRV = ["SRV-MAIL-01", "SRV-CODE-01", "SRV-PKI-01", "SRV-ARCH-01", "RD-SRV-01"]
CORE = ["DC-G1", "VPN-G1", "SRV-MON-01"]
FLEET = RD + HR + IT + SRV + CORE

# --- Fleet-wide benign baseline -------------------------------------------------------
# Planted at the START of the period on every endpoint. A host's first activity is therefore
# its baseline, months before any compromise — so a coherence measure anchored to first
# activity reads the same for a pair compromised a week apart and a pair compromised seven
# months apart.
BACKUP_ACCT = "CORP\\svc_backup"
INVENTORY_ACCT = "CORP\\svc_inventory"
FLEET_AGENT_SHA = sha("corp-inventory-agent-4.2")
FLEET_TASK = "\\Microsoft\\Windows\\Application Experience\\MareBackup"


def benign_baseline(host, idx):
    return [
        {"Type": "Scheduled Task", "Target": FLEET_TASK,
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(0, 2, 5),
         "sha256": FLEET_AGENT_SHA},
        {"Type": "Autorun Entry", "Target": "OneDriveSetup.exe",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(0, 2, 20)},
        {"Type": "Authentication", "Target": f"{INVENTORY_ACCT} inventory scan",
         "Verdict": IND, "Confidence": "Low", "MITRE": [],
         "observed_at": at(0, 1, (idx * 3) % 60), "account": INVENTORY_ACCT},
        {"Type": "Authentication", "Target": f"{BACKUP_ACCT} nightly backup",
         "Verdict": IND, "Confidence": "Low", "MITRE": [],
         "observed_at": at(1, 1, (idx * 7) % 60), "account": BACKUP_ACCT},
        # Patching runs all period, so the estate is active throughout — an intrusion is not
        # the only thing spread across these eight months.
        {"Type": "Package Manager Transaction", "Target": "KB5041583",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(120, 4, 0)},
    ]


def benign_principals():
    return [{"name": BACKUP_ACCT, "kind": "service"},
            {"name": INVENTORY_ACCT, "kind": "service"}]


# --- Glass Heron ----------------------------------------------------------------------
# The habits, carried the whole eight months. Infrastructure is not: the C2 domain changes
# each quarter, so no indicator spans the campaign and only tradecraft can.
WMI_FILTER = "BVTFilter"
WMI_CONSUMER = "BVTConsumer"
LOADER = "wuaueng.dll"
LOADER_SHA = sha("glass-heron-loader-2")
STAGING = "~WRD0001.tmp"
FAMILY = "GlassHeron"
YARA_RULE = "APT_GlassHeron_Loader"
OPERATOR_ACCT = "CORP\\a.pemberton"

C2_BY_QUARTER = {
    0: "cdn-eu-west.glassmetrics.example",
    1: "static.northbridge-cdn.example",
    2: "assets.meridian-analytics.example",
}


def c2_for(day):
    return C2_BY_QUARTER[min(day // 90, 2)]


# (host, day, what the operator did there). Adjacent steps are weeks apart; the ends of the
# chain are 238 days apart.
CHAIN = [
    ("RD-WS-04", 3, "entry"),
    ("IT-WS-01", 41, "credentials"),
    ("SRV-CODE-01", 96, "source"),
    ("DC-G1", 152, "directory"),
    ("SRV-PKI-01", 187, "certificates"),
    ("SRV-ARCH-01", 214, "archive"),
    ("RD-SRV-01", 241, "exfil"),
]
CHAIN_DAY = {h: d for h, d, _ in CHAIN}
CAMPAIGN = sorted(CHAIN_DAY)

# The operator came back over the corporate VPN rather than hopping, so only the two hops
# taken inside one session were ever recorded.
MOVEMENT_S = [
    ("DC-G1", "SRV-PKI-01", 187, "T1021.006", "WinRM", OPERATOR_ACCT),
    ("DC-G1", "SRV-ARCH-01", 214, "T1021.002", "SMB", OPERATOR_ACCT),
]
NO_MOVEMENT = sorted(set(CAMPAIGN) - {"DC-G1", "SRV-PKI-01", "SRV-ARCH-01"})


def heron(host):
    day = CHAIN_DAY.get(host)
    if day is None:
        return []
    domain = c2_for(day)
    # The habits, on every host the operator touched, stamped WHEN they were placed.
    out = [
        {"Type": "WMI Event Subscription", "Target": f"{WMI_FILTER} -> {WMI_CONSUMER}",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1546.003"],
         "observed_at": at(day, 11, 20)},
        {"Type": "DLL Sideload", "Target": LOADER,
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1574.002"],
         "observed_at": at(day, 11, 5), "sha256": LOADER_SHA,
         "malware_family": FAMILY, "yara_matches": [YARA_RULE]},
        {"Type": "C2 Beacon", "Target": f"{domain} (443)",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"],
         "observed_at": at(day, 12, 0), "domain": domain},
    ]
    stage = {
        "entry": [
            # The delivery is gone: the logs that held it rotated months ago. The collector
            # reports that it could not establish whether the artifact was there, which is a
            # third answer and not a clean one.
            {"Type": "Deleted File Scan Incomplete",
             "Target": "journal window predates retention (delivery artifact undetermined)",
             "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(day, 10, 0)},
            {"Type": "Credential Dumping", "Target": "lsass.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.001"],
             "observed_at": at(day, 13, 30)},
        ],
        "credentials": [
            {"Type": "Credential Dumping", "Target": "lsass.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.001"],
             "observed_at": at(day, 13, 0)},
        ],
        "source": [
            {"Type": "Data Staged", "Target": f"C:\\Users\\Public\\{STAGING}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1560.001"],
             "observed_at": at(day, 14, 0)},
        ],
        "directory": [
            {"Type": "DCSync", "Target": "CORP\\krbtgt",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.006"],
             "observed_at": at(day, 14, 20)},
        ],
        "certificates": [
            {"Type": "Certificate Theft", "Target": "CORP-ISSUING-CA private key export",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1649"],
             "observed_at": at(day, 15, 0)},
        ],
        "archive": [
            {"Type": "Data Staged", "Target": f"E:\\archive\\{STAGING}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1560.001"],
             "observed_at": at(day, 15, 30)},
        ],
        "exfil": [
            {"Type": "Data Staged", "Target": f"D:\\rd\\{STAGING}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1560.001"],
             "observed_at": at(day, 15, 40)},
            {"Type": "Exfiltration Over C2", "Target": f"{domain} (18 GB over 9 days)",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1041"],
             "observed_at": at(day, 16, 0), "domain": domain},
        ],
    }
    stage_name = next(s for h, d, s in CHAIN if h == host)
    return out + stage[stage_name]


# --- Shadow IT, twice, six months apart -----------------------------------------------
# The same unsanctioned remote-access tool, installed by two different people 190 days apart.
# Adjudicated a likely true positive on both, so both endpoints are compromised — and they
# are NOT one campaign. Whatever window holds Glass Heron together must still separate these.
RMM = "AnyDesk.exe"
RMM_SHA = sha("anydesk-7.1.13")
SHADOW_IT = [("HR-WS-02", 30), ("RD-WS-07", 220)]
SHADOW_HOSTS = sorted(h for h, _ in SHADOW_IT)


def shadow(host):
    day = dict(SHADOW_IT)[host]
    return [
        {"Type": "Remote Access Tool", "Target": RMM,
         "Verdict": LTP, "Confidence": "High", "MITRE": ["T1219"],
         "observed_at": at(day, 10, 15), "sha256": RMM_SHA},
        {"Type": "External Connection", "Target": "relay.anydesk.example (443)",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(day, 10, 30)},
    ]


CLEAN = [h for h in FLEET if h not in CAMPAIGN and h not in SHADOW_HOSTS]

CAPTURED = ["RD-WS-04", "DC-G1", "SRV-ARCH-01", "HR-WS-02", "RD-WS-01", "SRV-MON-01"]


def movement_findings(host):
    out = []
    for src, dst, day, tech, proto, acct in MOVEMENT_S:
        if src != host:
            continue
        out.append({
            "Type": "Lateral Movement", "Target": f"{src} -> {dst} ({proto})",
            "Verdict": TP, "Confidence": "High", "MITRE": [tech], "observed_at": at(day, 14, 45),
            "src_host": src, "dst_host": dst, "technique": tech, "protocol": proto,
            "account": acct,
        })
    return out


def build():
    hosts = {}
    for idx, host in enumerate(FLEET):
        findings = benign_baseline(host, idx) + heron(host) + movement_findings(host)
        principals = benign_principals()
        iocs, mem = {}, []
        if host in CAMPAIGN:
            day = CHAIN_DAY[host]
            principals.append({"name": OPERATOR_ACCT, "kind": "account"})
            iocs = {"hash": [LOADER_SHA], "domain": [c2_for(day)], "tool": [LOADER]}
            mem = [c2_for(day), LOADER, WMI_CONSUMER]
        elif host in SHADOW_HOSTS:
            findings += shadow(host)
            iocs = {"hash": [RMM_SHA], "tool": [RMM]}
            mem = [RMM]
        hosts[host] = {
            "hostname": host,
            "machine_id": machine_id(host),
            "incident_id": INC_S,
            "investigation": INV_S,
            "findings": findings,
            "iocs": {k: sorted(set(v)) for k, v in iocs.items() if v},
            "principals": principals,
            "memory_artifacts": mem,
            "capture": host in CAPTURED,
        }
    assert len(hosts) == 20, f"corpus S must be 20 endpoints, built {len(hosts)}"
    return hosts


def main(outdir):
    import os
    os.makedirs(outdir, exist_ok=True)
    hosts = build()
    for host, scenario in hosts.items():
        with open(os.path.join(outdir, f"{host}.json"), "w") as fh:
            json.dump(scenario, fh, indent=1, sort_keys=True)

    def compromised(s):
        return any(f["Verdict"] in (TP, LTP) for f in s["findings"])

    span = max(CHAIN_DAY.values()) - min(CHAIN_DAY.values())
    gaps = sorted(CHAIN_DAY.values())
    manifest = {
        "endpoints": sorted(hosts),
        "investigations": {INC_S: INV_S},
        "compromised": sorted(h for h, s in hosts.items() if compromised(s)),
        "clean": sorted(h for h, s in hosts.items() if not compromised(s)),
        "captured": sorted(CAPTURED),
        "campaign_hosts": CAMPAIGN,
        "campaign_order": [h for h, _, _ in CHAIN],
        "campaign_days": CHAIN_DAY,
        "campaign_span_days": span,
        "largest_gap_days": max(b - a for a, b in zip(gaps, gaps[1:])),
        "no_movement_record": NO_MOVEMENT,
        "shadow_it_hosts": SHADOW_HOSTS,
        "shadow_it_gap_days": abs(SHADOW_IT[0][1] - SHADOW_IT[1][1]),
        "shadow_tool": RMM,
        "entry": "RD-WS-04",
        "wmi_filter": WMI_FILTER,
        "loader": LOADER,
        "staging": STAGING,
        "family": FAMILY,
        "c2_domains": sorted(set(C2_BY_QUARTER.values())),
        "fleet_task": FLEET_TASK,
    }
    with open(os.path.join(outdir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(f"wrote {len(hosts)} endpoint scenarios + manifest -> {outdir}")
    print(f"  compromised: {len(manifest['compromised'])}  clean: {len(manifest['clean'])}"
          f"  span: {span}d  largest gap: {manifest['largest_gap_days']}d"
          f"  shadow-IT gap: {manifest['shadow_it_gap_days']}d")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "scenario-out-slow")

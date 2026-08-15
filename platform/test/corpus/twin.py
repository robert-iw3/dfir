#!/usr/bin/env python3
"""
Corpus X — 26 collections, "Twin Adders". Two actors in one fleet at the same time.

Every corpus before this one contains a single intrusion, so the engine's whole job was to
decide which hosts belong to THE campaign. This one asks the harder question: given evidence
from a fleet two unrelated actors are working simultaneously, does it find two campaigns or
one blob?

  concurrency  Copper Adder (financial, phishing entry) and Iron Adder (espionage, exposed
               VPN entry) run in the same ninety-six hours. Temporal coherence is high for
               every cross-actor pair, so time argues for merging them and must not decide.
  shared tools both actors use PsExec and Mimikatz — the commodity tooling half the industry
               uses. If shared tooling links hosts, the two campaigns become one and the
               report names a single actor that does not exist. This is the corpus's point.
  shared victim SRV-X02 was compromised by BOTH, independently, four days apart. It belongs
               to two campaigns at once, which no earlier corpus contains.
  rename       RELAY-01 is renamed RELAY-02 mid-campaign. Same machine, two collections. It
               must remain one host in one campaign, not two members.
  near-miss    two clean hosts share the commodity tool and the fleet backup account and
               nothing else. They sit just under the link threshold and must be DECLINED
               with a reason, not quietly omitted.

  twin.py <outdir>     write <outdir>/<host>.json x26 + manifest.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone

DAY = datetime(2026, 8, 3, tzinfo=timezone.utc)

INC_X, INV_X = "INC-CORPUS-X", "Corpus - Twin Adders"

TP, LTP, IND = "True Positive", "Likely True Positive", "Indeterminate"


def at(hh, mm, day=0):
    return (DAY + timedelta(days=day, hours=hh, minutes=mm)).isoformat()


def sha(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


def machine_id(host):
    return hashlib.md5(f"corpus-twin:{host}".encode()).hexdigest()


# --- The fleet ------------------------------------------------------------------------
WS = [f"WS-X0{i}" for i in range(1, 9)]
SRV = [f"SRV-X0{i}" for i in range(1, 7)]
INFRA = ["DC-X1", "DC-X2", "VPN-X1", "JUMP-X1", "BKP-X1", "MON-X1"]
DEV = [f"DEV-X0{i}" for i in range(1, 5)]
# One machine, two collections: renamed between them. The second name is what it is called
# now; the first is what its earlier evidence was collected under.
RELAY_OLD, RELAY_NEW = "RELAY-01", "RELAY-02"

FLEET = WS + SRV + INFRA + DEV
COLLECTIONS = FLEET + [RELAY_OLD, RELAY_NEW]

# --- Fleet-wide benign baseline -------------------------------------------------------
BACKUP_ACCT = "CORP\\svc_backup"
MON_ACCT = "CORP\\svc_monitor"
FLEET_TASK = "\\Microsoft\\Windows\\UpdateOrchestrator\\Scan"
FLEET_AGENT_SHA = sha("corp-monitor-agent-4.1")

# The commodity tooling. BOTH actors carry these, and so do two administrators. A link that
# rests on either is a link between everyone who has ever run a sysinternals binary.
PSEXEC = "PsExec64.exe"
PSEXEC_SHA = sha("sysinternals-psexec-2.43")     # the real, signed, widely deployed binary
MIMIKATZ = "mimikatz.exe"
MIMIKATZ_SHA = sha("mimikatz-2.2.0-20220919")


def benign_baseline(host, idx):
    return [
        {"Type": "Scheduled Task", "Target": FLEET_TASK,
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(2, 5),
         "sha256": FLEET_AGENT_SHA},
        {"Type": "Autorun Entry", "Target": "OneDriveSetup.exe",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(2, 20)},
        {"Type": "Authentication", "Target": f"{BACKUP_ACCT} nightly backup",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(1, (idx * 3) % 60),
         "account": BACKUP_ACCT},
        {"Type": "Remote Execution", "Target": f"monitoring poll -> {host}",
         "Verdict": IND, "Confidence": "Low", "MITRE": ["T1021.002"],
         "observed_at": at(3, (idx * 7) % 60), "src_host": "MON-X1", "dst_host": host,
         "protocol": "SMB", "account": MON_ACCT},
    ]


# --- Copper Adder: financially motivated, phishing entry ------------------------------
C_ENTRY = "WS-X03"
C_C2_DOMAIN = "cdn-copper-sync.example.net"
C_C2_IP = "203.0.113.41"
C_IMPLANT = "CopperSvc.exe"
C_IMPLANT_SHA = sha("copper-adder-implant-1")
C_MUTEX = "Global\\copper-adder-7f2a"
C_UA = "Mozilla/5.0 (Windows NT 10.0) CopperSync/2.1"
C_FAMILY = "CopperAdder"
C_YARA = "APT_CopperAdder_Implant"
C_ACCT = "CORP\\j.whitfield"
C_TASK = "\\Microsoft\\Windows\\Multimedia\\SystemSoundsCopper"

COPPER_ONLY = [C_ENTRY, "JUMP-X1", "SRV-X01", "DC-X1"]

MOVEMENT_C = [
    (C_ENTRY, "JUMP-X1", (9, 20, 0), "T1021.001", "RDP", C_ACCT),
    ("JUMP-X1", "SRV-X01", (10, 5, 0), "T1021.002", "SMB", "CORP\\svc_sql"),
    ("JUMP-X1", "DC-X1", (11, 40, 0), "T1021.006", "WinRM", "CORP\\da_copper"),
    # Four days before Iron reaches the same server, by a different route.
    ("SRV-X01", "SRV-X02", (14, 10, 0), "T1021.002", "SMB", "CORP\\svc_sql"),
]


def copper(host):
    """Copper Adder's own material — its implant, its C2, its persistence."""
    out = []
    if host == C_ENTRY:
        out += [
            {"Type": "Phishing Attachment", "Target": "Remittance_Advice.xlsm",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1566.001"],
             "observed_at": at(8, 55)},
            {"Type": "Macro Execution", "Target": "EXCEL.EXE -> wscript.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1204.002"],
             "observed_at": at(9, 2)},
        ]
    out += [
        {"Type": "Implant Dropped", "Target": f"%APPDATA%\\{C_IMPLANT}",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"],
         "observed_at": at(9, 30), "sha256": C_IMPLANT_SHA},
        {"Type": "C2 Beacon", "Target": f"{C_C2_DOMAIN} ({C_C2_IP}:443)",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"],
         "observed_at": at(9, 45), "user_agent": C_UA, "mutex": C_MUTEX,
         "malware_family": C_FAMILY, "yara_matches": [C_YARA]},
        {"Type": "Scheduled Task Persistence", "Target": C_TASK,
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1053.005"],
         "observed_at": at(10, 0)},
    ]
    return out


# --- Iron Adder: espionage, exposed VPN entry -----------------------------------------
I_ENTRY = "VPN-X1"
I_C2_DOMAIN = "updates-iron-mesh.example.org"
I_C2_IP = "198.51.100.77"
I_IMPLANT = "IronHost.dll"
I_IMPLANT_SHA = sha("iron-adder-implant-1")
I_MUTEX = "Global\\iron-adder-b91c"
I_UA = "Mozilla/5.0 (X11; Linux x86_64) IronMesh/1.4"
I_FAMILY = "IronAdder"
I_YARA = "APT_IronAdder_Loader"
I_ACCT = "CORP\\svc_vpn_relay"
I_SERVICE = "IronHostSvc"

# RELAY_NEW rather than RELAY_OLD: the campaign membership is asserted under the name the
# host carries NOW, which is the whole point of following a rename.
IRON_ONLY = [I_ENTRY, RELAY_NEW, "SRV-X04", "DC-X2"]

MOVEMENT_I = [
    (I_ENTRY, RELAY_OLD, (22, 15, 1), "T1021.002", "SMB", I_ACCT),
    (RELAY_OLD, "SRV-X04", (23, 40, 1), "T1021.006", "WinRM", "CORP\\svc_files"),
    (RELAY_OLD, "DC-X2", (1, 20, 2), "T1021.006", "WinRM", "CORP\\da_iron"),
    # The second actor reaches the shared server, four days after the first.
    ("SRV-X04", "SRV-X02", (2, 50, 4), "T1021.002", "SMB", "CORP\\svc_files"),
]


def iron(host):
    out = []
    if host == I_ENTRY:
        out += [
            {"Type": "Credential Stuffing", "Target": "VPN portal, 41 accounts",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1110.004"],
             "observed_at": at(21, 40, 1)},
        ]
    out += [
        {"Type": "Implant Dropped", "Target": f"C:\\Windows\\System32\\{I_IMPLANT}",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"],
         "observed_at": at(22, 30, 1), "sha256": I_IMPLANT_SHA},
        {"Type": "C2 Beacon", "Target": f"{I_C2_DOMAIN} ({I_C2_IP}:8443)",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"],
         "observed_at": at(22, 50, 1), "user_agent": I_UA, "mutex": I_MUTEX,
         "malware_family": I_FAMILY, "yara_matches": [I_YARA]},
        {"Type": "Service Persistence", "Target": I_SERVICE,
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1543.003"],
         "observed_at": at(23, 10, 1)},
    ]
    return out


# --- The shared victim ----------------------------------------------------------------
# Compromised by both actors, independently, four days apart. It carries both implants,
# both C2 addresses and both persistence mechanisms.
SHARED = "SRV-X02"

# --- Commodity tooling ----------------------------------------------------------------
# Both actors, and two administrators who have nothing to do with either.
COMMODITY_ADMIN = ["SRV-X05", "DEV-X01"]
COMMODITY_HOSTS = COPPER_ONLY + IRON_ONLY + [SHARED] + COMMODITY_ADMIN


def commodity(host, hour):
    """PsExec and Mimikatz, identical bytes wherever they appear."""
    return [
        {"Type": "Remote Execution Tool", "Target": f"C:\\Windows\\{PSEXEC}",
         "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1569.002"],
         "observed_at": at(hour, 5), "sha256": PSEXEC_SHA},
        {"Type": "Credential Dumping", "Target": f"%TEMP%\\{MIMIKATZ}",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.001"],
         "observed_at": at(hour, 25), "sha256": MIMIKATZ_SHA},
    ]


def admin_commodity(host):
    """An administrator's own use of the same tools, on a host neither actor touched.

    Adjudicated Likely True Positive rather than Indeterminate on purpose: the platform
    cannot tell these bytes from the actors' copies, and pretending it can would make the
    negative assertion trivial.
    """
    return [
        {"Type": "Remote Execution Tool", "Target": f"C:\\Tools\\{PSEXEC}",
         "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1569.002"],
         "observed_at": at(15, 30), "sha256": PSEXEC_SHA},
        {"Type": "Credential Dumping", "Target": f"C:\\Tools\\{MIMIKATZ}",
         "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1003.001"],
         "observed_at": at(16, 10), "sha256": MIMIKATZ_SHA},
    ]


CAMPAIGN_C = COPPER_ONLY + [SHARED]
CAMPAIGN_I = IRON_ONLY + [SHARED]
# Under collection names: RELAY_OLD's bundle belongs to the same machine as RELAY_NEW.
COMPROMISED_COLLECTIONS = sorted(set(CAMPAIGN_C) | set(CAMPAIGN_I)
                                 | {RELAY_OLD} | set(COMMODITY_ADMIN))

CAPTURED = [C_ENTRY, I_ENTRY, SHARED, RELAY_NEW, "SRV-X05", "WS-X01"]


def movement_findings(host, table):
    out = []
    for src, dst, when, tech, proto, acct in table:
        if src != host:
            continue
        hh, mm, day = when
        out.append({
            "Type": "Lateral Movement", "Target": f"{src} -> {dst} ({proto})",
            "Verdict": TP, "Confidence": "High", "MITRE": [tech],
            "observed_at": at(hh, mm, day),
            "src_host": src, "dst_host": dst, "technique": tech, "protocol": proto,
            "account": acct,
        })
    return out


def build():
    hosts = {}
    for idx, name in enumerate(COLLECTIONS):
        # The renamed machine reports one machine-id under both of its names.
        mid = machine_id(RELAY_OLD) if name in (RELAY_OLD, RELAY_NEW) else machine_id(name)
        findings = benign_baseline(name, idx)
        principals = [{"name": BACKUP_ACCT, "kind": "service"},
                      {"name": MON_ACCT, "kind": "service"}]
        iocs, mem = {}, []

        in_copper = name in CAMPAIGN_C
        in_iron = name in CAMPAIGN_I or name == RELAY_OLD

        if in_copper:
            findings += copper(name) + movement_findings(name, MOVEMENT_C)
            principals.append({"name": C_ACCT, "kind": "account"})
            iocs.setdefault("hash", []).append(C_IMPLANT_SHA)
            iocs.setdefault("domain", []).append(C_C2_DOMAIN)
            iocs.setdefault("ip", []).append(C_C2_IP)
            mem += [C_IMPLANT, C_C2_DOMAIN, C_MUTEX]
        if in_iron:
            findings += iron(name) + movement_findings(name, MOVEMENT_I)
            principals.append({"name": I_ACCT, "kind": "account"})
            iocs.setdefault("hash", []).append(I_IMPLANT_SHA)
            iocs.setdefault("domain", []).append(I_C2_DOMAIN)
            iocs.setdefault("ip", []).append(I_C2_IP)
            mem += [I_IMPLANT, I_C2_DOMAIN, I_MUTEX]
        if in_copper or in_iron:
            findings += commodity(name, 12 if in_copper else 20)
            iocs.setdefault("hash", []).extend([PSEXEC_SHA, MIMIKATZ_SHA])
            mem += [PSEXEC, MIMIKATZ]
        elif name in COMMODITY_ADMIN:
            findings += admin_commodity(name)
            iocs.setdefault("hash", []).extend([PSEXEC_SHA, MIMIKATZ_SHA])
            mem += [PSEXEC, MIMIKATZ]

        hosts[name] = {
            "hostname": name,
            "machine_id": mid,
            "incident_id": INC_X,
            "investigation": INV_X,
            "findings": findings,
            "iocs": {k: sorted(set(v)) for k, v in iocs.items() if v},
            "principals": principals,
            "memory_artifacts": sorted(set(mem)),
            "capture": name in CAPTURED,
        }
    assert len(hosts) == 26, f"corpus X must be 26 collections, built {len(hosts)}"
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

    manifest = {
        "endpoints": sorted(hosts),
        "investigations": {INC_X: INV_X},
        "compromised": sorted(h for h, s in hosts.items() if compromised(s)),
        "clean": sorted(h for h, s in hosts.items() if not compromised(s)),
        "captured": sorted(CAPTURED),
        # The two campaigns, under the names their hosts carry now.
        "copper_hosts": sorted(CAMPAIGN_C),
        "iron_hosts": sorted(CAMPAIGN_I),
        "copper_only": sorted(COPPER_ONLY),
        "iron_only": sorted(IRON_ONLY),
        "shared_victim": SHARED,
        "copper_entry": C_ENTRY,
        "iron_entry": I_ENTRY,
        "copper_family": C_FAMILY,
        "iron_family": I_FAMILY,
        "copper_c2": C_C2_DOMAIN,
        "iron_c2": I_C2_DOMAIN,
        "copper_hash": C_IMPLANT_SHA,
        "iron_hash": I_IMPLANT_SHA,
        # Shared by both actors AND by two uninvolved administrators.
        "commodity_hashes": sorted([PSEXEC_SHA, MIMIKATZ_SHA]),
        "commodity_admin_hosts": sorted(COMMODITY_ADMIN),
        "commodity_hosts": sorted(set(COMMODITY_HOSTS)),
        "renamed_from": RELAY_OLD,
        "renamed_to": RELAY_NEW,
        "renamed_machine_id": machine_id(RELAY_OLD),
        "fleet_task": FLEET_TASK,
        "ubiquitous_account": BACKUP_ACCT,
    }
    with open(os.path.join(outdir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(f"wrote {len(hosts)} endpoint scenarios + manifest -> {outdir}")
    print(f"  copper: {len(CAMPAIGN_C)}  iron: {len(CAMPAIGN_I)}  shared victim: {SHARED}"
          f"  commodity-only admins: {len(COMMODITY_ADMIN)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "scenario-out-twin")

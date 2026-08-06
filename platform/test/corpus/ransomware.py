#!/usr/bin/env python3
"""
Corpus R — 24 endpoints, "Vault Serpent". Mass encryption and deliberate destruction.

The third attack shape, and the one that inverts the assumptions the first two share. An
intrusion is rare by nature: a handful of hosts out of a fleet, reached one hop at a time,
leaving evidence that survives to be collected. A ransomware event is none of those things.

  scale        the campaign's defining artifact — the ransom note, the appended extension —
               is on EVERY host it touched. Rarity reads "present on most of the fleet" as
               "environment", so the more hosts an event hits, the less its own signature
               says they are related.
  deployment   the payload goes out from one host by scheduled task over a group policy
               object. There is no per-host movement record to find, because there was no
               per-host hop: 13 of the 16 compromised endpoints have no edge at all.
  destruction  shadow copies deleted, event logs cleared, backup catalogs wiped. On several
               hosts the evidence that would date the compromise is the evidence the actor
               removed first, so "when was this host compromised" has no answer rather than
               a late one.
  time         the whole event fits in ninety minutes. Temporal coherence decays over
               thirty days, so it is 1.0 for every pair here and decides nothing.

Partial completion is modelled too: the actor was interrupted, so some hosts carry the
payload and the staging with no encryption, and one carries a note with no payload left on
disk. A campaign whose members are at different stages is the normal case, not the exception.

  ransomware.py <outdir>     write <outdir>/<host>.json x24 + manifest.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone

DAY = datetime(2026, 7, 29, tzinfo=timezone.utc)

INC_R, INV_R = "INC-CORPUS-R", "Corpus - Vault Serpent"

TP, LTP, IND = "True Positive", "Likely True Positive", "Indeterminate"


def at(hh, mm, day=0):
    return (DAY + timedelta(days=day, hours=hh, minutes=mm)).isoformat()


def sha(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


def machine_id(host):
    return hashlib.md5(f"corpus-ransom:{host}".encode()).hexdigest()


# --- The fleet ------------------------------------------------------------------------
FIN = [f"FIN-WS-0{i}" for i in range(1, 9)]
ENG = [f"ENG-WS-0{i}" for i in range(1, 7)]
SRV = ["SRV-SQL-01", "SRV-SQL-02", "SRV-FS-01", "SRV-FS-02", "SRV-PRINT-01"]
CORE = ["DC-R1", "DC-R2", "SRV-BKP-01", "SRV-VC-01", "HV-01"]
FLEET = FIN + ENG + SRV + CORE

# --- Fleet-wide benign baseline -------------------------------------------------------
BACKUP_ACCT = "CORP\\svc_veeam"          # backup agent, authenticates everywhere
AV_ACCT = "CORP\\svc_defender"           # management agent, fleet-wide
PATCH_HOST = "WSUS-01"
FLEET_TASK = "\\Microsoft\\Windows\\UpdateOrchestrator\\Scan"
FLEET_AGENT_SHA = sha("corp-backup-agent-12.3")


def benign_baseline(host, idx):
    """Ordinary estate life, including a nightly job that touches every host at once."""
    return [
        {"Type": "Scheduled Task", "Target": FLEET_TASK,
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(2, 5),
         "sha256": FLEET_AGENT_SHA},
        {"Type": "Autorun Entry", "Target": "OneDriveSetup.exe",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(2, 20)},
        # The backup window: one account authenticating to the whole fleet inside one hour,
        # which is exactly the shape mass deployment has.
        {"Type": "Authentication", "Target": f"{BACKUP_ACCT} backup session",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(1, (idx * 2) % 60),
         "account": BACKUP_ACCT},
        {"Type": "Remote Execution", "Target": f"WSUS scan -> {host}",
         "Verdict": IND, "Confidence": "Low", "MITRE": ["T1021.002"],
         "observed_at": at(3, (idx * 5) % 60), "src_host": PATCH_HOST, "dst_host": host,
         "protocol": "SMB", "account": AV_ACCT},
        {"Type": "Package Manager Transaction", "Target": "KB5039212",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(3, 40)},
    ]


def benign_principals():
    return [{"name": BACKUP_ACCT, "kind": "service"},
            {"name": AV_ACCT, "kind": "service"}]


# --- Vault Serpent --------------------------------------------------------------------
# The affiliate's own material. The note name and the appended extension are the campaign's
# signature, and they are on every host it reached — which is the point.
NOTE = "!!!_RESTORE_YOUR_FILES_!!!.txt"
EXTENSION = ".vs3rp"
PAYLOAD = "vssrv32.exe"
PAYLOAD_SHA = sha("vault-serpent-locker-3")
LOADER = "MpDefenderCore.dll"            # sideloaded beside a signed binary
DEPLOY_TASK = "\\Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestart"
GPO_NAME = "Corp-Endpoint-Baseline-v4"
LEAK_SITE = "vs3rp7kqjxn4wzlm.onion"
CONTACT = "vaultserpent@onionmail.example"
RANSOM_WALLET = "bc1qv4ults3rp3nt9x0000000000000000000wxyz"
FAMILY = "VaultSerpent"
YARA_RULE = "RANSOM_VaultSerpent_Locker_v3"

ENTRY = "FIN-WS-03"
STAGER = "DC-R1"

# The only movement anyone recorded: the operator's own hops. Everything after this went out
# by scheduled task from a group policy object, which leaves no per-host edge.
MOVEMENT_R = [
    (ENTRY, "SRV-FS-01", (21, 40), "T1021.002", "SMB", "CORP\\m.reyes"),
    (ENTRY, STAGER, (22, 5), "T1021.006", "WinRM", "CORP\\svc_sql_admin"),
]

# Encrypted outright.
ENCRYPTED = ["FIN-WS-01", "FIN-WS-02", ENTRY, "FIN-WS-05", "FIN-WS-07",
             "ENG-WS-02", "ENG-WS-04",
             "SRV-SQL-01", "SRV-FS-01", "SRV-FS-02", "SRV-VC-01", "HV-01"]
# Reached and staged, but the operator was interrupted before encryption.
STAGED_ONLY = ["ENG-WS-05", "SRV-PRINT-01"]
# Infrastructure the operator worked from or destroyed, without encrypting it. The backup
# server received the payload like everything else the policy object reached; the operator
# additionally emptied its catalog by hand.
OPERATED = [STAGER, "SRV-BKP-01"]

# A public, signed file-transfer binary. Ransomware operators stage exfiltration with it
# before encrypting, and so does everyone else — which is why it is here. It is adjudicated
# True Positive on every host that carries it, in BOTH compromises, so it is exactly the
# evidence a confirmed-everywhere rarity floor could wrongly promote. If it merges the two,
# the floor is too generous.
RCLONE = "rclone.exe"
RCLONE_SHA = sha("rclone-v1.66.0-windows-amd64")
RCLONE_HOSTS = [ENTRY, "SRV-FS-01", "SRV-FS-02"]

# The unrelated compromise: a departing employee moving files out with the same public
# binary, a week of staging, and nothing else in common with Vault Serpent.
INSIDER_HOSTS = ["FIN-WS-06", "ENG-WS-06"]
INSIDER_ACCT = "CORP\\d.whitcombe"


def insider(host):
    return [
        {"Type": "Implant Dropped", "Target": f"C:\\Users\\{INSIDER_ACCT.split(chr(92))[1]}\\rclone.exe",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"], "observed_at": at(11, 5),
         "sha256": RCLONE_SHA},
        # A different staging name from the operator's, so the ONLY thing the two compromises
        # share is the public binary itself.
        {"Type": "Data Staged", "Target": "C:\\Users\\Public\\personal_export.zip",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1560.001"], "observed_at": at(11, 40)},
        {"Type": "Exfiltration Over Web Service", "Target": "personal cloud storage (3.1 GB)",
         "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1567.002"], "observed_at": at(12, 15),
         "account": INSIDER_ACCT},
    ]

CAMPAIGN = sorted(set(ENCRYPTED) | set(STAGED_ONLY) | set(OPERATED))

# Hosts where the actor cleared the log that would date the compromise. The point is not that
# they look clean — they carry loud impact evidence — but that nothing on them can answer
# WHEN it began, so the contradiction test has no baseline to work from.
LOGS_CLEARED = ["SRV-FS-01", "SRV-VC-01", STAGER, "SRV-BKP-01"]


def encryption_findings(host):
    """What an encrypted endpoint carries. Identical on every one of them, by construction."""
    return [
        {"Type": "Ransomware", "Target": NOTE,
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1486"], "observed_at": at(23, 10),
         "malware_family": FAMILY, "yara_matches": [YARA_RULE],
         "onion": [LEAK_SITE], "wallets": [RANSOM_WALLET],
         "indicators": [EXTENSION, CONTACT]},
        {"Type": "Shadow Copy Deletion", "Target": "vssadmin.exe delete shadows /all /quiet",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1490"], "observed_at": at(23, 2)},
        {"Type": "Service Stop", "Target": "MSSQLSERVER, VeeamBackupSvc, ShadowProtectSvc",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1489"], "observed_at": at(23, 4)},
    ]


def payload_findings(host):
    """The delivery, on every host the group policy object reached."""
    return [
        {"Type": "Implant Dropped", "Target": f"C:\\ProgramData\\{PAYLOAD}",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"], "observed_at": at(22, 48),
         "sha256": PAYLOAD_SHA},
        {"Type": "Scheduled Task Persistence", "Target": DEPLOY_TASK,
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1053.005"], "observed_at": at(22, 52)},
        {"Type": "Defender Disabled", "Target": "Set-MpPreference -DisableRealtimeMonitoring",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1562.001"], "observed_at": at(22, 55)},
    ]


def serpent(host):
    per_host = {
        ENTRY: [
            {"Type": "Phishing Attachment", "Target": "Remittance_Advice_0729.iso",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1566.001"],
             "observed_at": at(19, 12)},
            {"Type": "DLL Sideload", "Target": LOADER,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1574.002"],
             "observed_at": at(19, 25), "sha256": sha("vault-serpent-loader")},
            {"Type": "Credential Dumping", "Target": "lsass.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.001"],
             "observed_at": at(20, 40)},
        ],
        STAGER: [
            {"Type": "Implant Dropped", "Target": f"C:\\Windows\\SYSVOL\\{PAYLOAD}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"], "observed_at": at(22, 20),
             "sha256": PAYLOAD_SHA},
            # The deployment itself: ONE finding, on ONE host, for thirteen endpoints. There
            # is no per-host record to correlate on because there was no per-host hop.
            {"Type": "Group Policy Modification", "Target": GPO_NAME,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1484.001"],
             "observed_at": at(22, 30), "indicators": [DEPLOY_TASK]},
            {"Type": "Scheduled Task Persistence", "Target": DEPLOY_TASK,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1053.005"], "observed_at": at(22, 34)},
        ],
        "SRV-BKP-01": [
            {"Type": "Backup Deletion", "Target": "Veeam backup catalog purged (41 restore points)",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1490"], "observed_at": at(22, 58)},
            {"Type": "Service Stop", "Target": "VeeamBackupSvc",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1489"], "observed_at": at(22, 59)},
        ],
    }
    out = list(per_host.get(host, []))
    if host in RCLONE_HOSTS:
        out.append({"Type": "Implant Dropped", "Target": f"C:\\ProgramData\\{RCLONE}",
                    "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"],
                    "observed_at": at(21, 10), "sha256": RCLONE_SHA})
        out.append({"Type": "Data Staged", "Target": "D:\\shares\\_exfil.7z",
                    "Verdict": TP, "Confidence": "High", "MITRE": ["T1560.001"],
                    "observed_at": at(21, 25)})
    if host in ENCRYPTED or host in OPERATED:
        out += payload_findings(host)
    if host in ENCRYPTED:
        out += encryption_findings(host)
    elif host in STAGED_ONLY:
        # Delivered, never fired. These hosts belong to the campaign and carry no impact at
        # all — membership has to rest on the delivery artifacts alone.
        out += payload_findings(host)
    if host in LOGS_CLEARED:
        # Recorded on the host whose history it removed. It says something happened; it
        # cannot say when the host was first compromised, and nothing else on these hosts
        # can either.
        out.append({"Type": "Event Log Cleared", "Target": "Security, System (1102)",
                    "Verdict": TP, "Confidence": "High", "MITRE": ["T1070.001"],
                    "observed_at": at(23, 30)})
    return out


CLEAN = [h for h in FLEET if h not in CAMPAIGN and h not in INSIDER_HOSTS]

CAPTURED = [ENTRY, STAGER, "SRV-FS-01", "SRV-BKP-01", "ENG-WS-05",
            "FIN-WS-04", "ENG-WS-01"]          # last two clean


def movement_findings(host):
    out = []
    for src, dst, (hh, mm), tech, proto, acct in MOVEMENT_R:
        if src != host:
            continue
        out.append({
            "Type": "Lateral Movement", "Target": f"{src} -> {dst} ({proto})",
            "Verdict": TP, "Confidence": "High", "MITRE": [tech], "observed_at": at(hh, mm),
            "src_host": src, "dst_host": dst, "technique": tech, "protocol": proto,
            "account": acct,
        })
    return out


def build():
    hosts = {}
    for idx, host in enumerate(FLEET):
        findings = benign_baseline(host, idx) + serpent(host) + movement_findings(host)
        principals = benign_principals()
        iocs, mem = {}, []
        if host in CAMPAIGN:
            principals.append({"name": "CORP\\m.reyes", "kind": "account"})
            iocs = {"hash": [PAYLOAD_SHA], "onion": [LEAK_SITE], "tool": [PAYLOAD]}
            mem = [PAYLOAD, NOTE, LEAK_SITE]
        elif host in INSIDER_HOSTS:
            findings += insider(host)
            principals.append({"name": INSIDER_ACCT, "kind": "account"})
            iocs = {"hash": [RCLONE_SHA], "tool": [RCLONE]}
            mem = [RCLONE]
        hosts[host] = {
            "hostname": host,
            "machine_id": machine_id(host),
            "incident_id": INC_R,
            "investigation": INV_R,
            "findings": findings,
            "iocs": {k: sorted(set(v)) for k, v in iocs.items() if v},
            "principals": principals,
            "memory_artifacts": mem,
            "capture": host in CAPTURED,
        }
    assert len(hosts) == 24, f"corpus R must be 24 endpoints, built {len(hosts)}"
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
        "investigations": {INC_R: INV_R},
        "compromised": sorted(h for h, s in hosts.items() if compromised(s)),
        "clean": sorted(h for h, s in hosts.items() if not compromised(s)),
        "captured": sorted(CAPTURED),
        "campaign_hosts": sorted(CAMPAIGN),
        "encrypted": sorted(ENCRYPTED),
        "staged_only": sorted(STAGED_ONLY),
        "no_movement_record": sorted(set(CAMPAIGN) - {ENTRY, "SRV-FS-01", STAGER}),
        "logs_cleared": sorted(LOGS_CLEARED),
        "insider_hosts": sorted(INSIDER_HOSTS),
        "commodity_tool": RCLONE,
        "commodity_hosts": sorted(set(RCLONE_HOSTS) | set(INSIDER_HOSTS)),
        "entry": ENTRY,
        "stager": STAGER,
        "ransom_note": NOTE,
        "extension": EXTENSION,
        "payload": PAYLOAD,
        "deploy_task": DEPLOY_TASK,
        "gpo": GPO_NAME,
        "family": FAMILY,
        "fleet_task": FLEET_TASK,
        "ubiquitous_account": BACKUP_ACCT,
    }
    with open(os.path.join(outdir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(f"wrote {len(hosts)} endpoint scenarios + manifest -> {outdir}")
    print(f"  compromised: {len(manifest['compromised'])}  clean: {len(manifest['clean'])}"
          f"  encrypted: {len(ENCRYPTED)}  no movement record: {len(manifest['no_movement_record'])}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "scenario-out-ransomware")

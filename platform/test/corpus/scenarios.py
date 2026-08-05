#!/usr/bin/env python3
"""
Corpus v2 — 25 endpoints whose default state is ORDINARY.

Generates one scenario file per endpoint for the collector's injector
(collector/scenario_inject.py): the real collector runs, real hunts and all, and these
findings/indicators/principals are merged into its output before the custody seal — so
shipping, ingest, analysis and correlation all exercise the production path on content
this file controls.

The corpus exists to make the engine DECLINE links, which the malicious-only seed never
demanded. Every host carries a benign baseline: fleet software with identical hashes,
patch management pushing on schedule, an inventory scanner authenticating everywhere, a
helpdesk account present on every machine — each one a trap that fuses the fleet into one
mega-campaign if linkage has no rarity or verdict weighting.

Adversaries layered on top (planning/CORRELATION-ENGINE-V2.md §5):
  INV-A  "Ember Fox"   10-host intrusion, shared C2/implant, credential-reuse chain,
                       plus a disjoint 2-host cryptominer that must STAY separate.
  INV-B  "Quiet Fox"   the same ACTOR, different engagement: C2 rotated per host,
                       implant re-hashed per host — only tradecraft (persistence names,
                       staging convention, technique sequence) links it. One movement
                       edge is timestamped before its source's first evidence: a
                       deliberate contradiction that must discount, not silently count.

  scenarios.py <outdir>     write <outdir>/<host>.json x25 + manifest.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone

DAY = datetime(2026, 7, 15, tzinfo=timezone.utc)

INC_A, INV_A = "INC-CORPUS-A", "Corpus - Ember Fox"
INC_B, INV_B = "INC-CORPUS-B", "Corpus - Quiet Fox"

TP, LTP, IND = "True Positive", "Likely True Positive", "Indeterminate"


def at(hh, mm, day=0):
    return (DAY + timedelta(days=day, hours=hh, minutes=mm)).isoformat()


def sha(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


def machine_id(host):
    return hashlib.md5(f"corpus-v2:{host}".encode()).hexdigest()


# --- Fleet-wide benign baseline -------------------------------------------------------
# On EVERY host, clean or not. None of this may bind hosts into a campaign.
AGENT_SHA = sha("fleet-edr-agent-7.4.1")            # identical on all 25 — environment
UPDATE_DOMAIN = "updates.fleetvendor.example"       # every host resolves it
SCCM_ACCT = "CORP\\svc_sccm"                        # patch management, fleet-wide
SCANNER_ACCT = "CORP\\svc_inventory"                # nightly inventory scan, fleet-wide
HELPDESK_ACCT = "CORP\\svc_helpdesk"                # the ubiquitous-account trap (G2)


def benign_baseline(host, idx):
    """Ordinary life on an endpoint, including things that LOOK like lateral movement."""
    return [
        {"Type": "Installed Agent", "Target": f"fleet-edr-agent 7.4.1 ({AGENT_SHA[:16]})",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(3, 5),
         "sha256": AGENT_SHA, "domain": UPDATE_DOMAIN},
        {"Type": "Package Manager Transaction", "Target": "package curl",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(3, 30)},
        {"Type": "Scheduled Task", "Target": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(4, 0)},
        {"Type": "Autorun Entry", "Target": "OneDriveSetup.exe",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(4, 10)},
        # Patch management "moving" to this host on its schedule — legitimate remote
        # execution, verdict-weighted out of linkage, never a campaign edge.
        {"Type": "Remote Execution", "Target": f"SCCM push -> {host}",
         "Verdict": IND, "Confidence": "Low", "MITRE": ["T1021.002"],
         "observed_at": at(2, (idx * 7) % 60), "src_host": "SCCM-01", "dst_host": host,
         "protocol": "SMB", "account": SCCM_ACCT},
        {"Type": "Authentication", "Target": f"{SCANNER_ACCT} inventory scan",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(1, (idx * 3) % 60),
         "account": SCANNER_ACCT},
    ]


def benign_principals():
    return [
        {"name": HELPDESK_ACCT, "kind": "service"},
        {"name": SCCM_ACCT, "kind": "service"},
        {"name": SCANNER_ACCT, "kind": "service"},
    ]


# --- INV-A: Ember Fox (shared-indicator intrusion, as an actor who does not rotate) ----
C2_IP_A = "198.51.100.23"
C2_DOMAIN_A = "updates.cdn-telemetry.net"
IMPLANT_A = "svchost_helper.exe"
IMPLANT_SHA_A = sha(IMPLANT_A)
ACCT_USER = "CORP\\j.okafor"
ACCT_SVC = "CORP\\svc_backup"
ACCT_DA = "CORP\\da_admin"

# The actor's TRADECRAFT — identical in INV-B, which is what attribution keys on.
PERSIST_TASK = "\\Microsoft\\Windows\\UpdateOrchestrator\\Sync"
PERSIST_SVC = "WinDefendHelper"
STAGING = "_archive.7z"

# Implant-level indicators recovered by memory enrichment, MWCP config extraction and the
# reverse engineer — the material that survives infrastructure rotation. The user-agent and
# mutex are hard-coded in the builder, so every host running this implant carries them
# identically even when its C2 address is unique. That is what makes them stronger linkage
# than an address, and why they must reach the graph.
IMPLANT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EmberSync/2.1"
IMPLANT_MUTEX = "1BA6BD98D9"            # bare hex token — a high-confidence implant lock
CAMPAIGN_ID = "EF-2026-Q3"              # MWCP config: the operation, not the address
SLEEP_JITTER = "60s/15%"
YARA_RULE = "APT_EmberFox_Loader_v2"
MALWARE_FAMILY = "EmberFox"
RE_WALLET = "bc1qe4mb3rf0xstag1ngw4ll3t0000000000xyz"

# Builder-fixed transport internals, recovered by MWCP beside the campaign id: the named
# pipe, the TLS client fingerprint and the config stash are compiled into the builder, so
# they survive infrastructure rotation exactly as the user-agent does. The C2 certificate
# belongs to the INFRASTRUCTURE and rotates with it — INV-A only, where the C2 is shared.
IMPLANT_PIPE = "\\\\.\\pipe\\ef-sync-9921"
IMPLANT_JA3 = "6734f37431670b3ab4292b8f60f29984"
IMPLANT_REGKEY = "HKCU\\Software\\Classes\\CLSID\\{E8F2-EF26}\\InprocServer32"
C2_CERT_SHA1 = "a3b1c94de07f5512890cc4ffb3e2d81a90f7d3c2"

# Each on exactly ONE host: they exercise their indicator kind without adding a link, so
# classification is untouched by their presence.
STOLEN_AWS_KEY = "AKIAIOSFODNN7CORPDEV"
STAGE2_NAME = "ef-stage2-dropper.ps1"

MOVEMENT_A = [
    ("WS-007", "JUMP-01", (8, 52), "T1021.001", "RDP", ACCT_USER),
    ("JUMP-01", "SRV-FILE-01", (9, 30), "T1021.002", "SMB", ACCT_SVC),
    ("JUMP-01", "DC-01", (10, 5), "T1021.006", "WinRM", ACCT_SVC),
    ("DC-01", "SRV-DB-01", (11, 0), "T1021.006", "WinRM", ACCT_DA),
    ("DC-01", "SRV-BACKUP-01", (11, 20), "T1021.002", "SMB", ACCT_DA),
    ("DC-01", "DC-02", (11, 45), "T1021.006", "WinRM", ACCT_DA),
    ("DC-01", "SRV-APP-01", (12, 5), "T1021.006", "WinRM", ACCT_DA),
    ("DC-01", "WS-003", (12, 20), "T1021.002", "SMB", ACCT_DA),
    ("DC-01", "WS-011", (12, 30), "T1021.002", "SMB", ACCT_DA),
]


def ember(host):
    """Ember Fox activity for one compromised INV-A host."""
    # The beacon carries what enrichment recovers from the implant, not just the address it
    # spoke to: the builder-fixed user-agent and mutex, and the extracted C2 config.
    beacon = {"Type": "C2 Beacon", "Target": f"{C2_DOMAIN_A} ({C2_IP_A}:443)",
              "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"],
              "user_agent": IMPLANT_UA, "mutex": IMPLANT_MUTEX,
              "pipe": IMPLANT_PIPE, "ja3": IMPLANT_JA3,
              "registry_key": IMPLANT_REGKEY, "certificate": C2_CERT_SHA1,
              "urls": [f"https://{C2_DOMAIN_A}/gate/v2"],
              "config_extracted": {"campaign_id": CAMPAIGN_ID, "sleep": SLEEP_JITTER,
                                   "address": C2_DOMAIN_A, "port": "443"},
              "yara_matches": [YARA_RULE], "malware_family": MALWARE_FAMILY}
    per_host = {
        "WS-007": [
            {"Type": "Phishing Attachment", "Target": "Q3_Budget_Review.xlsm",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1566.001"], "observed_at": at(8, 14)},
            {"Type": "Macro Execution", "Target": "EXCEL.EXE -> wscript.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1204.002"], "observed_at": at(8, 22)},
            {"Type": "Implant Dropped", "Target": f"%APPDATA%\\{IMPLANT_A}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"], "observed_at": at(8, 26),
             "sha256": IMPLANT_SHA_A, "indicators": [STAGE2_NAME]},
            {**beacon, "observed_at": at(8, 31)},
            {"Type": "Credential Dumping", "Target": "lsass.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.001"], "observed_at": at(8, 47),
             "aws_keys": [STOLEN_AWS_KEY]},
        ],
        "JUMP-01": [
            {**beacon, "observed_at": at(9, 2)},
            {"Type": "Credential Dumping", "Target": "lsass.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.001"], "observed_at": at(9, 10)},
            {"Type": "Scheduled Task Persistence", "Target": PERSIST_TASK,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1053.005"], "observed_at": at(9, 18)},
        ],
        "SRV-FILE-01": [
            {**beacon, "observed_at": at(9, 40)},
            {"Type": "Data Staged", "Target": f"D:\\shares\\finance\\{STAGING}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1560.001"], "observed_at": at(9, 55)},
            {"Type": "Exfiltration Over C2", "Target": f"{C2_IP_A}:443 (2.4 GB)",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1041"], "observed_at": at(10, 15)},
            {"Type": "Scheduled Task Persistence", "Target": PERSIST_TASK,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1053.005"], "observed_at": at(9, 44)},
        ],
        "DC-01": [
            {**beacon, "observed_at": at(10, 12)},
            {"Type": "DCSync", "Target": "CORP\\krbtgt",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.006"], "observed_at": at(10, 40)},
            {"Type": "Service Persistence", "Target": PERSIST_SVC,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1543.003"], "observed_at": at(10, 52)},
        ],
        "DC-02": [
            {**beacon, "observed_at": at(11, 50)},
            {"Type": "Service Persistence", "Target": PERSIST_SVC,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1543.003"], "observed_at": at(11, 58)},
        ],
        "SRV-DB-01": [
            {**beacon, "observed_at": at(11, 8)},
            {"Type": "Database Dump", "Target": "corp_hr.bak",
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1005"], "observed_at": at(11, 30)},
        ],
        "SRV-BACKUP-01": [
            {**beacon, "observed_at": at(11, 26)},
            {"Type": "Backup Deletion", "Target": "vssadmin delete shadows /all",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1490"], "observed_at": at(11, 35)},
        ],
        "SRV-APP-01": [{**beacon, "observed_at": at(12, 10)}],
        "WS-003": [
            {"Type": "Implant Dropped", "Target": f"%APPDATA%\\{IMPLANT_A}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"], "observed_at": at(12, 24),
             "sha256": IMPLANT_SHA_A},
            {**beacon, "Verdict": LTP, "Confidence": "Medium", "observed_at": at(12, 28)},
        ],
        "WS-011": [
            {"Type": "Implant Dropped", "Target": f"%APPDATA%\\{IMPLANT_A}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"], "observed_at": at(12, 34),
             "sha256": IMPLANT_SHA_A},
        ],
    }
    return per_host.get(host, [])


EMBER_HOSTS = set(h for pair in MOVEMENT_A for h in (pair[0], pair[1]))

# The disjoint compromise: a cryptominer that shares NOTHING with Ember Fox except the
# fleet's benign baseline. If it ever joins Ember's campaign, linkage is broken.
MINER_IP = "203.0.113.77"
MINER_DOMAIN = "pool.monero-hash.example"
MINER_ACCT = "CORP\\svc_render"
MINER_HOSTS = ["WS-012", "VPN-GW-01"]
# The miner's OWN payout material — deliberately not RE_WALLET, which belongs to the Ember
# actor: sharing a wallet across families would hand cross-family attribution a false link.
MINER_WALLET = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
MINER_ONION = "xmrpool3kh4dsxxx4mmm5577aaaqqqzzz2vwlqyd.onion"


def miner(host):
    return [
        {"Type": "Cryptominer Process", "Target": "xmrig -o pool.monero-hash.example:3333",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1496"], "observed_at": at(6, 10),
         "domain": MINER_DOMAIN, "ip": MINER_IP,
         "wallets": [MINER_WALLET], "onion": [MINER_ONION]},
        {"Type": "C2 Beacon", "Target": f"{MINER_DOMAIN} ({MINER_IP}:3333)",
         "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"], "observed_at": at(6, 20)},
    ]


CLEAN_A = ["WS-001", "WS-002", "WS-004", "WS-005", "WS-006", "WS-008", "WS-009", "WS-010"]

# --- INV-B: Quiet Fox — the same actor, rotated everything, one day later --------------
# DC-101 is reached with NO movement recorded — the collector never caught the hop. Its only
# tie to the campaign is tradecraft: the persistence service name it shares with
# SRV-FILE-101. That isolates the artifact path, which movement would otherwise outrank
# everywhere, and is what makes "clusters on tradecraft" a proven claim rather than an
# assumed one.
MOVEMENT_B = [
    ("WS-101", "JUMP-101", (9, 40), "T1021.001", "RDP", "CORP\\l.tanaka"),
    ("JUMP-101", "SRV-FILE-101", (10, 25), "T1021.002", "SMB", "CORP\\svc_nas"),
]

# The contradiction: movement out of JUMP-101 recorded BEFORE anything compromised it.
CONTRADICTION_EDGE = ("JUMP-101", "SRV-FILE-101")


def quiet(host, idx):
    """Quiet Fox: per-host C2 and hash, the SAME tradecraft.

    Address and hash rotate per host; the user-agent, mutex and campaign id do not, because
    they are compiled into the builder. Those are what still tie these hosts together, and
    the reason the graph has to carry more than addresses.
    """
    ip = f"203.0.113.{110 + idx}"
    domain = f"cdn-sync-{idx:02d}.example.net"
    implant_sha = sha(f"quiet-fox:{host}")
    # Builder-fixed only — no certificate, no urls, no config address: those rotate with
    # the infrastructure, and rotation is what this investigation exists to model.
    builder = {"user_agent": IMPLANT_UA, "mutex": IMPLANT_MUTEX,
               "pipe": IMPLANT_PIPE, "ja3": IMPLANT_JA3, "registry_key": IMPLANT_REGKEY,
               "config_extracted": {"campaign_id": CAMPAIGN_ID, "sleep": SLEEP_JITTER}}
    chain = {
        "WS-101": [
            # The reverse engineer's determination on a carved region: recovered C2 and
            # wallet, the family, the rule that matched. Rotation changes the address, not
            # these — so this is the material that must reach correlation.
            {"Type": "Reverse Engineering: EmberFox", "Target": "carved/ws-101-0x7ffe.bin",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"],
             "observed_at": at(12, 0, 1), "malware_family": MALWARE_FAMILY,
             "yara_matches": [YARA_RULE], "user_agent": IMPLANT_UA,
             "mutex": IMPLANT_MUTEX,
             "config_extracted": {"campaign_id": CAMPAIGN_ID, "sleep": SLEEP_JITTER},
             "network_indicators": [{"type": "domain", "value": C2_DOMAIN_A, "role": "fallback"}],
             "crypto_material": [{"type": "wallet", "value": RE_WALLET}]},
            {"Type": "Phishing Attachment", "Target": "Invoice_0714.xlsm",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1566.001"], "observed_at": at(9, 5, 1)},
            {"Type": "Macro Execution", "Target": "EXCEL.EXE -> wscript.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1204.002"], "observed_at": at(9, 12, 1)},
            {"Type": "Implant Dropped", "Target": "%APPDATA%\\wsvc_helper.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1105"], "observed_at": at(9, 16, 1),
             "sha256": implant_sha},
            {"Type": "C2 Beacon", "Target": f"{domain} ({ip}:443)", **builder,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"], "observed_at": at(9, 21, 1)},
            {"Type": "Credential Dumping", "Target": "lsass.exe",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1003.001"], "observed_at": at(9, 33, 1)},
        ],
        "JUMP-101": [
            {"Type": "C2 Beacon", "Target": f"{domain} ({ip}:443)", **builder,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"], "observed_at": at(9, 55, 1)},
            {"Type": "Scheduled Task Persistence", "Target": PERSIST_TASK,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1053.005"], "observed_at": at(10, 5, 1)},
        ],
        "SRV-FILE-101": [
            {"Type": "C2 Beacon", "Target": f"{domain} ({ip}:443)", **builder,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"], "observed_at": at(10, 40, 1)},
            {"Type": "Data Staged", "Target": f"D:\\shares\\legal\\{STAGING}",
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1560.001"], "observed_at": at(10, 55, 1)},
            # The other end of DC-101's only tie to this campaign.
            {"Type": "Service Persistence", "Target": PERSIST_SVC,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1543.003"], "observed_at": at(11, 5, 1)},
        ],
        "DC-101": [
            {"Type": "C2 Beacon", "Target": f"{domain} ({ip}:443)", **builder,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1071.001"], "observed_at": at(11, 25, 1)},
            {"Type": "Service Persistence", "Target": PERSIST_SVC,
             "Verdict": TP, "Confidence": "High", "MITRE": ["T1543.003"], "observed_at": at(11, 40, 1)},
        ],
    }
    return chain.get(host, []), ip, domain, implant_sha


QUIET_HOSTS = ["WS-101", "JUMP-101", "SRV-FILE-101", "DC-101"]
CLEAN_B = ["WS-102"]

# Memory captures: a subset spanning compromised AND clean, so the analyzer runs against
# both and a clean host's capture proves the absence path.
CAPTURED = ["WS-007", "JUMP-01", "DC-01", "SRV-FILE-01", "WS-012",
            "WS-001", "WS-005",                      # clean, INV-A
            "WS-101", "DC-101", "WS-102"]            # INV-B, incl. clean


def movement_findings(movement, host, contradiction=None):
    """Movement rows for edges this host is an endpoint of, recorded on the source."""
    out = []
    for src, dst, (hh, mm), tech, proto, acct in movement:
        if src != host:
            continue
        # The contradiction edge is stamped BEFORE the source's first compromise evidence
        # — a record that cannot be right and must be seen to be discounted.
        day = 1 if movement is MOVEMENT_B else 0
        when = at(7, 30, 1) if (src, dst) == (contradiction or ("", "")) else at(hh, mm, day)
        out.append({
            "Type": "Lateral Movement", "Target": f"{src} -> {dst} ({proto})",
            "Verdict": TP, "Confidence": "High", "MITRE": [tech], "observed_at": when,
            "src_host": src, "dst_host": dst, "technique": tech, "protocol": proto,
            "account": acct,
        })
    return out


def build():
    hosts = {}
    idx = 0

    def add(host, incident, investigation, findings, iocs, principals, mem):
        nonlocal idx
        hosts[host] = {
            "hostname": host,
            "machine_id": machine_id(host),
            "incident_id": incident,
            "investigation": investigation,
            "findings": benign_baseline(host, idx) + findings,
            "iocs": {k: sorted(set(v)) for k, v in iocs.items() if v},
            "principals": benign_principals() + principals,
            "memory_artifacts": mem,
            "capture": host in CAPTURED,
        }
        idx += 1

    # INV-A — Ember Fox world
    for host in sorted(EMBER_HOSTS):
        f = ember(host) + movement_findings(MOVEMENT_A, host)
        accts = sorted({m[5] for m in MOVEMENT_A if host in (m[0], m[1])})
        add(host, INC_A, INV_A, f,
            {"ip": [C2_IP_A], "domain": [C2_DOMAIN_A], "hash": [IMPLANT_SHA_A],
             "tool": [IMPLANT_A]},
            [{"name": a, "kind": "account"} for a in accts],
            [f"{C2_DOMAIN_A}", f"GET /sync HTTP/1.1\r\nHost: {C2_IP_A}\r\n",
             f"%APPDATA%\\{IMPLANT_A}"])
    for host in MINER_HOSTS:
        add(host, INC_A, INV_A, miner(host),
            {"ip": [MINER_IP], "domain": [MINER_DOMAIN], "tool": ["xmrig"]},
            [{"name": MINER_ACCT, "kind": "account"}],
            [MINER_DOMAIN, f"stratum+tcp://{MINER_IP}:3333"])
    for host in CLEAN_A:
        add(host, INC_A, INV_A, [], {}, [], [])

    # INV-B — Quiet Fox
    for i, host in enumerate(QUIET_HOSTS):
        f, ip, domain, ih = quiet(host, i)
        f += movement_findings(MOVEMENT_B, host, contradiction=CONTRADICTION_EDGE)
        accts = sorted({m[5] for m in MOVEMENT_B if host in (m[0], m[1])})
        add(host, INC_B, INV_B, f,
            {"ip": [ip], "domain": [domain], "hash": [ih]},
            [{"name": a, "kind": "account"} for a in accts],
            [domain, f"GET /sync HTTP/1.1\r\nHost: {ip}\r\n"])
    for host in CLEAN_B:
        add(host, INC_B, INV_B, [], {}, [], [])

    assert len(hosts) == 25, f"corpus must be 25 endpoints, built {len(hosts)}"
    return hosts


def main(outdir):
    import os
    os.makedirs(outdir, exist_ok=True)
    hosts = build()
    for host, scenario in hosts.items():
        with open(os.path.join(outdir, f"{host}.json"), "w") as fh:
            json.dump(scenario, fh, indent=1, sort_keys=True)
    manifest = {
        "endpoints": sorted(hosts),
        "investigations": {INC_A: INV_A, INC_B: INV_B},
        "compromised": sorted(h for h, s in hosts.items()
                              if any(f["Verdict"] != IND for f in s["findings"])),
        "clean": sorted(h for h, s in hosts.items()
                        if all(f["Verdict"] == IND for f in s["findings"])),
        "captured": sorted(h for h in CAPTURED),
        "ubiquitous_account": HELPDESK_ACCT,
        "contradiction_edge": list(CONTRADICTION_EDGE),
    }
    with open(os.path.join(outdir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(f"wrote {len(hosts)} endpoint scenarios + manifest -> {outdir}")
    print(f"  compromised: {len(manifest['compromised'])}  clean: {len(manifest['clean'])}"
          f"  captured: {len(manifest['captured'])}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "scenario-out")

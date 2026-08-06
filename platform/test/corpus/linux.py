#!/usr/bin/env python3
"""
Corpus L — 22 Linux endpoints, "Rust Fox".

The second attack shape. Corpus v2 (`scenarios.py`) is a Windows intrusion: phishing,
scheduled tasks, SMB/WinRM movement, `DOMAIN\\account` principals, and evidence the toolkit
adjudicates True Positive. Every correlation threshold in the engine was tuned while that was
the only dataset. This one changes the platform, the vocabulary and the verdict ceiling at
once, so anything that only held because of those assumptions has to show itself.

Four things differ, and each is load-bearing:

  finding types   the Linux hunts' own vocabulary (`playbooks/linux/threat_hunting/`):
                  Webshell, Systemd Persistence, Cron Persistence, Shell Init Backdoor,
                  Library Preload Hijack, Suspicious Kernel Module, SSH Authorized Key.
  verdicts        Linux adjudication tops out at Likely True Positive — ALWAYS_TP in
                  `adjudicate.py` returns LTP, not TP. Nothing here is True Positive, so
                  every weight that multiplies by the verdict ladder is scored at 0.75.
  accounts        Unix accounts have no domain part, and `root` is on all 22 hosts — a
                  harder ubiquity trap than a service account, because it is also the
                  account the intrusion actually uses.
  infrastructure  no shared C2. Each host egresses somewhere different, so indicators link
                  nothing and the campaign must hold on tradecraft and movement alone.

  linux.py <outdir>     write <outdir>/<host>.json x22 + manifest.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone

DAY = datetime(2026, 7, 22, tzinfo=timezone.utc)

INC_L, INV_L = "INC-CORPUS-L", "Corpus - Rust Fox"

# The Linux verdict ceiling. `adjudicate.py` ALWAYS_TP returns Likely True Positive for its
# highest-fidelity types; nothing on this platform reaches True Positive.
LTP, IND, LFP = "Likely True Positive", "Indeterminate", "Likely False Positive"


def at(hh, mm, day=0):
    return (DAY + timedelta(days=day, hours=hh, minutes=mm)).isoformat()


def sha(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


def machine_id(host):
    return hashlib.md5(f"corpus-linux:{host}".encode()).hexdigest()


# --- The fleet ------------------------------------------------------------------------
WEB = ["web-edge-01", "web-edge-02"]
APP = [f"app-node-0{i}" for i in (1, 2, 3, 4)]
DB = ["db-core-01", "db-core-02"]
BUILD = ["build-01", "build-02"]
CI = ["ci-runner-01", "ci-runner-02"]
K8S = [f"k8s-worker-0{i}" for i in (1, 2, 3)]
INFRA = ["bastion-01", "log-01", "nfs-01", "mail-01"]
DEV = [f"dev-ws-0{i}" for i in (1, 2, 3)]
FLEET = WEB + APP + DB + BUILD + CI + K8S + INFRA + DEV

# --- Fleet-wide benign baseline -------------------------------------------------------
# Ordinary Linux estate life. None of it may bind hosts into a campaign.
ROOT = "root"                                   # on all 22 — the ubiquity trap
ANSIBLE_ACCT = "ansible"                        # configuration management, fleet-wide
BACKUP_ACCT = "svc_borg"                        # backup agent, fleet-wide
CFG_HOST = "cfg-mgmt-01"                        # the control node pushes to everyone
FLEET_UNIT = "node_exporter.service"            # legitimate systemd unit, all 22 hosts
# Ships with the distribution and reduces to `<name>-<name>.service` — the SAME shape as the
# actor's unit. Nothing in the name separates them, so the fingerprint's rarity floor is the
# whole of the difference.
FLEET_UNIT_SAME_SHAPE = "fwupd-refresh.service"
FLEET_CRON = "/etc/cron.d/unattended-upgrades"  # legitimate cron entry, all 22 hosts
FLEET_AGENT_SHA = sha("borgmatic-1.9.2")        # identical hash fleet-wide


def benign_baseline(host, idx):
    """Ordinary life on a Linux endpoint, including things shaped like an intrusion."""
    return [
        # A legitimate systemd unit on every host. If it reaches a campaign fingerprint as a
        # naming convention, the rarity floor is not holding.
        {"Type": "Systemd Unit", "Target": f"/etc/systemd/system/{FLEET_UNIT}",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(2, 15),
         "sha256": FLEET_AGENT_SHA},
        {"Type": "Systemd Unit", "Target": f"/usr/lib/systemd/system/{FLEET_UNIT_SAME_SHAPE}",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(2, 17)},
        {"Type": "Cron Entry", "Target": FLEET_CRON,
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(2, 20)},
        {"Type": "Listening Service", "Target": "sshd :22",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(2, 25)},
        {"Type": "Package Manager Transaction", "Target": "apt upgrade openssl",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(3, 0)},
        # Packaged and unmodified, so adjudication calls it a likely false positive. Present
        # to prove a non-ladder verdict neither compromises a host nor links one.
        {"Type": "Unexpected SUID Binary", "Target": "/usr/bin/pkexec",
         "Verdict": LFP, "Confidence": "Medium", "MITRE": ["T1548.001"],
         "observed_at": at(3, 10)},
        # Configuration management reaching every host on its schedule: legitimate remote
        # execution over the same protocol the intrusion uses.
        {"Type": "Remote Execution", "Target": f"ansible-playbook -> {host}",
         "Verdict": IND, "Confidence": "Low", "MITRE": ["T1021.004"],
         "observed_at": at(1, (idx * 5) % 60), "src_host": CFG_HOST, "dst_host": host,
         "protocol": "SSH", "account": ANSIBLE_ACCT},
        {"Type": "Authentication", "Target": f"{BACKUP_ACCT} backup session",
         "Verdict": IND, "Confidence": "Low", "MITRE": [], "observed_at": at(4, (idx * 3) % 60),
         "account": BACKUP_ACCT},
    ]


def benign_principals():
    return [
        {"name": ROOT, "kind": "account"},
        {"name": ANSIBLE_ACCT, "kind": "service"},
        {"name": BACKUP_ACCT, "kind": "service"},
    ]


# --- Rust Fox — the actor's tradecraft -------------------------------------------------
# Habits, not addresses. These are what has to hold the campaign together, because the
# infrastructure below is unique per host by construction.
PERSIST_UNIT = "sysstat-collector.service"      # near-miss on the real sysstat-collect.service
PERSIST_CRON = "/etc/cron.d/certbot-renew-helper"
PERSIST_PROFILE = "/etc/profile.d/00-locale-fix.sh"
PRELOAD_LIB = "/usr/lib/x86_64-linux-gnu/libnss_cache.so.2"
ROOTKIT_KO = "nf_conntrack_helper.ko"
PAYLOAD = "kdevtmpfsi"                          # memfd-resident, never on disk
SSH_KEY_COMMENT = "rustfox@build"
SSH_KEY_FP = "SHA256:9rXqPmT4vK2sLbN8wJhF6dYcZgQ1eR3aUiO7pM5nB0k"
STAGING_SUFFIX = ".tar.zst"

# Movement is over SSH and only PARTLY recorded. build-02 and ci-runner-01 are reached with
# no movement finding at all — the actor cleared journald there — so their only tie to the
# campaign is the tradecraft they carry. That isolates the artifact path, which movement
# outranks everywhere it exists.
MOVEMENT_L = [
    ("web-edge-02", "app-node-01", (10, 12), "T1021.004", "SSH", ROOT),
    ("web-edge-02", "app-node-03", (10, 40), "T1021.004", "SSH", ROOT),
    ("app-node-01", "bastion-01", (11, 25), "T1021.004", "SSH", "deploy"),
    ("bastion-01", "db-core-01", (12, 10), "T1021.004", "SSH", ROOT),
    ("bastion-01", "nfs-01", (12, 35), "T1021.004", "SSH", ROOT),
]

# Reached without a movement record — tradecraft is the only tie.
UNTRACKED = ["build-02", "ci-runner-01"]

RUSTFOX_HOSTS = sorted({h for m in MOVEMENT_L for h in (m[0], m[1])} | set(UNTRACKED))


def egress(host, idx):
    """Per-host infrastructure. Nothing here is shared, so nothing here can link."""
    return f"198.18.{40 + idx}.{7 + idx}", f"cdn-{host.replace('-', '')}.example.org"


def rustfox(host, idx):
    """Rust Fox activity for one compromised host."""
    ip, domain = egress(host, idx)
    # Planted key material. Adjudication files an authorized_keys entry as HUMAN_REVIEW —
    # Indeterminate — even when the key is the actor's. It is the strongest artifact a Linux
    # intrusion leaves and the ladder scores it as a lead.
    ssh_key = {"Type": "SSH Authorized Key", "Target": f"/root/.ssh/authorized_keys ({SSH_KEY_COMMENT})",
               "Verdict": IND, "Confidence": "Low", "MITRE": ["T1098.004"],
               "observed_at": at(13, 5), "indicators": [SSH_KEY_FP]}
    staged = {"Type": "Data Staged", "Target": f"/var/tmp/.cache/.rf-{host}{STAGING_SUFFIX}",
              "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1560.001"],
              "observed_at": at(14, 20)}
    beacon = {"Type": "External Connection", "Target": f"{domain} ({ip}:443)",
              "Verdict": IND, "Confidence": "Low", "MITRE": ["T1071.001"],
              "observed_at": at(13, 40), "ip": ip, "domain": domain}

    per_host = {
        "web-edge-02": [
            {"Type": "Webshell", "Target": "/var/www/html/uploads/.sess_handler.php",
             "Verdict": LTP, "Confidence": "High", "MITRE": ["T1190", "T1505.003"],
             "observed_at": at(9, 30), "sha256": sha("rustfox-webshell")},
            {"Type": "Execution From Writable Path", "Target": f"/dev/shm/.systemd-private/{PAYLOAD}",
             "Verdict": LTP, "Confidence": "High", "MITRE": ["T1059.004"],
             "observed_at": at(9, 48)},
            {"Type": "Systemd Persistence", "Target": f"/etc/systemd/system/{PERSIST_UNIT}",
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1543.002"],
             "observed_at": at(10, 2)},
            ssh_key, beacon, staged,
        ],
        "app-node-01": [
            {"Type": "Systemd Persistence", "Target": f"/etc/systemd/system/{PERSIST_UNIT}",
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1543.002"],
             "observed_at": at(10, 30)},
            {"Type": "Library Preload Hijack", "Target": f"/etc/ld.so.preload -> {PRELOAD_LIB}",
             "Verdict": LTP, "Confidence": "High", "MITRE": ["T1574.006"],
             "observed_at": at(10, 55)},
            ssh_key, beacon,
        ],
        "app-node-03": [
            {"Type": "Cron Persistence", "Target": PERSIST_CRON,
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1053.003"],
             "observed_at": at(11, 5)},
            {"Type": "Memory-Only Executable (memfd)", "Target": f"memfd:{PAYLOAD}",
             "Verdict": LTP, "Confidence": "High", "MITRE": ["T1620"],
             "observed_at": at(11, 15)},
            ssh_key, beacon,
        ],
        "bastion-01": [
            {"Type": "Systemd Persistence", "Target": f"/etc/systemd/system/{PERSIST_UNIT}",
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1543.002"],
             "observed_at": at(11, 45)},
            {"Type": "Shell Init Backdoor", "Target": PERSIST_PROFILE,
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1546.004"],
             "observed_at": at(11, 58)},
            {"Type": "Audit Logging Disabled", "Target": "auditd stopped, rules flushed",
             "Verdict": LTP, "Confidence": "High", "MITRE": ["T1562.001"],
             "observed_at": at(12, 2)},
            ssh_key, beacon,
        ],
        "db-core-01": [
            {"Type": "Library Preload Hijack", "Target": f"/etc/ld.so.preload -> {PRELOAD_LIB}",
             "Verdict": LTP, "Confidence": "High", "MITRE": ["T1574.006"],
             "observed_at": at(12, 25)},
            {"Type": "Suspicious Kernel Module", "Target": ROOTKIT_KO,
             "Verdict": LTP, "Confidence": "High", "MITRE": ["T1014"],
             "observed_at": at(12, 40)},
            beacon, staged,
        ],
        "nfs-01": [
            {"Type": "Cron Persistence", "Target": PERSIST_CRON,
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1053.003"],
             "observed_at": at(12, 50)},
            beacon, staged,
        ],
        # No movement recorded to either of these.
        "build-02": [
            {"Type": "Systemd Persistence", "Target": f"/etc/systemd/system/{PERSIST_UNIT}",
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1543.002"],
             "observed_at": at(13, 20)},
            {"Type": "Shell Init Backdoor", "Target": PERSIST_PROFILE,
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1546.004"],
             "observed_at": at(13, 30)},
            ssh_key, beacon,
        ],
        "ci-runner-01": [
            {"Type": "Cron Persistence", "Target": PERSIST_CRON,
             "Verdict": LTP, "Confidence": "Medium", "MITRE": ["T1053.003"],
             "observed_at": at(13, 50)},
            {"Type": "Library Preload Hijack", "Target": f"/etc/ld.so.preload -> {PRELOAD_LIB}",
             "Verdict": LTP, "Confidence": "High", "MITRE": ["T1574.006"],
             "observed_at": at(14, 0)},
            ssh_key, beacon, staged,
        ],
    }
    return per_host.get(host, [])


# --- The disjoint compromise -----------------------------------------------------------
# A contractor's unsanctioned root logins on two developer workstations. Genuinely
# compromised, adjudicated LTP, and sharing nothing with Rust Fox — it must stay its own
# campaign.
CONTRACTOR_HOSTS = ["dev-ws-02", "dev-ws-03"]
CONTRACTOR_ACCT = "svc_deploy2"

# The routine admin hop from the bastion to a developer workstation, recorded as movement
# and adjudicated Indeterminate because the hunt could not tell it from an intrusion. The
# bastion is a Rust Fox member; the workstation is not. If verdict is ignored on movement,
# this single record fuses the contractor compromise into Rust Fox.
ADMIN_HOP = ("bastion-01", "dev-ws-02", (16, 30), "T1021.004", "SSH", ANSIBLE_ACCT)


def contractor(host):
    return [
        {"Type": "Unauthorized UID0 Account", "Target": f"{CONTRACTOR_ACCT} (uid=0)",
         "Verdict": LTP, "Confidence": "High", "MITRE": ["T1136.001"],
         "observed_at": at(15, 10), "account": CONTRACTOR_ACCT},
        {"Type": "Empty Password Account", "Target": f"{CONTRACTOR_ACCT} in /etc/shadow",
         "Verdict": LTP, "Confidence": "High", "MITRE": ["T1078.003"],
         "observed_at": at(15, 15)},
    ]


CLEAN = [h for h in FLEET if h not in RUSTFOX_HOSTS and h not in CONTRACTOR_HOSTS]

# Captures spanning compromised and clean, so the analyzer runs against both.
CAPTURED = ["web-edge-02", "bastion-01", "build-02", "dev-ws-02", "web-edge-01", "log-01"]


def movement_findings(host):
    """Movement rows for edges this host is the source of."""
    out = []
    for src, dst, (hh, mm), tech, proto, acct in MOVEMENT_L:
        if src != host:
            continue
        out.append({
            "Type": "Lateral Movement", "Target": f"{src} -> {dst} ({proto})",
            "Verdict": LTP, "Confidence": "High", "MITRE": [tech], "observed_at": at(hh, mm),
            "src_host": src, "dst_host": dst, "technique": tech, "protocol": proto,
            "account": acct,
        })
    src, dst, (hh, mm), tech, proto, acct = ADMIN_HOP
    if src == host:
        out.append({
            "Type": "Lateral Movement", "Target": f"{src} -> {dst} ({proto})",
            "Verdict": IND, "Confidence": "Low", "MITRE": [tech], "observed_at": at(hh, mm),
            "src_host": src, "dst_host": dst, "technique": tech, "protocol": proto,
            "account": acct,
        })
    return out


def build():
    hosts = {}

    for idx, host in enumerate(FLEET):
        findings = list(benign_baseline(host, idx))
        principals = list(benign_principals())
        iocs = {}
        mem = []

        if host in RUSTFOX_HOSTS:
            findings += rustfox(host, idx)
            ip, domain = egress(host, idx)
            iocs = {"ip": [ip], "domain": [domain]}
            principals.append({"name": "deploy", "kind": "account"})
            mem = [domain, f"/dev/shm/.systemd-private/{PAYLOAD}", PERSIST_UNIT]
        elif host in CONTRACTOR_HOSTS:
            findings += contractor(host)
            principals.append({"name": CONTRACTOR_ACCT, "kind": "account"})
            mem = [CONTRACTOR_ACCT]

        findings += movement_findings(host)

        hosts[host] = {
            "hostname": host,
            "machine_id": machine_id(host),
            "incident_id": INC_L,
            "investigation": INV_L,
            "findings": findings,
            "iocs": {k: sorted(set(v)) for k, v in iocs.items() if v},
            "principals": principals,
            "memory_artifacts": mem,
            "capture": host in CAPTURED,
        }

    assert len(hosts) == 22, f"corpus L must be 22 endpoints, built {len(hosts)}"
    return hosts


def main(outdir):
    import os
    os.makedirs(outdir, exist_ok=True)
    hosts = build()
    for host, scenario in hosts.items():
        with open(os.path.join(outdir, f"{host}.json"), "w") as fh:
            json.dump(scenario, fh, indent=1, sort_keys=True)

    def compromised(s):
        return any(f["Verdict"] == LTP for f in s["findings"])

    manifest = {
        "endpoints": sorted(hosts),
        "investigations": {INC_L: INV_L},
        "compromised": sorted(h for h, s in hosts.items() if compromised(s)),
        "clean": sorted(h for h, s in hosts.items() if not compromised(s)),
        "captured": sorted(CAPTURED),
        "campaign_hosts": sorted(RUSTFOX_HOSTS),
        "tradecraft_only_hosts": sorted(UNTRACKED),
        "disjoint_hosts": sorted(CONTRACTOR_HOSTS),
        "ubiquitous_account": ROOT,
        "fleet_unit": FLEET_UNIT,
        "fleet_unit_same_shape": FLEET_UNIT_SAME_SHAPE,
        "persistence_unit": PERSIST_UNIT,
        "persistence_cron": PERSIST_CRON,
        "persistence_profile": PERSIST_PROFILE,
        "preload_library": PRELOAD_LIB,
        "staging_suffix": STAGING_SUFFIX,
        "admin_hop": list(ADMIN_HOP[:2]),
        "verdict_ceiling": LTP,
    }
    with open(os.path.join(outdir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    print(f"wrote {len(hosts)} endpoint scenarios + manifest -> {outdir}")
    print(f"  compromised: {len(manifest['compromised'])}  clean: {len(manifest['clean'])}"
          f"  captured: {len(manifest['captured'])}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "scenario-out-linux")

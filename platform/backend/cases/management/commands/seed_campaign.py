"""
Seed a multi-host intrusion across 20 endpoints, for exercising correlation and the
attack graph against data that has a known-correct answer.

The scenario is declarative (see CAMPAIGN below) and the command prints the ground truth
as JSON on completion, so the UAT asserts against the same facts the seed encodes rather
than against whatever the code happens to produce.

Three investigations, deliberately:
  * Ember Fox    — the intrusion: one initial vector, a credential-driven lateral chain,
                   and a blast radius spanning workstations, servers and both DCs.
  * Helpdesk     — clean hosts. Correlation must not manufacture links between them.
  * Cryptominer  — a genuinely separate compromise with disjoint IOCs and accounts. This is
                   the negative control: if correlation folds these hosts into Ember Fox,
                   it is matching on coincidence rather than shared evidence.

Usage: manage.py seed_campaign [--reset]
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone

from django.core.management.base import BaseCommand
from django.db import transaction

from cases.models import (
    Finding,
    Host,
    IOC,
    Investigation,
    MemoryAnalysisRun,
    MemoryCapture,
    MemoryFinding,
    Principal,
    CollectionRun,
)

DAY = datetime(2026, 7, 20, tzinfo=timezone.utc)


def at(hh, mm):
    return DAY + timedelta(hours=hh, minutes=mm)


def sha(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


# --- Shared intrusion evidence -------------------------------------------------------
# These values appear on every Ember Fox host and are what correlation must key on.
C2_IP = "198.51.100.23"
C2_DOMAIN = "updates.cdn-telemetry.net"
IMPLANT_SHA = sha("svchost_helper.exe")
IMPLANT = "svchost_helper.exe"

# Accounts, in the order the intrusion acquires them. Credential reuse is the strongest
# lateral-movement signal in the data, so the chain below is driven by it.
ACCT_USER = "CORP\\j.okafor"       # local admin harvested on patient zero
ACCT_SVC = "CORP\\svc_backup"      # service account harvested on the jump host
ACCT_DA = "CORP\\da_admin"         # domain admin obtained via DCSync

# --- The lateral chain ---------------------------------------------------------------
# (src, dst, time, ATT&CK technique, protocol, account used)
MOVEMENT = [
    ("WS-007", "JUMP-01", at(8, 52), "T1021.001", "RDP", ACCT_USER),
    ("JUMP-01", "SRV-FILE-01", at(9, 30), "T1021.002", "SMB", ACCT_SVC),
    ("JUMP-01", "DC-01", at(10, 5), "T1021.006", "WinRM", ACCT_SVC),
    ("DC-01", "SRV-DB-01", at(11, 0), "T1021.006", "WinRM", ACCT_DA),
    ("DC-01", "SRV-BACKUP-01", at(11, 20), "T1021.002", "SMB", ACCT_DA),
    ("DC-01", "DC-02", at(11, 45), "T1021.006", "WinRM", ACCT_DA),
    ("DC-01", "SRV-APP-01", at(12, 5), "T1021.006", "WinRM", ACCT_DA),
    ("DC-01", "WS-003", at(12, 20), "T1021.002", "SMB", ACCT_DA),
    ("DC-01", "WS-011", at(12, 30), "T1021.002", "SMB", ACCT_DA),
]

PATIENT_ZERO = "WS-007"

# Per-host activity beyond the movement itself: (type, target, verdict, confidence,
# mitre, time, source).
TP = "True Positive"
LTP = "Likely True Positive"
IND = "Indeterminate"

HOST_ACTIVITY = {
    "WS-007": [
        ("Phishing Attachment", "Q3_Budget_Review.xlsm", TP, "High", ["T1566.001"], at(8, 14)),
        ("Macro Execution", "EXCEL.EXE -> wscript.exe", TP, "High", ["T1204.002"], at(8, 22)),
        ("Implant Dropped", f"%APPDATA%\\{IMPLANT}", TP, "High", ["T1105"], at(8, 26)),
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", TP, "High", ["T1071.001"], at(8, 31)),
        ("Credential Dumping", "lsass.exe", TP, "High", ["T1003.001"], at(8, 47)),
        ("Remote System Discovery", "net view /domain", LTP, "Medium", ["T1018"], at(8, 49)),
    ],
    "JUMP-01": [
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", TP, "High", ["T1071.001"], at(9, 2)),
        ("Credential Dumping", "lsass.exe", TP, "High", ["T1003.001"], at(9, 10)),
        ("Scheduled Task Persistence", "\\Microsoft\\Windows\\UpdateOrchestrator\\Sync",
         TP, "High", ["T1053.005"], at(9, 18)),
    ],
    "SRV-FILE-01": [
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", TP, "High", ["T1071.001"], at(9, 40)),
        ("Data Staged", "D:\\shares\\finance\\_archive.7z", TP, "High", ["T1560.001"], at(9, 55)),
        ("Exfiltration Over C2", f"{C2_IP}:443 (2.4 GB)", TP, "High", ["T1041"], at(10, 15)),
        ("Scheduled Task Persistence", "\\Microsoft\\Windows\\UpdateOrchestrator\\Sync",
         TP, "High", ["T1053.005"], at(9, 44)),
    ],
    "DC-01": [
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", TP, "High", ["T1071.001"], at(10, 12)),
        ("DCSync", "CORP\\krbtgt", TP, "High", ["T1003.006"], at(10, 40)),
        ("Account Created", "CORP\\svc_monitor", TP, "High", ["T1136.002"], at(10, 48)),
        ("Service Persistence", "WinDefendHelper", TP, "High", ["T1543.003"], at(10, 52)),
    ],
    "DC-02": [
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", TP, "High", ["T1071.001"], at(11, 50)),
        ("Service Persistence", "WinDefendHelper", TP, "High", ["T1543.003"], at(11, 58)),
    ],
    "SRV-DB-01": [
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", TP, "High", ["T1071.001"], at(11, 8)),
        ("Database Dump", "corp_hr.bak", LTP, "Medium", ["T1005"], at(11, 30)),
    ],
    "SRV-BACKUP-01": [
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", TP, "High", ["T1071.001"], at(11, 26)),
        ("Backup Deletion", "vssadmin delete shadows /all", TP, "High", ["T1490"], at(11, 35)),
    ],
    "SRV-APP-01": [
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", TP, "High", ["T1071.001"], at(12, 10)),
    ],
    "WS-003": [
        ("Implant Dropped", f"%APPDATA%\\{IMPLANT}", TP, "High", ["T1105"], at(12, 24)),
        ("C2 Beacon", f"{C2_DOMAIN} ({C2_IP}:443)", LTP, "Medium", ["T1071.001"], at(12, 28)),
    ],
    "WS-011": [
        ("Implant Dropped", f"%APPDATA%\\{IMPLANT}", TP, "High", ["T1105"], at(12, 34)),
    ],
}

# Benign-but-noisy findings, so verdict filtering and triage have something to separate.
NOISE = [
    ("Package Manager Transaction", "package curl", IND, "Low", []),
    ("Scheduled Task", "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", IND, "Low", []),
    ("Autorun Entry", "OneDriveSetup.exe", IND, "Low", []),
]

CLEAN_EMBER = ["WS-001", "WS-002", "WS-004", "WS-005"]
HELPDESK = ["WS-006", "WS-008", "WS-009", "WS-010"]

# Negative control: real compromise, entirely disjoint evidence.
MINER_IP = "203.0.113.77"
MINER_DOMAIN = "pool.monero-hash.example"
MINER_ACCT = "CORP\\svc_render"
MINER_HOSTS = ["WS-012", "VPN-GW-01"]

SERVER_HOSTS = {"SRV-FILE-01", "SRV-DB-01", "SRV-APP-01", "SRV-BACKUP-01", "DC-01", "DC-02", "JUMP-01"}

# Hosts whose captures are retained, and which get server-side memory analysis.
CAPTURED = ["WS-007", "JUMP-01", "DC-01", "SRV-FILE-01", "SRV-DB-01", "DC-02"]
# One capture carries two analysis runs so the re-analysis diff has real input.
DIFF_HOST = "WS-007"


class Command(BaseCommand):
    help = "Seed a 20-host intrusion campaign for correlation and attack-graph testing."

    def add_arguments(self, parser):
        parser.add_argument("--reset", action="store_true",
                            help="Delete the seeded investigations before re-seeding.")

    @transaction.atomic
    def handle(self, *args, **opts):
        names = ["Ember Fox", "Helpdesk Triage", "Cryptominer Outbreak"]
        if opts["reset"]:
            Investigation.objects.filter(name__in=names).delete()

        ember = Investigation.objects.create(
            name="Ember Fox", incident_id="INC-2026-0143", operator="default-analyst",
            severity="critical", status="open",
            notes="Suspected spearphishing leading to domain-wide compromise.",
        )
        helpdesk = Investigation.objects.create(
            name="Helpdesk Triage", incident_id="INC-2026-0144", operator="default-analyst",
            severity="low", status="open", notes="Routine triage of user-reported slowness.",
        )
        miner = Investigation.objects.create(
            name="Cryptominer Outbreak", incident_id="INC-2026-0145", operator="default-analyst",
            severity="medium", status="open", notes="Unauthorized mining on two hosts.",
        )

        compromised = set(HOST_ACTIVITY)
        movement_by_dst = {dst: (src, t, tech, proto, acct)
                           for src, dst, t, tech, proto, acct in MOVEMENT}

        runs = {}

        def make_run(inv, hostname, collected, compromised_flag):
            host, _ = Host.objects.get_or_create(
                hostname=hostname,
                defaults={"platform": "windows",
                          "clock_context": {"tz": "UTC", "skew_seconds": 0}},
            )
            run = CollectionRun.objects.create(
                investigation=inv, host=host,
                stamp=collected.strftime("%Y%m%dT%H%M%SZ"),
                toolkit_version="2.4.0", overall_status="COMPLETED",
                custody_verified=True,
                custody_summary={"sealed": True, "algorithm": "sha256"},
                collected_at=collected, run_kind="initial",
            )
            runs[hostname] = run
            return run

        # --- Ember Fox: the intrusion ------------------------------------------------
        for hostname, activity in HOST_ACTIVITY.items():
            first = min(t for *_, t in activity)
            run = make_run(ember, hostname, first + timedelta(hours=6), True)

            for ftype, target, verdict, conf, mitre, when in activity:
                Finding.objects.create(
                    run=run, finding_type=ftype, target=target, verdict=verdict,
                    confidence=conf, mitre=mitre, source="collector",
                    subject_path=target,
                    raw={"observed_at": when.isoformat(), "campaign": "Ember Fox"},
                )

            # The movement that reached this host, recorded with both endpoints so the
            # graph is built from evidence rather than inferred from timing alone.
            mv = movement_by_dst.get(hostname)
            if mv:
                src, when, tech, proto, acct = mv
                Finding.objects.create(
                    run=run, finding_type="Lateral Movement", target=f"{src} -> {hostname} ({proto})",
                    verdict=TP, confidence="High", mitre=[tech], source="collector",
                    subject_path=proto,
                    raw={"observed_at": when.isoformat(), "src_host": src, "dst_host": hostname,
                         "technique": tech, "protocol": proto, "account": acct,
                         "campaign": "Ember Fox"},
                )

            for ftype, target, verdict, conf, mitre in NOISE:
                Finding.objects.create(
                    run=run, finding_type=ftype, target=target, verdict=verdict,
                    confidence=conf, mitre=mitre, source="collector",
                    raw={"benign": True},
                )

            # Shared indicators — the correlation key.
            IOC.objects.create(run=run, ioc_type="ip", value=C2_IP,
                               context={"role": "c2", "campaign": "Ember Fox"})
            IOC.objects.create(run=run, ioc_type="domain", value=C2_DOMAIN,
                               context={"role": "c2"})
            if hostname in (PATIENT_ZERO, "WS-003", "WS-011"):
                IOC.objects.create(run=run, ioc_type="hash", value=IMPLANT_SHA,
                                   context={"file": IMPLANT})
            if any("T1003" in m for *_, m, _ in activity):
                IOC.objects.create(run=run, ioc_type="tool", value="mimikatz",
                                   context={"detected_in": "memory"})

            # Accounts implicated on this host: the one used to reach it, plus any
            # harvested here.
            accts = set()
            if mv:
                accts.add(mv[4])
            if hostname == PATIENT_ZERO:
                accts.add(ACCT_USER)
            if hostname == "JUMP-01":
                accts.add(ACCT_SVC)
            if hostname == "DC-01":
                accts.update({ACCT_DA, "CORP\\svc_monitor"})
            for a in sorted(accts):
                Principal.objects.create(run=run, name=a,
                                         context={"campaign": "Ember Fox", "host": hostname})

            run.tp_count = run.findings.filter(verdict=TP).count()
            run.evaluate_compromise()
            run.save()

        # Clean hosts inside the same investigation.
        for hostname in CLEAN_EMBER:
            run = make_run(ember, hostname, at(14, 0), False)
            for ftype, target, verdict, conf, mitre in NOISE:
                Finding.objects.create(run=run, finding_type=ftype, target=target,
                                       verdict=verdict, confidence=conf, mitre=mitre,
                                       source="collector", raw={"benign": True})
            run.evaluate_compromise()
            run.save()

        # --- Helpdesk: clean ---------------------------------------------------------
        for hostname in HELPDESK:
            run = make_run(helpdesk, hostname, at(15, 0), False)
            for ftype, target, verdict, conf, mitre in NOISE:
                Finding.objects.create(run=run, finding_type=ftype, target=target,
                                       verdict=verdict, confidence=conf, mitre=mitre,
                                       source="collector", raw={"benign": True})
            run.evaluate_compromise()
            run.save()

        # --- Cryptominer: separate compromise, disjoint evidence ---------------------
        for hostname in MINER_HOSTS:
            run = make_run(miner, hostname, at(16, 0), True)
            Finding.objects.create(
                run=run, finding_type="Coin Miner", target="xmrig.exe", verdict=TP,
                confidence="High", mitre=["T1496"], source="collector",
                raw={"observed_at": at(16, 0).isoformat(), "campaign": "Cryptominer"},
            )
            Finding.objects.create(
                run=run, finding_type="C2 Beacon", target=f"{MINER_DOMAIN} ({MINER_IP}:3333)",
                verdict=TP, confidence="High", mitre=["T1071.001"], source="collector",
                raw={"observed_at": at(16, 5).isoformat(), "campaign": "Cryptominer"},
            )
            IOC.objects.create(run=run, ioc_type="ip", value=MINER_IP, context={"role": "pool"})
            IOC.objects.create(run=run, ioc_type="domain", value=MINER_DOMAIN,
                               context={"role": "pool"})
            Principal.objects.create(run=run, name=MINER_ACCT, context={"campaign": "Cryptominer"})
            run.tp_count = run.findings.filter(verdict=TP).count()
            run.evaluate_compromise()
            run.save()

        # --- Memory captures + server-side analysis ----------------------------------
        for hostname in CAPTURED:
            run = runs[hostname]
            size = 256 * 1024**3 if hostname in SERVER_HOSTS else 32 * 1024**3
            cap = MemoryCapture.objects.create(
                run=run, store_backend="minio", bucket="ir-evidence",
                object_key=f"INC-2026-0143/{hostname}/memory_{hostname}.aff4",
                etag=sha(f"etag-{hostname}")[:32], size_bytes=size,
                sha256=sha(f"capture-{hostname}"), image_format="aff4",
                capture_tool="avml", is_synthetic=True,
                symbol_context={"kernel": "10.0.20348", "isf": "ntkrnlmp-10.0.20348.json"},
                retention_status="retained",
                retention_reason="host assessed compromised — retained as evidence",
            )
            self._analyze(cap, hostname, "current", at(18, 0))
            if hostname == DIFF_HOST:
                # An earlier pass with a weaker ruleset, so the diff shows real gain.
                self._analyze(cap, hostname, "2026.05", at(9, 0), reduced=True)

        truth = {
            "investigations": {"ember": ember.id, "helpdesk": helpdesk.id, "miner": miner.id},
            "hosts_total": Host.objects.count(),
            "patient_zero": PATIENT_ZERO,
            "ember_compromised": sorted(compromised),
            "ember_compromised_count": len(compromised),
            "movement_edges": len(MOVEMENT),
            "shared_c2_ip": C2_IP,
            "shared_c2_domain": C2_DOMAIN,
            "accounts": [ACCT_USER, ACCT_SVC, ACCT_DA],
            "miner_hosts": MINER_HOSTS,
            "miner_ip": MINER_IP,
            "clean_hosts": sorted(CLEAN_EMBER + HELPDESK),
            "captures": len(CAPTURED),
            "diff_host": DIFF_HOST,
        }
        self.stdout.write(json.dumps(truth, indent=2))

    def _analyze(self, cap, hostname, ruleset, when, reduced=False):
        """One server-side analysis pass over a capture."""
        run = MemoryAnalysisRun.objects.create(
            capture=cap, engine="native-scan", engine_version="1.0",
            ruleset_version=ruleset, status="completed",
            started_at=when, finished_at=when + timedelta(minutes=12),
        )
        findings = [
            ("External IPv4 in memory", "Medium", f"routable address {C2_IP} present 1632x in image", 0),
            ("URL in memory", "Medium", f"http://{C2_DOMAIN}/payload/stage2.bin", 1572864),
            ("High-entropy region (packed/encrypted candidate)", "Low", "entropy 7.999", 1835008),
        ]
        if not reduced:
            findings += [
                ("Credential material in memory", "High",
                 "LSASS-derived secret pattern near cached logon", 2621440),
                ("Injected thread (no backing file)", "High",
                 f"RX private memory in {IMPLANT}", 3145728),
                ("Known tool signature", "Critical", "mimikatz sekurlsa module string", 4194304),
            ]
        for ftype, sev, detail, off in findings:
            MemoryFinding.objects.create(
                analysis=run, finding_type=ftype, severity=sev, detail=detail,
                offset=off or None, evidence={"host": hostname, "ruleset": ruleset},
            )
        run.summary = {"finding_count": len(findings), "ruleset_version": ruleset,
                       "image_size_bytes": cap.size_bytes}
        run.save()

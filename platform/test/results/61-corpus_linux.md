## Corpus L — 22 Linux endpoints, end to end

*What passing proves:* A Linux-native intrusion correlates through the production path on the Linux hunts' own vocabulary and verdict ceiling: persistence names reach the graph, two hosts reached without any movement record join on tradecraft alone, an unrelated compromise on the same fleet stays separate, and the estate's own units and accounts bind nothing.

- Run: `uat_corpus_linux.sh` — 2026-08-12 14:24:28Z

**Preconditions**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | ir-dmz_receiver_1 running |
| ✅ PASS | ir-enclave_puller_1 running |
| ✅ PASS | ir-enclave_backend_1 running |
| ✅ PASS | ir-enclave_worker_1 running |
| ✅ PASS | collector image current with collector/ |
| ✅ PASS | the collector runs the full forensics collection (--deep) |
| ✅ PASS | 22 Linux endpoint scenarios generated |
| ✅ PASS | manifest published to the backend for comparison |
| ✅ PASS | prior INC-CORPUS-L data reset (real evidence untouched) |
| ✅ PASS | receiver holds an address on the edge network |

**Collection — 22 real collector runs, shipped from the edge**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 22 bundles collected, sealed and accepted by the receiver |

**Ingest — the puller delivers all 22 runs**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 22 INC-CORPUS-L runs ingested through receiver -> puller -> ingest |
| ✅ PASS | 22 distinct hosts with 22 distinct machine ids — no endpoint merged into another |

**Analysis — every capture is analyzed and adjudicated before compromise is read**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | captures terminal and compromise settled (22 analyzed, 10 compromised) |
| ✅ PASS | every analysis completed (22) |
| ✅ PASS | every analysis was adjudicated by the investigation engine (22) |

**Correlation**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | correlation ran for INC-CORPUS-L (1 investigation(s)) |

**Classification — the Linux verdict ceiling still separates compromised from clean**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | 10 endpoints classify compromised, exactly the planted set |
| ✅ PASS | 12 endpoints classify clean despite carrying the full fleet baseline |
| ✅ PASS | no finding reaches True Positive — Linux adjudication's ceiling is intact (['Indeterminate', 'Likely False Positive', 'Likely True Positive']) |
| ✅ PASS | the fleet's packaged SUID binary is adjudicated a likely false positive on every host (22) |

**L0 — Linux tradecraft reaches the graph as artifacts, named by what the actor chose**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the persistence unit is an artifact node valued 'sysstat-collector.service' on 4 host(s) |
| ✅ PASS | the cron entry is an artifact node valued 'certbot-renew-helper' on 3 host(s) |
| ✅ PASS | the shell-init backdoor is an artifact node valued '00-locale-fix.sh' on 2 host(s) |
| ✅ PASS | the preloaded library is an artifact node valued 'libnss_cache.so.2' on 3 host(s) |
| ✅ PASS | the webshell is an artifact node valued '.sess_handler.php' on 1 host(s) |
| ✅ PASS | the kernel module is an artifact node valued 'nf_conntrack_helper.ko' on 1 host(s) |
| ✅ PASS | no persistence artifact carries its mandatory directory — the path is the platform's, the name is the actor's |
| ✅ PASS | the payload keeps the directory it was placed in (/dev/shm/.systemd-private/kdevtmpfsi) |
| ✅ PASS | the estate's own node_exporter.service is on all 22 hosts, not a rare artifact |
| ✅ PASS | the estate's own fwupd-refresh.service is on all 22 hosts, not a rare artifact |

**L1/L2 — the campaign holds together, including the hosts no movement record reaches**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | all 8 Rust Fox hosts are one campaign |
| ✅ PASS | build-02 is a member with no movement record anywhere |
| ✅ PASS | and it is held by persistence_shell_init evidence, not movement (weight 0.5086) |
| ✅ PASS | ci-runner-01 is a member with no movement record anywhere |
| ✅ PASS | and it is held by persistence_cron evidence, not movement (weight 0.4613) |
| ✅ PASS | dev-ws-02 — an unrelated compromise on the same fleet — does not join Rust Fox |
| ✅ PASS | dev-ws-03 — an unrelated compromise on the same fleet — does not join Rust Fox |
| ✅ PASS | the routine bastion-01 -> dev-ws-02 admin session is DECLINED (weight 0.2499, verdict factor 0.25) |
| ✅ PASS | no clean endpoint appears in any campaign (12 clean) |
| ✅ PASS | no pair is joined by 'root', present on every host in the estate |
| ✅ PASS | patient zero is the exposed web host (web-edge-02) |

**L4 — the fingerprint is the actor's habits, not the distribution's**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the campaign has naming conventions at all (10): ['persistence_service:<name>-<name>.service', 'persistence_preload:<name>_<name>.so.2', 'persistence_shell_init:<number>-<name>-<name>.sh', 'kernel_module:nf_<name>_<name>.ko'] |
| ✅ PASS | the estate's node_exporter.service is not reported as this actor's tradecraft |
| ✅ PASS | the estate's fwupd-refresh.service is not reported as this actor's tradecraft |
| ✅ PASS | the actor's unit naming habit is reported (persistence_service:<name>-<name>.service) |
| ✅ PASS | and it names the collected value it was abstracted from (sysstat-collector.service) |
| ✅ PASS | the technique sequence opens on the exploited service (['T1190', 'T1548', 'T1071', 'T1098', 'T1505']) |
| ✅ PASS | movement is recorded as SSH (['SSH']) |
| ✅ PASS | the account shape records no domain style, because Unix accounts have none |

**L5 / population — an unrelated fleet in the same deployment changes nothing**

| Result | Assertion — with evidence |
|---|---|
| · | deployment host population at correlation time: 92 |
| ✅ PASS | Rust Fox is not attributed to the Windows actor — no habit is shared |
| ✅ PASS | INC-CORPUS-A still classifies 12 compromised with a larger fleet around it |
| ✅ PASS | INC-CORPUS-B still classifies 4 compromised with a larger fleet around it |
| ✅ PASS | no INC-CORPUS-A campaign reaches a Linux endpoint |
| ✅ PASS | no INC-CORPUS-B campaign reaches a Linux endpoint |

**Verdict: PROVEN** — 55 assertions passed, 0 failed.

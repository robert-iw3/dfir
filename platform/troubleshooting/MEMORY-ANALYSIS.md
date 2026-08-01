# Memory analysis — diagnosing a run

Every technique here was used to find a real fault while validating this path against a
24 GB capture. The failures worth knowing about are the **silent** ones: the platform
reports a completed analysis while having done less than it appears to.

Companion docs: [`RUNBOOK.md`](RUNBOOK.md) (symptom → cause → fix),
[`COMPONENTS.md`](COMPONENTS.md) (hop-by-hop), [`../symbols/README.md`](../symbols/README.md)
(acquiring symbol tables).

---

## Is it actually running, and what phase?

```bash
podman exec ir-enclave_worker_1 sh -c \
  'ps -eo pid,etime,time,stat,args | grep -E "[a]nalyze_memory|[v]ol " | cut -c1-110'
```

The parent `analyze_memory_linux.py` sits in `S` (sleeping) with almost no CPU while each
Volatility plugin runs as a child — that is normal, not a hang. A child in `R`/`RN`
accumulating CPU is the work. **No child at all, with the parent burning CPU, means the
structural fallback is running instead of Volatility.**

Phase by output:

```bash
podman exec ir-enclave_worker_1 sh -c 'ls -la /scratch/memanalysis-*/'
```

| Present | Phase |
|---|---|
| nothing | still staging the capture, or the deep pass never started |
| `_yara_compiled_*.yarc` | rules compiled, plugin sweep under way |
| `_yara_results_*.jsonl` | YARA scanning |
| `carved/` with `.bin` files | regions being extracted |
| `Memory_Findings_*.json` | finished |

## Which engine actually ran?

A run that fell back still says `completed`. The engine is the tell:

```bash
podman exec ir-enclave_backend_1 python -c "
import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings'); django.setup()
from cases.models import MemoryAnalysisRun
for r in MemoryAnalysisRun.objects.order_by('-id')[:5]:
    print(r.id, r.status, r.engine, (r.error or '')[:120])"
```

`engine=native-scan` while a symbol table exists means the Volatility pass was attempted
and failed. The reason is saved to `error` as soon as the fallback happens.

## Did the symbol table resolve?

```bash
podman exec ir-enclave_worker_1 python -c "
import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings'); django.setup()
from cases.models import MemoryCapture
from cases import symbols
cap = MemoryCapture.objects.latest('id')
print('context:', cap.symbol_context)
print('resolved:', repr(symbols.find_isf(cap)))"
```

Empty means no table matched. The lookup tries the recorded key, the build-id, a
distro-qualified name, the bare release, and finally any table whose filename ends with the
release — so an empty result means the store genuinely lacks that kernel, not a naming
mismatch.

## Reading the kernel out of an image

Useful when a capture arrives without requisites:

```bash
podman run --rm --user root -v <dir>:/img:ro,z --entrypoint vol \
  localhost/ir-worker:latest -q -f /img/<capture> banners.Banners
```

`--user root` matters: under rootless podman the container's root maps to the invoking host
user, which is what can read a capture written `0600`. Without it the scan fails with
`Permission denied` and reports no banner.

Expect several banners from one image — kernel strings persist in memory from earlier boots
and from unrelated data. The live kernel is the most complete and most frequent one.

## Carving produced nothing

Carving only happens in the per-process YARA engine. The analyzer's default `native` engine
scans the whole image and reports matches without attributing them to a process, so there is
nothing to extract and `--carve` is silently a no-op.

```bash
podman exec ir-enclave_worker_1 sh -c 'ps -eo args | grep "[a]nalyze_memory" | tr " " "\n" | grep -A1 yara-engine'
```

Should print `vol`. Override with `IR_YARA_ENGINE`; set `IR_CARVE_ANY=1` to carve every hit
rather than only injected (anonymous + executable) regions.

## The same capture is being analyzed twice

```bash
podman exec ir-enclave_worker_1 sh -c 'ls -d /scratch/memanalysis-*/ /scratch/ir-mem-*/'
podman exec ir-enclave_backend_1 python -c "
import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings'); django.setup()
from cases.models import MemoryAnalysisRun
print(list(MemoryAnalysisRun.objects.filter(status='running').values_list('id','capture_id')))"
```

Two `running` rows for one capture means the broker redelivered the task. With `acks_late`
the acknowledgement comes at the end of the analysis, and Redis hands a task to another
worker once its **visibility timeout** expires — a default of one hour, against a pass that
runs longer than that. The second copy is not a retry of a failure: the first is still
running, and now both stage their own 24 GB image and compete for the same disk, which is
what makes MinIO start answering `SlowDownRead`.

`CELERY_BROKER_TRANSPORT_OPTIONS["visibility_timeout"]` is derived from `IR_VOL3_TIMEOUT`
for this reason. Raising the analysis timeout without raising it is what reintroduces this.

Clearing a duplicate that is already running — keep the older run, it is further along:

```bash
podman exec ir-enclave_worker_1 sh -c 'celery -A ir_platform purge -f'   # queued copies
podman exec ir-enclave_worker_1 sh -c 'pkill -f "memanalysis-<dir-of-the-duplicate>"'
podman exec ir-enclave_backend_1 python manage.py reap_stale_analyses
```

Then remove the abandoned staging directory — it holds a whole capture.

## Staging capacity

```bash
podman exec ir-enclave_worker_1 sh -c 'df -h /scratch; du -sh /scratch/*'
```

Staging is disk-backed on purpose — a capture does not fit in a tmpfs, and a tmpfs is RAM.
Budget the capture size again on local disk on top of the object store's copy. A preflight
check refuses the run when the staging area is too small, rather than failing part-way
through the transfer.

A killed worker leaves its staging directory behind. Clean it and close out the run:

```bash
podman exec ir-enclave_worker_1 sh -c 'rm -rf /scratch/ir-mem-*'
podman exec ir-enclave_backend_1 python manage.py reap_stale_analyses --dry-run
```

## Findings exist but the run shows none

Memory findings are stored against the analysis and **promoted** into findings on the run so
they can be triaged. If the capture panel shows results while `Findings (0)` sits above it,
promotion has not run:

```bash
podman exec ir-enclave_backend_1 python manage.py promote_findings
```

Promotion is idempotent and happens automatically when an analysis completes; the command
is for analyses that finished before it was wired in.

## Adjudication did not run

Verdicts come from the toolkit's investigation engine, which runs automatically once the
memory pass completes. The result of that step is recorded on the analysis:

```bash
podman exec ir-enclave_backend_1 python -c "
import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings'); django.setup()
from cases.models import MemoryAnalysisRun
r = MemoryAnalysisRun.objects.latest('id')
print(r.summary.get('adjudication'))
print('processes judged:', r.process_verdicts.count())"
```

`{'ran': False, 'reason': ...}` says why. The reasons that matter:

| Reason | Meaning |
|---|---|
| `investigation engine not present under /opt/toolkit` | the worker image predates the engine being staged — rebuild with `backend/build_worker.sh` |
| `engine found no usable findings` | the report folder held nothing the engine parses |
| `RuntimeError: investigation engine produced no report` | the engine ran and failed; its last lines are in the reason |

Confirm the engine is in the image at all:

```bash
podman exec ir-enclave_worker_1 sh -c 'PYTHONPATH=/opt/toolkit python3 -c "from playbooks.linux.investigation import live_runner; print(\"ok\")"'
```

Re-run it over stored evidence — no Volatility pass, so this is quick:

```bash
podman exec ir-enclave_worker_1 python manage.py adjudicate --analysis <id>
```

## Everything came back Undetermined

Usually correct rather than broken. The engine's trust anchor is **provenance** — package
ownership, package integrity, path trust — and those fields come from the collector, not
from memory. A capture analyzed without its collection bundle gives the engine behavior
without ownership, and its threshold for a true positive is three independent positive
dimensions. Check what it actually loaded:

```bash
podman exec ir-enclave_backend_1 python -c "
import os,django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','ir_platform.settings'); django.setup()
from cases.models import MemoryAnalysisRun, Finding
r = MemoryAnalysisRun.objects.latest('id')
print('source files:', r.investigation.get('summary', {}).get('source_files'))
print('collector findings on the run:', Finding.objects.filter(run=r.capture.run, source='collector').count())"
```

`source_files` listing only `Memory_Findings_*` means no collector evidence was staged. Once
the host's bundle is ingested, re-run `manage.py adjudicate --analysis <id>` and the same
memory findings can reach a different verdict.

A single-mechanism signal repeated across many PIDs is also downgraded on purpose — the
engine's false-positive closure treats "seven processes all show this one thing" as an
argument for a systemic artifact, not seven intrusions. That rationale is recorded verbatim
on each finding under `raw.adjudication`.

## A finding names ordinary software as C2 or malware

The config extractors (`mwcp_parsers/`) run over carved regions and over on-disk files, and a
region is process memory: it holds every URL, token and quoted rule the process has touched.
A parser keyed on string presence reports that content as a recovered configuration. Before
treating such a finding as real, check what the parser matched on rather than what it named.

Confirm whether the shape is a general defect or specific to this capture by running the
catalog over ordinary content on an uncompromised host — nothing there is malicious, so every
finding it prints is a false positive:

```bash
python3 test/linux/lab_mwcp/fp_corpus_audit.py
```

A clean run prints `TOTAL false findings: 0`. Anything above that is a parser defect, not a
tuning preference; `planning/BACKLOG.md` §12b records the last measured baseline, the defect
classes already fixed, and the ones still open.

The audit reads files, so it exercises the same path as `edr_hunt.py`'s on-disk structural
pass. It cannot reproduce heap content, which is where the original false positives came from
— for that, carve regions from a real capture and run `extract_all()` against them.

Two gates already sit in front of these parsers, and a finding that reaches an analyst has
passed both. `driver.extract_all()` suppresses any region that is overwhelmingly prose, so
documentation, notes and rule sources never produce a configuration. Individual parsers
require their signals to be co-located, because two matches at opposite ends of a megabyte
region are not one structure. A finding that survives both and still looks wrong is worth
reporting as a defect rather than reclassifying by hand.

## Results are correct but nothing renders in the web app

Check the chain the browser uses, not the API directly — a probe inside the backend proves
nothing about traefik, oauth2-proxy or nginx:

```bash
podman run --rm --network ir-edge --dns <DNS_EDGE_IP> --entrypoint python3 \
  -v /path/to/probe.py:/m.py:ro,z localhost/ir-browser:latest /m.py
```

A `502` on `/api/*` while the backend is healthy means nginx is holding a stale upstream
address — see the corresponding RUNBOOK entry. Bring tiers up with `deploy.sh`, which
sequences them; recreating containers individually is what causes it.

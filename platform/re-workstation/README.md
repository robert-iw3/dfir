# RE workstation — a disassembler over live malware, with nothing to reach

Component reference for the reverse-engineering tier. The workflow an RE follows is in
[`WORKFLOW-RE.md`](../WORKFLOW-RE.md); this covers what the component *is*, how it is
contained, and what the containment costs.

Carved regions are live malware taken out of a memory image. This is the most hazardous
interactive surface in the platform, and its threat direction is the reverse of the analyst
tier: that one is hardened to stop evidence getting **out**, this one to stop malware getting
**anywhere**.

---

## 1. Containment

A session runs with:

| Control | Effect |
|---|---|
| `--network none` | no network namespace at all — not a firewall rule, an absence |
| `--cap-drop ALL` | no capabilities |
| `--security-opt no-new-privileges` | a setuid binary inside cannot escalate |
| `--userns=keep-id:uid=1001,gid=1001` | runs as an unprivileged user mapped to the caller |
| `/regions:ro` | the samples are read-only |
| `--memory` (default 4g) | a sample cannot exhaust host memory |
| `--rm` | the container and everything it wrote are destroyed on exit |

Both tools are free of licensing, activation and call-home, which is what makes
`--network none` possible rather than aspirational — nothing in a session has any reason to
reach the network, so it is given no way to. Network exists only while the **image is built**.

The workstation holds **no credentials and never reaches the object store.** Regions arrive
through a mediator (§3), not by the session fetching them.

---

## 2. Files

| File | Purpose |
|---|---|
| `Dockerfile` | Binary Ninja Free on Debian 12, pinned by digest |
| `Dockerfile.ghidra` | Ghidra, same containment |
| `launch.sh` | starts one session over one host's staged regions |
| `stage_regions.sh` | the mediator: pulls one host's regions from the object store |
| `binja-settings.json` | preferences mounted read-only — update checks and telemetry pinned off |
| `ghidra-session.sh` | in-container entrypoint for the Ghidra path |

`binja-settings.json` is mounted **read-only on purpose**. A session opening live malware does
not get write access to its own security settings; a sample able to edit them could re-enable
call-home for every session that follows. Change preferences on the host.

---

## 3. Running a session

```bash
./stage_regions.sh --host WS-007
./launch.sh --host WS-007
```

Staging is a separate step with object-store access, so the session itself needs none. One
host per session: carved regions live in a bucket per host, so a session can be handed exactly
one investigation's malware and nothing else.

Tool selection is narrowest-first — `--tool binja|ghidra`, then an exported `IR_RE_TOOL`, then
the deployment default in `deploy/.env`. The containment is identical either way; only the
disassembler differs.

`launch.sh` refuses to open a session over zero regions. An empty session is
indistinguishable from a broken one — the tool starts, the file list is empty, and nothing
says whether the analysis carved nothing or the mount failed to arrive.

---

## 4. The display

The session window arrives over a mounted X11 socket with the caller's auth cookie passed
explicitly, rather than by opening the host display with `xhost +local:`. Loosening host
access for every local client, in order to run a session that opens live malware, is the wrong
trade. On a Wayland desktop the socket alone is not enough: Xwayland issues a cookie, and
without it the tool reports itself as running headless — which reads as a broken image rather
than a missing credential.

`DISPLAY` unset is reported by the launcher, not left to a Java stack trace inside the
container.

---

## 5. Ghidra's divergence

Ghidra cannot open a file from a read-only mount the way Binary Ninja does: a region must be
imported into a project, and a project is a directory it writes to. Its launcher also resolves
and then **saves** the JDK path under the user's home, and treats being unable to write there
as "no JDK found" — falling back to a prompt that, with no TTY, aborts every import with an
error about the prompt rather than about Java.

So the project and the home directory share one writable tmpfs, with the mode set explicitly:
podman copies the image directory's permissions onto a tmpfs without its ownership, so mounting
over `/home/ghidra` otherwise yields a root-owned `0700` directory the session user cannot
write to.

Everything ephemeral in one tmpfs also means the analysis database built from live malware
dies with the container — the same lifetime the Binary Ninja path gets by mounting only its
settings file.

---

## 6. Proof

`test/uat_re_workstation.sh` asserts the containment: no network namespace, no capabilities,
read-only regions, no credentials present, and that the staged set belongs to exactly one host.

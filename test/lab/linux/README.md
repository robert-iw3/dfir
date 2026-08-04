# Linux endpoint lab

A disposable container stands in for a compromised endpoint. A scenario plants real artifacts
inside it, the **real** `Invoke-IRCollection-Linux.sh` runs against them, and the assertions ask
one question: *did the collection bring back what we know was there?*

Nothing about the collector is stubbed. A FAIL here is a collection gap, not a broken test —
the artifact was demonstrably on the endpoint and the collection did not return it.

## Run

```bash
test/lab/linux/run_lab.sh                    # every scenario, the profile the platform ships
test/lab/linux/run_lab.sh --shallow          # without --deep
test/lab/linux/run_lab.sh --compare          # both, side by side
test/lab/linux/run_lab.sh --distro=fedora    # against an RPM endpoint
test/lab/linux/run_lab.sh package_integrity --distro=alpine
```

`--compare` prints exactly what a profile gives up — a number rather than an opinion.

## Scenarios

| Scenario | Covers |
|---|---|
| `initial_access_webshell` | webshells detected by content, not filename |
| `novice_persistence` | cron, systemd, OpenRC, authorized_keys, SUID, `ld.so.preload`, shell init |
| `privesc_credaccess` | file capabilities, sudoers, shell history, `known_hosts` |
| `credaccess_staging` | credential files staged for collection |
| `defense_evasion_impact` | emptied logs, neutered history, queued at-jobs |
| `antiforensics_residency` | deleted-but-running binaries, unlinked payloads held open, wtmp truncation |
| `login_record_tampering` | one login removed from wtmp while lastlog still records it |
| `kernel_bpf_state` | loaded modules, eBPF objects, kernel taint |
| `timeline_timestomp` | MACB body-file timeline, ctime/mtime divergence |
| `package_integrity` | a backdoored package-owned binary, per package manager |
| `benign_workstation` | the control — what the collection said that it should not have |

`benign_workstation` is the only one that asks *what else did you say?*. Every other scenario
is satisfied by a detector that fires on everything.

## The distro is a dimension

The trust anchor is package ownership and integrity, and `pkg_modified()` branches per package
manager — `debsums`, `rpm -Vf`, `pacman -Qkk`, `apk audit`. A branch that never executes is a
trust anchor nobody has weighed.

Three endpoints run today (Debian, Fedora, Alpine); `pacman` is unexercised. Add one by
dropping in `Dockerfile.<name>` with that endpoint's own tooling — package names differ
(`procps-ng` not `procps`), the scenarios do not change.

Two things bite when adding a distro. Alpine's busybox and coreutils are multi-call binaries
that dispatch on `argv[0]`, so a plant that copies `/bin/sleep` under a new name silently
exits before collection runs — copy the Python interpreter instead, which ignores `argv[0]`.
And an endpoint may not run the subsystem an expectation names; use `requires`.

## Writing a scenario

```jsonc
{
  "name": "...", "incident_id": "IR-LAB-...",
  "plant":  [ {"id": "suid", "type": "suid", "path": "/usr/local/bin/ir-lab-suid"} ],
  "expect": [ {"id": "SUID binaries are collected",
               "artifact": "suid_sgid_files.txt", "contains": "ir-lab-suid",
               "needs_plant": "suid"} ]
}
```

**Expectations name the artifact, never where it came from.** Loose files under the host folder
and members of the deep collector's tarball are both searched, so one expectation holds across
both profiles — which is what makes `--compare` meaningful. A `*` in the path is a glob, for
artifacts named after runtime facts such as a holder's pid.

`needs_plant` ties an expectation to its plant. A plant that could not run — no
`CAP_LINUX_IMMUTABLE` for `chattr +i`, no kernel support — reports **SKIP** and is scored
neither way. An unprovable claim has to look unproven; the one thing this harness must never do
is go green because the evidence was never planted.

`requires` guards an expectation on a subsystem the endpoint may not run (`systemd`, `openrc`).
A statement about the distro is not a statement about the collector.

### Expectation forms

| Form | Claim |
|---|---|
| `artifact` + `contains` | the collection returned the file, carrying the value |
| `finding_contains` | a hunt phase **flagged** it — collected *and* understood |
| `finding_contains: {type, contains}` | one named check flagged it, so two checks covering the same artifact cannot stand in for each other |
| `finding_absent` | the control: it discriminates rather than merely triggers |
| `adjudication: {subject_contains, field, equals\|contains}` | reads the record by field, not by grepping its JSON |
| `max_findings: {type\|severity, at_most}` | a cap |
| `only_types: {allow: {type: cap}}` | allow-list — anything undeclared fails |

`only_types` is the strongest form and the only one that constrains checks nobody thought to
name. Prefer it over a cap when adding to `benign_workstation`.

## Design notes

**The toolkit is mounted read-only from the working tree**, never baked into the image, so a
run always exercises the code being edited.

**Narrow capabilities, not `--privileged`.** The lab should reflect what a collector sees with
the privileges it is actually given.

**The host is never touched.** Everything is planted inside the container, which is removed when
the run ends.

## Not covered here

- **Discovery, lateral movement, exfiltration.** A believable exfil test needs a peer the
  container can reach, which the isolated network denies by design.
- **Container escape.** `container_hunt.py` skips cleanly with no runtime present.
- **A loaded eBPF program.** State is collected; detection needs `CAP_BPF` and a compiler.
- **`chattr +i`** and anything else overlayfs will not honor — needs a VM-backed endpoint.
- **An Arch endpoint**, for the one package-integrity branch never executed.

What each round of this lab found, and why each check is shaped the way it is, lives in
`planning/LINUX-ENDPOINT-COVERAGE.md` and the change logs.

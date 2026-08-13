# Change management — decide the blast radius before writing the change

Third companion to the two reference maps. `CODE_GRAPH.md` shows how the *code* fits together.
`troubleshooting/TOPOLOGY.md` shows how the *running system* does. This one is used **before**
a change, not after it: look up what you are about to touch, and it tells you the full set of
things that have to move with it.

Used that way a change lands complete in one pass. Used afterwards it is a list of things
already wrong.

The reason it exists: nothing on the surface of this platform announces its own staleness. A
diagram showing a hop that no longer exists renders fine. A CI gate resolving a path that
moved exits non-zero for a reason nobody reads. An ACL admitting three ports nothing listens
on passes every test. A UAT asserting the shape a design deliberately replaced simply fails,
and looks like a regression. Each of those reads as working, or as somebody else's problem.

---

## 1. Change intake — do this first

1. **Write the plan before the change.** Anything beyond a local fix gets a section in the
   relevant `planning/` document *first*, stating: the problem with its measurement, the
   options considered and why one was chosen, the scope it touches (from §3), what proves it,
   and what is explicitly out of scope. A change with no plan has no agreed scope, so nothing
   can be said to be missing from it — which is how work arrives complete and wrong.
2. **Name the change type** and read its row in §3. That row is the initial scope, not a
   suggestion.
3. **Grep for the thing you are changing** — the port number, the service name, the variable,
   the route. Every hit is in scope until you have decided otherwise. `grep -rn` across the
   tree costs ten seconds and is the single most reliable step here.
4. **Write down what you will not do**, in the plan and in `CONSOLIDATED-BACKLOG.md`. Scope
   silently dropped is scope nobody knows is missing.
5. **Then write the change**, its assertion, and its documentation together.
6. **Close the plan out** with what was delivered and what the change *exposed* — the second
   is usually the more valuable half, and it is the half that gets lost.

The order matters. Deciding scope after the code is written turns every discovery into a
choice between widening the change and leaving something wrong. Deciding it beforehand turns
the same discovery into a line in the plan.

**The plan is a working document, not a proposal.** It is revised as measurements come in —
including when a measurement contradicts the plan's own premise, which is a result worth
recording rather than an embarrassment to quietly correct.

---

## 2. Ground rules

**0. Plan the change before making it.** The scope is decided in `planning/` in advance, not
discovered while implementing. See §1 — this is the rule the rest of them depend on, because
every other obligation here is only checkable against a stated scope.

**1. The codebase performs the change, never the operator.** A hand-run command that fixes
something is a defect report, not a fix. If a container had to be restarted by hand, or config
written by hand, or a session cancelled by hand to make things work, the change is not done —
the script that deploys it has to do it. Anything else means the next deployment starts broken
and nobody knows why.

**2. A change is not done until an assertion proves it.** Not "it works now", not a passing
health check — an assertion in a UAT that fails if the property is lost. The verdict must be
able to say *cannot verify* as a third answer distinct from pass and fail; a check that cannot
tell "the thing is broken" from "the checker is broken" proves nothing in either direction.

**3. Diagnosis belongs in the codebase.** Whatever was needed to find the problem goes into
`troubleshooting/` or into the UAT. A diagnosis performed once and not written down will be
performed again from scratch.

**4. Reconcile the description to the system in the same change.** Every diagram, topology,
port table, ACL, README and manifest naming the thing you changed is now wrong. They are part
of the change, not follow-up work.

**5. One stack at a time.** Never bring up, tear down or load-test two stacks in parallel, and
never redeploy while a suite is running. Doing so has produced outages read as regressions and
whole suites of contaminated results.

**6. Comments state what the code does and the constraint that shapes it — nothing else.**
Present tense, clear and concise. A comment carries the constraint a reader would otherwise
undo, and stops there.

Not in a comment: dates, measurements, benchmark numbers, incident accounts, before-and-after
framing, or any narrative of what something used to be. **That material belongs in
`change_logs/`**, which exists for exactly this and is where a reader can find it in full. A
comment may point at one — `see change_logs/2026-08-08-broker-distribution.md` — but must not
retell it.

The codebase must not be half prose. `ci/comment-style-check.sh` fails on narrative comments
and on any file that is majority comment.

```sh
# Right — the constraint, in the present tense:
# No health check: a TCP probe against a Boundary proxy is itself a session connection.

# Wrong — the story of how it was found:
# Measured 2026-08-08: `nc -z` polling gave 37 successes and 714 failures because dialing
# the proxy churned the very session the check protected, which read as a platform outage.
```

**7. Prefer the tightest thing that works.** When a change makes a permission, a port range or
an exposure wider than it needs to be, narrow it in the same change. Surplus permission never
fails a test.

---

## 3. Blast radius by change type

Find the row matching what you are about to touch. Everything in its column is in scope.

| Changing… | In scope |
|---|---|
| **A compose service** (added, removed, renamed) | `deploy.sh` stage + readiness gate · `TOPOLOGY.md` §1 diagram and hop list · `COMPONENTS.md` entry · `NETWORKING.md` flow table · `troubleshooting/diagnose.sh` · `ci/image-currency.sh` (self-updating, reads compose) · `img/*.svg` · code graph |
| **A published or listened-on port** | `.env` + `.env.example` · `policy.hujson` tailnet ACL · `NETWORKING.md` firewall policy · `TOPOLOGY.md` port table · every UAT that dials it · `COMPONENTS.md` health probe |
| **A network boundary** (netns sharing, new network, a route) | `SECURITY-MODEL.md` · the **negative** assertions proving a tier cannot reach something · `NETWORKING.md` · `TOPOLOGY.md` · SRG tracker if an enforcement point moved |
| **An upstream image** | `ci/image-currency.sh --record` · `ci/base-images.lock` **only for base images** (a `FROM`), never for runtime images · air-gap transfer list |
| **A Django model** | migration via `ci/makemigrations.sh` · `uat_schema.sh` · serializer + view · frontend consumer · code graph |
| **An API route** | `uat_ui.sh` / `uat_e2e.sh` · RBAC matrix in `backend/cases/rbac.py` · frontend caller · code graph · **audit coverage is automatic** — a write is recorded by `auditmiddleware.py` without a call site, so what needs checking is whether the route belongs in its `SKIP_PREFIXES` |
| **A role or permission** | `seed_roles.py` · RBAC assertions · the `WORKFLOW-*.md` for that role · SRG access-control controls |
| **Auth flow** (OIDC, proxy, session) | `uat_baseline.sh` · `uat_srg_webtier.sh` · `uat_audit.sh` (sign-on recording reads the gate's forwarded token) · `uat_load.sh` security phase · `admin/README.md` · `deploy/enclave/oauth2-templates/` if the gate's error paths change |
| **The audit trail** (a new action, entry type or coverage rule) | `uat_audit.sh` · `WORKFLOW-AUDITOR.md` action list · `SECURITY-MODEL.md` P5 · whether the entry is `covers_request` (a bookkeeping entry that claims to cover the request suppresses the record of the actual write) · chain verification still passing |
| **A secret or signing key** | Vault setup script (generate-once-preserve — never regenerate on deploy) · `uat_vault.sh` · key-id propagation if it signs anything |
| **A detection or parser** | `uat_corpus*.sh` · the false-positive corpus · `planning/BACKLOG.md` detection section |
| **Anything with logic** | `python3 gen_code_graph.py` (tree root) — `ci/code-graph-check.sh` fails otherwise |

---

## 4. Document inventory — what each doc claims, and what invalidates it

Every document in the tree. The middle column is what it asserts about the system; the right
column is the change type that makes it wrong. `ci/docs-check.sh` fails if a document exists
that is not listed here.

### Entry points

| Document | Claims | Invalidated by |
|---|---|---|
| `README.md` | What the platform is, the architecture diagrams, the doc index | a tier, service or document changing |
| `SUMMARY.md` | Condensed capability statement | a capability landing or being dropped |
| `CODE_GRAPH.md` | Generated: services, wiring, scripts, API surface, UAT coverage | any logic change — regenerate, never hand-edit |
| `SECURITY-MODEL.md` | Each security principle, what enforces it, the test that proves it | an enforcement point moving |
| `UI_OVERVIEW.md` | The web application screen by screen | a page, panel or workflow changing |
| `CHANGE-MANAGEMENT.md` | This document | a new doc, CI gate or change type |
| `re-workstation/README.md` | The RE tier: containment, staging, tool selection, display | RE containment, staging or tooling changes |

### Role workflows

| Document | Claims | Invalidated by |
|---|---|---|
| `USER-GUIDE.md` | Every capability, where it lives, and what the platform refuses | any capability added, removed or declined |
| `WORKFLOW-LIFECYCLE.md` | One case from collection to report, in the order it happens | a stage of the forensic lifecycle changing shape |
| `WORKFLOW-ANALYST.md` | Working an incident: adjudication, triage, the investigation record | analyst-facing UI or permission changes |
| `WORKFLOW-RE.md` | Carved regions: staging a session, determinations, purge | RE workstation or carving changes |
| `WORKFLOW-ADMIN.md` | Deployment, management access, accounts, symbols, retention | deployment, account or access changes |
| `WORKFLOW-AUDITOR.md` | Audit trail, chain verification, export, custody | audit, custody or export changes |
| `admin/README.md` | Administrative access to management interfaces, per tier | a management port, credential path or tier |

### Deployment and network

| Document | Claims | Invalidated by |
|---|---|---|
| `deploy/README.md` | Configuration, staged rollout, per-tier installation | a stage, variable or tier changing |
| `deploy/NETWORKING.md` | VLANs, routing, firewall policy, IDPS placement, DNS | any port, flow or boundary change |

### Troubleshooting

| Document | Claims | Invalidated by |
|---|---|---|
| `troubleshooting/TOPOLOGY.md` | Every hop, its port and protocol, and what refuses it | a service, port or path change |
| `troubleshooting/COMPONENTS.md` | Per component: configuration, network path, health probe | a component's config or probe |
| `troubleshooting/RUNBOOK.md` | Symptom to resolution | a new failure mode |
| `troubleshooting/ANALYST-ACCESS.md` | The analyst path end to end, and each way it breaks | tailnet, broker, distributor or gate changes |
| `troubleshooting/UI-AND-API-FAULTS.md` | UI and API faults and their causes | route or frontend changes |
| `troubleshooting/MEMORY-ANALYSIS.md` | Memory analysis faults, symbols, Volatility | analysis pipeline or symbol changes |

### Component-local

| Document | Claims | Invalidated by |
|---|---|---|
| `collector/README.md` | The endpoint collector: what it gathers, how it seals | collection scope or custody changes |
| `collector/bin/README.md` | Vendored collector binaries and their provenance | a vendored tool changing |
| `symbols/README.md` | The ISF symbol store and how it is populated | symbol acquisition changes |
| `hashicorp/keycloak/pki-logon/README.md` | PKI/CAC logon configuration | the IdP or certificate trust chain |

### Records

| Document | Claims | Invalidated by |
|---|---|---|
| `change_logs/README.md` | How a change is recorded | this process changing |
| `change_logs/*.md` | Historical: what changed and the assertion proving it | nothing — these are append-only history |
| `artifacts/WEB-SERVER-SRG-TRACKER.md` | Per-control implementation state | an enforcement point moving; gated by `ci/srg-tracker-check.sh` |

### Planning (`../planning/`, v1 scope unless marked otherwise)

| Document | Claims |
|---|---|
| `ROADMAP-FORENSIC-PLATFORM.md` | Roadmap and delivery status |
| `CONSOLIDATED-BACKLOG.md` | Every open item for v1 |
| `BACKLOG.md` | Detection and engine backlog |
| `DECISIONS.md` | Design decisions and their reasoning |
| `SEQUENCE.md` | Delivery order |
| `NEXT-SESSION.md` | Immediate next work |
| `SCALE-50-WORKSTATIONS.md` | Fleet scale: sessions, distribution, measured limits |
| `PARALLEL-ANALYSIS-CAPACITY.md` | Concurrent analysis capacity |
| `STORAGE-TIERING.md`, `enterprise_storage_roadmap.md` | Evidence storage tiers and growth |
| `DATA-PIPELINE.md` | Ingest through analysis |
| `EVIDENCE-SCHEMA-INTEGRITY.md` | Schema and integrity constraints |
| `CORRELATION-ENGINE-V2.md`, `CORRELATION-UI-PHASE.md` | Correlation engine and its UI |
| `CASE-MANAGEMENT-UI.md`, `platform_ui_roadmap.md` | Case management and UI roadmap |
| `VISUALIZATION.md` | Per-page visualization track |
| `LINUX-ENDPOINT-COVERAGE.md`, `COLLECTOR-DEPLOYMENT.md` | Endpoint coverage and collector rollout |
| `KEYCLOAK-POSTGRES.md` | Identity store on the platform database |
| `WEB-SERVER-SRG.md` | Web Server SRG implementation track |
| `PROJECTION-INTEGRATION.md` | The sealed one-way projection to DCO |
| `PLATFORM-V2-VISION.md` | **Not planned work** — explicitly out of v1 |

---

## 5. Obligations checklist

Everything here has been missed at least once.

### Code and deployment
- [ ] Applied by `deploy.sh`, in the right stage, gated on a check that tests the **property**
      rather than the container's existence.
- [ ] The gate cannot pass on an empty result. An unbound port, an empty probe output and a
      missing container must each fail differently.
- [ ] `.env` **and** `.env.example` carry any new variable, with its reasoning.
- [ ] No `KEY: ${KEY:-default}` self-reference in compose — podman-compose passes the literal
      through. Defaults belong in `env_file` or the image.
- [ ] Teardown ordering respects namespace sharing; removing a service another container shares
      a netns with deadlocks the runtime.

### CI gates
- [ ] `ci/docs-check.sh` — links resolve, every document is inventoried.
- [ ] `ci/comment-style-check.sh` — no narrative comments, no file that is majority prose.
- [ ] `ci/code-graph-check.sh` — regenerate with `gen_code_graph.py` at the tree root.
- [ ] `ci/image-currency.sh` — a new image must land CURRENT; `--record` after a review.
- [ ] `ci/pin-base-images.sh` — base images only, via `--update && --apply`.
- [ ] `ci/build-inputs-check.sh` — after touching a build context or shared input.
- [ ] `ci/makemigrations.sh` — after a model change.
- [ ] `ci/srg-tracker-check.sh` — after anything moving a control's enforcement point.

### Tests
- [ ] A UAT asserts the new property, with the evidence in the assertion text.
- [ ] The UATs asserting the **old** shape are updated. An assertion invalidated by a
      deliberate design change is a test to rewrite, not a failure to explain away.
- [ ] Negative assertions still hold — what must be unreachable is still proven unreachable.
- [ ] The UAT mutates no host state and removes every container it started.
- [ ] Full regression afterwards, sequentially, from a settled stack.

### Documentation
- [ ] Every document §4 lists against your change type is updated.
- [ ] `img/*.svg` redrawn if a hop changed.
- [ ] `README.md` index updated if a document was added.
- [ ] A `change_logs/` entry: what changed, and the assertion that proves it.

### Planning
- [ ] The plan written at intake (§1) exists and named this scope **before** the work started.
- [ ] The `planning/` tracker reflects the delivered state, including what the change
      **exposed** rather than only what it fixed.
- [ ] Where a measurement contradicted the plan's premise, the plan records the correction and
      why the original reading was wrong — not just the final answer.
- [ ] Anything deferred is an open item in `CONSOLIDATED-BACKLOG.md`, not a commit message.

### Publication — before any mirror commit or push
Every rule here exists because its violation was found sitting in the public mirror: a TLS
private key, Consul's management token, the Boundary controller's key, a signing keystore —
each deposited by a sync that predated its exclusion, each invisible to later scans because
rsync lists only what it would transfer and `--delete` never removes an excluded path.

- [ ] `ci/sync-public-mirror.sh` for the right scope, never a hand copy: it carries the
      leakage scan (usernames, home paths, hostnames, machine-id, address ranges), the
      secret-shaped-file gate on the copy set, the publish-time rewrites (image paths,
      relocated-doc links), and the **destination sweep**.
- [ ] The destination sweep is green: no secret-shaped file and no excluded directory
      anywhere in the mirror tree — the sweep scans what will actually publish, not what
      this run copied.
- [ ] A path added to the tree that is deploy-generated state (certs, rendered maps, tokens,
      run logs) joins THREE lists at once: the sync script's `EXCLUDES`, the mirror's
      `.gitignore`, and — if a UAT or deploy writes it — the teardown that removes it.
      Any one alone eventually leaks: excludes stop the copy, the ignore stops the commit,
      and the sweep catches what predates both.
- [ ] The mirror's `.gitignore` covers the new pattern at the depth it occurs — a top-level
      `test/logs/` does not match `platform/test/logs/`; verify with `git check-ignore`.
- [ ] `git status` in the mirror shows only what the sync intended; the commit lands on a
      branch, and **pushing is a separate, deliberate act** that never happens in the same
      breath as the sync.

---

## 6. Worked example — the DMZ connection distributor

The change: the bastion's Boundary session listeners moved to loopback, and an L4 distributor
took the analyst-facing port and spread the fleet across them.

Four lines of compose. What it actually reached:

| Surface | Why |
|---|---|
| `hashicorp/access/boundary_session.sh` | bind address and port base both changed |
| `hashicorp/access/broker_distributor.sh` | new component |
| `deploy/dmz/docker-compose.yml` | new service, revised broker environment |
| `deploy/.env`, `.env.example` | `BROKER_SESSION_BASE` added, `BROKER_LISTEN` redefined |
| `deploy/deploy.sh` | new stage; the old gate would have passed a DMZ with a bound port and **no session behind it** |
| `hashicorp/access/policy.hujson` | the ACL admitted `8443-8446`; only `8443` is analyst-facing now |
| `test/uat_boundary.sh` | port constants, session counting, and a new assertion that connections actually spread |
| `test/uat_tailnet.sh` | asserts which ports the ACL permits |
| `test/uat_srg_webtier.sh`, `test/uat_load.sh` | dial the analyst port |
| `ci/image-currency.sh` | picked the new image up unaided — one of the few that self-updates |
| `TOPOLOGY.md`, `COMPONENTS.md`, `ANALYST-ACCESS.md`, `NETWORKING.md`, `img/*.svg` | the analyst path gained a hop |
| `planning/SCALE-50-WORKSTATIONS.md` | M2b delivered; the distribution decision recorded |

The ACL is the one worth dwelling on. Nothing would have failed if it had kept admitting
`8443-8446`: the platform works, every test passes, and the surplus is invisible until someone
asks why the policy permits three ports nothing listens on. Over-permission does not announce
itself, which is why it belongs on a checklist rather than to judgment in the moment.

---

## 7. When a change exposes something else

Fix what you were sent to fix. Record what you found next to it, with the measurement, and do
not silently widen the change to chase it.

Two things must never be quietly repaired:

- **A break in the audit or custody chain.** Re-chaining rows to make a panel green is exactly
  what a tamper-evident ledger exists to prevent. A genuine break is recorded as a known break
  with its cause; any repair is itself logged as a repair.
- **A UAT that fails because the design changed.** Update the assertion to the new intent and
  say why in the assertion text. Deleting it, or loosening it until it passes, removes the only
  thing that would notice the property being lost later.

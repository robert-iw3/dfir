"""L4 — campaign fingerprints, and the similarity measure L5 compares them with.

Built from the L0 behavior graph, deliberately not from indicators. Infrastructure is what an
actor rotates between engagements; tradecraft is what they carry with them, and it is the only
thing a cross-investigation comparison can honestly rest on. Quiet Fox in the corpus exists to
make that concrete: every indicator rotated per host, and the campaign still holds together on
a persistence naming convention.

Two shapes of comparison, one measure. Weighted per-component overlap, with the matched
members named — a score an analyst cannot decompose into "these three techniques in this
order, and this naming convention" is not something they can defend in a report, and
attribution is exactly where that matters most.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

# Kill-chain order, so a sequence means something. Two actors using the same techniques in a
# different order are doing different things, and an unordered set cannot say so.
PHASE_ORDER = [
    "T1190", "T1566", "T1078",              # initial access
    "T1059", "T1204",                       # execution
    "T1547", "T1053", "T1543", "T1037",     # persistence
    "T1548", "T1068",                       # privilege escalation
    "T1562", "T1070", "T1027", "T1014",     # defense evasion
    "T1003", "T1552", "T1110",              # credential access
    "T1087", "T1018", "T1057",              # discovery
    "T1021", "T1550",                       # lateral movement
    "T1560", "T1005",                       # collection
    "T1071", "T1090", "T1573", "T1568",     # command and control
    "T1041", "T1567", "T1048",              # exfiltration
    "T1486", "T1490", "T1489", "T1496",     # impact
]
_PHASE_RANK = {t: i for i, t in enumerate(PHASE_ORDER)}

NGRAM_N = 3

# Component weights for the similarity measure. Ordered sequence outranks the bare set
# because sharing techniques is common and sharing their ORDER is not; naming conventions
# outrank both, since a convention is a habit rather than a capability.
COMPONENT_WEIGHT = {
    "artifact_conventions": 0.35,
    "technique_ngrams": 0.30,
    "techniques": 0.20,
    "c2_pattern": 0.10,
    "account_chain": 0.05,
}

def _informative(shape):
    """Does this name-shape distinguish anyone?

    A convention made only of placeholders does not. `<name><name><name>` is every
    CamelCase Windows service ever shipped, and `{<guid>}` is most of the rest — matching on
    either would tie unrelated intrusions to each other, and the artifact convention is the
    most heavily weighted component of the comparison, so a generic one does the most damage.

    Two ways a shape earns its place.

    Literal text surviving abstraction: `svc_<number>` keeps `svc`, which is a choice somebody
    made. This alone was the whole test, and it discards habits whose signal is STRUCTURE —
    `<name>-<name>.service` and `<name>_<name>.so` name the same platform facility with
    different conventions, and `WinDefendHelper` reduced to `<name><name><name>` and left the
    fingerprint entirely.

    Or three or more abstracted segments with at least two distinct separators: a shape that
    specific is a layout, and a layout is a habit. Two segments is not enough — `<name>-<name>`
    is every hyphenated name ever written.

    The rarity and verdict floors in `build_fingerprint` are what make the second rule safe:
    a structural shape that describes the platform is on the whole fleet, so it never reaches
    here. Widening this without those floors would tie unrelated intrusions together on the
    most heavily weighted component of the comparison.
    """
    if not shape:
        return False
    residue = re.sub(r"<[a-z]+>", "", shape)
    if any(c.isalnum() for c in residue):
        return True
    segments = len(re.findall(r"<[a-z]+>", shape))
    separators = {c for c in residue if not c.isspace()}
    return segments >= 3 and len(separators) >= 2


def _base_technique(tid):
    """T1021.002 -> T1021. Sub-techniques are implementation; the parent is the tradecraft."""
    return (tid or "").split(".")[0].strip().upper()


# Type suffixes kept verbatim regardless of length. Named explicitly, because a length
# threshold silently decides which platforms have legible tradecraft.
KNOWN_SUFFIX = (
    r"\.(service|timer|socket|target|mount|path|slice|scope"     # systemd units
    r"|so(\.\d+)*|ko|a|sh|py|pl|rb|bash|zsh"                     # unix objects and scripts
    r"|exe|dll|sys|scr|ps1|bat|cmd|vbs|lnk|msi"                  # windows
    r"|conf|cfg|ini|json|yaml|yml|plist"                         # config
    r"|zip|7z|rar|tar|gz|bz2|xz|cab)$"
)


def convention_of(name):
    """The SHAPE of an artifact name, not the name.

    `WinDefendHelper` and `WinUpdateHelper` are the same habit wearing different words, and an
    actor who renames between engagements keeps the habit. Digits, hex runs and GUID-like
    segments collapse to placeholders; word boundaries are kept because they are the part that
    recurs.
    """
    if not name:
        return ""
    s = str(name).strip()
    # A trailing type suffix is held out and restored verbatim. It is a format, not a name,
    # and abstracting it destroys the shape rather than generalizing it: `_archive.7z` became
    # `_<name>.<number>z`, which reads as a parse failure.
    #
    # Matched by KNOWN suffix first, then by length. On length alone `.timer` (5) survived
    # while `.service` (7) was abstracted to `<name>` — so systemd units, the most common
    # Linux persistence artifact there is, produced uninformative shapes and were dropped
    # from every fingerprint. The threshold was deciding which platforms have tradecraft.
    ext = ""
    m = re.search(KNOWN_SUFFIX, s, flags=re.I) or re.search(r"\.[A-Za-z0-9]{1,5}$", s)
    if m:
        s, ext = s[:m.start()], m.group(0)
    s = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<guid>", s, flags=re.I)
    s = re.sub(r"[0-9a-f]{16,}", "<hex>", s, flags=re.I)
    s = re.sub(r"\d+", "<number>", s)
    # CamelCase and snake/kebab segments become <name>, separators kept verbatim.
    s = re.sub(r"[A-Z][a-z]{2,}", "<name>", s)
    s = re.sub(r"(?<![<>a-zA-Z])[a-z]{3,}(?![<>])", "<name>", s)
    return (s + ext)[:80]


def _ngrams(seq, n=NGRAM_N):
    return [" > ".join(seq[i:i + n]) for i in range(len(seq) - n + 1)]


def build_fingerprint(hosts, edges, nodes, technique_first=None, confirmed_nodes=None):
    """The L4 vector for one campaign, from its slice of the behavior graph.

    `nodes` are the campaign's own; passing the whole run's would fingerprint the
    investigation rather than the campaign, and two campaigns in one investigation are two
    intrusions precisely because the engine declined to link them.

    `technique_first` maps a technique to when it was FIRST OBSERVED, from the confirming
    finding that carried it. Without it the order can only be read from each host's
    first_activity, which is the earliest thing seen on that host at all — an inventory scan
    or an agent install, hours before the intrusion and identical across the fleet. Ordering
    by that sorts techniques by the benign scanner's schedule and calls the result a sequence.

    `confirmed_nodes` is the set of behavior-node ids carrying at least one confirming
    verdict. With the rarity floor below it keeps ordinary fleet software out of an actor's
    tradecraft; passing None disables the check and fingerprints whatever is present.
    """
    hostnames = {h.hostname for h in hosts}
    technique_first = technique_first or {}

    # --- techniques, as a set and as an observed sequence --------------------------------
    tech_first = {}
    for h in hosts:
        for t in h.techniques or []:
            base = _base_technique(t)
            if not base:
                continue
            when = technique_first.get(base) or h.first_activity
            if base not in tech_first or (when and tech_first[base] and when < tech_first[base]):
                tech_first[base] = when
    techniques = sorted(tech_first)

    # Ordered by observation where the timeline supports it, by kill-chain rank where it does
    # not — a campaign whose techniques share a timestamp has no observed order to read.
    def order_key(t):
        return (tech_first.get(t) or _MAX_TIME, _PHASE_RANK.get(t, len(PHASE_ORDER)), t)

    ordered = sorted(techniques, key=order_key)
    ngrams = _ngrams(ordered)

    # --- naming conventions --------------------------------------------------------------
    conventions = Counter()
    # The collected value each shape was abstracted FROM, kept beside it. A shape on its own
    # is unfalsifiable to a reader: `EF-<number>-Q<number>` is indistinguishable from a
    # placeholder unless the record can also say it came from `EF-2026-Q3` on 9 hosts. Only
    # ever the widest-seen example, and never used for matching — the shape is the evidence,
    # this is the provenance of it.
    examples = {}
    for n in nodes:
        if n.kind != "artifact":
            continue
        # RARITY FLOOR. `host_count` is run-wide, so an artifact on more hosts than this
        # campaign has is present on hosts outside it — the environment, not this actor.
        # Without this the fleet's own software becomes the campaign's top convention:
        # `OneDriveSetup.exe` sits on all 20 corpus endpoints, clean ones included, and was
        # being reported as tradecraft AND used as shared evidence between two campaigns.
        if (n.host_count or 1) > len(hostnames):
            continue
        # VERDICT FLOOR. An artifact nobody adjudicated as compromise describes the host,
        # not the intrusion. Linkage already refuses to link on Indeterminate alone; a
        # fingerprint that accepts it contradicts the same case's own linkage decisions.
        if confirmed_nodes is not None and n.id not in confirmed_nodes:
            continue
        shape = convention_of(n.value)
        if not _informative(shape):
            continue
        key = f"{n.subkind or 'artifact'}:{shape}"
        hosts = n.host_count or 1
        conventions[key] += hosts
        if hosts >= examples.get(key, {}).get("hosts", 0):
            examples[key] = {"example": n.value[:120], "hosts": hosts}
    # Deduplicated by SHAPE. One artifact recorded under two subkinds — `campaign_id` from
    # the hunt and `c2_campaign_id` from config extraction — is one habit, and listing it
    # twice both pads the panel and double-counts it in the overlap score.
    artifact_conventions, seen_shapes = [], set()
    for key, _ in conventions.most_common():
        shape = key.split(":", 1)[-1]
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)
        artifact_conventions.append(key)
        if len(artifact_conventions) >= 12:
            break
    convention_examples = {k: examples[k] for k in artifact_conventions if k in examples}

    # --- C2 and movement protocol pattern -------------------------------------------------
    protocols = Counter(e.protocol for e in edges if e.protocol)
    techniques_movement = Counter(_base_technique(e.technique) for e in edges if e.technique)
    c2_pattern = {
        "movement_protocols": [p for p, _ in protocols.most_common(6)],
        "movement_techniques": [t for t, _ in techniques_movement.most_common(6)],
        "beacon_kinds": sorted({n.subkind for n in nodes
                                if n.kind == "indicator" and n.subkind})[:6],
    }

    # --- account acquisition shape --------------------------------------------------------
    accounts = [e.account for e in edges if e.account]
    per_account = Counter(accounts)
    account_chain = {
        "distinct_accounts": len(per_account),
        # One account reaching many hosts is a different shape from one account per hop.
        "max_hosts_per_account": max(per_account.values()) if per_account else 0,
        "reuses_single_account": bool(per_account) and len(per_account) == 1 and len(edges) > 1,
        "domain_style": sorted({a.split("\\")[0] for a in accounts if "\\" in a})[:4],
    }

    basis = {
        "hosts": len(hostnames),
        "edges": len(edges),
        "artifact_nodes": sum(1 for n in nodes if n.kind == "artifact"),
        "technique_count": len(techniques),
        # Named so a thin fingerprint reads as thin evidence rather than as an actor with
        # little tradecraft. L5 refuses to compare below this.
        #
        # One naming convention is a habit and enough on its own. Without any, the bar is a
        # RICH technique profile, because techniques are the most generic evidence there is:
        # T1071, T1053 and T1003 are in nearly every intrusion, and three of them was
        # clearing this gate. Two unrelated cases could then reach 0.50 on techniques and
        # their order alone — over the 0.30 similarity floor, and reported as "seen before".
        "sufficient": bool(artifact_conventions) or len(techniques) >= 5,
    }

    return {
        # The SET, for the similarity component that compares sets. Sorted by id, which is not
        # an order anything happened in — `technique_sequence` is what a reader wants.
        "techniques": techniques,
        "technique_sequence": ordered,
        "technique_ngrams": ngrams,
        "artifact_conventions": artifact_conventions,
        "convention_examples": convention_examples,
        "c2_pattern": c2_pattern,
        "account_chain": account_chain,
        "basis": basis,
    }


class _MaxTime:
    """Sorts after every real datetime, so techniques with no observed time land last."""

    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return True

    def __eq__(self, other):
        return isinstance(other, _MaxTime)


_MAX_TIME = _MaxTime()


def _overlap(a, b):
    """(score, shared) for two collections, by Jaccard. Empty on either side is 0, not 1."""
    sa, sb = set(a or ()), set(b or ())
    if not sa or not sb:
        return 0.0, []
    shared = sa & sb
    return len(shared) / len(sa | sb), sorted(shared)


def _c2_overlap(a, b):
    """(score, shared) — `shared` is a flat list of readable strings, like every component.

    One shape for every component's `shared`. A consumer that has to branch on the type of
    each one will eventually forget, and the first thing it does with the wrong type is
    throw — which is a blank page, not a graceful degradation.
    """
    parts, shared = [], []
    for key in ("movement_protocols", "movement_techniques", "beacon_kinds"):
        score, common = _overlap((a or {}).get(key), (b or {}).get(key))
        parts.append(score)
        shared += [f"{key}: {v}" for v in common]
    return (sum(parts) / len(parts) if parts else 0.0), shared


def _chain_overlap(a, b):
    a, b = a or {}, b or {}
    if not a or not b:
        return 0.0, []
    same_reuse = a.get("reuses_single_account") == b.get("reuses_single_account")
    style, style_shared = _overlap(a.get("domain_style"), b.get("domain_style"))
    score = (0.5 if same_reuse else 0.0) + 0.5 * style
    shared = []
    if same_reuse:
        shared.append("account reuse: " + (
            "one account across hops" if a.get("reuses_single_account") else "account per hop"))
    shared += [f"domain: {v}" for v in style_shared]
    return score, shared


def compare(fp_a, fp_b):
    """(score, rationale) — weighted per-component overlap, naming what matched.

    Returns 0 with a stated reason when either side is too thin to compare. A similarity
    computed from two techniques and nothing else is a coincidence with a number on it, and
    ranking it beside a real match is how a heuristic becomes a false accusation.
    """
    basis_a = (fp_a or {}).get("basis") or {}
    basis_b = (fp_b or {}).get("basis") or {}
    if not (basis_a.get("sufficient", True) and basis_b.get("sufficient", True)):
        return 0.0, {"declined": "one side carries too little tradecraft to compare",
                     "components": {}}

    components, total = {}, 0.0
    for key in ("artifact_conventions", "technique_ngrams", "techniques"):
        score, shared = _overlap((fp_a or {}).get(key), (fp_b or {}).get(key))
        total += COMPONENT_WEIGHT[key] * score
        if shared:
            components[key] = {"score": round(score, 4), "shared": shared[:8]}

    c2_score, c2_shared = _c2_overlap((fp_a or {}).get("c2_pattern"), (fp_b or {}).get("c2_pattern"))
    total += COMPONENT_WEIGHT["c2_pattern"] * c2_score
    if c2_shared:
        components["c2_pattern"] = {"score": round(c2_score, 4), "shared": c2_shared}

    ch_score, ch_shared = _chain_overlap((fp_a or {}).get("account_chain"),
                                         (fp_b or {}).get("account_chain"))
    total += COMPONENT_WEIGHT["account_chain"] * ch_score
    if ch_shared:
        components["account_chain"] = {"score": round(ch_score, 4), "shared": ch_shared}

    return round(total, 4), {
        "components": components,
        # The dominant reason, so a UI has something to show without unpacking the whole
        # structure — and so the record says what carried the score rather than only what it was.
        "carried_by": max(components, key=lambda k: components[k]["score"]) if components else "",
    }


def profile_as_fingerprint(profile):
    """An `ActorProfile` in fingerprint shape, so one measure serves both comparisons."""
    techniques = sorted({_base_technique(t) for t in (profile.techniques or []) if t})
    # A profile carries no timeline, so kill-chain rank is the only order available.
    ordered = sorted(techniques, key=lambda t: _PHASE_RANK.get(t, len(PHASE_ORDER)))
    return {
        "techniques": techniques,
        "technique_sequence": ordered,
        "technique_ngrams": _ngrams(ordered),
        "artifact_conventions": list(profile.artifact_conventions or []),
        "c2_pattern": profile.c2_pattern or {},
        "account_chain": {},
        "basis": {"sufficient": len(techniques) >= 3 or bool(profile.artifact_conventions)},
    }

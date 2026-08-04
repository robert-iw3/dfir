"""Shared helpers used by every family parser in c2_parsers/."""
from __future__ import annotations

import json
import re
from typing import List


def decode(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


# How close two signals must sit before they count as one construct. A real configuration
# holds its parts together — a token inside the URL that uses it, a header beside the request
# it belongs to — within a few hundred bytes.
CO_LOCATION_WINDOW = 512


def co_located(data: bytes, first, second, window: int = CO_LOCATION_WINDOW) -> bool:
    """Do two signals appear close enough together to be part of the same structure?

    Two patterns matching *somewhere* in the same buffer is not evidence they are related.
    A carved region is megabytes of process memory: a token-shaped string at one end and an
    API hostname at the other are almost certainly unconnected, and treating that as a
    recovered configuration is how an editor's heap gets reported as a C2 channel.

    `first` and `second` are each a compiled pattern or a literal bytes value.
    """
    def spans(pat):
        if isinstance(pat, (bytes, bytearray)):
            out, start = [], 0
            while True:
                i = data.find(pat, start)
                if i == -1:
                    return out
                out.append((i, i + len(pat)))
                start = i + 1
                if len(out) > 512:      # pathological repetition; enough to judge proximity
                    return out
        return [(m.start(), m.end()) for m in pat.finditer(data)]

    a, b = spans(first), spans(second)
    if not a or not b:
        return False
    for s1, e1 in a:
        for s2, e2 in b:
            if max(s1, s2) - min(e1, e2) <= window:
                return True
    return False


# Bytes that read as prose or source code rather than as a packed structure: a rule's own
# definition quoted in an editor buffer, API documentation, a log line.
_TEXT_RUN = re.compile(rb'[\x20-\x7e\r\n\t]{200,}')


# Prose and source code carry word separators; packed binary data and padding do not. A URL
# surrounded by NULs or by unbroken filler is a value in a structure, while the same URL in a
# sentence or an assignment is someone writing *about* it.
_MIN_WHITESPACE_RATIO = 0.08


def in_text_run(data: bytes, pos: int, pad: int = 64) -> bool:
    """Is this offset sitting inside human-readable prose or source code?

    A match embedded in running text is quoted content — documentation, a configuration
    example, a detection rule being edited — not a packed structure a program parses at
    runtime. The same discipline already gates BPFDoor's magic sequence.

    Printability alone is not enough to make that call: a config blob can be entirely
    printable, and unbroken filler like `junkjunkjunk...` is printable but is not text.
    Whitespace density is what separates the two.
    """
    for m in _TEXT_RUN.finditer(data):
        if not (m.start() - pad <= pos <= m.end() + pad):
            continue
        run = m.group(0)
        spaces = sum(1 for c in run if c in b' \t\r\n')
        if spaces / max(len(run), 1) >= _MIN_WHITESPACE_RATIO:
            return True
    return False


def structural_hit(data: bytes, literals, need: int = 2,
                   window: int = CO_LOCATION_WINDOW):
    """Offset where `need` distinct `literals` cluster together outside running text.

    "N of these strings appear somewhere in the buffer" is the weakest possible test and it
    is true of every document that *describes* the family — a parser's own source listing its
    field names, a detection rule, incident notes, API documentation. A configuration a
    program parses at runtime holds its fields together and is not embedded in sentences, so
    both conditions are required: proximity, and not sitting in prose.

    Returns the cluster's first offset (truthy positions start at 0, so callers must test
    `is not None`), or None.
    """
    hits = []
    for idx, lit in enumerate(literals):
        start, seen = 0, 0
        while True:
            i = data.find(lit, start)
            if i == -1:
                break
            hits.append((i, idx))
            start, seen = i + 1, seen + 1
            if seen > 256:                  # pathological repetition; enough to judge
                break
    if len(hits) < need:
        return None
    hits.sort()
    lo = 0
    for hi in range(len(hits)):
        while hits[hi][0] - hits[lo][0] > window:
            lo += 1
        cluster = hits[lo:hi + 1]
        if len({idx for _, idx in cluster}) < need:
            continue
        # Every member outside prose. One packed field beside a paragraph that mentions the
        # rest is a description with a coincidence in it, not a recovered structure.
        if all(not in_text_run(data, pos) for pos, _ in cluster):
            return cluster[0][0]
    return None


def values_near(data: bytes, value_re: 're.Pattern', anchor, window: int = CO_LOCATION_WINDOW,
                limit: int = 10) -> List[bytes]:
    """Matches of `value_re` that sit within `window` bytes of `anchor`.

    When a parser cannot pull a field out of a parsed structure, reaching for "any value
    of the right shape anywhere in the region" fabricates the field rather than recovering
    it. A carved region is megabytes of process memory holding every URL the process has
    touched, so the first or the sorted-first URL in it is unrelated to the config that
    triggered the parser -- and reporting it names an innocent host as C2 infrastructure.
    Requiring the value to sit beside the anchor keeps the fallback a fallback.

    `anchor` is a compiled pattern or a literal bytes value.
    """
    def spans(pat):
        if isinstance(pat, (bytes, bytearray)):
            out, start = [], 0
            while True:
                i = data.find(pat, start)
                if i == -1:
                    return out
                out.append((i, i + len(pat)))
                start = i + 1
                if len(out) > 512:
                    return out
        return [(m.start(), m.end()) for m in pat.finditer(data)]

    anchors = spans(anchor)
    if not anchors:
        return []
    out = []
    for m in value_re.finditer(data):
        if any(max(m.start(), a) - min(m.end(), b) <= window for a, b in anchors):
            out.append(m.group(0))
            if len(out) >= limit:
                break
    return out


def find_json_objects(data: bytes, anchor_re: 're.Pattern', max_len: int = 4000) -> List[dict]:
    """Extract JSON objects near an anchor pattern (config blobs embedded in a Go
    binary are not always at a clean object boundary, so search a window)."""
    out = []
    for m in anchor_re.finditer(data):
        start = max(0, m.start() - max_len)
        end = min(len(data), m.end() + max_len)
        window = data[start:end]
        brace_start = window.rfind(b'{', 0, m.start() - start + 1)
        if brace_start == -1:
            continue
        depth = 0
        for i in range(brace_start, len(window)):
            if window[i:i + 1] == b'{':
                depth += 1
            elif window[i:i + 1] == b'}':
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(window[brace_start:i + 1].decode('utf-8', 'ignore'))
                        if isinstance(obj, dict):
                            out.append(obj)
                    except (ValueError, UnicodeDecodeError):
                        pass
                    break
    return out

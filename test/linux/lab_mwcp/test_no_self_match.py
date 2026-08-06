"""Text that merely *describes* a family must not be reported as a live configuration.

A carved region is process memory. On any machine where detection content is written, read
or edited, that memory holds rule sources, parser sources, documentation and analyst notes —
all of which quote the exact literals the parsers search for. A parser firing on those
asserts a live implant configuration from a description of one.

Not hypothetical: `blackcat_linux.identify()` returned True for its own source file, and on a
live 24 GB workstation capture the cloud_saas parsers reported `api.telegram.org`,
`api.github.com`, `pastebin.com` and `content.dropboxapi.com` as recovered C2 configuration
out of an editor's heap. The investigation engine then correlated those into a True Positive
verdict on a text editor. See `planning/BACKLOG.md` §12a.

The synthetic false-positive corpus did not catch it: those samples are built from what
malware looks like, not from what a developer's memory looks like.

Two levels are asserted:

  * `extract_all()` — the production contract. `memory_enrich.py` and `edr_hunt.py` call
    only this, so its gate is what actually protects an investigation.
  * `identify()` per parser — the stricter standard, and now the standard for all of them.
    `extract_all()`'s prose gate is a whole-region judgment; a parser whose own gate is
    "these strings appear somewhere" still fires the moment a region is not prose enough to
    be suppressed. Both have to hold.
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
PARSERS_ROOT = REPO / "playbooks" / "linux" / "threat_hunting" / "mwcp_parsers"
PACKAGE = "playbooks.linux.threat_hunting.mwcp_parsers"

driver = importlib.import_module(f"{PACKAGE}.driver")

PROSE = (
    b"Incident notes. The host was assessed for SaaS-based C2. We checked for "
    b"api.telegram.org, api.github.com/repos/, content.dropboxapi.com/2/files/upload "
    b"and pastebin.com/raw/ABCD1234 with the Dropbox-API-Arg header, plus config_id, "
    b"public_key, extension, note_file_name, kill_services, kill_processes, "
    b"exclude_directory_names and exclude_file_names in any JSON blob. Markers such as "
    b"pupy.pupyimporter, rpyc.core, ReverseSlave and dnscnc were searched for. None of "
    b"this indicates the host is compromised; it records what was looked for.\n"
) * 8


def _parser_modules():
    found = []
    for sub in sorted(p for p in PARSERS_ROOT.iterdir() if p.is_dir()):
        if sub.name.startswith((".", "_")) or sub.name == "__pycache__":
            continue
        for mod in pkgutil.iter_modules([str(sub)]):
            if mod.name.startswith("_"):
                continue
            dotted = f"{PACKAGE}.{sub.name}.{mod.name}"
            try:
                m = importlib.import_module(dotted)
            except Exception as exc:                       # noqa: BLE001
                pytest.fail(f"{dotted} failed to import: {exc}")
            if hasattr(m, "identify"):
                found.append((mod.name, m, sub / f"{mod.name}.py"))
    return found


PARSERS = _parser_modules()
CATALOG = b"\n".join(p.read_bytes() for _, _, p in PARSERS)


def test_parsers_were_discovered():
    assert PARSERS, f"no parsers found under {PARSERS_ROOT}"


# --- The production contract -------------------------------------------------------------

@pytest.mark.parametrize("name,module,source", PARSERS, ids=[n for n, _, _ in PARSERS])
def test_extract_all_ignores_parser_source(name, module, source):
    """A region holding a parser's own definition yields no configuration."""
    assert driver.extract_all(source.read_bytes()) == [], (
        f"extract_all() reported a configuration from {name}'s own source"
    )


def test_extract_all_ignores_the_whole_catalog():
    """An editor with several parsers open — the union of every family's literals."""
    assert driver.extract_all(CATALOG) == []


def test_extract_all_ignores_prose_about_the_families():
    """Documentation and incident notes naming what was searched for."""
    assert driver.extract_all(PROSE) == []


def test_prose_gate_does_not_swallow_real_samples():
    """The gate must not suppress the true-positive corpus it sits in front of."""
    tp_dir = REPO / "test" / "linux" / "lab_mwcp" / "samples" / "tp"
    samples = sorted(tp_dir.glob("*.bin"))
    assert samples, f"no TP samples under {tp_dir}"
    for s in samples:
        assert driver.prose_fraction(s.read_bytes()) < driver._PROSE_SUPPRESSION_THRESHOLD, (
            f"{s.name} would be suppressed as prose — the threshold is too low"
        )


# --- The stricter per-parser standard ----------------------------------------------------

@pytest.mark.parametrize("name,module,source", PARSERS, ids=[n for n, _, _ in PARSERS])
def test_parser_identify_rejects_its_own_source(name, module, source):
    assert module.identify(source.read_bytes()) is False


@pytest.mark.parametrize("name,module,source", PARSERS, ids=[n for n, _, _ in PARSERS])
def test_parser_identify_rejects_prose(name, module, source):
    assert module.identify(PROSE) is False

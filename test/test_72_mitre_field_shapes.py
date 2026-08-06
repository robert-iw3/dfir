"""The MITRE field arrives in two shapes, and the investigation engine must survive both.

The finding schema permits either, and both producers are in the tree: the hunts write a
list of technique ids, the MWCP parsers write one string of
`'T1071.001 (Web Protocols), T1027 (Obfuscated Files)'`.

Reading only the string shape raised `AttributeError: 'list' object has no attribute
'split'` inside `_extract_mitre`, which aborted the whole run — the engine reported
"produced no report", the platform recorded the host as unadjudicated, and a compromised
endpoint carried no determination at all. A label field taking down the determination is
worth a test of its own, on both platforms, because neither runner had one.

Surfaced by corpus L (`platform/test/corpus/linux.py`), whose Linux findings carry list
MITRE values the way the Linux hunts do.
"""
import pytest

from playbooks.linux.investigation.chain_builder import mitre_ids as linux_ids
from playbooks.windows.investigation.live_runner import mitre_ids as windows_ids

EXTRACTORS = pytest.mark.parametrize("ids", [linux_ids, windows_ids],
                                     ids=["linux", "windows"])


@EXTRACTORS
def test_a_list_of_ids_survives(ids):
    """The shape the hunts emit. This is the one that raised."""
    assert ids(["T1190", "T1505.003"]) == ["T1190", "T1505.003"]


@EXTRACTORS
def test_a_single_string_still_works(ids):
    assert ids("T1071.001") == ["T1071.001"]


@EXTRACTORS
def test_every_id_in_a_parser_string_is_kept(ids):
    """The MWCP shape. Only the first id was read, so a finding naming two techniques and
    the report describing it disagreed about the same evidence."""
    assert ids("T1071.001 (Web Protocols), T1027 (Obfuscated Files)") == \
        ["T1071.001", "T1027"]


@EXTRACTORS
def test_empty_and_missing_produce_nothing(ids):
    for empty in ("", None, [], ["", None]):
        assert ids(empty) == []


@EXTRACTORS
def test_a_nested_list_is_flattened_rather_than_stringified(ids):
    """A merge that wraps one finding's list inside another's is not supposed to happen, and
    a crash here costs the host's entire determination. Flattened, so the ids are still
    readable instead of arriving as the repr of a list."""
    assert ids([["T1190"], "T1027"]) == ["T1190", "T1027"]

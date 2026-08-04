"""Linux memory IOC enrichment (playbooks/linux/threat_hunting/memory_enrich.py).

After the YARA worker carves true-positive regions, this scans their strings (ASCII + UTF-16LE) and
recovers the adversary IOCs the implant left behind (C2 / Tor / crypto / exfil / creds), emitting
common-schema findings that flow into Combined_Findings -> adjudication -> IOCs.json + the report.
These cover the extraction core, FP-resistance (benign infra dropped), and the region->findings driver.
"""
import importlib.util
import json
import os

from conftest import LINUX_HUNT

# Load by path under a UNIQUE name: the Windows test_36 also has a module named `memory_enrich`,
# and a plain `import memory_enrich` would return whichever sys.modules cached first.
_spec = importlib.util.spec_from_file_location(
    "memory_enrich_linux", os.path.join(LINUX_HUNT, "memory_enrich.py"))
me = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(me)


def test_extracts_full_ioc_catalog():
    blob = (b"http://45.77.13.9:8080/gate.php\x00c2.badactor.top\x00"
            b"stratum+tcp://xmr.pool.evil.su:3333 -u 48EdfHASHWALLET00000\x00"
            b"AKIAIOSFODNN7EXAMPLE\x00-----BEGIN RSA PRIVATE KEY-----\x00")
    i = me.extract_threat_iocs(blob)
    assert "45.77.13.9" in i["ips"]
    assert "c2.badactor.top" in i["domains"] and "xmr.pool.evil.su" in i["domains"]
    assert any("gate.php" in u for u in i["urls"])
    assert "AKIAIOSFODNN7EXAMPLE" in i["aws_keys"]
    assert i["miner_configs"] and "48EdfHASHWALLET00000" in i["wallets"]
    assert i["private_keys"] == 1


def test_benign_infra_is_dropped():
    # OS/CDN/distro hosts + RFC1918/loopback IPs must NOT be reported as C2 (no FP flood)
    blob = (b"https://ubuntu.com/x\x00https://python.org\x00https://googleapis.com\x00"
            b"10.0.0.5\x00127.0.0.1\x00192.168.1.1\x00")
    i = me.extract_threat_iocs(blob)
    assert i["domains"] == [] and i["ips"] == []


def test_utf16le_strings_are_caught():
    # wide-char C2 string (some loaders store config as UTF-16) must still be recovered
    i = me.extract_threat_iocs("http://evil-wide.top/c2".encode("utf-16-le"))
    assert "evil-wide.top" in i["domains"]


def test_no_bare_ip_scrape_from_oids():
    # crypto OIDs / version numbers look like IPs — bare numbers must NOT be captured as C2 IPs
    assert me.extract_c2_iocs(b"oid 2.5.4.3 sha 1.3.14.3.2.26 version 5.1.0.0")["ips"] == []


def test_defang_renders_inert():
    d = me.defang("http://45.77.13.9/x and bad.example.com")
    assert "hxxp" in d and "45[.]77[.]13[.]9" in d and "bad[.]example[.]com" in d


def test_enrich_region_reads_sidecar(tmp_path):
    binp = tmp_path / "pid6502_implant_0x7f0000.bin"
    binp.write_bytes(b"http://45.77.13.9/gate\x00")
    (tmp_path / "pid6502_implant_0x7f0000.json").write_text(json.dumps(
        {"pid": "6502", "process": "implant", "base_address": "0x7f0000",
         "region": "anon", "perms": "rwx", "matched_rules": ["Linux_Trojan_Demo"]}))
    d = me.enrich_region(str(binp))
    assert d["pid"] == "6502" and d["process"] == "implant" and d["region"] == "anon"
    assert "45.77.13.9" in d["iocs"]["ips"]


def test_dossiers_to_findings_are_c2_typed():
    base = {k: [] for k in ("ips", "domains", "urls", "onion", "xmr", "aws_keys",
                            "telegram_tokens", "discord_webhooks", "miner_configs", "wallets")}
    dossiers = [{"region_file": "r.bin", "pid": "6502", "process": "implant",
                 "base_address": "0x7f0000", "matched_rules": [],
                 "iocs": {**base, "private_keys": 0,
                          "ips": ["45.77.13.9"], "domains": ["c2.badactor.top"]}}]
    f = me.dossiers_to_findings(dossiers)
    types = {x["Type"] for x in f}
    targets = {x["Target"] for x in f}
    assert "C2 Endpoint (memory)" in types          # the type IOCs.json/report C2 extractor matches
    assert "45.77.13.9" in targets and "c2.badactor.top" in targets
    assert all("T1071" in x["MITRE"] for x in f) and all(x["Source"] == "memory_enrich" for x in f)


# --- region provenance as a gate --------------------------------------------------------
# The carver records each region's permissions and backing, and both were read into the
# dossier and then ignored: an anonymous executable region and a read-write heap slice
# produced identical High findings. They are different claims -- code the process was
# RUNNING versus bytes it was HOLDING -- and this is what makes them score differently.

def _dossier(**over):
    base = {k: [] for k in ("ips", "domains", "urls", "onion", "xmr", "aws_keys",
                            "telegram_tokens", "discord_webhooks", "miner_configs", "wallets")}
    d = {"region_file": "r.bin", "pid": "6502", "process": "implant",
         "base_address": "0x7f0000", "matched_rules": [],
         "iocs": {**base, "private_keys": 0, "ips": ["45.77.13.9"]}}
    d.update(over)
    return d


def _sev(findings, ftype="C2 Endpoint (memory)"):
    return next(f["Severity"] for f in findings if f["Type"] == ftype)


def _detail(findings, ftype="C2 Endpoint (memory)"):
    return next(f["Details"] for f in findings if f["Type"] == ftype)


def test_injected_region_keeps_the_full_execution_claim():
    f = me.dossiers_to_findings([_dossier(region="anon", perms="rwx", injected=True)])
    assert _sev(f) == "High"
    assert "no on-disk backing" in _detail(f)


def test_non_executable_region_is_held_not_run():
    """A C2 string in rw- memory is data the process had, which any browser or editor has."""
    f = me.dossiers_to_findings([_dossier(region="anon", perms="rw-")])
    assert _sev(f) == "Medium"
    assert "not code it was executing" in _detail(f)


def test_executable_mapping_of_a_file_names_the_file_to_verify():
    """An r-x mapping of a library is very often a rule grazing that library."""
    f = me.dossiers_to_findings([_dossier(region="file", perms="r-x",
                                          backing_path="/usr/lib/x86_64-linux-gnu/libc.so.6")])
    assert _sev(f) == "Medium"
    assert "libc.so.6" in _detail(f)


def test_missing_provenance_changes_nothing():
    """A sidecar the carver could not write is not evidence the region was harmless.

    Downgrading on absent metadata would quietly weaken every real detection wherever a
    carve lost its sidecar -- concluding from silence, in the direction that hides things.
    """
    f = me.dossiers_to_findings([_dossier()])
    assert _sev(f) == "High"
    assert "Region provenance" not in _detail(f)


def test_credential_findings_are_not_re_weighted_by_region():
    """A key recovered from a heap is exposed whether or not the region was executable.

    The gate is about whether the process was RUNNING something, and that claim is no part
    of "this credential was in memory".
    """
    d = _dossier(region="anon", perms="rw-")
    d["iocs"]["ips"] = []
    d["iocs"]["aws_keys"] = ["AKIAIOSFODNN7EXAMPLE"]
    f = me.dossiers_to_findings([d])
    assert _sev(f, "Cloud Credential in Memory") == "High"


def test_region_context_is_applied_per_region_not_across_the_batch():
    """Two regions in one run keep their own verdicts.

    The findings list is shared across regions, so a gate applied to the whole list would
    let the last region's provenance rewrite every earlier region's severity.
    """
    ran = _dossier(region="anon", perms="rwx", injected=True)
    held = _dossier(region="anon", perms="rw-", region_file="r2.bin")
    held["iocs"] = {**held["iocs"], "ips": ["203.0.113.77"]}
    f = me.dossiers_to_findings([ran, held])
    by_target = {x["Target"]: x["Severity"] for x in f}
    assert by_target["45.77.13.9"] == "High"
    assert by_target["203.0.113.77"] == "Medium"


def test_enrich_writes_outputs_and_findings(tmp_path):
    carve = tmp_path / "carve"
    carve.mkdir()
    (carve / "pid7_x_0x1000.bin").write_bytes(b"http://45.77.13.9/c2\x00c2.evil.top\x00")
    (carve / "pid7_x_0x1000.json").write_text(json.dumps({"pid": "7", "process": "x"}))
    out = tmp_path / "report"
    findings, dossiers = me.enrich(str(carve), str(out), "20260101_000000", quiet=True)
    assert findings and dossiers
    doc = json.load(open(out / "Memory_Enrichment_20260101_000000.json"))
    assert doc["regions_with_iocs"] == 1 and "45.77.13.9" in doc["ioc_bundle"]["ips"]
    md = open(out / "Memory_Enrichment_20260101_000000.md", encoding="utf-8").read()
    assert "45[.]77[.]13[.]9" in md                 # defanged in the human report


def test_parse_capa_json_extracts_caps_and_attack():
    sample = json.dumps({"rules": {
        "encrypt data via RC4": {"meta": {"name": "encrypt data via RC4",
                                          "attack": [{"id": "T1573.001"}]}},
        "create TCP socket": {"meta": {"name": "create TCP socket", "attack": ["[T1095] Non-App"]}}}})
    out = me.parse_capa_json(sample)
    assert "encrypt data via RC4" in out["capabilities"]
    assert "T1573.001" in out["attack"] and "T1095" in out["attack"]


def test_parse_capa_json_bad_input_safe():
    assert me.parse_capa_json("not json") == {"capabilities": [], "attack": []}


def test_parse_floss_json_extracts_deobfuscated():
    sample = json.dumps({"strings": {
        "static_strings": [{"string": "libc.so.6"}, {"string": "x"}],
        "stack_strings": [{"string": "evil-c2.top"}],
        "tight_strings": [{"string": "stratum+tcp://pool.bad:7333"}],
        "decoded_strings": [{"string": "RC4_decoded_config"}]}})
    out = me.parse_floss_json(sample)
    assert out["decoded"] == ["RC4_decoded_config"] and out["stack"] == ["evil-c2.top"]
    assert out["static_count"] == 2


def test_floss_deobfuscated_iocs_merge_in(tmp_path, monkeypatch):
    # FLOSS recovers an ENCODED C2 string plain `strings` misses -> it must surface as an IOC.
    binp = tmp_path / "pid1_x_0x1000.bin"
    binp.write_bytes(b"\x00\x00 opaque packed bytes \x00\x00")     # no plaintext IOC
    (tmp_path / "pid1_x_0x1000.json").write_text(json.dumps({"pid": "1", "process": "x"}))
    monkeypatch.setattr(me, "find_capa", lambda: None)
    monkeypatch.setattr(me, "run_floss", lambda *_a, **_k: {
        "decoded": ["http://hidden-c2.top/gate"], "stack": [], "tight": [], "static_count": 0})
    d = me.enrich_region(str(binp))
    assert "hidden-c2.top" in d["iocs"]["domains"]                 # deobfuscated C2 recovered


def test_capa_capabilities_make_region_notable(tmp_path, monkeypatch):
    # a region with capa capabilities but no network IOC is still kept + reported
    binp = tmp_path / "pid2_y_0x2000.bin"
    binp.write_bytes(b"\x90\x90 some code \x90")
    (tmp_path / "pid2_y_0x2000.json").write_text(json.dumps({"pid": "2", "process": "y"}))
    monkeypatch.setattr(me, "run_capa", lambda *_a, **_k: {
        "capabilities": ["inject APC", "encrypt data via RC4"], "attack": ["T1055", "T1573.001"]})
    monkeypatch.setattr(me, "find_floss", lambda: None)
    findings, dossiers = me.enrich(str(tmp_path), None, "s", quiet=True)
    assert dossiers and dossiers[0]["capa"]["capabilities"]
    assert any(f["Type"] == "Memory Capabilities (capa)" for f in findings)


def test_enrich_clean_region_yields_nothing(tmp_path):
    # a benign carved region (no adversary IOCs) must produce ZERO findings — no FP flood
    carve = tmp_path / "carve"
    carve.mkdir()
    (carve / "pid9_py_0x400000.bin").write_bytes(b"python3.13\x00/usr/lib/libc.so.6\x00GLIBC_2.34\x00")
    (carve / "pid9_py_0x400000.json").write_text(json.dumps({"pid": "9", "process": "py"}))
    findings, dossiers = me.enrich(str(carve), None, "s", quiet=True)
    assert findings == [] and dossiers == []

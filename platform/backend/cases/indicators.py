"""The indicator vocabulary — ONE definition, read by ingest and by correlation.

Producers write recovered material into `Finding.raw`: the collector's hunts, memory
enrichment, MWCP config extraction and a reverse engineer's determination. Two consumers
read it, and they must read the same keys or they disagree about what the evidence says:

  cases.ingest        rolls each finding's indicators up into IOC rows, so the host's IOC
                      list and cross-investigation IOC search see them.
  correlation.behavior builds the behavior graph from them.

Defined here, in the app that RECEIVES evidence, because a key exists the moment a producer
emits it — before anything correlates. correlation/behavior.py imports these names.
"""

# Single-valued keys -> the indicator type they become.
SCALAR_INDICATORS = {
    "sha256": "hash", "md5": "hash", "domain": "domain", "ip": "ip", "url": "url",
    "user_agent": "user_agent", "useragent": "user_agent", "mutex": "mutex",
    "pipe": "pipe", "onion": "onion", "wallet": "wallet", "certificate": "certificate",
    "ja3": "ja3", "registry_key": "registry_key",
}

# List-valued keys. `related_hashes` matters for rotation: a recompiled implant has a new
# hash, and the sample it is related to is what still ties two hosts together.
LIST_INDICATORS = {
    "urls": "url", "domains": "domain", "ips": "ip", "onion": "onion",
    "wallets": "wallet", "xmr": "wallet", "mutexes": "mutex", "pipes": "pipe",
    "user_agents": "user_agent", "related_hashes": "hash", "hashes": "hash",
    "aws_keys": "credential", "telegram_tokens": "credential",
    "discord_webhooks": "url", "crypto_material": "crypto_material",
    "network_indicators": "network_indicator", "indicators": "indicator",
}

# Fields of the C2 configuration that are INDICATORS in their own right — an address or a
# key is pivotable, a sleep interval is not. Named explicitly: rolling the whole config up
# would fill the IOC index with timing values nobody searches for.
CONFIG_INDICATORS = {
    "address": "domain", "c2": "domain", "host": "domain", "domain": "domain",
    "ip": "ip", "url": "url", "campaign_id": "campaign_id", "key": "crypto_material",
    "rc4_key": "crypto_material", "aes_key": "crypto_material", "public_key": "crypto_material",
}


def as_values(value):
    """Flatten a raw list into indicator strings.

    Producers emit these shapes interchangeably: a bare list of strings, a list of
    `{"value": ...}` / `{"indicator": ...}` / `{"address": ...}` records, and occasionally a
    single string. Reading only the first shape silently drops the structured ones, which
    are exactly the entries a reverse engineer fills in by hand.
    """
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    out = []
    for item in value if isinstance(value, (list, tuple)) else []:
        if isinstance(item, str) and item.strip():
            out.append(item)
        elif isinstance(item, dict):
            found = item.get("value") or item.get("indicator") or item.get("address")
            if found and str(found).strip():
                out.append(str(found))
    return out


def extract(raw):
    """Every indicator a finding carries, as (ioc_type, value, context) triples.

    Context records WHERE the value came from, because provenance decides how much an
    indicator is worth: a C2 address recovered from an extracted config is a different
    claim from a domain a hunt happened to observe.
    """
    if not isinstance(raw, dict):
        return []
    out = []

    for key, ioc_type in SCALAR_INDICATORS.items():
        v = raw.get(key)
        if v is None or (isinstance(v, str) and not v.strip()):
            continue
        if isinstance(v, (dict, list)):
            continue
        out.append((ioc_type, str(v), {"field": key, "origin": "finding"}))

    for key, ioc_type in LIST_INDICATORS.items():
        for v in as_values(raw.get(key)):
            out.append((ioc_type, v, {"field": key, "origin": "finding"}))

    config = raw.get("config_extracted")
    if isinstance(config, dict):
        for key, val in config.items():
            ioc_type = CONFIG_INDICATORS.get(key)
            if not ioc_type or not isinstance(val, (str, int, float)):
                continue
            if not str(val).strip():
                continue
            out.append((ioc_type, str(val), {"field": key, "origin": "config_extracted"}))

    # Attribution, not an address, but it is what an analyst pivots on across cases.
    for key, ioc_type in (("malware_family", "malware_family"),):
        v = raw.get(key)
        if isinstance(v, str) and v.strip():
            out.append((ioc_type, v, {"field": key, "origin": "finding"}))
    for rule in as_values(raw.get("yara_matches")):
        out.append(("yara_rule", rule, {"field": "yara_matches", "origin": "finding"}))

    return out

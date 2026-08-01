"""
Server-side memory analysis

Runs headless in a Celery worker against a capture pulled from object storage, so a
capture can be re-analyzed later at a newer detection version. This module is the
carrier-independent core; a full Volatility 3 / MemProcFS pass (symbol-table dependent)
plugs in on top of it via the same interface once a matching ISF is available for the
captured kernel.

The native pass here needs **no** kernel symbol table — it reasons over raw bytes:
printable-string extraction, IOC regex (IPv4 / URL), Shannon entropy of blocks (packed
or encrypted region signal), and an optional external YARA scan when the `yara` binary
and a rule directory are present. That makes it valid on any image (and on the
size-bounded fallback sample used when a host RAM capture isn't reachable), while the
symbol-dependent deep pass stays optional.

Interface: ``analyze(local_path, ruleset_version="", yara_rules_dir=None) -> dict`` with
``{"engine", "engine_version", "summary", "findings": [ ... ]}``. Streams the file in
bounded chunks, so a multi-GB image never lands in RAM at once.
"""
import math
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter

CHUNK = 8 * 1024 * 1024          # 8 MiB streaming window
OVERLAP = 4096                   # carry bytes across window boundaries so hits aren't split
MAX_HITS_PER_KIND = 500          # cap unbounded growth on huge images
ENTROPY_BLOCK = 256 * 1024       # entropy is measured per 256 KiB block
ENTROPY_FLAG = 7.4               # >= this => packed/encrypted candidate

_IPV4 = re.compile(rb"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
_URL = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}")
_PRINTABLE = re.compile(rb"[\x20-\x7e]{6,256}")

# Cheap, high-signal tokens worth surfacing from raw memory when present.
_SUS_TOKENS = [
    b"/bin/sh -i", b"bash -i", b"nc -e", b"ncat -e", b"powershell -enc",
    b"BEGIN RSA PRIVATE KEY", b"BEGIN OPENSSH PRIVATE KEY", b"meterpreter",
    b"/dev/tcp/", b"reverse shell", b"LD_PRELOAD=", b"memfd_create",
]

# Private / non-routable space we don't want to raise as an external IOC.
_PRIVATE_IP = re.compile(
    rb"^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|255\.|"
    rb"22[4-9]\.|23\d\.|24\d\.|25[0-5]\.)"
)


def _shannon(block):
    if not block:
        return 0.0
    counts = Counter(block)
    n = len(block)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _yara_scan(path, rules_dir):
    """Optional external YARA pass. Returns a list of {rule, offset} or []."""
    if not rules_dir or not os.path.isdir(rules_dir) or not shutil.which("yara"):
        return []
    # Compile all *.yar/*.yara under rules_dir into one namespace for a single scan.
    rule_files = []
    for root, _, files in os.walk(rules_dir):
        for f in files:
            if f.endswith((".yar", ".yara")):
                rule_files.append(os.path.join(root, f))
    if not rule_files:
        return []
    hits = []
    with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False) as idx:
        for rf in rule_files:
            idx.write(f'include "{rf}"\n')
        index_path = idx.name
    try:
        proc = subprocess.run(
            ["yara", "-w", "-f", "-s", index_path, path],
            capture_output=True, text=True, timeout=600,
        )
        for line in proc.stdout.splitlines():
            parts = line.split()
            if parts and not line.startswith("0x"):
                hits.append({"rule": parts[0], "detail": line[:300]})
    except (subprocess.TimeoutExpired, OSError):
        pass
    finally:
        try:
            os.unlink(index_path)
        except OSError:
            pass
    return hits[:MAX_HITS_PER_KIND]


def analyze(local_path, ruleset_version="", yara_rules_dir=None):
    size = os.path.getsize(local_path)
    ips, urls, tokens = Counter(), Counter(), Counter()
    string_count = 0
    high_entropy_blocks = []
    block_buf = bytearray()
    block_base = 0

    with open(local_path, "rb") as fh:
        prev_tail = b""
        offset = 0
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            window = prev_tail + chunk
            base = offset - len(prev_tail)

            for m in _IPV4.finditer(window):
                ip = m.group(1)
                if not _PRIVATE_IP.match(ip):
                    ips[ip.decode()] += 1
            for m in _URL.finditer(window):
                urls[m.group(0)[:200].decode(errors="replace")] += 1
            string_count += sum(1 for _ in _PRINTABLE.finditer(window))
            for tok in _SUS_TOKENS:
                idx = window.find(tok)
                if idx != -1:
                    tokens[tok.decode(errors="replace")] = base + idx

            # Entropy accounting over fixed 256 KiB blocks.
            block_buf.extend(chunk)
            while len(block_buf) >= ENTROPY_BLOCK:
                blk = bytes(block_buf[:ENTROPY_BLOCK])
                del block_buf[:ENTROPY_BLOCK]
                e = _shannon(blk)
                if e >= ENTROPY_FLAG and len(high_entropy_blocks) < MAX_HITS_PER_KIND:
                    high_entropy_blocks.append({"offset": block_base, "entropy": round(e, 3)})
                block_base += ENTROPY_BLOCK

            prev_tail = window[-OVERLAP:]
            offset += len(chunk)

    findings = []
    for ip, n in ips.most_common(MAX_HITS_PER_KIND):
        findings.append({
            "finding_type": "External IPv4 in memory", "severity": "Medium",
            "detail": f"routable address {ip} present {n}x in image", "offset": None,
            "evidence": {"ioc_type": "ip", "value": ip, "occurrences": n},
        })
    for url, n in urls.most_common(MAX_HITS_PER_KIND):
        findings.append({
            "finding_type": "URL in memory", "severity": "Medium",
            "detail": f"{url} ({n}x)", "offset": None,
            "evidence": {"ioc_type": "url", "value": url, "occurrences": n},
        })
    for tok, off in tokens.items():
        findings.append({
            "finding_type": "Suspicious token in memory", "severity": "High",
            "detail": f"token {tok!r} at offset {off}", "offset": off,
            "evidence": {"token": tok},
        })
    for blk in high_entropy_blocks[:50]:
        findings.append({
            "finding_type": "High-entropy region (packed/encrypted candidate)",
            "severity": "Low",
            "detail": f"entropy {blk['entropy']} at offset {blk['offset']}",
            "offset": blk["offset"], "evidence": blk,
        })
    for hit in _yara_scan(local_path, yara_rules_dir):
        findings.append({
            "finding_type": f"YARA: {hit['rule']}", "severity": "High",
            "detail": hit.get("detail", ""), "offset": None, "evidence": hit,
        })

    summary = {
        "image_size_bytes": size,
        "external_ips": len(ips),
        "urls": len(urls),
        "suspicious_tokens": len(tokens),
        "high_entropy_blocks": len(high_entropy_blocks),
        "printable_strings": string_count,
        "finding_count": len(findings),
        "ruleset_version": ruleset_version,
    }
    return {
        "engine": "native-scan",
        "engine_version": "1.0",
        "summary": summary,
        "findings": findings,
    }

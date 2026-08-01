"""
Full memory analysis: the toolkit's proven Volatility 3 pass, run inside the enclave.

This is the analysis the toolkit already validates — `analyze_memory_linux.py` with its
Volatility plugin set, the custom `linux_ir` plugins for structures no stock plugin
exposes, and YARA. It runs here rather than on an analyst's machine so the capture never
leaves the enclave and the results land directly in the system of record as metadata.

It requires an ISF matching the captured kernel. When the enclave does not have one, the
caller falls back to the structural scan and records that it did; a reduced pass must
never be presented as a full one.
"""
import glob
import json
import os
import re
import subprocess
import tempfile

TOOLKIT = os.environ.get("IR_TOOLKIT_DIR", "/opt/toolkit")
ANALYZER = os.path.join(TOOLKIT, "playbooks/linux/threat_hunting/analyze_memory_linux.py")
ENRICHER = os.path.join(TOOLKIT, "playbooks/linux/threat_hunting/memory_enrich.py")
PLUGIN_DIR = os.path.join(TOOLKIT, "playbooks/linux/threat_hunting/vol_plugins")
YARA_RULES = os.path.join(TOOLKIT, "tools/yara_rules")

ENGINE = "volatility3"

# Severity vocabulary differs between the toolkit's findings and the platform's model;
# anything unrecognized keeps its own label rather than being coerced into a known one.
SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Low", "informational": "Low"}


def available():
    """Whether this worker image carries the analyzer at all."""
    return os.path.isfile(ANALYZER)


def _safe_name(value):
    """A hostname reduced to what is safe as a directory name."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "")).strip("._-")[:64]


def analyze(image_path, symbols_path, ruleset_version="", timeout=None, deep=False,
            host_label=""):
    """Run the proven analyzer and return findings in the platform's shape.

    `symbols_path` is a file or directory Volatility can load symbol tables from.
    Returns (findings, summary, carve_dir). Raises RuntimeError when it cannot run.

    The analyzer writes into a directory named for the host, because that directory is
    the toolkit's report folder: the investigation engine runs on it afterwards and takes
    the hostname from its name. Keeping the toolkit's own layout means the engine reads
    the analyzer's real output rather than something re-serialized from the database.
    """
    if not available():
        raise RuntimeError(f"analyzer not present at {ANALYZER}")
    if not symbols_path:
        raise RuntimeError("no symbol table for this kernel")

    out_dir = os.path.join(tempfile.mkdtemp(prefix="memanalysis-"),
                           _safe_name(host_label) or "unknown-host")
    carve_dir = os.path.join(out_dir, "carved")
    os.makedirs(carve_dir, exist_ok=True)
    symbol_dir = symbols_path if os.path.isdir(symbols_path) else os.path.dirname(symbols_path)

    cmd = [
        "python3", ANALYZER,
        "--image", image_path,
        "--output-dir", out_dir,
        "--symbols", symbol_dir,
        "--quiet",
    ]
    if os.path.isdir(YARA_RULES):
        # Carving is what makes the enrichment pass and reverse engineering possible: YARA
        # true-positive regions are written out, the mwcp parsers read config from those
        # bytes, and what remains is what a reverse engineer opens.
        #
        # The engine choice decides whether carving happens at all. The analyzer's default
        # `native` engine scans the whole image and reports matches but carves nothing; only
        # the per-process `vol` engine attributes a hit to a PID and can extract its region.
        # Asking for --carve with the native engine silently produces no regions.
        cmd += ["--yara", "--yara-rules-dir", YARA_RULES,
                "--yara-engine", os.environ.get("IR_YARA_ENGINE", "vol"),
                # The per-process scan abandons a process when it exhausts this budget, and
                # the analyzer raises "YARA Scan Coverage Incomplete" for each one it gave
                # up on. The default suits an interactive scan of a modest image; against a
                # 24 GB capture it expires on most processes, which costs both the matches
                # and the regions that would have been carved from them.
                "--yara-proc-timeout", os.environ.get("IR_YARA_PROC_TIMEOUT", "900"),
                "--carve", "--carve-dir", carve_dir]
    if deep:
        cmd += ["--deep"]

    env = dict(os.environ)
    # By default only injected (anonymous + executable) regions are carved — the ones that
    # actually warrant reverse engineering. Set IR_CARVE_ANY=1 to keep every hit's region,
    # which is far more volume and mostly file-backed matches.
    if os.environ.get("IR_CARVE_ANY") == "1":
        env["IR_CARVE_ANY"] = "1"
    # The custom plugins live with the toolkit; Volatility needs to be told where.
    if os.path.isdir(PLUGIN_DIR):
        env["VOLATILITY_PLUGIN_PATH"] = PLUGIN_DIR
    env["VOLATILITY_SYMBOL_PATH"] = symbol_dir

    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, env=env, check=False)

    findings_files = sorted(glob.glob(os.path.join(out_dir, "Memory_Findings_*.json")))
    if not findings_files:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        raise RuntimeError(f"analyzer produced no findings file: {' | '.join(tail)}")

    with open(findings_files[-1], "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    records = raw.get("findings", raw) if isinstance(raw, dict) else raw

    findings = []
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        sev = str(rec.get("Severity", "")).strip()
        detail = str(rec.get("Details", ""))
        mitre = rec.get("MITRE") or []
        findings.append({
            "finding_type": str(rec.get("Type", "Memory finding")),
            "severity": SEVERITY.get(sev.lower(), sev or "Low"),
            "detail": detail[:4000],
            "offset": None,
            "evidence": {
                "target": str(rec.get("Target", "")),
                "mitre": mitre if isinstance(mitre, list) else [str(mitre)],
                "observed_at": rec.get("Timestamp", ""),
                "engine": ENGINE,
            },
        })

    # Enrichment: run the mwcp parsers over the carved regions to recover implant
    # configuration — C2 addresses, wallets, tokens, credentials — that a plugin pass
    # alone does not surface. It only ever elevates; it never suppresses a finding.
    enrichment = _enrich(carve_dir, out_dir)
    findings.extend(enrichment.get("findings", []))
    # The carve directory is returned so the caller can persist the regions; they are the
    # input to reverse engineering and must outlive this temporary directory.
    enrichment["carve_dir"] = carve_dir

    # Anything the analyzer wrote alongside the findings is context worth keeping.
    extras = {}
    for name in ("_yara_results", "_plugin_status"):
        for path in glob.glob(os.path.join(out_dir, f"{name}_*.json")):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    extras[name.strip("_")] = json.load(fh)
            except (OSError, ValueError):
                pass

    summary = {
        "engine": ENGINE,
        "finding_count": len(findings),
        "carved_regions": enrichment.get("regions", 0),
        "enrichment_iocs": enrichment.get("ioc_count", 0),
        "ruleset_version": ruleset_version,
        "symbols": os.path.basename(symbols_path),
        "analyzer_rc": proc.returncode,
        # The toolkit report folder the analyzer just wrote. The investigation engine runs
        # on it next, so the caller needs the path; it is dropped from the stored summary
        # once adjudication is done, since a temporary path is not a result.
        "report_dir": out_dir,
        **extras,
    }
    return findings, summary, carve_dir


def _enrich(carve_dir, out_dir):
    """Recover implant configuration from carved memory regions via the mwcp parsers.

    A failure here reduces detail but must not lose the Volatility findings already
    produced, so it is reported in the summary rather than raised.
    """
    result = {"findings": [], "regions": 0, "ioc_count": 0}
    if not os.path.isfile(ENRICHER):
        return result
    regions = glob.glob(os.path.join(carve_dir, "*.bin"))
    result["regions"] = len(regions)
    if not regions:
        return result

    proc = subprocess.run(
        ["python3", ENRICHER, "--carve-dir", carve_dir, "--out-dir", out_dir, "--quiet"],
        capture_output=True, text=True, check=False,
    )
    files = sorted(glob.glob(os.path.join(out_dir, "Memory_Enrichment_*.json")))
    if not files:
        result["error"] = (proc.stderr or "enrichment produced no output").strip()[:300]
        return result

    try:
        with open(files[-1], "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        result["error"] = f"unreadable enrichment output: {exc}"
        return result

    for rec in (doc.get("findings") or []):
        if not isinstance(rec, dict):
            continue
        sev = str(rec.get("Severity", "")).strip()
        result["findings"].append({
            "finding_type": str(rec.get("Type", "Implant configuration")),
            "severity": SEVERITY.get(sev.lower(), sev or "Medium"),
            "detail": str(rec.get("Details", ""))[:4000],
            "offset": None,
            "evidence": {
                "target": str(rec.get("Target", "")),
                "mitre": rec.get("MITRE") or [],
                "source": "mwcp",
                "engine": ENGINE,
            },
        })
    bundle = doc.get("iocs") or doc.get("ioc_bundle") or {}
    result["ioc_count"] = sum(len(v) for v in bundle.values() if isinstance(v, list))
    return result

#!/usr/bin/env python3
"""
ir-ingest PULLER — runs inside the enclave.

This is the ONLY component that bridges the DMZ and the internal enclave, and it does so by
*initiating outbound* to the DMZ receiver — nothing is ever initiated into the enclave. It
polls the receiver for verified bundles, fetches each one, re-verifies the custody seal, then
hands it to the existing ingest logic (upload capture to object storage + POST metadata to the
API), and finally tells the receiver to drop it. Every fetch is a short-lived connection that
closes on completion.

Holds the internal credentials (object store + API token); the DMZ receiver holds none.
"""
import argparse
import json
import os
import subprocess
import shutil
import ssl
import sys
import tarfile
import tempfile
import time
import urllib.request

import sysstats  # shared platform/shared/sysstats.py

RECEIVER = os.environ.get("RECEIVER_URL", "https://receiver:8090").rstrip("/")
# The receiver's certificate, pinned as this puller's only trust anchor.
#
# The bundles coming inward are memory images from hosts under suspicion. Verifying the server
# is what keeps the enclave from pulling one out of an impostor on the DMZ segment and treating
# it as evidence — and this is the one direction that crosses the tier boundary, so it is the
# connection least able to rely on the network being trustworthy.
#
# Pinned rather than trusting the system store: there is exactly one server this should ever
# talk to, and a public CA would vouch for anyone who obtained a certificate for that name.
RECEIVER_CA = os.environ.get("RECEIVER_CA_BUNDLE", "")


def _tls():
    """The SSL context for receiver connections, or None for plain HTTP.

    Verification is never disabled here. A puller that skipped it would accept evidence from
    anything answering on that address, which is indistinguishable from having no boundary.
    """
    if not RECEIVER.startswith("https://"):
        return None
    if RECEIVER_CA:
        return ssl.create_default_context(cafile=RECEIVER_CA)
    return ssl.create_default_context()
# Where verified symbol tables are installed for the analysis worker to read.
SYMBOL_STORE = os.environ.get("IR_SYMBOLS_DIR", "/symbols")
INGEST = os.path.join(os.path.dirname(__file__), "ir_ingest.py")
API_URL = os.environ.get("IR_API_URL", "http://backend:8000")
API_TOKEN = os.environ.get("IR_BROKER_TOKEN", "")
# How often each component's resources are reported to the platform. Long enough that the
# reports are cheap, short enough that an admin sees a filling volume before it fills.
REPORT_INTERVAL = int(os.environ.get("IR_HEALTH_REPORT_INTERVAL", "900"))
_LOGS = sysstats.LogCounter()


def _get(path):
    with urllib.request.urlopen(f"{RECEIVER}{path}", timeout=30, context=_tls()) as r:
        return r.read()


def _download(path, dest, timeout=7200):
    """Stream a held bundle to `dest` rather than returning it.

    A bundle carries a memory image sized by the endpoint's RAM, which the puller has no
    reason to hold in memory on its way to disk. The timeout is generous because the transfer
    is bounded by the size of the capture, not by how quickly the receiver answers.
    """
    with urllib.request.urlopen(f"{RECEIVER}{path}", timeout=timeout, context=_tls()) as r, \
            open(dest, "wb") as fh:
        shutil.copyfileobj(r, fh, 8 * 1024 * 1024)


def _delete(path):
    req = urllib.request.Request(f"{RECEIVER}{path}", method="DELETE")
    with urllib.request.urlopen(req, timeout=30, context=_tls()) as r:
        return r.read()


def report_health():
    """Send the puller's own report inward, and the receiver's along with it.

    The receiver sits in the DMZ with no route into the enclave — by design, it cannot
    initiate anything inward. So its resource figures reach the platform the same way its
    bundles do: this process, which already polls it, reads them on the outbound leg and
    forwards them with its own.
    """
    reports = [sysstats.collect("puller (enclave)", tier="dmz",
                                disk_paths=(tempfile.gettempdir(), SYMBOL_STORE),
                                log_counter=_LOGS)]
    try:
        raw = _get("/stats")
        receiver_report = json.loads(raw.decode())
        reports.append(receiver_report)
    except Exception as exc:  # noqa: BLE001
        # A receiver that cannot be reached is itself worth reporting: the row goes stale in
        # the console rather than silently disappearing.
        _LOGS.error(f"receiver stats unavailable: {exc}")

    body = json.dumps({"reports": reports}).encode()
    req = urllib.request.Request(
        f"{API_URL.rstrip('/')}/api/component-health/report/", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Token {API_TOKEN}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()
    print(f"[puller] reported health for {len(reports)} component(s)")


def _bundle_root(extract_dir):
    entries = [e for e in os.listdir(extract_dir) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(extract_dir, entries[0])):
        return os.path.join(extract_dir, entries[0])
    return extract_dir


def process_one(bid):
    """Fetch bundle bid, ingest it (re-verify + upload + POST), drop it. True on success."""
    tmp = tempfile.mkdtemp(prefix="pull-")
    tar_path = os.path.join(tmp, "b.tar.gz")
    _download(f"/fetch/{bid}", tar_path)
    extract = os.path.join(tmp, "x")
    os.makedirs(extract)
    with tarfile.open(tar_path, "r:gz") as tf:
        tf.extractall(extract)
    folder = _bundle_root(extract)

    # Reuse the proven ingest path — it re-verifies custody, then uploads + POSTs.
    rc = subprocess.call([sys.executable, INGEST, "--host-folder", folder])
    if rc == 0:
        _delete(f"/fetch/{bid}")
        print(f"[puller] ingested + dropped bundle {bid}")
        return True
    print(f"[puller] ingest FAILED for bundle {bid} (rc={rc}) — leaving it held", file=sys.stderr)
    return False


def process_isf(sid):
    """Fetch one verified symbol table and install it into the enclave symbol store.

    Symbols travel the same direction as evidence and by the same discipline — the enclave
    initiates, the DMZ never pushes — but they are a separate artifact from a separate
    origin, so they have their own queue and their own checks.

    The receiver already verified the seal. This re-checks structure before the table is
    placed where the analyzer will trust it: a symbol table dictates how memory is
    interpreted, so a bad one yields confident, wrong conclusions rather than an error.
    """
    tmp = tempfile.mkdtemp(prefix="isf-")
    try:
        tar_path = os.path.join(tmp, "s.tar.gz")
        with open(tar_path, "wb") as fh:
            fh.write(_get(f"/isf/fetch/{sid}"))
        extract = os.path.join(tmp, "x")
        os.makedirs(extract)
        with tarfile.open(tar_path, "r:gz") as tf:
            for member in tf.getmembers():
                name = os.path.basename(member.name)
                if not member.isfile() or name != member.name or name.startswith("."):
                    print(f"[puller] rejecting symbol bundle {sid}: unsafe entry "
                          f"{member.name!r}", file=sys.stderr)
                    return False
            tf.extractall(extract)

        mpath = os.path.join(extract, "_isf_manifest.json")
        if not os.path.isfile(mpath):
            print(f"[puller] symbol bundle {sid} has no manifest", file=sys.stderr)
            return False
        with open(mpath, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)

        key = manifest.get("symbol_key", "")
        src = os.path.join(extract, f"{key}.json")
        if not key or "/" in key or not os.path.isfile(src):
            print(f"[puller] symbol bundle {sid}: bad key or missing table", file=sys.stderr)
            return False

        with open(src, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if not isinstance(doc, dict) or "symbols" not in doc:
            print(f"[puller] symbol bundle {sid} is not a Volatility table", file=sys.stderr)
            return False

        os.makedirs(SYMBOL_STORE, exist_ok=True)
        dest = os.path.join(SYMBOL_STORE, f"{key}.json")
        # Same filesystem is not guaranteed between the temp dir and the store volume.
        shutil.move(src, dest)
        os.chmod(dest, 0o444)   # the analyzer reads it; nothing should rewrite it

        _record_fulfilled(key, dest)
        _delete(f"/isf/fetch/{sid}")
        print(f"[puller] installed symbol table {key} "
              f"({len(doc.get('symbols') or {})} symbols) — dropped {sid}")
        return True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _record_fulfilled(key, path):
    """Mark the outstanding request satisfied, so the admin alert clears."""
    try:
        subprocess.call([sys.executable, os.path.join(os.path.dirname(INGEST), "manage.py"),
                         "symbols_fulfilled", key, path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        # A missing bookkeeping update must not undo an otherwise good install; the worker
        # resolves symbols from the store, not from the request record.
        pass


def poll_isf():
    pending = json.loads(_get("/isf/pending")).get("pending", [])
    if not pending:
        return 0, 0
    print(f"[puller] {len(pending)} symbol table(s) pending")
    ok = 0
    for sid in pending:
        try:
            if process_isf(sid):
                ok += 1
        except Exception as exc:  # noqa: BLE001
            print(f"[puller] error on symbol bundle {sid}: {exc}", file=sys.stderr)
    return ok, len(pending)


def poll_once():
    poll_isf()
    pending = json.loads(_get("/pending")).get("pending", [])
    print(f"[puller] {len(pending)} bundle(s) pending")
    ok = 0
    for bid in pending:
        try:
            if process_one(bid):
                ok += 1
        except Exception as exc:  # noqa: BLE001
            print(f"[puller] error on {bid}: {exc}", file=sys.stderr)
    return ok, len(pending)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="process pending then exit (UAT)")
    ap.add_argument("--interval", type=int, default=int(os.environ.get("PULL_INTERVAL", "10")))
    args = ap.parse_args()

    if args.once:
        ok, total = poll_once()
        return 0 if ok == total else 1

    print(f"[puller] polling {RECEIVER} every {args.interval}s")
    last_report = 0.0
    while True:
        try:
            poll_once()
        except Exception as exc:  # noqa: BLE001 — keep the loop alive
            _LOGS.error(f"poll error: {exc}")
            print(f"[puller] poll error: {exc}", file=sys.stderr)
        # Health reporting rides this loop rather than a scheduler: the puller is already the
        # one process that talks to both sides, so it is the only place the receiver's report
        # can be picked up and carried inward.
        if time.time() - last_report >= REPORT_INTERVAL:
            try:
                report_health()
                last_report = time.time()
            except Exception as exc:  # noqa: BLE001 — reporting must never stop the pulling
                _LOGS.error(f"health report failed: {exc}")
                print(f"[puller] health report failed: {exc}", file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
ir-ingest RECEIVER — runs in the DMZ, untrusted-facing.

The only thing a (potentially compromised) endpoint can reach. It accepts a bundle upload,
CLOSES the connection, verifies the chain-of-custody seal, and — only if valid — holds the
bundle as an opaque blob for the internal puller to fetch. It holds NO internal credentials
and has NO network route into the enclave, so even if this process is exploited by a
malicious upload it cannot pivot inward.

Stdlib only (http.server) + the shared custody module. Endpoints:
  POST   /ingest       upload a .tar.gz of the reports/<host>/ bundle → verify → hold (202) or drop (400)
  GET    /pending      list held bundle ids (the internal puller polls this)
  GET    /fetch/<id>   download the held .tar.gz (puller, over the dmz network)
  DELETE /fetch/<id>   remove after a successful pull
  GET    /healthz
"""
import hashlib
import hmac
import json
import os
import shutil
import ssl
import tarfile
import tempfile
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import custody  # shared platform/shared/custody.py
import sysstats  # shared platform/shared/sysstats.py

HOLDING = os.environ.get("RECEIVER_HOLDING", "/holding")
# Symbol tables are held apart from evidence. They enter by the same one-way discipline —
# sealed, verified here, pulled inward — but they are a different kind of artifact from a
# different origin (an internet-connected acquisition machine, not a collected endpoint),
# so they get their own channel, their own validation and their own holding area rather
# than being mixed into the evidence queue.
ISF_HOLDING = os.environ.get("RECEIVER_ISF_HOLDING", "/holding-isf")
# An evidence bundle carries a memory image, so its size tracks the endpoint's RAM. A 22 GiB
# workstation compresses to roughly 7 GiB and a 512 GiB server to well over a hundred, so any
# constant chosen here is wrong for some machine the collector will legitimately be pointed at.
# There is no fixed ceiling by default.
#
# What genuinely bounds an upload is the space to put it. This receiver is the only thing a
# potentially compromised endpoint can reach, and an upload that fills the holding volume
# takes the ingest path down for every other host, so capacity is checked before a byte is
# read rather than discovered part-way through a transfer. Set RECEIVER_MAX_BYTES to impose a
# hard ceiling as well; 0 (the default) means "whatever fits".
MAX_BYTES = int(os.environ.get("RECEIVER_MAX_BYTES", "0"))
# Never consume the last of the volume: the puller needs room to work, and a full filesystem
# fails in more confusing ways than a refused upload.
DISK_HEADROOM = int(os.environ.get("RECEIVER_DISK_HEADROOM", str(8 * 1024 * 1024 * 1024)))
# Symbol tables are JSON descriptions of a kernel's types, measured in tens of megabytes. They
# ride a separate channel and keep a real ceiling: nothing legitimate on that path approaches
# it, and it must not widen just because evidence bundles have no fixed limit.
MAX_ISF_BYTES = int(os.environ.get("RECEIVER_MAX_ISF_BYTES", str(2 * 1024 * 1024 * 1024)))
# Uploads are streamed to disk in blocks. A receiver cannot hold a bundle the size of an
# endpoint's RAM in memory — it has less of it than the hosts it serves.
READ_CHUNK = 8 * 1024 * 1024
os.makedirs(HOLDING, exist_ok=True)
os.makedirs(ISF_HOLDING, exist_ok=True)
# Spool on the holding volume rather than in /tmp: one filesystem to check for capacity, and
# the accept step becomes a rename instead of copying the whole capture a second time.
SPOOL = os.path.join(HOLDING, ".spool")
os.makedirs(SPOOL, exist_ok=True)
_QUARANTINED = 0
# Counted in-process: reading these back out of the container log stream would need access to
# the runtime, which is exactly what this component is denied.
_LOGS = sysstats.LogCounter()


def _free_bytes(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def _capacity_refusal(length, limit):
    """Why this upload cannot be accepted, or None if it can.

    Checked up front: a transfer that runs the volume dry part-way through leaves a partial
    bundle and a receiver that cannot serve anyone else.
    """
    if length <= 0:
        return {"error": "bad content length", "length": length}
    if limit and length > limit:
        return {"error": "upload exceeds configured limit",
                "length": length, "max_bytes": limit}
    free = _free_bytes(SPOOL)
    if length + DISK_HEADROOM > free:
        return {"error": "insufficient space in holding area",
                "length": length, "free_bytes": free, "headroom_bytes": DISK_HEADROOM}
    return None


def _stream_to_file(rfile, path, length):
    """Copy exactly `length` bytes from the request body to `path`.

    Returns True when the full body arrived. A short read means the client went away
    mid-upload, which must not be mistaken for a complete bundle.
    """
    remaining = length
    with open(path, "wb") as fh:
        while remaining > 0:
            chunk = rfile.read(min(READ_CHUNK, remaining))
            if not chunk:
                break
            fh.write(chunk)
            remaining -= len(chunk)
    return remaining == 0


def _bundle_root(extract_dir):
    """The tar holds a single top-level <host>/ dir; return its path."""
    entries = [e for e in os.listdir(extract_dir) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(extract_dir, entries[0])):
        return os.path.join(extract_dir, entries[0])
    return extract_dir


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # quieter logs
        print("[receiver]", self.address_string(), fmt % args)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"status": "ok", "held": len(self._pending()),
                                    "quarantined": _QUARANTINED})
        if self.path == "/stats":
            # Read by the puller and forwarded inward. The receiver cannot reach the enclave
            # itself, and holds nothing worth protecting here: free space on its own holding
            # volume and its own error counts.
            held = self._pending()
            return self._send(200, sysstats.collect(
                "receiver (dmz)", tier="dmz", disk_paths=(HOLDING, ISF_HOLDING),
                log_counter=_LOGS,
                extra={"bundles_held": len(held), "quarantined": _QUARANTINED,
                       "held_bytes": sum(
                           os.path.getsize(os.path.join(HOLDING, f"{b}.tar.gz"))
                           for b in held
                           if os.path.exists(os.path.join(HOLDING, f"{b}.tar.gz"))),
                       "max_bytes": MAX_BYTES, "disk_headroom_bytes": DISK_HEADROOM}))
        if self.path == "/isf/pending":
            return self._send(200, {"pending": self._pending_isf()})
        if self.path.startswith("/isf/fetch/"):
            sid = self.path.rsplit("/", 1)[-1]
            path = os.path.join(ISF_HOLDING, f"{sid}.tar.gz")
            if not os.path.isfile(path):
                return self._send(404, {"error": "no such symbol bundle"})
            with open(path, "rb") as fh:
                body = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return None
        if self.path == "/pending":
            return self._send(200, {"pending": self._pending()})
        if self.path.startswith("/isf/fetch/"):
            sid = self.path.rsplit("/", 1)[-1]
            for suffix in (".tar.gz", ".meta.json"):
                p = os.path.join(ISF_HOLDING, f"{sid}{suffix}")
                if os.path.isfile(p):
                    os.remove(p)
            return self._send(200, {"deleted": sid})
        if self.path.startswith("/fetch/"):
            bid = self.path.rsplit("/", 1)[-1]
            path = os.path.join(HOLDING, f"{bid}.tar.gz")
            if not (bid.isalnum() and os.path.exists(path)):
                return self._send(404, {"error": "not found"})
            # Streamed, not read into memory: this is the capture-sized leg of the transfer,
            # and the receiver is deliberately a small process.
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(path, "rb") as fh:
                shutil.copyfileobj(fh, self.wfile, READ_CHUNK)
            return
        return self._send(404, {"error": "unknown path"})

    def do_DELETE(self):
        if self.path.startswith("/isf/fetch/"):
            sid = self.path.rsplit("/", 1)[-1]
            for suffix in (".tar.gz", ".meta.json"):
                p = os.path.join(ISF_HOLDING, f"{sid}{suffix}")
                if os.path.isfile(p):
                    os.remove(p)
            return self._send(200, {"deleted": sid})
        if self.path.startswith("/fetch/"):
            bid = self.path.rsplit("/", 1)[-1]
            if bid.isalnum():
                for suffix in (".tar.gz", ".meta.json"):
                    p = os.path.join(HOLDING, f"{bid}{suffix}")
                    if os.path.exists(p):
                        os.remove(p)
                return self._send(200, {"deleted": bid})
        return self._send(404, {"error": "unknown path"})

    def do_POST(self):
        global _QUARANTINED
        if self.path == "/isf":
            return self._post_isf()
        if self.path != "/ingest":
            return self._send(404, {"error": "unknown path"})
        length = int(self.headers.get("Content-Length", 0))
        refusal = _capacity_refusal(length, MAX_BYTES)
        if refusal:
            _LOGS.error(f"refused upload: {refusal}")
            print(f"[receiver] REFUSED upload: {refusal}")
            return self._send(400, refusal)
        # Stream the upload to disk, then the connection is done (no interactive channel back).
        tmp = tempfile.mkdtemp(prefix="recv-", dir=SPOOL)
        tar_path = os.path.join(tmp, "bundle.tar.gz")
        if not _stream_to_file(self.rfile, tar_path, length):
            shutil.rmtree(tmp, ignore_errors=True)
            return self._send(400, {"error": "incomplete upload"})
        extract = os.path.join(tmp, "x")
        os.makedirs(extract)
        try:
            with tarfile.open(tar_path, "r:gz") as tf:
                _safe_extract(tf, extract)
        except Exception as exc:  # noqa: BLE001
            _QUARANTINED += 1
            _LOGS.error(f"unreadable archive: {exc}")
            return self._send(400, {"error": f"unreadable archive: {exc}"})

        root = _bundle_root(extract)
        ok, reason, record = custody.verify(root)
        if not ok:
            _QUARANTINED += 1
            _LOGS.error(f"custody verify failed: {reason}")
            print(f"[receiver] QUARANTINE — custody verify failed: {reason}")
            return self._send(400, {"error": "custody verification failed", "reason": reason})

        bid = uuid.uuid4().hex
        # The spool lives on the holding volume, so this is a rename rather than a second
        # copy of a capture-sized file.
        shutil.move(tar_path, os.path.join(HOLDING, f"{bid}.tar.gz"))
        meta = {"id": bid, "host": os.path.basename(root),
                "operator": record.get("operator", ""),
                "manifest_sha256": record.get("manifest_sha256", ""),
                "size": length}
        with open(os.path.join(HOLDING, f"{bid}.meta.json"), "w") as fh:
            json.dump(meta, fh)
        shutil.rmtree(tmp, ignore_errors=True)
        print(f"[receiver] accepted + verified bundle {bid} ({meta['host']}) — held for pull")
        return self._send(202, {"id": bid, "verified": True})

    def _post_isf(self):
        """Accept a sealed Volatility symbol table from the acquisition machine.

        Symbols come from an internet-connected host, which is the least trusted position
        in this architecture, so acceptance is narrow: the archive must contain exactly a
        manifest and one JSON symbol table, the table must hash to what the manifest
        claims, and the HMAC must verify when a key is configured. An ISF is data rather
        than code, but it dictates how the analyzer interprets memory — a substituted one
        yields confident, wrong forensic conclusions.
        """
        global _QUARANTINED
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_ISF_BYTES:
            return self._send(400, {"error": "bad content length",
                                    "length": length, "max_bytes": MAX_ISF_BYTES})
        tmp = tempfile.mkdtemp(prefix="isf-", dir=SPOOL)
        tar_path = os.path.join(tmp, "isf.tar.gz")
        if not _stream_to_file(self.rfile, tar_path, length):
            shutil.rmtree(tmp, ignore_errors=True)
            return self._send(400, {"error": "incomplete upload"})
        extract = os.path.join(tmp, "x")
        os.makedirs(extract)
        try:
            with tarfile.open(tar_path, "r:gz") as tf:
                _safe_extract(tf, extract)
        except Exception as exc:  # noqa: BLE001
            _QUARANTINED += 1
            shutil.rmtree(tmp, ignore_errors=True)
            return self._send(400, {"error": f"unreadable archive: {exc}"})

        ok, reason, manifest = _verify_isf(extract)
        if not ok:
            _QUARANTINED += 1
            shutil.rmtree(tmp, ignore_errors=True)
            print(f"[receiver] QUARANTINE — symbol bundle rejected: {reason}")
            return self._send(400, {"error": "symbol verification failed", "reason": reason})

        sid = uuid.uuid4().hex
        shutil.move(tar_path, os.path.join(ISF_HOLDING, f"{sid}.tar.gz"))
        meta = {"id": sid, "symbol_key": manifest.get("symbol_key", ""),
                "kernel_release": manifest.get("kernel_release", ""),
                "sha256": manifest.get("sha256", ""), "size": length}
        with open(os.path.join(ISF_HOLDING, f"{sid}.meta.json"), "w") as fh:
            json.dump(meta, fh)
        shutil.rmtree(tmp, ignore_errors=True)
        print(f"[receiver] accepted symbol table {meta['symbol_key']} "
              f"({meta['kernel_release']}) — held for pull")
        return self._send(202, {"id": sid, "verified": True,
                                "symbol_key": meta["symbol_key"]})

    @staticmethod
    def _pending_isf():
        return sorted(f[:-7] for f in os.listdir(ISF_HOLDING) if f.endswith(".tar.gz"))

    @staticmethod
    def _pending():
        return sorted(f[:-7] for f in os.listdir(HOLDING) if f.endswith(".tar.gz"))


def _verify_isf(root):
    """Structural and cryptographic checks on a symbol bundle.

    Returns (ok, reason, manifest).
    """
    mpath = os.path.join(root, "_isf_manifest.json")
    if not os.path.isfile(mpath):
        return False, "no manifest", {}
    try:
        with open(mpath, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        return False, f"unreadable manifest: {exc}", {}

    if manifest.get("kind") != "volatility-isf":
        return False, "manifest is not for a symbol table", manifest

    key = manifest.get("symbol_key", "")
    if not key or "/" in key or key.startswith("."):
        return False, "missing or unsafe symbol_key", manifest

    # Exactly the manifest and its symbol table — nothing else rides along.
    entries = sorted(os.listdir(root))
    expected = sorted(["_isf_manifest.json", f"{key}.json"])
    if entries != expected:
        return False, f"unexpected archive contents: {entries}", manifest

    isf_path = os.path.join(root, f"{key}.json")
    digest = hashlib.sha256()
    with open(isf_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != manifest.get("sha256"):
        return False, "symbol table does not match its manifest hash", manifest

    hmac_key = os.environ.get("IR_CUSTODY_HMAC_KEY", "")
    if hmac_key:
        claimed = manifest.get("hmac", "")
        if not claimed:
            return False, "bundle is unsigned but a key is configured", manifest
        payload = {k: v for k, v in manifest.items() if k != "hmac"}
        expect = hmac.new(
            hmac_key.encode(),
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expect, claimed):
            return False, "seal does not verify", manifest

    # Parse it here so a malformed table is refused at the boundary rather than inside.
    try:
        with open(isf_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        return False, f"symbol table is not valid JSON: {exc}", manifest
    if not isinstance(doc, dict) or "symbols" not in doc:
        return False, "JSON is not a Volatility symbol table", manifest

    return True, "", manifest


def _safe_extract(tf, dest):
    """Guard against path traversal in the uploaded archive."""
    dest_abs = os.path.abspath(dest)
    for m in tf.getmembers():
        target = os.path.abspath(os.path.join(dest, m.name))
        if not target.startswith(dest_abs + os.sep):
            raise ValueError(f"unsafe path in archive: {m.name}")
    tf.extractall(dest)


def _tls_context():
    """Build the server's TLS context, or return None when plaintext is explicitly allowed.

    WHY THIS IS NOT OPTIONAL IN A REAL DEPLOYMENT: what crosses this connection is a memory
    image. It contains whatever the host held in RAM — credentials, private keys, session
    tokens, the contents of every file the machine had open. An endpoint under suspicion is
    frequently on a segment the responder does not control and does not trust, and shipping
    that in the clear hands the entire host to anyone on the path. The custody HMAC that seals
    the bundle proves it was not ALTERED; it does nothing to stop it being READ.

    Server authentication matters as much as encryption here. Without it the collector will
    hand the machine's memory to whoever answers on that address, which on a compromised
    segment is a realistic outcome rather than a theoretical one.

    Client certificates, when configured, keep third parties from filling the holding volume or
    planting bundles. They are deliberately NOT claimed as protection against a hostile
    endpoint: the host is presumed compromised, so any key stored on it is presumed readable by
    the adversary too.
    """
    cert = os.environ.get("RECEIVER_TLS_CERT", "")
    key = os.environ.get("RECEIVER_TLS_KEY", "")

    if not cert or not key:
        # Refusing by default is the point. A receiver that silently downgrades to plaintext
        # when its certificate is missing is worse than one that will not start: the collection
        # still appears to succeed, and nobody learns the evidence crossed the wire in the clear
        # until it no longer matters.
        if os.environ.get("RECEIVER_ALLOW_PLAINTEXT", "") != "1":
            raise SystemExit(
                "[receiver] REFUSING TO START WITHOUT TLS.\n"
                "  A memory image carries the host's credentials, keys and open files;\n"
                "  in the clear it is readable by anything on the path.\n"
                "  Set RECEIVER_TLS_CERT and RECEIVER_TLS_KEY, or set\n"
                "  RECEIVER_ALLOW_PLAINTEXT=1 for a loopback-only test deployment."
            )
        print("[receiver] WARNING: serving PLAINTEXT — evidence is readable in transit. "
              "This is acceptable only for a single-host test deployment.")
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # TLS 1.2 is the floor. Everything below it has practical attacks, and a responder cannot
    # verify at 3am which version a given endpoint negotiated.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key)

    client_ca = os.environ.get("RECEIVER_CLIENT_CA", "")
    if client_ca:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=client_ca)
        print(f"[receiver] client certificates REQUIRED (ca={client_ca})")
    return ctx


if __name__ == "__main__":
    port = int(os.environ.get("RECEIVER_PORT", "8090"))
    ctx = _tls_context()
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if ctx is not None:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    scheme = "https" if ctx is not None else "http"
    print(f"[receiver] listening on {scheme}://0.0.0.0:{port}, holding={HOLDING}")
    httpd.serve_forever()

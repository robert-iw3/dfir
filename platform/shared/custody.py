#!/usr/bin/env python3
"""
Platform chain-of-custody: seal on the collector, verify on the broker.

The collector, as its final step, seals the *entire* evidence folder (collection
artifacts + the memory image + capture metadata) into a manifest of sha256 hashes and a
custody record over that manifest. The store-and-forward broker re-verifies the seal
*before* anything is uploaded or ingested — a bundle that fails verification is
quarantined, never loaded. Optional HMAC (IR_CUSTODY_HMAC_KEY) makes the seal
unforgeable without the shared secret.

Stdlib only, so it runs in the minimal collector image and on an air-gapped box.
"""
import datetime
import getpass
import hashlib
import hmac
import json
import os
import socket

MANIFEST_NAME = "_manifest_platform.json"
CUSTODY_NAME = "_custody_platform.json"
# Files that are part of the seal machinery itself are excluded from the manifest.
_SELF = {MANIFEST_NAME, CUSTODY_NAME}


def _sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def build_manifest(folder):
    """sha256 every file under folder (except the seal files), relative paths sorted."""
    entries = {}
    for root, _, files in os.walk(folder):
        for name in files:
            if name in _SELF:
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, folder)
            entries[rel] = {"sha256": _sha256_file(full), "size": os.path.getsize(full)}
    return dict(sorted(entries.items()))


def _manifest_sha(manifest):
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _hmac(manifest_sha):
    key = os.environ.get("IR_CUSTODY_HMAC_KEY")
    if not key:
        return ""
    return hmac.new(key.encode(), manifest_sha.encode(), hashlib.sha256).hexdigest()


def seal(folder, incident_id="", operator=None):
    manifest = build_manifest(folder)
    with open(os.path.join(folder, MANIFEST_NAME), "w") as fh:
        json.dump(manifest, fh, indent=2)
    m_sha = _manifest_sha(manifest)
    op = operator or os.environ.get("IR_OPERATOR") or f"{getpass.getuser()}@{socket.gethostname()}"
    record = {
        "operator": op,
        "sealed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "incident_id": incident_id,
        "file_count": len(manifest),
        "manifest_sha256": m_sha,
        "hmac_sha256": _hmac(m_sha),
        "signed": bool(os.environ.get("IR_CUSTODY_HMAC_KEY")),
    }
    with open(os.path.join(folder, CUSTODY_NAME), "w") as fh:
        json.dump(record, fh, indent=2)
    return record


def verify(folder):
    """Return (ok, reason, record). ok=False on any manifest/HMAC mismatch."""
    cpath = os.path.join(folder, CUSTODY_NAME)
    mpath = os.path.join(folder, MANIFEST_NAME)
    if not (os.path.exists(cpath) and os.path.exists(mpath)):
        return False, "missing custody seal", {}
    with open(cpath) as fh:
        record = json.load(fh)
    with open(mpath) as fh:
        sealed_manifest = json.load(fh)

    # 1. the manifest on disk must hash to what the custody record claims
    if _manifest_sha(sealed_manifest) != record.get("manifest_sha256"):
        return False, "manifest sha256 mismatch (custody record tampered)", record
    # 2. the actual files must match the sealed manifest (no add/remove/modify)
    current = build_manifest(folder)
    if current != sealed_manifest:
        added = set(current) - set(sealed_manifest)
        removed = set(sealed_manifest) - set(current)
        changed = {k for k in set(current) & set(sealed_manifest)
                   if current[k]["sha256"] != sealed_manifest[k]["sha256"]}
        return False, f"content tamper (added={sorted(added)} removed={sorted(removed)} changed={sorted(changed)})", record
    # 3. HMAC, when the seal claims to be signed
    if record.get("signed"):
        if _hmac(record["manifest_sha256"]) != record.get("hmac_sha256"):
            return False, "HMAC verification failed (unsigned or wrong key)", record
    return True, "ok", record


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3 or sys.argv[1] not in ("seal", "verify"):
        print("usage: custody.py {seal|verify} FOLDER [incident_id]", file=sys.stderr)
        sys.exit(2)
    cmd, folder = sys.argv[1], sys.argv[2]
    if cmd == "seal":
        rec = seal(folder, incident_id=sys.argv[3] if len(sys.argv) > 3 else "")
        print(json.dumps(rec, indent=2))
    else:
        ok, reason, _ = verify(folder)
        print(json.dumps({"verified": ok, "reason": reason}))
        sys.exit(0 if ok else 1)

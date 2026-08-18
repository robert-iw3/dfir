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


# What `verify` returns as its reason. A caller deciding whether evidence is cryptographically
# attributable must check for these rather than for `ok` alone: `ok` means "safe to ingest",
# and only VERIFIED and SUPERSEDED mean "this came from who it says".
VERIFIED = "ok"
SUPERSEDED = "superseded key"
UNSIGNED = "unsigned — no signature to verify"


def attributable(reason):
    """Whether a verify() reason means the seal was cryptographically checked."""
    return reason in (VERIFIED, SUPERSEDED)


def _hmac(manifest_sha, key=None):
    key = key if key is not None else os.environ.get("IR_CUSTODY_HMAC_KEY")
    if not key:
        return ""
    return hmac.new(key.encode(), manifest_sha.encode(), hashlib.sha256).hexdigest()


def _key_id(key):
    """Which key sealed this, so a ROTATION can be told from a FORGERY.

    Without it the two collapse into one message, and an archive sealed before a rotation
    reads as tampered — which teaches an operator to dismiss the alarm a real forgery also
    raises. `cases/audit.py` solved this for the audit chain; this is the same idea on the
    seal that leaves the platform.
    """
    return hashlib.sha256(key.encode()).hexdigest()[:16] if key else ""


def _retired_keys():
    """Keys this deployment has rotated away from, newest first.

    A seal written under a retired key is SUPERSEDED, not failed: the evidence is intact and
    the key moved on. Restore has to keep working across a rotation or one rotation makes
    every archived case permanently unrestorable.
    """
    raw = os.environ.get("IR_CUSTODY_HMAC_KEYS_RETIRED", "")
    return [k for k in (s.strip() for s in raw.split(",")) if k]


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
        "key_id": _key_id(os.environ.get("IR_CUSTODY_HMAC_KEY", "")),
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
    # 3. The HMAC, decided by THIS verifier's configuration rather than by the bundle.
    #
    # `record["signed"]` is read off the untrusted bundle: an author who sets it false skipped
    # the only unforgeable check here, and steps 1 and 2 are self-consistency over files that
    # same author controls. Where a key is configured, a seal without a valid HMAC is refused
    # no matter what the record claims about itself.
    key = os.environ.get("IR_CUSTODY_HMAC_KEY", "")
    if key:
        offered = record.get("hmac_sha256") or ""
        if not offered:
            # No signature at all, which is a supported collection: an endpoint under
            # investigation may never have been issued a key, and `respond.sh` says so when
            # one is not passed. That is NOT the same as a signature that fails, and refusing
            # it would reject evidence the platform is meant to accept.
            #
            # The defect this file was fixed for is the false STAMP, not the ingest: the seal
            # used to skip its only unforgeable check when the bundle set its own
            # `signed: false`, and the run was then recorded custody_verified=True. An
            # unsigned bundle is now accepted and reported as unverified — a third value, the
            # way every other checker here reports one it could not answer.
            return True, UNSIGNED, record
        if hmac.compare_digest(_hmac(record["manifest_sha256"], key), offered):
            return True, "ok", record
        for retired in _retired_keys():
            if hmac.compare_digest(_hmac(record["manifest_sha256"], retired), offered):
                # A third state, not a pass and not a forgery: the evidence verifies under a
                # key this deployment has rotated away from.
                return True, SUPERSEDED, record
        return False, "HMAC verification failed (forged seal or unknown key)", record
    elif record.get("signed"):
        # The bundle was sealed with a key and this verifier has none — it cannot answer,
        # which is a third value rather than a pass.
        return False, "sealed bundle but no custody key is configured here", record
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

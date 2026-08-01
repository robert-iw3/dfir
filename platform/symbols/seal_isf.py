#!/usr/bin/env python3
"""
Seal an acquired ISF for transfer into the enclave.

Symbol tables are the one artifact that legitimately travels *inward*, and they arrive
from an internet-connected machine — the least trusted position in this architecture. So
they enter the same way evidence does: sealed, carried to the DMZ receiver, verified
there, and pulled inward by the enclave. No new inbound channel is opened, and the enclave
still initiates every transfer that crosses its boundary.

An ISF is data, not code — Volatility reads it as JSON — but it directly controls how the
analyzer interprets memory. A tampered symbol table produces confident, wrong forensic
conclusions, which is worse than no analysis. Hence the seal.

Usage:
  seal_isf.py <isf.json> <symbol_key> [--out DIR]

Produces `<symbol_key>.isf.tar.gz` plus a manifest carrying the SHA-256 and, when
IR_CUSTODY_HMAC_KEY is set, an HMAC over it.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import tarfile
import tempfile
import time


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Seal an ISF for enclave transfer")
    ap.add_argument("isf")
    ap.add_argument("symbol_key")
    ap.add_argument("--out", default=".")
    ap.add_argument("--kernel-release", default="")
    ap.add_argument("--banner", default="")
    args = ap.parse_args()

    if not os.path.isfile(args.isf):
        print(f"seal: no such ISF: {args.isf}", file=sys.stderr)
        return 2

    # Refuse anything that is not a parseable symbol table: the enclave should never be
    # handed an opaque blob under a symbol-table name.
    try:
        with open(args.isf, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"seal: {args.isf} is not valid JSON ({exc})", file=sys.stderr)
        return 2
    if not isinstance(doc, dict) or "symbols" not in doc:
        print("seal: JSON does not look like a Volatility ISF (no 'symbols' key)",
              file=sys.stderr)
        return 2

    digest = sha256_file(args.isf)
    manifest = {
        "kind": "volatility-isf",
        "symbol_key": args.symbol_key,
        "kernel_release": args.kernel_release,
        "banner": args.banner,
        "sha256": digest,
        "symbol_count": len(doc.get("symbols") or {}),
        "type_count": len(doc.get("user_types") or {}),
        "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    key = os.environ.get("IR_CUSTODY_HMAC_KEY", "")
    if key:
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest["hmac"] = hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()
    else:
        print("seal: IR_CUSTODY_HMAC_KEY unset — sealing with a hash only; the receiver "
              "can detect corruption but not substitution", file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)
    bundle = os.path.join(args.out, f"{args.symbol_key}.isf.tar.gz")
    with tempfile.TemporaryDirectory() as tmp:
        mpath = os.path.join(tmp, "_isf_manifest.json")
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        with tarfile.open(bundle, "w:gz") as tf:
            tf.add(args.isf, arcname=f"{args.symbol_key}.json")
            tf.add(mpath, arcname="_isf_manifest.json")

    print(json.dumps({"bundle": bundle, "sha256": digest,
                      "symbols": manifest["symbol_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

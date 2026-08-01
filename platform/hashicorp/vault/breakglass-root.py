#!/usr/bin/env python3
"""Mint a temporary root token from the unseal key and print it.

    breakglass-root.py            prints a root token on stdout

The initial root token is revoked once provisioning completes, so this is the only way back to
root privilege. It is deliberately noisy in the audit log: `generate-root` is the operation an
auditor should expect to see rarely and be able to account for every time.

Callers must revoke what they mint (`auth/token/revoke-self`).
"""
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

ADDR = os.environ.get("VAULT_ADDR", "https://vault:8200")
CACERT = os.environ.get("VAULT_CACERT", "/certs/vault-ca.crt.pem")
STATE = os.environ.get("IR_VAULT_STATE", "/vault/state")
CTX = ssl.create_default_context(cafile=CACERT)


def api(path, method="GET", body=None, token=None, tolerate=False):
    req = urllib.request.Request(
        f"{ADDR}/v1/{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json",
                 **({"X-Vault-Token": token} if token else {})})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if tolerate:
            return None
        raise SystemExit(
            f"breakglass: {method} {path} -> {e.code}: "
            f"{e.read().decode(errors='replace')[:300]}") from e


def _decode(encoded, otp):
    # The encoded token is the root token XOR'd bytewise with the OTP, base64-encoded. Vault
    # emits unpadded base64, std or urlsafe depending on version; tolerate both.
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = base64.b64decode(padded)
    except Exception:
        raw = base64.urlsafe_b64decode(padded)
    return "".join(chr(a ^ b) for a, b in zip(raw, otp.encode()))


def mint():
    keys = json.load(open(f"{STATE}/vault-init.json"))["unseal_keys_b64"]

    # Cancel and retry only if an attempt is already in progress from an interrupted run. An
    # unconditional DELETE is refused when nothing is in progress.
    att = api("sys/generate-root/attempt", "POST", {}, tolerate=True)
    if not att or "otp" not in att:
        api("sys/generate-root/attempt", "DELETE", tolerate=True)
        att = api("sys/generate-root/attempt", "POST", {})
    otp, nonce = att["otp"], att["nonce"]

    enc = None
    for k in keys:
        upd = api("sys/generate-root/update", "PUT", {"key": k, "nonce": nonce})
        if upd.get("complete"):
            enc = upd.get("encoded_token") or upd.get("encoded_root_token")
            break
    if not enc:
        raise SystemExit("breakglass: generate-root never completed — wrong or too few unseal keys")

    root = _decode(enc, otp)
    # Prove the decode before returning it: a subtly wrong XOR yields garbage that surfaces later
    # as a misleading 403.
    api("auth/token/lookup-self", token=root)
    return root


if __name__ == "__main__":
    sys.stdout.write(mint())

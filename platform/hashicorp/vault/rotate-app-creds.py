#!/usr/bin/env python3
"""
Revoke the application tier's database leases and refresh the agent's secret_id.

Runs in a vault-image container with /vault/state mounted writable and the CA cert readable
(rotate-app-creds.sh arranges both). Pure API — no value this script handles ever appears on a
command line, where the process list would carry it.

AUTHORITY. The initial root token is revoked at provisioning, deliberately, so no standing
credential can revoke leases. Rotation instead mints a TEMPORARY root through Vault's documented
break-glass path — `generate-root`, authorized by the unseal key — uses it for exactly two calls,
and revokes it. This adds no exposure: the unseal key lives on the same volume this script reads,
and anyone holding that volume could run the same flow. What it preserves is the absence of a
standing revocation credential during the other 99.99% of the platform's life.

WHAT ROTATES.
  * Every lease under database/creds/ir-platform — Postgres drops the old dynamic users via the
    role's revocation statements, so a captured credential dies now rather than at TTL.
  * The agent's AppRole secret_id — it is bounded (72h by default), so rotation is also what
    keeps a restarted agent able to authenticate. A fresh one is written for the agent to read
    on its next start.
KV values (Django key, HMAC keys) do NOT rotate here: changing the custody key would orphan
every existing custody seal. That is a migration, not a rotation.
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
STATE = "/vault/state"
PREFIX = "database/creds/ir-platform"
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
        detail = e.read().decode(errors="replace")[:300]
        raise SystemExit(f"rotate: {method} {path} -> {e.code}: {detail}") from e


def decode_root(encoded, otp):
    # The encoded token is the root token XOR'd bytewise with the OTP, base64-encoded.
    # Vault emits unpadded base64 (std or urlsafe depending on version); tolerate both.
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = base64.b64decode(padded)
    except Exception:
        raw = base64.urlsafe_b64decode(padded)
    return "".join(chr(a ^ b) for a, b in zip(raw, otp.encode()))


def main():
    keys = json.load(open(f"{STATE}/vault-init.json"))["unseal_keys_b64"]

    # Start the attempt; only if one is already in progress (stale nonce from an interrupted
    # run) cancel it and start again. An unconditional DELETE is refused when nothing is in
    # progress, which failed the whole rotation before it began.
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
        raise SystemExit("rotate: generate-root never completed — wrong or insufficient unseal keys")

    root = decode_root(enc, otp)
    # Prove the decode before acting with it: a subtly wrong XOR produces garbage that would
    # surface as a misleading 403 on the revoke call.
    api("auth/token/lookup-self", token=root)
    print("rotate: temporary root minted (break-glass via unseal key)")

    try:
        api(f"sys/leases/revoke-prefix/{PREFIX}", "PUT", {}, token=root)
        print(f"rotate: revoked all leases under {PREFIX} — old database users are dropped")

        sid = api("auth/approle/role/ir-platform/secret-id", "POST", {}, token=root)
        with open(f"{STATE}/secret_id", "w") as f:
            f.write(sid["data"]["secret_id"])
        os.chmod(f"{STATE}/secret_id", 0o600)
        print("rotate: fresh agent secret_id written (resets its expiry window)")
    finally:
        # Whatever happened above, the temporary root does not outlive this run.
        api("auth/token/revoke-self", "POST", {}, token=root)
        print("rotate: temporary root revoked")


if __name__ == "__main__":
    sys.exit(main())

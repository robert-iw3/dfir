# Smartcard (CAC/PIV) logon — opt-in

Certificate-based authentication for analysts, off by default and enabled per deployment.

**Why opt-in.** It cannot function without a real PKI: an issuing CA whose chain the platform
trusts, cards holding certificates from it, and revocation data reachable from inside an enclave
that has no egress. None of that can be stood up here, so the plumbing ships **complete and
inert** rather than half-configured — a certificate flow that is enabled without trust anchors
fails closed and locks every analyst out of the platform.

Enable it where a PKI exists. Leave it off everywhere else, and password authentication with
the realm's policy and MFA remains the path.

## What it covers

| Control | What this provides |
|---|---|
| `SRG-APP-000427-WSR-000186` | Only client certificates issued by an accepted CA are honored |
| `SRG-APP-000820/825-WSR-000170/180` | The card plus its PIN is multifactor by construction |
| `SRG-APP-000175-WSR-000095` | Certification path validation against the configured anchors |
| `SRG-APP-000875-WSR-000280` | Revocation checking, from data staged into the enclave |

## Turning it on

1. **Stage the trust anchors.** Put the issuing CA chain in
   [`trust-anchors/`](trust-anchors/) as PEM. Only CAs whose certificates you intend to accept
   belong here — this directory is the allow-list, and anything in it can mint a login
   (`SRG-APP-000910-WSR-000300`).

2. **Stage revocation data.** A CRL per issuer in [`crl/`](crl/). The enclave cannot fetch these,
   so they arrive the way symbol tables do: an operator brings them in, on a cadence shorter
   than their validity. An expired CRL is treated as no CRL, which fails closed.

3. **Set the flag** in `deploy/.env`:

   ```
   IR_PKI_LOGON=1
   ```

4. Deploy. `deploy.sh enclave` renders the x509 authentication flow into the realm, switches the
   ingress to request a client certificate, and recreates Keycloak so the import applies.

## How it fits the ingress

TLS terminates at Traefik, so Keycloak never sees the TLS session — the certificate has to be
carried to it. Traefik is configured to **request** (not require) a client certificate and pass
the verified chain in `Ssl-Client-Cert`; Keycloak reads it through its reverse-proxy certificate
lookup provider.

`optional` rather than `require` is deliberate: requiring a certificate at the TLS layer refuses
the connection before Keycloak can offer any other authenticator, so a user without a card
cannot reach the login page at all — including the administrator who needs to fix the
configuration. The decision to accept or reject belongs in the authentication flow, where it can
be reasoned about and audited, not in the handshake.

## Verifying it

`test/uat_srg_webtier.sh` asserts the plumbing is coherent whichever way the flag is set: with
`IR_PKI_LOGON=0` it asserts the ingress does **not** request a certificate and the realm carries
no x509 flow, so an unconfigured deployment is not silently half-enabled. With `IR_PKI_LOGON=1`
it additionally asserts the trust anchors are present and non-empty, the ingress requests a
certificate, and the realm's browser flow includes the x509 authenticator.

Proving that a **card** authenticates requires a card. That test belongs to the environment that
has one, and this repository does not claim it.

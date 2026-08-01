# Tailnet nodes could not register, and the DERP relay was never used

**Date:** 2026-07-30

**Area:** `platform/hashicorp/access/tailnet_bootstrap.sh`, `platform/hashicorp/access/headscale.yaml.tmpl`, `platform/deploy/deploy.sh`, `platform/deploy/{dmz,workstation}/docker-compose.yml`

**Status:** fixed

## Defect

**An unrecoverable enrolment deadlock.** `tailnet_bootstrap.sh` skipped issuing a pre-auth key
when headscale already listed the node (`already enrolled — no key needed`). If the node's own
credentials no longer worked — state volume replaced, key expired, control-plane database
rebuilt — the node started with no key, failed to authenticate, and exited; the bootstrap saw it
still listed and again declined to issue one. Every re-run reproduced it. The analyst browser
had no route, with nothing in the browser to say why.

**A hostname login server is silently rewritten.** Given `http://headscale:8080`, tailscale
forces TLS for any non-loopback host and dials port **443**, discarding the port in the URL. The
node dialled a port nothing served and exited without registering.

**The DERP relay was configured but never used.** Tailscale refuses to use a DERP relay that is
not served over TLS and does not report declining. headscale served plain HTTP, so both nodes
came up, reported themselves connected, and had no relay — invisible until two peers cannot
build a direct path. On a segment with no internet the public DERP fleet is not a fallback
either, so the embedded relay is the only one there is.

## Changes

**Keys are always minted.** The `already enrolled` shortcut is removed. Keys are reusable and
expire in hours; a node holding valid state simply never presents one. The deadlock cannot form.

**headscale serves TLS.** `hashicorp/access/gen-headscale-cert.sh` (new) issues a certificate
covering the control-plane name, separate from both the platform's web certificate and the
receiver's. `headscale.yaml` sets `tls_cert_path` / `tls_key_path` and advertises
`server_url: https://…`. Nodes pin that certificate via `SSL_CERT_FILE`, which for a Go process
replaces the trust pool entirely — tailscaled verifies headscale and nothing else.
`hashicorp/access/certs/` is gitignored.

**The login server is a name again.** With genuine HTTPS there is no forced-TLS rewrite, so the
port is honoured as written. It is passed as `HEADSCALE_LOGIN_URL`, a variable `.env` does not
define: podman-compose interpolates from `--env-file` in preference to the process environment,
so exporting a name that `.env` also defines is silently discarded.

**Ordering.** The tailnet nodes are created last, after the control plane's address is settled.
Bringing everything up in one call could relocate headscale after the value was computed,
leaving nodes dialling an address nothing answered on.

**Join checks poll.** Both node checks now wait up to 90s. The bastion's was a single sample
taken immediately after `up`, which reported a healthy node as missing twice.

## Verification

Both nodes hold tailnet addresses (`100.64.0.1`, `100.64.0.2`) and relay through the embedded
region. `uat_tailnet.sh` asserts, from `tailscale status` rather than the log, that each node has
a DERP relay, that it is the embedded region and not a public one, that no health warnings are
reported, and that the control plane advertises `https`. The first version read a bounded log
tail and was flaky as the DERP line scrolled out of the window.

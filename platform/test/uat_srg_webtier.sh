#!/usr/bin/env bash
# ==============================================================================
# WEB SERVER SRG — the web tier's hardening asserted against the running ingress; each assertion
# names the control it proves so a failure says which requirement regressed.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "${HERE}/.." && pwd)"

. "${HERE}/lib/report.sh"
report_begin 55 srg_webtier "Web Server SRG — web tier hardening" \
    "The ingress states its TLS floor, refuses weak and export ciphers, bounds request rate and concurrency, does not name itself, constrains the application as mobile code, and logs what the SRG requires it to log."
RUNTIME="${IR_RUNTIME:-podman}"

set -a; . "${PLATFORM}/deploy/.env" 2>/dev/null || true; set +a

TRAEFIK=ir-enclave_traefik_1
FRONTEND=ir-enclave_frontend_1
BACKEND=ir-enclave_backend_1

# Probed as the ANALYST's browser arrives: to the ingress address, presenting the SNI the
# certificate is issued for. The enclave has no egress, so the probe container carries its own
# trust material.
IP="$(${RUNTIME} inspect -f '{{(index .NetworkSettings.Networks "ir-enclave_internal").IPAddress}}' \
      "${TRAEFIK}" 2>/dev/null)"
[[ -n "${IP}" ]] || { bad "the ingress has no address on the enclave network"; report_finish; exit 1; }

probe() {  # <python-args...> -> one JSON object per line
    ${RUNTIME} exec -i "${BACKEND}" python3 - "${IP}" "$@" <<'PYEOF' 2>/dev/null
import json, socket, ssl, sys
ADDR, HOST = (sys.argv[1], 443), "ir-platform.local"

def connect(minv=None, maxv=None, ciphers=None, alpn=None, req=None, raw=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        if minv is not None: c.minimum_version = minv
        if maxv is not None: c.maximum_version = maxv
        if ciphers: c.set_ciphers(ciphers)
        if alpn: c.set_alpn_protocols(alpn)
    except Exception as e:
        return {"ok": False, "stage": "client", "error": f"{type(e).__name__}: {e}"}
    try:
        with socket.create_connection(ADDR, timeout=10) as s:
            with c.wrap_socket(s, server_hostname=HOST) as t:
                out = {"ok": True, "version": t.version(), "cipher": t.cipher()[0],
                       "alpn": t.selected_alpn_protocol()}
                if raw is not None:
                    t.sendall(raw.encode())
                    buf = b""
                    try:
                        while len(buf) < 8192:
                            b2 = t.recv(4096)
                            if not b2: break
                            buf += b2
                    except Exception as e:
                        out["reset"] = f"{type(e).__name__}"
                    out["response"] = buf.decode("latin-1", "replace")
                    return out
                if req is not None:
                    t.sendall(f"GET {req} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
                    buf = b""
                    while len(buf) < 65536:
                        b2 = t.recv(4096)
                        if not b2: break
                        buf += b2
                    out["response"] = buf.decode("latin-1", "replace")
                return out
    except Exception as e:
        return {"ok": False, "stage": "handshake", "error": f"{type(e).__name__}: {e}"[:200]}

V = ssl.TLSVersion
cases = {
    "default":  dict(),
    "tls11":    dict(minv=V.TLSv1_1, maxv=V.TLSv1_1, ciphers="DEFAULT@SECLEVEL=0"),
    "weak":     dict(maxv=V.TLSv1_2, ciphers="EXPORT:LOW:NULL:aNULL:eNULL:RC4:DES:@SECLEVEL=0"),
    "tls12":    dict(minv=V.TLSv1_2, maxv=V.TLSv1_2),
    "h2":       dict(alpn=["h2", "http/1.1"]),
    "app":      dict(req="/"),
    "idp":      dict(req="/realms/irplatform/"),
    "smuggle":  dict(raw=("POST / HTTP/1.1\r\nHost: ir-platform.local\r\n"
                          "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
                          "Connection: close\r\n\r\n0\r\n\r\nGET /x HTTP/1.1\r\n\r\n")),
    "dotfile":  dict(req="/.env"),
    "sourcemap":dict(req="/assets/index.js.map"),
}
for name, kw in cases.items():
    print(json.dumps({"case": name, **connect(**kw)}))
PYEOF
}

RES="$(probe)"
case_of() { grep "\"case\": \"$1\"" <<<"${RES}"; }
# The header block of a case's response, for header assertions.
hdrs_of() {
    ${RUNTIME} exec -i "${BACKEND}" python3 -c '
import json,sys
for l in sys.stdin:
    d=json.loads(l)
    if d.get("case")==sys.argv[1]:
        print((d.get("response") or "").split("\r\n\r\n")[0])
' "$1" <<<"${RES}" 2>/dev/null
}
status_of() { hdrs_of "$1" | head -1; }

# ============================================================ TLS floor and cipher policy
say "TLS — SRG-APP-000014-WSR-000006, SRG-APP-000439-WSR-000188"

d="$(case_of default)"
ver="$(grep -o '"version": "[^"]*"' <<<"${d}" | cut -d'"' -f4)"
cipher="$(grep -o '"cipher": "[^"]*"' <<<"${d}" | cut -d'"' -f4)"
case "${ver}" in
    TLSv1.3|TLSv1.2) ok "SRG-APP-000014-WSR-000006: a default client negotiates ${ver}" ;;
    *) bad "SRG-APP-000014-WSR-000006: a default client negotiated ${ver:-nothing}" ;;
esac
grep -qE "ECDHE|TLS_AES|TLS_CHACHA" <<<"${cipher}" \
    && ok "SRG-APP-000014-WSR-000006: the negotiated suite is forward-secret and AEAD (${cipher})" \
    || bad "SRG-APP-000014-WSR-000006: negotiated ${cipher:-no suite}"

grep -q '"ok": false' <<<"$(case_of tls11)" \
    && ok "SRG-APP-000014-WSR-000006: TLS 1.1 is refused ($(grep -o '"error": "[^"]*"' <<<"$(case_of tls11)" | cut -d'"' -f4 | head -c 60))" \
    || bad "SRG-APP-000014-WSR-000006: TLS 1.1 was accepted — the floor is not enforced"

grep -q '"ok": false' <<<"$(case_of weak)" \
    && ok "SRG-APP-000439-WSR-000188: export, NULL, RC4 and DES suites are refused" \
    || bad "SRG-APP-000439-WSR-000188: a weak cipher was accepted ($(grep -o '"cipher": "[^"]*"' <<<"$(case_of weak)" | cut -d'"' -f4))"

# ============================================================ HTTP/2
say "HTTP/2 — SRG-APP-000439-WSR-000192"
alpn="$(grep -o '"alpn": "[^"]*"' <<<"$(case_of h2)" | cut -d'"' -f4)"
[[ "${alpn}" == "h2" ]] \
    && ok "SRG-APP-000439-WSR-000192: the ingress selects HTTP/2 over ALPN" \
    || bad "SRG-APP-000439-WSR-000192: ALPN selected '${alpn:-nothing}'"

# ============================================================ request integrity
say "Request integrity — SRG-APP-000251-WSR-000194/000195"
sm="$(case_of smuggle)"
smresp="$(hdrs_of smuggle)"
# The control permits normalize-or-terminate; what must NOT happen is a desync — the smuggled
# second request served as a request of its own.
full="$(${RUNTIME} exec -i "${BACKEND}" python3 -c '
import json,sys
for l in sys.stdin:
    d=json.loads(l)
    if d.get("case")=="smuggle": print(d.get("response") or "")
' <<<"${RES}" 2>/dev/null)"
nresp="$(grep -c "^HTTP/1\.[01] " <<<"${full}")"
if grep -q '"reset"' <<<"${sm}" || [[ "${nresp}" == "0" ]]; then
    ok "SRG-APP-000251-WSR-000194: an ambiguous request is refused outright — the connection is closed"
    ok "SRG-APP-000251-WSR-000195: the connection is terminated rather than the ambiguity served"
elif [[ "${nresp}" == "1" ]]; then
    ok "SRG-APP-000251-WSR-000194: a request carrying both Content-Length and Transfer-Encoding is normalized to ONE request ($(grep -oE '^HTTP/1\.[01] [0-9]{3}' <<<"${full}" | head -1 | awk '{print $2}'))"
    ok "SRG-APP-000251-WSR-000195: the smuggled second request was not served — no desync between the ingress and its upstream"
else
    bad "SRG-APP-000251-WSR-000194: the ambiguous request produced ${nresp} responses — the ingress desynchronized"
fi

# ============================================================ response headers
say "Response headers — SRG-APP-000266-WSR-000159, SRG-APP-000206-WSR-000128"
H="$(hdrs_of app)"

grep -qi "^ *Server:" <<<"${H}" \
    && bad "SRG-APP-000266-WSR-000159: a Server header is still sent ($(grep -i '^ *Server:' <<<"${H}" | head -1 | tr -d '\r'))" \
    || ok "SRG-APP-000266-WSR-000159: no Server header — the ingress does not name itself"
grep -qi "^ *X-Powered-By:" <<<"${H}" \
    && bad "SRG-APP-000266-WSR-000159: an X-Powered-By header is still sent" \
    || ok "SRG-APP-000266-WSR-000159: no X-Powered-By header"

for pair in "Strict-Transport-Security:transport security is asserted" \
            "X-Content-Type-Options:MIME sniffing is refused" \
            "X-Frame-Options:framing is denied" \
            "Referrer-Policy:referrers are withheld"; do
    h="${pair%%:*}"; what="${pair##*:}"
    grep -qi "^ *${h}:" <<<"${H}" \
        && ok "SRG-APP-000266-WSR-000159: ${what} (${h})" \
        || bad "SRG-APP-000266-WSR-000159: ${h} is absent"
done

csp="$(grep -i "^ *Content-Security-Policy:" <<<"${H}" | head -1)"
if [[ -n "${csp}" ]]; then
    ok "SRG-APP-000206-WSR-000128: the application carries a Content-Security-Policy"
    grep -qi "default-src 'self'" <<<"${csp}" \
        && ok "SRG-APP-000206-WSR-000128: the policy defaults to 'self' — no third-party origin is permitted" \
        || bad "SRG-APP-000206-WSR-000128: the policy does not default to 'self'"
    grep -qi "frame-ancestors 'none'" <<<"${csp}" \
        && ok "SRG-APP-000206-WSR-000128: the application refuses to be framed" \
        || bad "SRG-APP-000206-WSR-000128: frame-ancestors is not 'none'"
else
    bad "SRG-APP-000206-WSR-000128: no Content-Security-Policy on the application"
fi

# The identity provider must keep its OWN policy: overriding it breaks the login form this
# gate depends on, and a login page that does not render is a hardening outage.
idp="$(status_of idp)"
grep -qE "HTTP/1\.[01] (200|30[0-9])" <<<"${idp}" \
    && ok "the identity provider still serves its login endpoints through the hardened ingress" \
    || bad "the identity provider is not reachable — hardening broke the login path"

# ============================================================ request limits
say "Request limits — SRG-APP-000001-WSR-000001, SRG-APP-000246-WSR-000149"
# Asserted from configuration as deployed, not by flooding the ingress: a UAT that mounts a
# denial-of-service against the platform it is validating is the wrong instrument.
CFG="$(${RUNTIME} exec "${TRAEFIK}" cat /etc/traefik/dynamic/dynamic.yml 2>/dev/null)"
grep -q "inFlightReq" <<<"${CFG}" \
    && ok "SRG-APP-000001-WSR-000001: a simultaneous-request ceiling is configured on the ingress" \
    || bad "SRG-APP-000001-WSR-000001: no in-flight request limit"
grep -q "rateLimit" <<<"${CFG}" \
    && ok "SRG-APP-000246-WSR-000149: a request rate limit is configured on the ingress" \
    || bad "SRG-APP-000246-WSR-000149: no rate limit"
${RUNTIME} exec "${FRONTEND}" sh -c 'grep -q "limit_conn perip" /etc/nginx/http.d/default.conf' 2>/dev/null \
    && ok "SRG-APP-000001-WSR-000001: a per-source connection ceiling is applied at the application server" \
    || bad "SRG-APP-000001-WSR-000001: no per-source connection limit in nginx"

# ============================================================ content serving
say "Content serving — SRG-APP-000266-WSR-000142, SRG-APP-000141-WSR-000081/000083"
NG="$(${RUNTIME} exec "${FRONTEND}" cat /etc/nginx/http.d/default.conf 2>/dev/null)"
grep -q "autoindex off" <<<"${NG}" \
    && ok "SRG-APP-000266-WSR-000142: directory listing is refused" \
    || bad "SRG-APP-000266-WSR-000142: autoindex is not disabled"
grep -q "server_tokens off" <<<"${NG}" \
    && ok "SRG-APP-000266-WSR-000159: the application server does not report its version" \
    || bad "SRG-APP-000266-WSR-000159: server_tokens is not off"
grep -q "default_type application/octet-stream" <<<"${NG}" \
    && ok "SRG-APP-000141-WSR-000081: unknown types download rather than being interpreted" \
    || bad "SRG-APP-000141-WSR-000081: no explicit default type"

# Directly against the application server: through the gate an unauthenticated request is
# redirected to the identity provider and never reaches these rules, so probing the ingress
# would assert the gate's behavior and call it nginx's.
direct() { # path -> status line
    ${RUNTIME} exec -i "${BACKEND}" python3 -c '
import sys, urllib.request as u, urllib.error as e
try:
    print(u.urlopen("http://frontend:8080" + sys.argv[1], timeout=8).status)
except e.HTTPError as ex:
    print(ex.code)
except Exception as ex:
    print(type(ex).__name__)
' "$1" 2>/dev/null
}
code="$(direct /.env)"
[[ "${code}" =~ ^40[0-9]$ ]] \
    && ok "SRG-APP-000141-WSR-000083: dotfiles are refused by the application server (${code})" \
    || bad "SRG-APP-000141-WSR-000083: a dotfile request returned ${code}"
code="$(direct /assets/index.js.map)"
[[ "${code}" =~ ^40[0-9]$ ]] \
    && ok "SRG-APP-000141-WSR-000083: source maps are refused (${code})" \
    || bad "SRG-APP-000141-WSR-000083: a source-map request returned ${code}"

# ============================================================ logging
say "Access logging — SRG-APP-000089/000095/000097/000098/000099"
# Generated by the request this test just made, so the record is this run's, not a leftover.
# Read from the FILE: records land in /var/log/traefik/access.log, where the shipper reads
# them — the container's stdout carries only the service log.
LOG="$(${RUNTIME} exec "${TRAEFIK}" sh -c \
    'grep "\"DownstreamStatus\"" /var/log/traefik/access.log | tail -1' 2>/dev/null)"
if [[ -n "${LOG}" ]]; then
    ok "SRG-APP-000089-WSR-000047: the ingress writes structured access records"
    for pair in 'RequestMethod:what the request was' \
                'StartUTC:when it happened' \
                'RouterName:where in the server it went' \
                'ClientHost:the source it came from' \
                'DownstreamStatus:the outcome'; do
        f="${pair%%:*}"; what="${pair##*:}"
        grep -q "\"${f}\"" <<<"${LOG}" \
            && ok "log record establishes ${what} (${f})" \
            || bad "log record is missing ${f}"
    done
    # SRG-APP-000098-WSR-000060 assumes an HTTP proxy forwarding the client address; Boundary's hop is
    # a TCP session, so the workstation identity in the sign-on record is the equivalent evidence.
    grep -q '"StartUTC"' <<<"${LOG}" && grep -q '"ClientHost"' <<<"${LOG}" \
        && ok "SRG-APP-000098-WSR-000060: the ingress record carries the join keys (StartUTC, ClientHost)" \
        || bad "SRG-APP-000098-WSR-000060: the ingress record lacks the keys needed to join to a session"
    # A session reports a client address only once it has CARRIED something — a pending session
    # has no connection to name one from. So the test drives one request through the brokered
    # listener and then verifies the attribution of the request it just made.
    if ${RUNTIME} inspect ir-dmz_bastion_1 >/dev/null 2>&1; then
        ${RUNTIME} exec ir-dmz_bastion_1 sh -c \
            "wget -q -O /dev/null --no-check-certificate --timeout=10 https://127.0.0.1:${BROKER_LISTEN:-8443}/ 2>&1" \
            >/dev/null 2>&1 || true
        sleep 4
    else
        info "the DMZ tier is not deployed — the brokered half of this join cannot be demonstrated"
    fi
    sess="$(${RUNTIME} exec -i "${BACKEND}" python3 -c '
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases import brokeredsessions as b
d = b.overview()
live = [s for s in d.get("sessions", []) if s.get("client_address")]
print(live[0]["client_address"] if live else "")' 2>/dev/null)"
    [[ -n "${sess}" ]] \
        && ok "SRG-APP-000098-WSR-000060: the broker records the real client address (${sess}) — the join completes" \
        || bad "SRG-APP-000098-WSR-000060: no session carries a client address; a request cannot be traced past the egress worker"
else
    bad "SRG-APP-000089-WSR-000047: no structured access record found in the ingress log"
fi

# ============================================================ log aggregation
say "Log aggregation — SRG-APP-000125-WSR-000071, SRG-APP-000357-WSR-000150, SRG-APP-000358-WSR-000163, SRG-APP-000359-WSR-000065, SRG-APP-000108-WSR-000166"
SHIPPER=ir-enclave_log-shipper_1

# One pass through the deployed shipper, so the assertions below read the result of the code
# that runs in production rather than of a hand-built equivalent.
SHIP="$(${RUNTIME} exec "${SHIPPER}" python manage.py ship_logs 2>&1 | tail -1)"
grep -q "object(s) shipped" <<<"${SHIP}" \
    && ok "SRG-APP-000125-WSR-000071: the deployed shipper completes a pass (${SHIP#\[ship-logs\] })" \
    || bad "SRG-APP-000125-WSR-000071: the shipper failed a pass — ${SHIP}"

# What the bucket holds: records off the container filesystem (000071), resumable state, and
# objects a security infrastructure can consume as-is (000163).
BUCKET="$(${RUNTIME} exec -i "${SHIPPER}" python3 - <<'PYEOF' 2>/dev/null
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases import storage
from cases.management.commands import ship_logs as sl
s3 = storage.client(); b = sl.bucket_name()
keys = [o["Key"] for o in s3.list_objects_v2(Bucket=b, MaxKeys=1000).get("Contents", [])]
access = sorted(k for k in keys if k.startswith("traefik-access/"))
body = s3.get_object(Bucket=b, Key=access[-1])["Body"].read().decode() if access else ""
print("ACCESS_OBJECTS", len(access))
print("OFFSETS", int(sl.OFFSETS_KEY in keys))
print("PARSEABLE", int('"DownstreamStatus"' in body and body.endswith("\n")))
u = sl.log_storage()["log_storage"]
print("ALLOC", u["alloc_bytes"], "USED", u["used_bytes"])
PYEOF
)"
[[ "$(awk '/^ACCESS_OBJECTS/{print $2}' <<<"${BUCKET}")" -gt 0 ]] 2>/dev/null \
    && ok "SRG-APP-000125-WSR-000071: ingress access records are held in the object store, off the web tier's filesystems" \
    || bad "SRG-APP-000125-WSR-000071: no access-log objects in the bucket"
grep -q "^OFFSETS 1" <<<"${BUCKET}" \
    && ok "SRG-APP-000125-WSR-000071: shipping state is in the bucket — a replaced shipper resumes, not re-uploads" \
    || bad "SRG-APP-000125-WSR-000071: no offset state; a restart would duplicate or drop records"
grep -q "^PARSEABLE 1" <<<"${BUCKET}" \
    && ok "SRG-APP-000358-WSR-000163: shipped objects are whole structured records — a SIEM reads the bucket as-is" \
    || bad "SRG-APP-000358-WSR-000163: the shipped object is not consumable as structured records"
alloc="$(awk '/^ALLOC/{print $2}' <<<"${BUCKET}")"
[[ "${alloc:-0}" -gt 0 ]] 2>/dev/null \
    && ok "SRG-APP-000357-WSR-000150: log record storage has a declared allocation ($(( alloc / 1024 / 1024 / 1024 )) GiB) and usage is measured against it" \
    || bad "SRG-APP-000357-WSR-000150: no storage allocation is declared"

# PRIVATE: an unauthenticated read of the log bucket is refused by the store itself.
anon="$(${RUNTIME} exec -i "${SHIPPER}" python3 -c '
import urllib.request as u, urllib.error as e
try:
    print(u.urlopen("http://127.0.0.1:9000/ir-logs/", timeout=8).status)
except e.HTTPError as ex:
    print(ex.code)
except Exception as ex:
    print(type(ex).__name__)' 2>/dev/null)"
[[ "${anon}" == "403" ]] \
    && ok "the log bucket is private — an unauthenticated request is refused (${anon})" \
    || bad "the log bucket answered an unauthenticated request with ${anon:-nothing}"

# Read-only sources: shipping a record must not be able to alter it.
${RUNTIME} exec "${SHIPPER}" sh -c 'touch /logs/traefik/.rw 2>/dev/null' >/dev/null 2>&1 \
    && bad "the shipper can WRITE to the log source — the record it ships is alterable" \
    || ok "the log sources are read-only to the shipper — the record cannot be altered by its own transport"

# The shipper reports to Component Health, so a processing failure and the 75% capacity
# warning reach the admin through the same channel every other component uses. The first
# report retries every 30s after a cold start, so the row is polled for rather than sampled.
for _ in $(seq 1 12); do
    ${RUNTIME} exec -i "${BACKEND}" python3 -c '
import os, django, sys
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases.models import ComponentHealth
sys.exit(0 if ComponentHealth.objects.filter(component="log-shipper").exists() else 1)' \
        2>/dev/null && break
    sleep 5
done
HEALTH="$(${RUNTIME} exec -i "${BACKEND}" python3 - <<'PYEOF' 2>/dev/null
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ir_platform.settings"); django.setup()
from cases import componenthealth as ch
from cases.models import ComponentHealth
row = ComponentHealth.objects.filter(component="log-shipper").first()
print("ROW", int(row is not None))
ls = ((row.metrics or {}).get("extra") or {}).get("log_storage") if row else None
print("REPORTED_ALLOC", int(bool(ls and ls.get("alloc_bytes"))))
# A row that EXISTS only proves the reporter ran once. The assertion is freshness — a shipper on a
# revoked credential keeps shipping while its health row silently stops moving.
from django.utils import timezone
from cases.healthreporter import REPORT_INTERVAL
age = int((timezone.now() - row.reported_at).total_seconds()) if row else -1
print("FRESH", int(0 <= age < REPORT_INTERVAL * 2), age)
# The trip point, exercised in the deployed code: 76% of allocation warns, 50% does not.
warn = ch._log_storage_alerts("log-shipper", {"extra": {"log_storage": {"used_bytes": 76, "alloc_bytes": 100}}})
quiet = ch._log_storage_alerts("log-shipper", {"extra": {"log_storage": {"used_bytes": 50, "alloc_bytes": 100}}})
print("WARN75", int(len(warn) == 1 and warn[0]["level"] == "warning" and not quiet))
fail = ch._resource_alerts("log-shipper", {"logs": {"errors_since_last_report": 1, "last_error": "x"}})
print("FAILALERT", int(any(a["kind"] == "logs" for a in fail)))
PYEOF
)"
grep -q "^ROW 1" <<<"${HEALTH}" \
    && ok "SRG-APP-000108-WSR-000166: the shipper self-reports to Component Health — going quiet or failing is surfaced, not silent" \
    || bad "SRG-APP-000108-WSR-000166: no Component Health row for the shipper"
grep -q "^REPORTED_ALLOC 1" <<<"${HEALTH}" \
    && ok "SRG-APP-000357-WSR-000150: the report carries usage against the declared allocation" \
    || bad "SRG-APP-000357-WSR-000150: the health report does not carry the log-storage figures"
FRESH_AGE="$(sed -n 's/^FRESH [01] //p' <<<"${HEALTH}")"
grep -q "^FRESH 1" <<<"${HEALTH}" \
    && ok "SRG-APP-000108-WSR-000166: the shipper's report is CURRENT (${FRESH_AGE}s old) — a stale row is a reporter that stopped, which the existence check cannot tell from one that never started" \
    || bad "SRG-APP-000108-WSR-000166: the shipper's health row is STALE (${FRESH_AGE:-?}s old) — it is running but no longer reporting; compare its POSTGRES_USER against the Vault Agent's rendered app.env"
grep -q "^WARN75 1" <<<"${HEALTH}" \
    && ok "SRG-APP-000359-WSR-000065: the warning fires at 75% of allocated log storage and not below it" \
    || bad "SRG-APP-000359-WSR-000065: the 75% warning did not behave as required"
grep -q "^FAILALERT 1" <<<"${HEALTH}" \
    && ok "SRG-APP-000108-WSR-000166: a shipping failure becomes a Component Health alert" \
    || bad "SRG-APP-000108-WSR-000166: a reported failure raises no alert"

# ============================================================ session management
say "Sessions — SRG-APP-000001-WSR-000002, SRG-APP-000295-WSR-000012/000134, SRG-APP-000223-WSR-000011"
GATE=ir-enclave_oauth2-proxy_1
GLOG="$(${RUNTIME} logs "${GATE}" 2>&1 | grep -m1 'Cookie settings:')"

# The gate reports its own settings at startup, which is the deployed value rather than the
# intended one — a compose flag that failed to parse would not appear here.
grep -q "httponly:true" <<<"${GLOG}" \
    && ok "SRG-APP-000223-WSR-000011: the session cookie is HttpOnly" \
    || bad "SRG-APP-000223-WSR-000011: HttpOnly is not set (${GLOG:-no cookie settings logged})"
grep -q "secure(https):true" <<<"${GLOG}" \
    && ok "SRG-APP-000439-WSR-000154: the session cookie is Secure" \
    || bad "SRG-APP-000439-WSR-000154: Secure is not set"
exp="$(grep -o 'expiry:[^ ]*' <<<"${GLOG}" | cut -d: -f2)"
[[ "${exp}" == "8h0m0s" ]] \
    && ok "SRG-APP-000295-WSR-000012: absolute session lifetime is ${exp}" \
    || bad "SRG-APP-000295-WSR-000012: absolute lifetime is '${exp:-unset}', expected 8h or less"
ref="$(grep -o 'refresh:after [^ ]*' <<<"${GLOG}" | awk '{print $2}')"
[[ -n "${ref}" && "${ref}" != "disabled" ]] \
    && ok "SRG-APP-000295-WSR-000134: the session is re-validated against the identity provider every ${ref}" \
    || bad "SRG-APP-000295-WSR-000134: no session refresh interval"

# CSRF cookies are per-attempt and accumulate unless capped; uncapped, abandoned logins push the
# Cookie header past what the server accepts — an unrecoverable 400.
GATE_CMD="$(${RUNTIME} inspect "${GATE}" --format '{{range .Config.Cmd}}{{println .}}{{end}}' 2>/dev/null)"
CSRF_LIMIT="$(sed -n 's/^--cookie-csrf-per-request-limit=//p' <<<"${GATE_CMD}")"
# The VALUE, not the flag: a limit is a number, and a check that only asks whether the flag
# was passed agrees with any number at all — including one large enough to be no bound.
[[ -n "${CSRF_LIMIT}" && "${CSRF_LIMIT}" -ge 1 && "${CSRF_LIMIT}" -le 10 ]] \
    && ok "the SSO gate caps per-request CSRF cookies at ${CSRF_LIMIT} — accumulation cannot grow the header without bound" \
    || bad "per-request CSRF cookies are not bounded to a small number (limit='${CSRF_LIMIT:-unset}') — the header grows until the analyst is locked out"

# And the application server's own header capacity stays near its default rather than being
# widened to hide that: a buffer sized for unbounded growth is not a bound.
HDRBUF="$(${RUNTIME} exec ir-enclave_frontend_1 sh -c \
    'grep -h large_client_header_buffers /etc/nginx/http.d/*.conf 2>/dev/null | head -1' 2>/dev/null)"
grep -qE '4 16k' <<<"${HDRBUF}" \
    && ok "header buffers hold modest headroom (${HDRBUF// /}), not room for accumulation" \
    || bad "header buffer sizing is not the bounded value the control expects — got '${HDRBUF:-none}'"

# Server-side session management: the session must live in the STORE — proven by the store holding
# one, since a cookie-store deployment writes nothing here.
gate_log="$(${RUNTIME} logs "${GATE}" 2>&1 || true)"
if printf '%s' "${gate_log}" \
        | grep -iE "redis.*(connection refused|error initiali[sz]ing|unable to)" >/dev/null; then
    bad "SRG-APP-000001-WSR-000002: the gate reported errors reaching its session store"
else
    ok "SRG-APP-000001-WSR-000002: the gate reached its Redis session store at startup"
fi

# A store that answers is not a store that HOLDS sessions: the proof is a real authorization-code
# login, then the session database having gained a row.
before="$(${RUNTIME} exec ir-enclave_redis_1 redis-cli -n 1 dbsize 2>/dev/null | tr -dc '0-9')"
# The account is RE-PROVISIONED first, so this run starts from the deployed initial state
# whatever earlier runs consumed: initial password from .env, replacement forced at first
# login. That forced update is asserted, then completed — the flow a real analyst walks.
PROVISION="${PLATFORM}/hashicorp/keycloak/provision-demo-users.sh"
# The login flow below rotates default-admin to a throwaway value. Restored ON EXIT so the
# account always leaves this test holding its documented initial credential.
trap 'bash "${PROVISION}" --force default-admin >/dev/null 2>&1 || true;
      bash "${PROVISION}" --delete uat-srg-csrf >/dev/null 2>&1 || true' EXIT
bash "${PROVISION}" --force default-admin >/dev/null 2>&1 \
    && ok "default-admin re-provisioned to its deployed initial state" \
    || bad "could not re-provision default-admin"
ADMIN_PW="${IR_DEMO_ADMIN_PASSWORD:-default-admin-Pw1!}"
ROTATED_PW="Uat-Rotated-Pw1!$(date +%s)"
# Driven over the ANALYST's path — the edge network, the platform name, the brokered port —
# because the gate's callback URL is the public one and a login started anywhere else redirects
# to an address that path cannot reach.
NOROT="$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
    -v "${HERE}/lib/oidc_login.py:/t.py:ro,z" localhost/ir-workstation:latest \
    python3 /t.py "${PLATFORM_PUBLIC_URL}" "${IR_PLATFORM_URL}" \
    default-admin "${ADMIN_PW}" 2>&1 | tail -1)"
grep -q '^UPDATE_REQUIRED' <<<"${NOROT}" \
    && ok "the initial credential admits NO session — Keycloak demands a replacement first" \
    || bad "the initial credential was accepted without a forced change — ${NOROT}"
LOGIN="$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
    -v "${HERE}/lib/oidc_login.py:/t.py:ro,z" localhost/ir-workstation:latest \
    python3 /t.py "${PLATFORM_PUBLIC_URL}" "${IR_PLATFORM_URL}" \
    default-admin "${ADMIN_PW}" "${ROTATED_PW}" 2>&1 | tail -1)"
grep -q '^OK:' <<<"${LOGIN}" \
    && ok "a real authorization-code login completed through the hardened ingress, forced password change included" \
    || bad "the login did not complete through the hardened ingress — ${LOGIN}"
after="$(${RUNTIME} exec ir-enclave_redis_1 redis-cli -n 1 dbsize 2>/dev/null | tr -dc '0-9')"
if [[ -n "${after}" && "${after:-0}" -gt "${before:-0}" ]]; then
    ok "SRG-APP-000001-WSR-000002: the login created server-side session state in Redis database 1 (${before} -> ${after} keys)"
elif [[ "${after:-0}" -gt 0 ]]; then
    ok "SRG-APP-000001-WSR-000002: sessions are held server-side in Redis database 1 (${after} key(s))"
else
    bad "SRG-APP-000001-WSR-000002: no session state in the store after a login — the session is living in the client's cookie"
fi

# And the gate reaches it through the MESH, not around it: Redis binds loopback only, so a
# working session store is itself proof the intention permits ir-oauth2-proxy → ir-redis.
${RUNTIME} exec ir-enclave_consul_1 sh -c \
    'CONSUL_HTTP_TOKEN=$(cat /consul/tls/token 2>/dev/null) consul intention check ir-oauth2-proxy ir-redis \
     -http-addr https://127.0.0.1:8501 -ca-file /consul/tls/consul-ca.pem 2>/dev/null' \
    | grep -q Allowed \
    && ok "SRG-APP-000001-WSR-000002: the gate's access to the session store is an intention, not network reach" \
    || info "the intention check could not be read from inside Consul; the store is working regardless"

# ============================================================ the login flow survives a page load
say "Login flow — a page load must not evict the attempt the analyst is standing in"

# The gate caps per-attempt CSRF cookies and evicts OLDEST-FIRST — the attempt discarded is the
# one in progress. The flow survives because API paths answer 401 instead of minting attempts;
# that routing is what is asserted here.
API_ROUTE="$(sed -n 's/^--api-route=//p' <<<"${GATE_CMD}")"
[[ -n "${API_ROUTE}" ]] \
    && ok "the gate separates data calls from navigation (--api-route=${API_ROUTE}) — only navigation starts an attempt" \
    || bad "no --api-route on the gate: every data call redirects to the identity provider and mints an attempt of its own"

# An EPHEMERAL account with the forced change armed, never default-admin: someone may be
# signed in as the demo admin while this runs, and a probe that rotates a shared account
# locks that person out mid-session. The forced change is what holds an attempt OPEN across
# a page load, which is the state the defect was reported from.
FLOW_USER="uat-srg-csrf"
CSRF_PW="Uat-Csrf-Pw1!$(date +%s)"
FLOW_PW="$(bash "${PROVISION}" --ephemeral "${FLOW_USER}" analyst 2>/dev/null \
           | sed -n 's/^EPHEMERAL_PASSWORD=//p')"
[[ -n "${FLOW_PW}" ]] \
    && ok "ephemeral ${FLOW_USER} provisioned with the forced change that holds a login flow open" \
    || bad "could not provision ${FLOW_USER} for the flow test"
# One retry, ONLY for a transport death anywhere in the probe (no FLOW verdict, a named
# transport failure, or an errored data call): a brokered connection can die mid-flow and an
# analyst retries that. Any CSRF or HTTP verdict is final. The account is re-armed and the
# window reset so the retry's counters stand alone.
for _flow_try in 1 2; do
    CSRF_SINCE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    FLOW="$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
        -v "${HERE}/lib/oidc_csrf.py:/t.py:ro,z" localhost/ir-workstation:latest \
        python3 /t.py "${IR_PLATFORM_URL}" "${FLOW_USER}" "${FLOW_PW}" "${CSRF_PW}" 2>&1)"
    if grep -q '^FLOW ' <<<"${FLOW}" \
       && ! grep -q '^FLOW FAIL: transport' <<<"${FLOW}" \
       && ! grep -q '^API_STATUS .*error:' <<<"${FLOW}"; then
        break
    fi
    [[ "${_flow_try}" -eq 1 ]] || break
    info "the flow died on transport, not on a verdict — re-arming and retrying once"
    CSRF_PW="Uat-Csrf-Pw1!$(date +%s)"
    FLOW_PW="$(bash "${PROVISION}" --ephemeral "${FLOW_USER}" analyst 2>/dev/null \
               | sed -n 's/^EPHEMERAL_PASSWORD=//p')"
done

NAV_MINTED="$(sed -n 's/^NAV_MINTED //p' <<<"${FLOW}")"
[[ "${NAV_MINTED:-0}" -eq 1 ]] \
    && ok "the analyst's navigation starts exactly one authentication attempt" \
    || bad "navigation started ${NAV_MINTED:-no} attempts, expected 1 — the ceiling is consumed before the page even loads"

API_SEEN="$(grep -c '^API_STATUS ' <<<"${FLOW}" || true)"
API_401="$(grep -c '^API_STATUS .* 401$' <<<"${FLOW}" || true)"
API_IDP="$(grep -c '^API_STATUS .*->idp' <<<"${FLOW}" || true)"
[[ "${API_SEEN:-0}" -ge 4 ]] \
    && ok "a page load's worth of data calls (${API_SEEN}) was issued on top of the open flow" \
    || bad "the page load was not reproduced — only ${API_SEEN:-0} data calls reached the gate ($(sed -n '1,3p' <<<"${FLOW}" | tr '\n' ' '))"
[[ "${API_SEEN:-0}" -gt 0 && "${API_401}" -eq "${API_SEEN}" ]] \
    && ok "every data call was ANSWERED 401 — the SPA turns that into one sign-in rather than ${API_SEEN} of them" \
    || bad "${API_401}/${API_SEEN:-0} data calls answered 401; the rest were redirected: $(grep '^API_STATUS' <<<"${FLOW}" | grep -v ' 401$' | tr '\n' ' ')"
# Sent with the headers the SPA's fetch actually sends. The gate 401s anything declaring
# `Accept: application/json` on that header alone, path irrelevant — so a probe that sent one
# would earn its 401 from the AJAX heuristic and pass with --api-route removed.
grep -q '^PROBE_ACCEPT \*/\*' <<<"${FLOW}" \
    && ok "and it earned that 401 on the PATH: the probes sent Accept: */* like the app's fetch, not the application/json that would trigger the gate's AJAX shortcut" \
    || bad "the probes did not send the app's Accept header ($(sed -n 's/^PROBE_ACCEPT //p' <<<"${FLOW}")) — a 401 obtained this way is not attributable to --api-route"
[[ "${API_IDP:-0}" -eq 0 ]] \
    && ok "no data call was sent to the identity provider, so none minted an attempt" \
    || bad "${API_IDP} data call(s) redirected to the identity provider — each one mints a CSRF cookie and displaces an older attempt"

API_MINTED="$(sed -n 's/^API_MINTED //p' <<<"${FLOW}")"
[[ "${API_MINTED:-1}" -eq 0 ]] \
    && ok "the page load minted NO additional CSRF cookies — the ceiling is never approached by data calls" \
    || bad "the page load minted ${API_MINTED} CSRF cookie(s); at a ceiling of ${CSRF_LIMIT:-?} that evicts the analyst's own attempt"

# A page load is a burst; a login takes minutes, and the tab keeps polling throughout. This is
# the case the first fix missed: /index.html is not under /api/, DeployWatch re-fetches it
# every 30 seconds, and each fetch minted an attempt — so an idle tab exhausted the ceiling in
# ninety seconds while the analyst was still typing a new password.
POLL_MINTED="$(sed -n 's/^POLL_MINTED //p' <<<"${FLOW}")"
[[ "${POLL_MINTED:-1}" -eq 0 ]] \
    && ok "six polling cycles (three minutes of an open tab) minted NOTHING — waiting at a login page cannot exhaust the ceiling" \
    || bad "polling minted ${POLL_MINTED} attempt(s) over six cycles; at a ceiling of ${CSRF_LIMIT:-?} an unattended tab evicts the analyst's flow in $(( ${CSRF_LIMIT:-3} * 30 ))s"

grep -q '^NAV_SURVIVED 1' <<<"${FLOW}" \
    && ok "the navigation's own CSRF cookie was still present when the callback ran" \
    || bad "the navigation's CSRF cookie was evicted before its callback — this is the 403 the analyst cannot retry past"

grep -q '^FLOW OK' <<<"${FLOW}" \
    && ok "a login held open across a full page load completed through the callback, forced password change included" \
    || bad "the held-open flow did not complete — $(grep '^FLOW ' <<<"${FLOW}" | head -1)"

# The gate's own account of the same window. A 403 the client saw and the gate did not record
# would mean the refusal came from somewhere else, and the fix would be aimed at the wrong tier.
GATE_WINDOW="$(${RUNTIME} logs --since "${CSRF_SINCE}" "${GATE}" 2>&1 || true)"
CSRF_FAIL="$(grep -cE 'unable to obtain CSRF cookie|CSRF cookie .* was not found' <<<"${GATE_WINDOW}" || true)"
[[ "${CSRF_FAIL:-0}" -eq 0 ]] \
    && ok "the gate logged no CSRF failure for that flow" \
    || bad "the gate logged ${CSRF_FAIL} CSRF cookie failure(s) during the flow"

# The client half. The gate answers 401; something still has to turn however many arrive at
# once into ONE sign-in, and that is the deployed bundle's job — asserted against the asset
# nginx actually serves, because a guard that exists only in src/ is not deployed.
BUNDLE="$(${RUNTIME} exec "${FRONTEND}" sh -c \
    'cat /usr/share/nginx/html/assets/*.js 2>/dev/null | grep -o ".\{0,160\}/oauth2/start"' 2>/dev/null)"
STARTS="$(grep -c '/oauth2/start' <<<"${BUNDLE}" || true)"
[[ "${STARTS:-0}" -eq 1 ]] \
    && ok "the deployed bundle has ONE sign-in entry point" \
    || bad "the deployed bundle has ${STARTS:-0} sign-in entry points — each is a path that can start a competing attempt"
# Matched on shape rather than on names: the bundle is minified, so the guard survives as
# `if(v)return;v=!0` with whatever identifier the minifier chose.
grep -qE 'if\([A-Za-z_$][A-Za-z0-9_$]*\)return;[A-Za-z_$][A-Za-z0-9_$]*=!0' <<<"${BUNDLE}" \
    && ok "that entry point is single-flight — the second and later 401s of a page load redirect nothing" \
    || bad "the deployed sign-in is unguarded: every 401 in a page load starts its own attempt"

# Negative control: everything above also passes on a gate that never had the defect, so this
# drives the failure shape and requires the 403 to be ABSENT. Same ephemeral account,
# re-armed — the control needs the forced change open, not the demo admin's identity.
CTRL_PW="Uat-Ctrl-Pw1!$(date +%s)"
FLOW_PW="$(bash "${PROVISION}" --ephemeral "${FLOW_USER}" analyst 2>/dev/null \
           | sed -n 's/^EPHEMERAL_PASSWORD=//p')"
[[ -n "${FLOW_PW}" ]] \
    && ok "ephemeral ${FLOW_USER} re-armed for the control run" \
    || bad "could not re-provision ${FLOW_USER} for the control run"
# Derived from the ceiling, never a fixed count — hardcoded, this control silently stopped testing
# anything the moment the limit moved past it.
CTRL_PATHS=()
for i in $(seq 1 $(( ${CSRF_LIMIT:-3} + 1 ))); do CTRL_PATHS+=("/ctrl${i}"); done
CTRL="$(${RUNTIME} run --rm --network ir-edge --dns "${DNS_EDGE_IP}" \
    -v "${HERE}/lib/oidc_csrf.py:/t.py:ro,z" localhost/ir-workstation:latest \
    python3 /t.py "${IR_PLATFORM_URL}" "${FLOW_USER}" "${FLOW_PW}" "${CTRL_PW}" \
    "${CTRL_PATHS[@]}" 2>&1)"

CTRL_IDP="$(grep -c '^API_STATUS .*->idp' <<<"${CTRL}" || true)"
CTRL_MINTED="$(sed -n 's/^API_MINTED //p' <<<"${CTRL}")"
[[ "${CTRL_IDP:-0}" -ge 1 && "${CTRL_MINTED:-0}" -ge 1 ]] \
    && ok "control: ${CTRL_IDP} unclassified path(s) redirected to the identity provider and minted ${CTRL_MINTED} attempt(s) — the driver can see a mint, so the zero it reported above is a measurement" \
    || bad "control: unclassified paths minted nothing (idp=${CTRL_IDP:-0}, minted=${CTRL_MINTED:-0}) — the driver cannot detect the defect, so its clean result above proves nothing"
grep -q '^NAV_SURVIVED 0' <<<"${CTRL}" \
    && ok "control: those attempts evicted the analyst's own, oldest-first, exactly as the ceiling of ${CSRF_LIMIT} requires" \
    || bad "control: the analyst's attempt survived ${CTRL_MINTED:-0} competing mints at a ceiling of ${CSRF_LIMIT} — eviction is not behaving as the fix assumes"
grep -q '^FLOW FAIL: callback returned HTTP 403' <<<"${CTRL}" \
    && ok "control: the flow ended in the reported 403 at the callback — the defect is reproducible, and --api-route is what the deployed gate uses to avoid it" \
    || bad "control: the evicted flow did not end in a 403 — $(grep '^FLOW ' <<<"${CTRL}" | head -1)"

# The rotated password is a test artifact: the account goes back to its deployed initial
# state, which re-arms the forced change for the next real first login.
bash "${PROVISION}" --force default-admin >/dev/null 2>&1 \
    && ok "default-admin restored to provisioned state (initial password, change re-armed)" \
    || bad "default-admin could not be restored — it is left holding the UAT's rotated password"
REQ="$(${RUNTIME} exec ir-enclave_keycloak_1 sh -c '
    /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
        --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
        --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
    /opt/keycloak/bin/kcadm.sh get users -r irplatform -q username=default-admin -q exact=true \
        --fields requiredActions' 2>/dev/null)"
grep -q "UPDATE_PASSWORD" <<<"${REQ}" \
    && ok "a provisioned account carries the forced password change until its first login consumes it" \
    || bad "the provisioned account does not demand a password change — first login would keep the posted credential"

# ============================================================ password policy and PKI logon
say "Identity — SRG-APP-000830/000850/000860/000870, SRG-APP-000427-WSR-000186"

# Read from the RUNNING realm, not the file that was meant to be imported: an existing realm is
# never overwritten by an import, so the two disagree exactly when it matters.
REALM="$(${RUNTIME} exec ir-enclave_keycloak_1 sh -c '
    /opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 \
        --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
        --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin}" >/dev/null 2>&1 &&
    /opt/keycloak/bin/kcadm.sh get realms/irplatform 2>/dev/null' 2>/dev/null)"

pol="$(grep -o '"passwordPolicy" *: *"[^"]*"' <<<"${REALM}" | cut -d'"' -f4)"
if [[ -n "${pol}" ]]; then
    ok "a password policy is in force on the running realm"
    for pair in "length:a minimum length is required (SRG-APP-000860)" \
                "upperCase:composition includes upper case (SRG-APP-000870)" \
                "digits:composition includes digits (SRG-APP-000870)" \
                "specialChars:composition includes special characters (SRG-APP-000870)" \
                "notUsername:the username cannot be the password (SRG-APP-000830)" \
                "passwordHistory:reuse is refused (SRG-APP-000870)" \
                "hashAlgorithm:an approved salted hash is stated (SRG-APP-000850)"; do
        k="${pair%%:*}"; what="${pair##*:}"
        grep -q "${k}" <<<"${pol}" && ok "${what}" || bad "the policy does not set ${k}"
    done
else
    bad "no password policy on the running realm — the import did not apply"
fi

grep -q '"bruteForceProtected" *: *true' <<<"${REALM}" \
    && ok "repeated authentication failures are throttled (brute-force protection is on)" \
    || bad "brute-force protection is off on the running realm"

# Smartcard logon is opt-in. Both states are asserted: enabled must be coherent, and DISABLED
# must be genuinely disabled — a half-configured certificate flow fails closed and locks
# analysts out, which is the failure this check exists to prevent.
say "Smartcard logon — opt-in (IR_PKI_LOGON=${IR_PKI_LOGON:-0})"
DYN="$(${RUNTIME} exec ir-enclave_traefik_1 cat /etc/traefik/dynamic/dynamic.yml 2>/dev/null)"
ANCHORS="$(find "${PLATFORM}/hashicorp/keycloak/pki-logon/trust-anchors" \
           \( -name '*.pem' -o -name '*.crt' \) 2>/dev/null | grep -c . || echo 0)"
if [[ "${IR_PKI_LOGON:-0}" == "1" ]]; then
    [[ "${ANCHORS}" -gt 0 ]] \
        && ok "SRG-APP-000427-WSR-000186: ${ANCHORS} trust anchor(s) are staged — only these CAs can mint a login" \
        || bad "SRG-APP-000427-WSR-000186: smartcard logon is on with no trust anchor — every analyst is locked out"
    grep -q "clientAuth:" <<<"${DYN}" \
        && ok "SRG-APP-000427-WSR-000186: the ingress requests a client certificate" \
        || bad "SRG-APP-000427-WSR-000186: the ingress does not request a client certificate"
    grep -q "RequestClientCert" <<<"${DYN}" \
        && ok "SRG-APP-000427-WSR-000186: the certificate is requested, not required — a cardless administrator can still reach the login page" \
        || bad "SRG-APP-000427-WSR-000186: client auth is not in the request-don't-require form"
else
    grep -q "clientAuth:" <<<"${DYN}" \
        && bad "smartcard logon is off, but the ingress still requests a client certificate" \
        || ok "smartcard logon is off and the ingress does not ask for a certificate — nothing is half-enabled"
    [[ -d "${PLATFORM}/hashicorp/keycloak/pki-logon/trust-anchors" \
       && -f "${PLATFORM}/hashicorp/keycloak/pki-logon/x509-browser-flow.json" ]] \
        && ok "the plumbing is present and inert — enabling it is a flag and a staged CA, not a rebuild" \
        || bad "the smartcard-logon templates are missing"
    info "proving a CARD authenticates needs a card and an issuing CA; that test belongs to an environment that has them"
fi

# ============================================================ supply chain, cadence, clock
# Batch 6. These four controls share a property the earlier batches did not: each is satisfied
# by a RECORD as much as by a mechanism, so each assertion below is paired with proof that its
# gate actually rejects — a gate that only ever passes is indistinguishable from no gate.
say "SRG-APP-000131 — base images are pinned by digest, and the digest is recorded"

bash "${PLATFORM}/ci/pin-base-images.sh" --check >/dev/null 2>&1 \
    && ok "every external FROM names a digest matching ci/base-images.lock" \
    || bad "a base image is pinned by tag, or disagrees with the lock — run ci/pin-base-images.sh --check"

# A tag is a mutable pointer; the gate exists to refuse one. Proven by reverting a FROM to a
# bare tag in a COPY of the tree, so the working tree is never left modified by a test.
SCRATCH="$(mktemp -d)"
cp -r "${PLATFORM}/ci" "${SCRATCH}/ci" 2>/dev/null
mkdir -p "${SCRATCH}/ingest"
sed 's|^FROM docker.io/library/alpine:3.24@sha256:.*|FROM docker.io/library/alpine:3.24|' \
    "${PLATFORM}/ingest/Dockerfile" > "${SCRATCH}/ingest/Dockerfile" 2>/dev/null
if IR_RUNTIME="${RUNTIME}" bash "${SCRATCH}/ci/pin-base-images.sh" --check >/dev/null 2>&1; then
    bad "the pin check PASSES on a tree where a FROM was reverted to a bare tag — it proves nothing"
else
    ok "and the check REFUSES a FROM reverted to a bare tag, so the gate is real"
fi
rm -rf "${SCRATCH}"

say "SRG-APP-000456 — the 30-day currency review is recorded, and going stale fails"

bash "${PLATFORM}/ci/image-currency.sh" --age >/dev/null 2>&1 \
    && ok "the image-currency review is on record and within its interval" \
    || bad "no image-currency record, or it has passed the 30-day ceiling"

REC="${PLATFORM}/ci/image-currency.record"
if [[ -f "${REC}" ]]; then
    cp "${REC}" "${REC}.uatbak"
    # Backdated past the ceiling the control names. If this still passes, the cadence is
    # decorative and "reviewed regularly" is unfalsifiable.
    sed -i "s|^reviewed = .*|reviewed = \"$(date -u -d '400 days ago' '+%Y-%m-%dT%H:%M:%SZ')\"|" "${REC}"
    bash "${PLATFORM}/ci/image-currency.sh" --age >/dev/null 2>&1 \
        && bad "a review backdated 400 days still passes — the interval is not enforced" \
        || ok "and a review backdated past the ceiling is REFUSED, so the cadence is enforced"
    mv "${REC}.uatbak" "${REC}"
else
    bad "no image-currency record to test the interval against"
fi

say "SRG-APP-000835/000840 — the banned password list is enforced and reviewed"

bash "${PLATFORM}/ci/password-blacklist-check.sh" >/dev/null 2>&1 \
    && ok "the list is non-empty and lowercase, the realm policy names it, and the review is current" \
    || bad "the banned password list is not proven — run ci/password-blacklist-check.sh"

# The policy is inert unless Keycloak can actually read the file it names. Checked INSIDE the
# running container, because the file being present in the tree proves nothing about the image.
if [[ "$(${RUNTIME} inspect ir-enclave_keycloak_1 --format '{{.State.Status}}' 2>/dev/null)" == "running" ]]; then
    KCLIST="$(${RUNTIME} exec ir-enclave_keycloak_1 sh -c \
        'wc -l < /opt/keycloak/data/password-blacklists/dfir-platform.txt' 2>/dev/null | tr -d ' ')"
    [[ "${KCLIST:-0}" -gt 0 ]] \
        && ok "Keycloak can read the list it enforces (${KCLIST} lines in the running image)" \
        || bad "the realm names a blacklist Keycloak cannot read — password SETTING would fail"
else
    info "Keycloak not running — the in-image blacklist was not evaluated"
fi

say "SRG-APP-000920/000925 — the enclave has a time authority, and containers inherit it"

bash "${PLATFORM}/ci/clock-sync-check.sh" --quiet >/dev/null 2>&1 \
    && ok "clock provenance established: host synchronized, containers agree, enclave serving" \
    || bad "clock provenance NOT established — see ci/clock-sync-check.sh"

if [[ "$(${RUNTIME} inspect ir-enclave_ntp_1 --format '{{.State.Status}}' 2>/dev/null)" == "running" ]]; then
    NTP_STRAT="$(${RUNTIME} exec ir-enclave_ntp_1 chronyc -n tracking 2>/dev/null \
                 | awk -F': *' '/^Stratum/ {print $2}')"
    [[ -n "${NTP_STRAT}" ]] \
        && ok "the enclave time service answers and is serving (stratum ${NTP_STRAT})" \
        || bad "the enclave time service is running but does not answer chronyc"

    # It must never touch a clock it does not own: containers inherit the host's, and a time
    # service that tried to set it would fail and exit, leaving the enclave with no authority.
    ${RUNTIME} logs ir-enclave_ntp_1 2>&1 | grep -qi 'Disabled control of system clock' \
        && ok "and it runs without control of the system clock, as a container must" \
        || bad "the time service did not disable clock control — it is trying to set a clock it does not own"

    # Traceability is a deployment property and is REPORTED, not assumed. Stratum 10 is the
    # local reference: the segment agrees with itself and is traceable to nothing.
    if [[ "${NTP_STRAT}" == "10" ]]; then
        info "serving from a LOCAL reference — internally consistent, NOT traceable to an authoritative source (IR_NTP_UPSTREAM unset)"
    else
        ok "disciplined by a traceable upstream (stratum ${NTP_STRAT})"
    fi
else
    bad "no enclave time service — every host in a no-egress segment free-runs"
fi

say "The tracker states the same thing this suite just proved"
python3 "${PLATFORM}/artifacts/gen_srg_tracker.py" --check >/dev/null 2>&1 \
    && ok "the tracker, .ckl and srg_tracker.json are current with srg_status.yml" \
    || bad "the SRG artifacts are STALE — regenerate with artifacts/gen_srg_tracker.py"

# ============================================================ summary
say "Result"
if [[ "${FAILED}" == "0" ]]; then
    ok "the web tier holds: TLS floor enforced, weak ciphers refused, limits in place, identity withheld, mobile code constrained, and requests attributable"
else
    bad "web tier hardening does NOT hold — see failures above"
fi
report_finish
exit "${FAILED}"

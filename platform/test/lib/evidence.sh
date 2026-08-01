#!/usr/bin/env bash
# Shared UAT helpers — build a sealed evidence bundle and assert it flows all the way
# through to the web app. Sourced by the UATs so every one of them validates real DATA
# FLOW (evidence actually lands and renders), not just network reachability.
#
#   mk_evidence_bundle <workdir> <hostname> [custody_hmac]   -> $workdir/<hostname>/ sealed
#   tar_bundle         <workdir> <hostname>                  -> $workdir/bundle.tar.gz
#   assert_data_flow   <backend_container> <token> [min_findings]
#
# Requires: PLATFORM to point at platform/.

# Build a realistic, custody-sealed evidence bundle (synthetic capture + findings + IOCs).
mk_evidence_bundle() {
    local work="$1" host="$2" hmac="${3:-}"
    local d="${work}/${host}"
    mkdir -p "$d"
    python3 "${PLATFORM}/collector/make_sample.py" "${d}/memory_${host}.raw" >/dev/null 2>&1
    local sha sz
    sha=$(sha256sum "${d}/memory_${host}.raw" | awk '{print $1}')
    sz=$(stat -c%s "${d}/memory_${host}.raw")
    cat > "${d}/_capture_meta.json" <<EOF
{"filename":"memory_${host}.raw","capture_tool":"synthetic","image_format":"raw","is_synthetic":true,"sha256":"${sha}","size_bytes":${sz},"kernel":"uat"}
EOF
    cat > "${d}/Adjudication_uat.json" <<'EOF'
[{"Type":"Remote Access Tool","Target":"pid 4412 (nc)","Verdict":"True Positive","Confidence":"High","MITRE":["T1219"],"SubjectPath":"/tmp/.x/nc"},
 {"Type":"Suspicious Kernel Module","Target":"rootkit_x","Verdict":"Likely True Positive","Confidence":"High","MITRE":["T1014"]},
 {"Type":"Persistence: cron","Target":"/etc/cron.d/.hidden","Verdict":"Likely True Positive","Confidence":"Medium","MITRE":["T1053"]},
 {"Type":"Package Manager Transaction","Target":"package curl","Verdict":"Indeterminate","Confidence":"Low"}]
EOF
    echo '{"overall":"COMPLETED","tp_count":1}' > "${d}/_status.json"
    echo '{"ip":["203.0.113.66","198.51.100.23"],"domain":["malicious-c2.example.net"],"hash":["d41d8cd98f00b204e9800998ecf8427e"]}' > "${d}/IOCs.json"
    echo '[{"name":"svc_backup"},{"name":"root"}]' > "${d}/Principals.json"
    IR_CUSTODY_HMAC_KEY="$hmac" python3 "${PLATFORM}/shared/custody.py" seal "$d" "${IR_INCIDENT_ID:-INC-UAT}" >/dev/null
}

tar_bundle() {
    local work="$1" host="$2"
    tar czf "${work}/bundle.tar.gz" -C "$work" "$host"
    echo "${work}/bundle.tar.gz"
}

# Read the platform's own stats through the API, from inside the enclave.
platform_stats() {  # backend_container token
    ${RUNTIME:-podman} exec "$1" python -c "
import urllib.request as u, json
r = u.Request('http://127.0.0.1:8000/api/stats/', headers={'Authorization':'Token $2'})
print(json.dumps(json.load(u.urlopen(r, timeout=8))))" 2>/dev/null
}

# Assert the evidence actually arrived and is renderable by the web app: runs, findings,
# captures, and the compromise assessment that drives retention.
assert_data_flow() {  # backend_container token [min_findings]
    local be="$1" tok="$2" minf="${3:-1}"
    local stats runs finds caps tps
    stats=$(platform_stats "$be" "$tok")
    if [[ -z "$stats" ]]; then
        bad "data flow: could not read /api/stats (auth or API down)"
        return 1
    fi
    runs=$(printf '%s' "$stats"  | sed -n 's/.*"runs": *\([0-9]*\).*/\1/p')
    finds=$(printf '%s' "$stats" | sed -n 's/.*"findings": *\([0-9]*\).*/\1/p')
    caps=$(printf '%s' "$stats"  | sed -n 's/.*"captures": *\([0-9]*\).*/\1/p')
    tps=$(printf '%s' "$stats"   | sed -n 's/.*"true_positives": *\([0-9]*\).*/\1/p')

    [[ "${runs:-0}"  -ge 1 ]]     && ok "data flow: collection run ingested (runs=${runs})"        || bad "data flow: no collection run ingested"
    [[ "${finds:-0}" -ge $minf ]] && ok "data flow: findings stored (findings=${finds})"           || bad "data flow: findings not stored (${finds:-0})"
    [[ "${caps:-0}"  -ge 1 ]]     && ok "data flow: capture recorded in object store (captures=${caps})" || bad "data flow: no capture recorded"
    [[ "${tps:-0}"   -ge 1 ]]     && ok "data flow: true-positive adjudication preserved (tp=${tps})"    || bad "data flow: true positives lost in ingest"
}

# Assert the web app actually SERVES that data to a browser (renderable end state).
assert_webapp_renders() {  # url_container curl_target token
    local ctr="$1" url="$2"
    local code
    code=$(${RUNTIME:-podman} exec "$ctr" curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "$url" 2>/dev/null)
    [[ "$code" == "200" ]] && ok "web app serves the SPA to the analyst (HTTP ${code})" \
                           || bad "web app did not serve the SPA (HTTP ${code})"
}

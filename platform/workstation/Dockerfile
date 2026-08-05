# Analyst-workstation browser — a locked-down Firefox kiosk that can reach exactly one
# thing: the SSO-gated platform frontend, over the brokered VPN path.
#
# Security posture (layered — each holds even if another fails):
#   * NETWORK: attached only to the tunnel-side network, which has no internet gateway,
#     so there is no route off-platform. Name resolution comes from the DMZ CoreDNS,
#     which answers only the platform name and REFUSES everything else (no DNS tunneling).
#   * BROWSER: DISA Mozilla Firefox STIG-aligned enterprise policy (policies.json) —
#     no add-ons, no telemetry, no password manager/autofill, no sync, no dev tools,
#     TLS 1.2 floor, pop-ups blocked, DoH off, sanitize on shutdown.
#   * KIOSK: WebsiteFilter blocks <all_urls> except the platform origin.
#
# Rendering: X11 — the host's X socket is bind-mounted and DISPLAY is passed in, so the
# browser window appears on the analyst's desktop while the process stays contained.
FROM docker.io/library/alpine:3.24

# firefox-esr = the ESR channel the STIG targets. The rest are the X11/font/audio-less
# runtime bits Firefox needs to render through a bind-mounted X socket.
RUN apk add --no-cache \
        firefox-esr \
        ttf-dejavu font-noto \
        dbus-x11 xauth \
        ca-certificates python3 \
    && mkdir -p /usr/lib/firefox-esr/distribution /etc/firefox/policies

# Enterprise policy (machine-wide, not user-overridable). Installed to both paths Firefox
# reads so the controls apply regardless of build layout.
COPY policies.json /usr/lib/firefox-esr/distribution/policies.json
COPY policies.json /etc/firefox/policies/policies.json
COPY launch.sh /usr/local/bin/launch.sh
RUN chmod +x /usr/local/bin/launch.sh

# Build-time smoke test: firefox present and the STIG policy is valid JSON with the
# kiosk allow-list — a malformed policy would silently un-harden the browser.
RUN firefox-esr --version \
    && python3 -c "\
import json; p = json.load(open('/usr/lib/firefox-esr/distribution/policies.json'))['policies']; \
assert p['InstallAddonsPermission']['Default'] is False, 'add-on installs not blocked'; \
assert p['DisableTelemetry'] is True, 'telemetry not disabled'; \
assert p['PasswordManagerEnabled'] is False, 'password manager not disabled'; \
assert p['DNSOverHTTPS']['Enabled'] is False, 'DoH not disabled'; \
assert p['DisableDeveloperTools'] is True, 'dev tools not disabled'; \
assert '<all_urls>' in p['WebsiteFilter']['Block'] and all(':' not in e.split('//')[1].split('/')[0] for e in p['WebsiteFilter']['Exceptions']), 'kiosk allow-list missing or has an invalid port-bearing pattern'; \
assert p['Preferences']['security.tls.version.min']['Value'] >= 3, 'TLS floor below 1.2'; \
print('firefox STIG policy OK')"

# Runs as container-root, which under ROOTLESS podman maps to the invoking unprivileged
# host user — it is not host root, and it is what lets the process open the bind-mounted
# X socket (a container uid mapped into the subuid range cannot). Privilege is still
# stripped at run time: cap_drop ALL + no-new-privileges (see docker-compose.access.yml).
# Add the GL/GTK bits Firefox looks for so the X session starts cleanly.
RUN apk add --no-cache mesa-gl mesa-egl libpciaccess 2>/dev/null || true
ENV HOME=/home/analyst
# The profile, and the ONE directory downloads may land in. It must exist in the image: the
# policies name it as the fixed download location, and a missing directory sends Firefox
# back to asking — a native file dialog this container cannot open without aborting.
RUN mkdir -p /home/analyst/profile /home/analyst/downloads

ENTRYPOINT ["/usr/local/bin/launch.sh"]

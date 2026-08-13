# Analyst-workstation browser — a locked-down Firefox kiosk reaching exactly one thing: the SSO-
# gated platform frontend over the brokered VPN path. Layered posture: tunnel-only network whose
# DNS refuses everything but the platform name, DISA Firefox STIG policy (policies.json),
# WebsiteFilter kiosk allowing only the platform origin; rendering uses the host's bind-mounted X
# socket.
FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# firefox-esr = the ESR channel the STIG targets. The rest are the X11/font/audio-less
# runtime bits Firefox needs to render through a bind-mounted X socket. `xdotool`
# reads the window title, which is the only way the supervisor can tell that a kiosk
# with no chrome has been left somewhere it cannot navigate back from.
RUN apk add --no-cache \
        firefox-esr \
        ttf-dejavu font-noto \
        dbus-x11 xauth xdotool \
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

# Container-root under ROOTLESS podman maps to the invoking unprivileged host user — not host
# root, and what lets the process open the bind-mounted X socket. Privilege is stripped at run
# time: cap_drop ALL + no-new-privileges.
RUN apk add --no-cache mesa-gl mesa-egl libpciaccess 2>/dev/null || true
ENV HOME=/home/analyst
# The profile, and the ONE directory downloads may land in. It must exist in the image: the
# policies name it as the fixed download location, and a missing directory sends Firefox
# back to asking — a native file dialog this container cannot open without aborting.
RUN mkdir -p /home/analyst/profile /home/analyst/downloads

ENTRYPOINT ["/usr/local/bin/launch.sh"]

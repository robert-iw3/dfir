# Keycloak with the platform's login theme baked in.
#
# The theme used to be bind-mounted from the working tree, and that fails in a way nothing
# reports: a bind mount tracks the directory's INODE, so rewriting the theme tree — which any
# editor doing atomic saves, or a checkout, will do — leaves the running container pointing at
# the old unlinked inode. The directory then reads as EMPTY inside the container while it is
# plainly populated on the host, Keycloak logs only "Failed to find LOGIN theme", and the login
# page silently reverts to the built-in one.
#
# Baking it makes the theme part of a versioned artifact: what was built is what is served, and
# a theme change is a rebuild rather than an invisible drift. Editing the theme therefore
# requires `deploy.sh enclave` to rebuild — which is the point.
FROM quay.io/keycloak/keycloak:26.7.0@sha256:0f198be292568439d700cdbfb893e69a6009bb43a94a06a945b1d3d506c76b13

COPY keycloak/themes/dfir /opt/keycloak/themes/dfir
# The banned-password list the realm's passwordBlacklist policy names. Baked rather
# than mounted for the same reason the theme is: a policy that names a file Keycloak
# cannot read fails password SETTING, and the first sign of it would be an analyst
# unable to complete a forced reset.
COPY keycloak/password-blacklists /opt/keycloak/data/password-blacklists
# Sources the Vault-rendered database credential before handing off to kc.sh.
COPY keycloak/entrypoint.sh /opt/keycloak/entrypoint.sh

# Fail the build if the theme is not actually present and complete, rather than discovering it
# as an unstyled login page after deployment.
USER root
RUN test -f /opt/keycloak/themes/dfir/login/theme.properties \
 && test -f /opt/keycloak/themes/dfir/login/error.ftl \
 && test -f /opt/keycloak/themes/dfir/login/resources/css/login.css \
 && test -f /opt/keycloak/themes/dfir/login/resources/img/logo.jpeg \
 && test -s /opt/keycloak/data/password-blacklists/dfir-platform.txt \
 && test -f /opt/keycloak/themes/dfir/login/resources/img/background.jpeg \
 && chown -R keycloak:root /opt/keycloak/themes/dfir \
 && chmod 0755 /opt/keycloak/entrypoint.sh
USER keycloak

ENTRYPOINT ["/opt/keycloak/entrypoint.sh"]

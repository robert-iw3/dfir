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
FROM quay.io/keycloak/keycloak:26.7.0

COPY keycloak/themes/dfir /opt/keycloak/themes/dfir
# Sources the Vault-rendered database credential before handing off to kc.sh.
COPY keycloak/entrypoint.sh /opt/keycloak/entrypoint.sh

# Fail the build if the theme is not actually present and complete, rather than discovering it
# as an unstyled login page after deployment.
USER root
RUN test -f /opt/keycloak/themes/dfir/login/theme.properties \
 && test -f /opt/keycloak/themes/dfir/login/error.ftl \
 && test -f /opt/keycloak/themes/dfir/login/resources/css/login.css \
 && test -f /opt/keycloak/themes/dfir/login/resources/img/logo.jpeg \
 && test -f /opt/keycloak/themes/dfir/login/resources/img/background.jpeg \
 && chown -R keycloak:root /opt/keycloak/themes/dfir \
 && chmod 0755 /opt/keycloak/entrypoint.sh
USER keycloak

ENTRYPOINT ["/opt/keycloak/entrypoint.sh"]

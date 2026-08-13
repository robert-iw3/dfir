<#--
  The access warning, shown on every login screen.

  Overriding footer.ftl rather than template.ftl keeps this to the one extension point
  Keycloak provides for it, so the login, OTP, reset and consent screens all carry the
  banner without any upstream markup being copied forward across a version upgrade.

  It is real text, not CSS generated content: a notice a user is held to has to be
  selectable, translatable and readable by a screen reader.
-->
<#macro content>
<section id="ir-access-warning" role="note" aria-labelledby="ir-access-warning-title">
  <h2 id="ir-access-warning-title">WARNING: Authorized Access Only</h2>
  <p>This system is restricted to authorized users for official business. Unauthorized
     access or use is a violation of state and federal law and may be subject to
     administrative action, civil prosecution, or criminal penalties. All activities on
     this system may be monitored and recorded.</p>
</section>
</#macro>

<#--
  The error page an analyst actually hits, made recoverable.

  The stock template offers "back to application" ONLY when a client context survives the
  failure (`client.baseUrl`). The common failure has no such context — an expired or evicted
  CSRF cookie, or Keycloak recreated mid-flow, produces a callback it no longer recognises —
  so the page rendered with no way forward. Refreshing cannot help: F5 resubmits the same
  dead callback. In the kiosk there is no address bar, so the analyst was stranded until an
  operator restarted the browser container.

  This always offers the way back, and takes it automatically for a kiosk that nobody is
  sitting at. `/` on this origin is the platform root, which starts a fresh authorization
  flow through the gate — the same path a first sign-in walks.

  The auto-return is COUNTED, not unconditional: if the underlying cause persists, redirecting
  forever turns a dead end into a hot loop that hides the error text. After two attempts the
  page stops and leaves the message and the link on screen, which is the state an operator
  needs to diagnose it.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${kcSanitize(msg("errorTitle"))?no_esc}
    <#elseif section = "form">
        <div id="kc-error-message">
            <p class="instruction">${kcSanitize(message.summary)?no_esc}</p>
            <#if traceId??>
                <p class="instruction" id="traceId">${msg("traceIdSupportMessage", traceId)}</p>
            </#if>

            <p class="instruction" id="ir-recovery-note">
                This sign-in attempt can no longer be completed. Starting again is safe —
                nothing was signed in to.
            </p>

            <p>
                <#if client?? && client.baseUrl?has_content>
                    <a id="backToApplication" class="ir-return" href="${client.baseUrl}">${msg("backToApplication")}</a>
                <#else>
                    <a id="backToApplication" class="ir-return" href="/">Return to sign-in</a>
                </#if>
            </p>
            <p class="instruction" id="ir-auto-return"></p>
        </div>

        <script type="text/javascript">
          (function () {
            var KEY = "irAuthRetryCount";
            var LIMIT = 2;
            var DELAY = 8;
            var link = document.getElementById("backToApplication");
            var note = document.getElementById("ir-auto-return");
            if (!link || !note) { return; }

            var tries = 0;
            try { tries = parseInt(sessionStorage.getItem(KEY) || "0", 10) || 0; } catch (e) { tries = LIMIT; }

            if (tries >= LIMIT) {
              note.textContent = "Automatic return stopped after " + LIMIT +
                " attempts — use the link above, or ask an operator to restart the browser.";
              return;
            }

            var left = DELAY;
            note.textContent = "Returning to sign-in in " + left + "s…";
            var timer = setInterval(function () {
              left -= 1;
              if (left > 0) {
                note.textContent = "Returning to sign-in in " + left + "s…";
                return;
              }
              clearInterval(timer);
              try { sessionStorage.setItem(KEY, String(tries + 1)); } catch (e) { /* counted as a try */ }
              window.location.assign(link.getAttribute("href"));
            }, 1000);

            // Clicking is an explicit choice and should not be rate-limited by the counter.
            link.addEventListener("click", function () { clearInterval(timer); });
          })();
        </script>
    </#if>
</@layout.registrationLayout>

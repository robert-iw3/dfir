## Web Server SRG — web tier hardening

*What passing proves:* The ingress states its TLS floor, refuses weak and export ciphers, bounds request rate and concurrency, does not name itself, constrains the application as mobile code, and logs what the SRG requires it to log.

- Run: `uat_srg_webtier.sh` — 2026-08-12 16:10:33Z

**TLS — SRG-APP-000014-WSR-000006, SRG-APP-000439-WSR-000188**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000014-WSR-000006: a default client negotiates TLSv1.3 |
| ✅ PASS | SRG-APP-000014-WSR-000006: the negotiated suite is forward-secret and AEAD (TLS_AES_128_GCM_SHA256) |
| ✅ PASS | SRG-APP-000014-WSR-000006: TLS 1.1 is refused (SSLError: [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert pr) |
| ✅ PASS | SRG-APP-000439-WSR-000188: export, NULL, RC4 and DES suites are refused |

**HTTP/2 — SRG-APP-000439-WSR-000192**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000439-WSR-000192: the ingress selects HTTP/2 over ALPN |

**Request integrity — SRG-APP-000251-WSR-000194/000195**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000251-WSR-000194: a request carrying both Content-Length and Transfer-Encoding is normalized to ONE request (302) |
| ✅ PASS | SRG-APP-000251-WSR-000195: the smuggled second request was not served — no desync between the ingress and its upstream |

**Response headers — SRG-APP-000266-WSR-000159, SRG-APP-000206-WSR-000128**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000266-WSR-000159: no Server header — the ingress does not name itself |
| ✅ PASS | SRG-APP-000266-WSR-000159: no X-Powered-By header |
| ✅ PASS | SRG-APP-000266-WSR-000159: transport security is asserted (Strict-Transport-Security) |
| ✅ PASS | SRG-APP-000266-WSR-000159: MIME sniffing is refused (X-Content-Type-Options) |
| ✅ PASS | SRG-APP-000266-WSR-000159: framing is denied (X-Frame-Options) |
| ✅ PASS | SRG-APP-000266-WSR-000159: referrers are withheld (Referrer-Policy) |
| ✅ PASS | SRG-APP-000206-WSR-000128: the application carries a Content-Security-Policy |
| ✅ PASS | SRG-APP-000206-WSR-000128: the policy defaults to 'self' — no third-party origin is permitted |
| ✅ PASS | SRG-APP-000206-WSR-000128: the application refuses to be framed |
| ✅ PASS | the identity provider still serves its login endpoints through the hardened ingress |

**Request limits — SRG-APP-000001-WSR-000001, SRG-APP-000246-WSR-000149**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000001-WSR-000001: a simultaneous-request ceiling is configured on the ingress |
| ✅ PASS | SRG-APP-000246-WSR-000149: a request rate limit is configured on the ingress |
| ✅ PASS | SRG-APP-000001-WSR-000001: a per-source connection ceiling is applied at the application server |

**Content serving — SRG-APP-000266-WSR-000142, SRG-APP-000141-WSR-000081/000083**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000266-WSR-000142: directory listing is refused |
| ✅ PASS | SRG-APP-000266-WSR-000159: the application server does not report its version |
| ✅ PASS | SRG-APP-000141-WSR-000081: unknown types download rather than being interpreted |
| ✅ PASS | SRG-APP-000141-WSR-000083: dotfiles are refused by the application server (403) |
| ✅ PASS | SRG-APP-000141-WSR-000083: source maps are refused (403) |

**Access logging — SRG-APP-000089/000095/000097/000098/000099**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000089-WSR-000047: the ingress writes structured access records |
| ✅ PASS | log record establishes what the request was (RequestMethod) |
| ✅ PASS | log record establishes when it happened (StartUTC) |
| ✅ PASS | log record establishes where in the server it went (RouterName) |
| ✅ PASS | log record establishes the source it came from (ClientHost) |
| ✅ PASS | log record establishes the outcome (DownstreamStatus) |
| ✅ PASS | SRG-APP-000098-WSR-000060: the ingress record carries the join keys (StartUTC, ClientHost) |
| ✅ PASS | SRG-APP-000098-WSR-000060: the broker records the real client address (10.89.0.13) — the join completes |

**Log aggregation — SRG-APP-000125-WSR-000071, SRG-APP-000357-WSR-000150, SRG-APP-000358-WSR-000163, SRG-APP-000359-WSR-000065, SRG-APP-000108-WSR-000166**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000125-WSR-000071: the deployed shipper completes a pass (2 object(s) shipped) |
| ✅ PASS | SRG-APP-000125-WSR-000071: ingress access records are held in the object store, off the web tier's filesystems |
| ✅ PASS | SRG-APP-000125-WSR-000071: shipping state is in the bucket — a replaced shipper resumes, not re-uploads |
| ✅ PASS | SRG-APP-000358-WSR-000163: shipped objects are whole structured records — a SIEM reads the bucket as-is |
| ✅ PASS | SRG-APP-000357-WSR-000150: log record storage has a declared allocation (10 GiB) and usage is measured against it |
| ✅ PASS | the log bucket is private — an unauthenticated request is refused (403) |
| ✅ PASS | the log sources are read-only to the shipper — the record cannot be altered by its own transport |
| ✅ PASS | SRG-APP-000108-WSR-000166: the shipper self-reports to Component Health — going quiet or failing is surfaced, not silent |
| ✅ PASS | SRG-APP-000357-WSR-000150: the report carries usage against the declared allocation |
| ✅ PASS | SRG-APP-000108-WSR-000166: the shipper's report is CURRENT (655s old) — a stale row is a reporter that stopped, which the existence check cannot tell from one that never started |
| ✅ PASS | SRG-APP-000359-WSR-000065: the warning fires at 75% of allocated log storage and not below it |
| ✅ PASS | SRG-APP-000108-WSR-000166: a shipping failure becomes a Component Health alert |

**Sessions — SRG-APP-000001-WSR-000002, SRG-APP-000295-WSR-000012/000134, SRG-APP-000223-WSR-000011**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | SRG-APP-000223-WSR-000011: the session cookie is HttpOnly |
| ✅ PASS | SRG-APP-000439-WSR-000154: the session cookie is Secure |
| ✅ PASS | SRG-APP-000295-WSR-000012: absolute session lifetime is 8h0m0s |
| ✅ PASS | SRG-APP-000295-WSR-000134: the session is re-validated against the identity provider every 15m0s |
| ✅ PASS | the SSO gate caps per-request CSRF cookies at 6 — accumulation cannot grow the header without bound |
| ✅ PASS | header buffers hold modest headroom (large_client_header_buffers416k;), not room for accumulation |
| ✅ PASS | SRG-APP-000001-WSR-000002: the gate reached its Redis session store at startup |
| ✅ PASS | default-admin re-provisioned to its deployed initial state |
| ✅ PASS | the initial credential admits NO session — Keycloak demands a replacement first |
| ✅ PASS | a real authorization-code login completed through the hardened ingress, forced password change included |
| ✅ PASS | SRG-APP-000001-WSR-000002: the login created server-side session state in Redis database 1 (8 -> 9 keys) |
| · | the intention check could not be read from inside Consul; the store is working regardless |

**Login flow — a page load must not evict the attempt the analyst is standing in**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the gate separates data calls from navigation (--api-route=^/(api/\|index\.html)) — only navigation starts an attempt |
| ✅ PASS | ephemeral uat-srg-csrf provisioned with the forced change that holds a login flow open |
| ✅ PASS | the analyst's navigation starts exactly one authentication attempt |
| ✅ PASS | a page load's worth of data calls (6) was issued on top of the open flow |
| ✅ PASS | every data call was ANSWERED 401 — the SPA turns that into one sign-in rather than 6 of them |
| ✅ PASS | and it earned that 401 on the PATH: the probes sent Accept: */* like the app's fetch, not the application/json that would trigger the gate's AJAX shortcut |
| ✅ PASS | no data call was sent to the identity provider, so none minted an attempt |
| ✅ PASS | the page load minted NO additional CSRF cookies — the ceiling is never approached by data calls |
| ✅ PASS | six polling cycles (three minutes of an open tab) minted NOTHING — waiting at a login page cannot exhaust the ceiling |
| ✅ PASS | the navigation's own CSRF cookie was still present when the callback ran |
| ✅ PASS | a login held open across a full page load completed through the callback, forced password change included |
| ✅ PASS | the gate logged no CSRF failure for that flow |
| ✅ PASS | the deployed bundle has ONE sign-in entry point |
| ✅ PASS | that entry point is single-flight — the second and later 401s of a page load redirect nothing |
| ✅ PASS | ephemeral uat-srg-csrf re-armed for the control run |
| ✅ PASS | control: 7 unclassified path(s) redirected to the identity provider and minted 7 attempt(s) — the driver can see a mint, so the zero it reported above is a measurement |
| ✅ PASS | control: those attempts evicted the analyst's own, oldest-first, exactly as the ceiling of 6 requires |
| ✅ PASS | control: the flow ended in the reported 403 at the callback — the defect is reproducible, and --api-route is what the deployed gate uses to avoid it |
| ✅ PASS | default-admin restored to provisioned state (initial password, change re-armed) |
| ✅ PASS | a provisioned account carries the forced password change until its first login consumes it |

**Identity — SRG-APP-000830/000850/000860/000870, SRG-APP-000427-WSR-000186**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | a password policy is in force on the running realm |
| ✅ PASS | a minimum length is required (SRG-APP-000860) |
| ✅ PASS | composition includes upper case (SRG-APP-000870) |
| ✅ PASS | composition includes digits (SRG-APP-000870) |
| ✅ PASS | composition includes special characters (SRG-APP-000870) |
| ✅ PASS | the username cannot be the password (SRG-APP-000830) |
| ✅ PASS | reuse is refused (SRG-APP-000870) |
| ✅ PASS | an approved salted hash is stated (SRG-APP-000850) |
| ✅ PASS | repeated authentication failures are throttled (brute-force protection is on) |

**Smartcard logon — opt-in (IR_PKI_LOGON=0)**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | smartcard logon is off and the ingress does not ask for a certificate — nothing is half-enabled |
| ✅ PASS | the plumbing is present and inert — enabling it is a flag and a staged CA, not a rebuild |
| · | proving a CARD authenticates needs a card and an issuing CA; that test belongs to an environment that has them |

**SRG-APP-000131 — base images are pinned by digest, and the digest is recorded**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | every external FROM names a digest matching ci/base-images.lock |
| ✅ PASS | and the check REFUSES a FROM reverted to a bare tag, so the gate is real |

**SRG-APP-000456 — the 30-day currency review is recorded, and going stale fails**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the image-currency review is on record and within its interval |
| ✅ PASS | and a review backdated past the ceiling is REFUSED, so the cadence is enforced |

**SRG-APP-000835/000840 — the banned password list is enforced and reviewed**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the list is non-empty and lowercase, the realm policy names it, and the review is current |
| ✅ PASS | Keycloak can read the list it enforces (118 lines in the running image) |

**SRG-APP-000920/000925 — the enclave has a time authority, and containers inherit it**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | clock provenance established: host synchronized, containers agree, enclave serving |
| ✅ PASS | the enclave time service answers and is serving (stratum 10) |
| ✅ PASS | and it runs without control of the system clock, as a container must |
| · | serving from a LOCAL reference — internally consistent, NOT traceable to an authoritative source (IR_NTP_UPSTREAM unset) |

**The tracker states the same thing this suite just proved**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the tracker, .ckl and srg_tracker.json are current with srg_status.yml |

**Result**

| Result | Assertion — with evidence |
|---|---|
| ✅ PASS | the web tier holds: TLS floor enforced, weak ciphers refused, limits in place, identity withheld, mobile code constrained, and requests attributable |

**Verdict: PROVEN** — 98 assertions passed, 0 failed.

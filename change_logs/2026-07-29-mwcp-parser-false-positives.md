# mwcp parser false positives on ordinary content

**Date:** 2026-07-29

**Area:** `playbooks/linux/threat_hunting/mwcp_parsers/`

**Status:** 9 defects fixed, 7 open

## Defect

Config extractors asserted a recovered implant configuration from the presence of a string,
with no structural gate. They run over carved memory regions (`memory_enrich.py`) and over
on-disk files (`edr_hunt.py`), so both paths were affected.

Two independent measurements:

**Live capture.** A 24 GB developer-workstation capture produced `C2 Endpoint` findings for
`api.telegram.org`, `pastebin.com`, `api.github.com`, `content.dropboxapi.com` and
`vscode-resource.vscode-cdn.net`, plus BlackCat ransomware indicators and a Pupy C2 config —
all from an editor's heap in anonymous **rw-** memory. The investigation engine correlated
eight positive dimensions on that PID and rated it True Positive at weight 21. The engine was
correct; its inputs were wrong.

**Ordinary host content.** The catalog run over 1,830 non-malicious files
(`/usr/lib`, `/usr/bin`, `/etc`, `/usr/share/doc`, `/usr/lib/python3`, `~/.local/lib`,
`/proc`) produced **188 false findings — one file in ten**:

| Family reported | Count |
|---|---|
| `Mirai/Gafgyt-class` | 185 |
| `SMTP-Exfil` | 2 |
| `Ebury-class` | 1 |

## Changes

**`_common.py`** — added `co_located()`, requiring two signals to sit within 512 bytes before
they count as one structure; `in_text_run()`, rejecting matches inside prose using whitespace
density rather than printability; and `values_near()`, restricting fallback field recovery to
values beside the anchor that triggered the parser.

**`driver.py`** — `extract_all()` returns nothing for a region that is 60% or more prose.
Measured separation: parser sources 0.96–1.00, every true-positive sample 0.00. The gate sits
at the driver so families added later inherit it.

**`cloud_saas/github.py`** — removed the bare-SHA-1 token alternative; requires a
`gh[pousr]_`/`github_pat_` token co-located with the API endpoint, and not inside a text run.

**`cloud_saas/telegram.py`** — removed the `api.telegram.org` presence fallback; requires the
bot token inside the URL path, or token and endpoint co-located.

**`cloud_saas/dropbox.py`, `cloud_saas/pastebin.py`** — co-location and text-run gates.

**`ransomware/blackcat_linux.py`** — config fields must appear inside a JSON object that
parses, not as loose strings.

**`c2_frameworks/pupy.py`** — co-location within 4096 bytes, plus a config anchor or a host
pattern.

**`native/mirai_gafgyt.py`** — three defects in the XOR string-table search:

- The token filter measured only the ratio of letters, so punctuation-laced runs
  (`@@DXBBlDhPD`, `$q$qUw`) counted as table entries. Tokens are now restricted to the
  identifier/path character set and must carry a vowel.
- Key `0x20` flips ASCII case, so any English text decoded into a word list — espeak
  dictionaries, `.pyc` docstring blobs and charset conversion tables all matched. The decoded
  tokens must now pack into one contiguous block, which is how `table.c` stores them: measured
  0.88 for a genuine table against 0.05 for case-flipped docstrings.
- The best of 255 keys was accepted on token count alone. `table.c` decodes with one
  compile-time key, so exactly one key must reveal the table — the best must exceed the
  runner-up by 3×.

**`native/ebury.py`** — the unverified fallback fired on any object containing both the
keyutils and network string sets. Reaching it requires only that the ELF fail to parse, which
truncation past a caller's read cap causes: `libsystemd-shared-257.so` is 4.2 MB against a
4 MB cap, and legitimately holds keyring helper names while linking the network primitives.
With no symbol table there is no export/import relationship to reason from, so the fallback now
requires the object to identify itself as libkeyutils via its own SONAME.

**`native/smtp_exfil.py`** — the credential label matched inside ordinary words (`cred` in
`credible`, `pwd` in a URL query string), producing `password='ible'` and
`password='wd=XXX&.persistent'` from a filtering proxy's rule file. Labels are now whole-word,
placeholder and query-fragment values are rejected, and the account the credentials
authenticate as is required — which the module docstring already claimed but the code did not
check.

**`c2_frameworks/merlin.py`, `sliver.py`, `generic_go_c2.py`** — all three fell back to the
first or sorted-first URL anywhere in the region when structured extraction returned nothing.
A carved region holds every URL the process has touched, so this named unrelated hosts as C2
infrastructure. Endpoints must now sit within the co-location window of the config keys that
triggered the parser. Sliver's `mtls://` and `wg://` URLs still count anywhere, since those
are its own transports and the scheme carries the claim.

## Verification

- False findings on the same 1,830-file corpus: **188 → 0**.
- True-positive corpus unaffected; every sample in `test/linux/lab_mwcp/samples/tp/` still
  produces a finding.
- Linux suite: 667 passed, 4 skipped, 22 xfailed (`test/run_tests.sh linux`).

**Tooling added.** `test/linux/lab_mwcp/fp_corpus_audit.py` runs the catalog over ordinary
content on the host and reports what fires; a clean run prints `TOTAL false findings: 0`. It is
not a pytest test because results depend on what is installed. Five false-positive samples were
added to `test/linux/lab_mwcp/samples/fp/` — case-flipped prose, words scattered through
binary, a charset conversion table, multipurpose-library strings, and a web proxy action file.
The lab's `test_no_parser_fires_on_any_fp_sample` runs every parser against all of them.

**Test corrections.** Two lab fixtures asserted contracts weaker than the mechanisms they
described and were updated: the Ebury sample now carries the SONAME a real carve of that
library contains, and `test_multiple_families_can_coexist` likewise.

Two approaches were tried and rejected by measurement. A best-versus-runner-up outlier test on
the XOR key search does not separate: a benign espeak dictionary scored 24.5× against the true
positive's 30×. A raw-printability gate does not separate either — a bare table at key `0x37`
measures 0.944 printable against 0.857 for case-flipped prose — and it suppressed real
detections, so it was removed after being tried.

## Open

None of the following fired on the file corpus. All are reachable on process-heap content,
which a file-based corpus cannot represent.

1. `specialized/anti_analysis.py` requires `TracerPid:` beside `/proc/self/status`, but that
   file's own contents contain the field name, so anything holding a copy matches.
2. `c2_frameworks/havoc.py` identifies on any 2 of
   `DemonID`/`SleepTime`/`Injection`/`encrypted_exchange_check`; `Injection` and `SleepTime`
   are ordinary words in dependency-injection and scheduler code.
3. `ransomware/generic_indicators.py` counts an embedded public key plus any 8 of 16 common
   file extensions, which a PKI-using archive or backup tool satisfies.
4. `ransomware/conti_linux.py` matches `-m all` plus `-p <arg>`, both routine in CLI help text.
5. `cloud_saas/ngrok.py` pairs a tunnel domain with generic YAML keys (`addr:`, `tunnels:`)
   anywhere in the region, with no co-location.
6. `cloud_saas/slack.py` matches Slack's own documentation example webhook, whose placeholder
   secret fits the 24-character shape.
7. Eleven parsers listed `UNHARDENED` in `test/linux/lab_mwcp/test_no_self_match.py` key on
   bare literal presence: `adaptix`, `generic_go_c2`, `havoc`, `merlin`, `mythic`, `sliver`,
   `ebury`, `mirai_gafgyt`, `esxi_encryptor`, `recovery_inhibition`, `anti_analysis`. The
   driver's prose gate covers them in production; each `identify()` is still permissive.

`mirai_gafgyt.identify()` also still fires on one pure-prose file
(`/usr/share/doc/cryptsetup/v1.1.3-ReleaseNotes`, prose fraction 1.00) where space-delimited
words decode densely under key `0x20`. `extract_all()` suppresses it. It is left at the driver
layer deliberately; duplicating that gate into each parser is what placing it there avoids.

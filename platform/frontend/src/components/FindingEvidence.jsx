/**
 * What a finding RECOVERED, shown under the finding itself.
 *
 * The collector, memory enrichment, MWCP config extraction and a reverse engineer all write
 * into `Finding.raw`, and correlation reads that vocabulary to build the behavior graph. The
 * findings table showed only type, target, verdict and ATT&CK — so a beacon carrying a
 * user-agent, a mutex, a JA3 hash and an extracted C2 config displayed none of it, and an
 * analyst had to reach the API to see the material the case actually turns on.
 *
 * The key lists below mirror correlation/behavior.py's SCALAR_INDICATORS and LIST_INDICATORS.
 * Anything in `raw` that is not a known key still renders, under "other" — a new producer
 * field appears here the day it is emitted rather than the day someone updates this file.
 */

// subkind -> label, in the order an analyst reads them: what identifies the implant, then
// where it talks, then what it left behind.
const SCALARS = [
  ["malware_family", "family"], ["yara_rule", "YARA rule"],
  ["user_agent", "user-agent"], ["useragent", "user-agent"],
  ["mutex", "mutex"], ["pipe", "named pipe"], ["ja3", "JA3"],
  ["certificate", "certificate"], ["registry_key", "registry key"],
  ["domain", "domain"], ["ip", "IP"], ["url", "URL"], ["onion", "onion"],
  ["sha256", "SHA-256"], ["md5", "MD5"], ["wallet", "wallet"],
  ["account", "account"], ["src_host", "from"], ["dst_host", "to"],
  ["protocol", "protocol"], ["technique", "technique"],
];

const LISTS = [
  ["yara_matches", "YARA matches"], ["urls", "URLs"], ["domains", "domains"],
  ["ips", "IPs"], ["hashes", "hashes"], ["related_hashes", "related hashes"],
  ["mutexes", "mutexes"], ["pipes", "named pipes"], ["user_agents", "user-agents"],
  ["wallets", "wallets"], ["xmr", "wallets"], ["onion", "onion"],
  ["aws_keys", "AWS keys"], ["telegram_tokens", "Telegram tokens"],
  ["discord_webhooks", "Discord webhooks"], ["crypto_material", "crypto material"],
  ["network_indicators", "network indicators"], ["indicators", "indicators"],
];

// Presentation only — never a place a value is dropped. Producers emit bare strings and
// records interchangeably ({"value": …} / {"indicator": …} / {"address": …}), the same
// shapes correlation's _as_values flattens; anything else is shown as JSON rather than
// silently skipped.
function itemText(item) {
  if (item == null) return "";
  if (typeof item === "string" || typeof item === "number") return String(item);
  if (typeof item === "object") {
    const v = item.value ?? item.indicator ?? item.address;
    if (v != null) {
      const kind = item.type || item.role;
      return kind ? `${v} (${kind})` : String(v);
    }
    try { return JSON.stringify(item); } catch { return String(item); }
  }
  return String(item);
}

// Fields every finding carries: its own columns, the collector's original record and the
// engine's bookkeeping. None of them is RECOVERED material, so none of them earns a row an
// expander — counting them made every row look like it held intelligence, which is the same
// as none of them doing so.
const BOOKKEEPING = new Set([
  "Type", "Target", "Verdict", "Confidence", "MITRE", "type", "target", "verdict",
  "confidence", "mitre", "observed_at", "adjudication", "severity", "offset", "detail",
  "source", "engine", "ruleset_version", "finding_type", "scenario", "is_synthetic",
]);

// Whether a finding has anything to show, decided by the same rules the panel renders by.
// Callers use this to decide if an expander belongs on the row — asking the component itself
// (rendering it and testing for null) works only while it stays hook-free.
export function hasEvidence(raw) {
  if (!raw || typeof raw !== "object") return false;
  for (const [k] of [...SCALARS, ...LISTS]) {
    const v = raw[k];
    if (v == null || v === "") continue;
    if (Array.isArray(v) ? v.length : true) return true;
  }
  const cfg = raw.config_extracted;
  return !!(cfg && typeof cfg === "object" && !Array.isArray(cfg) && Object.keys(cfg).length);
}

function Row({ label, children }) {
  return (
    <div style={{ display: "flex", gap: 10, padding: "2px 0", alignItems: "baseline" }}>
      <span className="muted" style={{ minWidth: 132, flexShrink: 0 }}>{label}</span>
      <span className="mono" style={{ wordBreak: "break-all" }}>{children}</span>
    </div>
  );
}

export default function FindingEvidence({ raw }) {
  if (!raw || typeof raw !== "object") return null;

  const seen = new Set(["observed_at", "adjudication"]);
  const rows = [];

  for (const [key, label] of SCALARS) {
    if (seen.has(key)) continue;
    const v = raw[key];
    seen.add(key);
    if (v == null || v === "") continue;
    rows.push(<Row key={key} label={label}>{String(v)}</Row>);
  }

  for (const [key, label] of LISTS) {
    if (seen.has(key)) continue;
    const v = raw[key];
    seen.add(key);
    const items = (Array.isArray(v) ? v : v ? [v] : []).map(itemText).filter(Boolean);
    if (!items.length) continue;
    rows.push(<Row key={key} label={label}>{items.join(", ")}</Row>);
  }

  // Recovered C2 configuration. Each field is a node in the graph, so each is a line here:
  // two implants sharing a campaign id are one operation even when every address differs.
  const cfg = raw.config_extracted;
  const cfgRows = cfg && typeof cfg === "object" && !Array.isArray(cfg)
    ? Object.entries(cfg).filter(([, v]) => v != null && v !== "")
    : [];
  seen.add("config_extracted");

  // Whatever a producer emitted that this file does not know about yet — minus the fields
  // the row already shows and the engine's own bookkeeping, which would otherwise repeat
  // the table back at the analyst.
  const other = Object.entries(raw).filter(
    ([k, v]) => !seen.has(k) && !BOOKKEEPING.has(k) && v != null && v !== "" &&
                (typeof v !== "object" || (Array.isArray(v) && v.length))
  );

  if (!rows.length && !cfgRows.length && !other.length) return null;

  return (
    <div style={{ padding: "6px 2px" }}>
      {rows.length > 0 && (
        <div style={{ marginBottom: cfgRows.length || other.length ? 10 : 0 }}>
          <div className="muted" style={{ marginBottom: 4 }}>Recovered indicators</div>
          {rows}
        </div>
      )}
      {cfgRows.length > 0 && (
        <div style={{ marginBottom: other.length ? 10 : 0 }}>
          <div className="muted" style={{ marginBottom: 4 }}>Extracted C2 configuration</div>
          {cfgRows.map(([k, v]) => (
            <Row key={k} label={k}>{typeof v === "object" ? JSON.stringify(v) : String(v)}</Row>
          ))}
        </div>
      )}
      {other.length > 0 && (
        <div>
          <div className="muted" style={{ marginBottom: 4 }}>Other</div>
          {other.map(([k, v]) => (
            <Row key={k} label={k}>
              {Array.isArray(v) ? v.map(itemText).filter(Boolean).join(", ")
                                : typeof v === "object" ? JSON.stringify(v) : String(v)}
            </Row>
          ))}
        </div>
      )}
    </div>
  );
}

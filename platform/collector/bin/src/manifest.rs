//! The sealed manifest — the contract between the endpoint and the platform.
//!
//! Shape is fixed by `planning/DATA-PIPELINE.md` §3 and must not drift from it: the receiver,
//! the verifier and the replicator all decode this. A change here means re-sealing evidence,
//! so `manifest_version` exists from the first release rather than being added later.
//!
//! Two properties this file exists to guarantee:
//!
//!   * `content.sha256` is over the ORIGINAL bytes, never the encoded form. The custody claim
//!     is about the evidence, not about how it was packed for transport.
//!   * `blake3_root` is a Merkle root over RAW chunk hashes, so a bad chunk is identified
//!     rather than poisoning the image, and verification never needs the whole thing
//!     reassembled.

use serde::{Deserialize, Serialize};

pub const MANIFEST_VERSION: u32 = 1;

/// What the endpoint produced. Selects the analysis engine on the platform side
/// (`aff4` -> MemProcFS, `raw`/`lime` -> Volatility 3), so it is routing metadata as much as
/// a description.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Raw,
    Lime,
    Aff4,
}

impl Format {
    /// Transport encoding is chosen by what the source format ALREADY does. AFF4 is chunked,
    /// compressed and sparse-aware in its own container; re-compressing it costs CPU on a
    /// production endpoint and returns nothing.
    pub fn transport_encoding(self) -> Encoding {
        match self {
            Format::Aff4 => Encoding::None,
            Format::Raw | Format::Lime => Encoding::Zstd,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    None,
    Zstd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub hostname: String,
    /// The join key on the platform side. Hostnames are renamed; this is not.
    pub machine_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acquisition {
    pub tool: String,
    pub version: String,
    /// The source that actually worked — `/proc/kcore`, `/dev/crash`, `/dev/mem`.
    pub source: String,
    /// Every source tried and refused, in order. A host where two methods failed before one
    /// worked is telling you something, and it is lost if only the winner is recorded.
    pub fallbacks_tried: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    pub raw_size: u64,
    /// Over the original content. The custody claim.
    pub sha256: String,
    /// Merkle root over raw per-chunk BLAKE3 hashes.
    pub blake3_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub i: u64,
    pub raw_off: u64,
    pub raw_len: u64,
    /// BLAKE3 of the RAW bytes, before any encoding.
    pub blake3: String,
    /// Bytes actually transmitted. Zero for an elided all-zero chunk.
    pub stored_len: u64,
    /// An all-zero chunk is RECORDED and not sent. On a host with large unused RAM this is
    /// the single biggest saving on the wire, and it costs one hash comparison.
    pub zero: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transport {
    pub chunk_size: u64,
    pub encoding: Encoding,
    pub chunks: Vec<Chunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Custody {
    pub hmac_sha256: String,
    pub key_id: String,
    pub sealed_at: String,
}

/// Conditions the collection ran under. The collector RECORDS these and draws no conclusion;
/// the platform decides whether a result is trustworthy. Anti-tamper on a host we do not
/// control is bounded — a collector that adjudicated its own integrity would be trusted more
/// than it deserves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conditions {
    pub ptrace_attached: bool,
    pub dumpable_disabled: bool,
    /// Present in the environment. Inert against a static binary — presence is still signal.
    pub loader_env: Vec<String>,
    pub kernel_taint: Option<String>,
    pub kernel_release: String,
    pub module_count: usize,
    /// Hash over the sorted loaded-module list, so a change between snapshots is one compare.
    pub module_list_sha256: String,
    /// Bytes/sec during acquisition. A rate implying interposition is worth seeing.
    pub read_rate_bps: u64,
    /// Processes that appeared or vanished DURING acquisition — evidence in its own right.
    pub snapshot_delta: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub capture_id: String,
    pub incident_id: String,
    pub host: Host,
    pub acquired_at: String,
    pub acquisition: Acquisition,
    pub format: Format,
    pub content: Content,
    pub transport: Transport,
    pub conditions: Conditions,
    /// Absent until `seal()` runs. Sealing is the last thing that happens before bytes move.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custody: Option<Custody>,
}

impl Manifest {
    /// The bytes the HMAC covers: the manifest with `custody` absent, canonically encoded.
    ///
    /// Canonical because the platform recomputes this to verify, and two encoders disagreeing
    /// about key order would fail every seal for a reason that looks like tampering.
    pub fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bare = self.clone();
        bare.custody = None;
        Ok(canonical_json(&serde_json::to_value(&bare)?))
    }

    /// Seal the manifest. Called BEFORE any chunk is transmitted, so a partially delivered
    /// capture still has a verifiable description of what it was meant to be.
    pub fn seal(&mut self, key: &[u8], key_id: &str, now: &str) -> anyhow::Result<()> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| anyhow::anyhow!("custody key rejected"))?;
        mac.update(&self.signing_bytes()?);
        self.custody = Some(Custody {
            hmac_sha256: hex(&mac.finalize().into_bytes()),
            key_id: key_id.to_string(),
            sealed_at: now.to_string(),
        });
        Ok(())
    }
}

/// Deterministic JSON: object keys sorted, no insignificant whitespace.
fn canonical_json(v: &serde_json::Value) -> Vec<u8> {
    fn write(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                out.push('{');
                for (n, k) in keys.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).unwrap_or_default());
                    out.push(':');
                    write(&m[*k], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(a) => {
                out.push('[');
                for (n, e) in a.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    write(e, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut s = String::new();
    write(v, &mut s);
    s.into_bytes()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

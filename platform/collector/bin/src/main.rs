//! ir-collect — field memory collector.
//!
//! One static binary, delivered over SSH into an anonymous memory file and executed from it.
//! No runtime on the endpoint, nothing written to its disk, nothing left behind.
//!
//! Lifecycle:
//!   harden -> snapshot -> acquire+chunk+seal+stream -> snapshot -> verify delivery -> exit
//!
//! Delivery is verified BEFORE the process exits. The collector's job is not done when the
//! last chunk is sent; it is done when the platform confirms the Merkle root matches.
//!
//! DRAFT — see planning/COLLECTOR-DEPLOYMENT.md. Not yet compiled or tested.

mod chunk;
mod conditions;
mod manifest;
mod snapshot;

use anyhow::{bail, Context, Result};
use manifest::{Acquisition, Content, Format, Host, Manifest, Transport, MANIFEST_VERSION};

struct Args {
    incident_id: String,
    capture_id: String,
    receiver: String,
    /// One-time, scoped, short-TTL. A stolen upload credential expires unused, which is why
    /// the endpoint never holds a durable one.
    upload_token: String,
    custody_key: Vec<u8>,
    custody_key_id: String,
    format: Format,
    dry_run: bool,
}

fn main() {
    if let Err(e) = run() {
        // stderr only. The endpoint's own logs are the organization's record of the action and
        // are deliberately left intact, but this process writes nothing to them itself.
        eprintln!("ir-collect: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = parse_args()?;

    // First, before anything observable: a non-root observer can no longer attach or read this
    // process's memory. Useless against root, so the outcome is recorded rather than trusted.
    let dumpable_disabled = conditions::harden();

    let before = snapshot::Snapshot::take(&now_iso())
        .context("pre-acquisition snapshot")?;

    let started = std::time::Instant::now();

    // --- acquire + chunk + seal + stream, in one pass -------------------------------------
    //
    // No local staging. Writing the image to disk first would double I/O on a machine somebody
    // is using, need free space that may not exist, and leave the whole capture sitting on a
    // host the adversary controls.
    let (source, acq_tool, acq_version, fallbacks) = acquire::open(args.format)
        .context("no memory acquisition method succeeded")?;

    let mut chunker = chunk::Chunker::new(args.format.transport_encoding());
    let mut shipper = ship::Shipper::new(&args.receiver, &args.upload_token, &args.capture_id)?;

    chunker.run(source, |encoded| shipper.send(encoded))?;

    let (sha256, blake3_root, chunks, raw_size) = chunker.finish();
    let elapsed = started.elapsed().as_secs_f64().max(0.001);

    let after = snapshot::Snapshot::take(&now_iso()).context("post-acquisition snapshot")?;
    let delta = snapshot::Snapshot::delta(&before, &after);

    let mut m = Manifest {
        manifest_version: MANIFEST_VERSION,
        capture_id: args.capture_id.clone(),
        incident_id: args.incident_id.clone(),
        host: Host {
            hostname: hostname(),
            machine_id: machine_id(),
        },
        acquired_at: now_iso(),
        acquisition: Acquisition {
            tool: acq_tool,
            version: acq_version,
            source: String::new(), // set by acquire::open via fallbacks.last()
            fallbacks_tried: fallbacks,
        },
        format: args.format,
        content: Content {
            raw_size,
            sha256,
            blake3_root,
        },
        transport: Transport {
            chunk_size: chunk::CHUNK_SIZE as u64,
            encoding: args.format.transport_encoding(),
            chunks,
        },
        conditions: conditions::collect(
            dumpable_disabled,
            (raw_size as f64 / elapsed) as u64,
            delta,
        ),
        custody: None,
    };

    m.seal(&args.custody_key, &args.custody_key_id, &now_iso())
        .context("sealing the manifest")?;

    if args.dry_run {
        println!("{}", serde_json::to_string_pretty(&m)?);
        return Ok(());
    }

    // The manifest goes last because it describes what was sent — but it is SEALED over content
    // hashes computed during the pass, so it still describes the original bytes rather than
    // whatever arrived.
    shipper.finish(&m).context("completing the upload")?;

    // Verified before exit. A collector that reports success on an unconfirmed upload has
    // destroyed the only copy of a volatile artifact.
    if !shipper.confirm(&m).context("confirming delivery")? {
        bail!("platform did not confirm the capture — leaving nothing torn down");
    }

    Ok(())
}

// --- stubs, pending the decisions in COLLECTOR-DEPLOYMENT.md §11 --------------------------

mod acquire {
    //! Memory acquisition via AVML as a library.
    //!
    //! AVML already owns the fallback chain across /proc/kcore -> /dev/crash -> /dev/mem, so
    //! this wraps it rather than reimplementing it.
    //!
    //! UNIMPLEMENTED. Blocked on O-009: confirm the crate exposes the fallback chain
    //! programmatically and returns a streaming reader rather than writing a file. If it only
    //! writes a file, this track needs a different approach — writing 24 GB to the endpoint's
    //! disk is the one thing the design refuses.
    //!
    //! On a host where NO method works, this must fail loudly. The container path already
    //! follows that rule and must not diverge here: never substitute anything for a real image.
    use super::manifest::Format;
    use anyhow::{bail, Result};
    use std::io::Read;

    pub fn open(_format: Format) -> Result<(Box<dyn Read>, String, String, Vec<String>)> {
        bail!("acquire::open is not implemented — see COLLECTOR-DEPLOYMENT.md §11")
    }
}

mod ship {
    //! Resumable chunked upload to the DMZ receiver.
    //!
    //! UNIMPLEMENTED. Contract, so the rest of the program is written against it:
    //!   * `send` streams one encoded chunk; a zero chunk sends no bytes.
    //!   * parallelism is BOUNDED — an unbounded transfer is what made the object store
    //!     report its own drive unhealthy, and on an endpoint it is what the user notices.
    //!   * resume asks the receiver which parts exist and sends only the difference.
    //!   * the receiver's certificate is PINNED; no system trust store is consulted.
    use super::chunk::Encoded;
    use super::manifest::Manifest;
    use anyhow::{bail, Result};

    pub struct Shipper;

    impl Shipper {
        pub fn new(_receiver: &str, _token: &str, _capture_id: &str) -> Result<Self> {
            bail!("ship::Shipper is not implemented — see COLLECTOR-DEPLOYMENT.md §11")
        }
        pub fn send(&mut self, _c: Encoded) -> Result<()> {
            unimplemented!()
        }
        pub fn finish(&mut self, _m: &Manifest) -> Result<()> {
            unimplemented!()
        }
        pub fn confirm(&mut self, _m: &Manifest) -> Result<bool> {
            unimplemented!()
        }
    }
}

// --- host identity + args ------------------------------------------------------------------

/// The join key on the platform side. Hostnames are renamed; this is not.
fn machine_id() -> String {
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(p) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn now_iso() -> String {
    // TODO: RFC 3339 in UTC without pulling in a date crate. The platform parses this, so the
    // format is part of the contract, not a detail.
    String::new()
}

fn parse_args() -> Result<Args> {
    // Hand-rolled: a clap dependency is measurable in a binary whose size is exposure, and the
    // surface is a handful of required flags.
    //
    // Secrets arrive by ENVIRONMENT, never argv — argv is world-readable through /proc on the
    // very host we are treating as hostile.
    bail!("parse_args is not implemented — see COLLECTOR-DEPLOYMENT.md §11")
}

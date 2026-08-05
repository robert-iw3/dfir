//! Conditions the collection ran under.
//!
//! This module RECORDS and does not judge. Anti-tamper on a host we do not control is bounded:
//! a kernel-level rootkit sees and can alter anything a userspace collector does, including
//! what this file reads. A collector that declared itself uncompromised would be asserting
//! exactly the thing it cannot know.
//!
//! So the endpoint reports and the platform concludes. Every field here is an input to that
//! judgment, not a verdict.

use crate::manifest::{hex, Conditions};
use sha2::{Digest, Sha256};
use std::fs;

/// Harden what can be hardened, and report whether it took.
///
/// `PR_SET_DUMPABLE = 0` stops a non-root process attaching with `ptrace` or reading this
/// process's `/proc/<pid>/mem`. It does nothing against root — which is most of the threat —
/// so the return value is recorded rather than relied on.
pub fn harden() -> bool {
    // SAFETY: prctl with PR_SET_DUMPABLE takes no pointers and cannot fail destructively.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 }
}

pub fn collect(dumpable_disabled: bool, read_rate_bps: u64, snapshot_delta: Vec<String>) -> Conditions {
    Conditions {
        ptrace_attached: tracer_pid().is_some_and(|p| p != 0),
        dumpable_disabled,
        loader_env: loader_env(),
        kernel_taint: read_trim("/proc/sys/kernel/tainted"),
        kernel_release: read_trim("/proc/sys/kernel/osrelease").unwrap_or_default(),
        module_count: modules().len(),
        module_list_sha256: modules_hash(),
        read_rate_bps,
        snapshot_delta,
    }
}

/// A debugger attached to the collector. Self-reported by the kernel, so a rootkit can lie —
/// which is why it is one signal among several rather than a gate.
fn tracer_pid() -> Option<i32> {
    let s = fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// Loader variables should be inert against a static binary — there is no dynamic loader to
/// honor them. Their PRESENCE still says something about the environment the collection ran in.
fn loader_env() -> Vec<String> {
    ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"]
        .iter()
        .filter(|k| std::env::var_os(k).is_some())
        .map(|k| (*k).to_string())
        .collect()
}

fn modules() -> Vec<String> {
    fs::read_to_string("/proc/modules")
        .map(|s| {
            let mut v: Vec<String> = s
                .lines()
                .filter_map(|l| l.split_whitespace().next().map(str::to_string))
                .collect();
            v.sort();
            v
        })
        .unwrap_or_default()
}

/// One value to compare across the pre- and post-acquisition snapshots. A module loaded while
/// the capture was running is worth surfacing, and a hash makes that a single comparison.
fn modules_hash() -> String {
    let mut h = Sha256::new();
    for m in modules() {
        h.update(m.as_bytes());
        h.update(b"\n");
    }
    hex(&h.finalize())
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

//! Fast volatile snapshot — process table, connections, modules, mounts.
//!
//! Taken twice: once before acquisition and once after. The delta is evidence in its own
//! right. A capture takes minutes, and a process that appeared or vanished while it was
//! running is exactly the kind of thing an adversary reacting to the collection would produce.
//!
//! Cheap by design — seconds, reading `/proc`. It runs before the expensive step so the memory
//! image has context even if acquisition later fails.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub taken_at: String,
    /// pid -> "comm(exe)". Ordered so two snapshots diff deterministically.
    pub processes: BTreeMap<i32, String>,
    pub connections: Vec<String>,
    pub modules: Vec<String>,
    pub mounts: Vec<String>,
}

impl Snapshot {
    pub fn take(now: &str) -> Result<Self> {
        Ok(Self {
            taken_at: now.to_string(),
            processes: processes(),
            connections: lines("/proc/net/tcp")
                .into_iter()
                .chain(lines("/proc/net/tcp6"))
                .collect(),
            modules: lines("/proc/modules"),
            mounts: lines("/proc/self/mounts"),
        })
    }

    /// What changed between two snapshots, as human-readable lines for the manifest.
    ///
    /// Processes only: connections churn constantly on a working machine and would bury the
    /// signal. A module or mount change is caught by the hashes in `conditions`.
    pub fn delta(before: &Snapshot, after: &Snapshot) -> Vec<String> {
        let mut out = Vec::new();
        for (pid, name) in &after.processes {
            if !before.processes.contains_key(pid) {
                out.push(format!("appeared: {pid} {name}"));
            }
        }
        for (pid, name) in &before.processes {
            if !after.processes.contains_key(pid) {
                out.push(format!("vanished: {pid} {name}"));
            }
        }
        out
    }
}

fn processes() -> BTreeMap<i32, String> {
    let mut out = BTreeMap::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return out;
    };
    for e in dir.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        // The resolved target, not the symlink text: a deleted binary still names what it was,
        // and " (deleted)" on the path is itself worth carrying into the record.
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "-".into());
        out.insert(pid, format!("{comm}({exe})"));
    }
    out
}

fn lines(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

//! Chunk, hash, elide and encode — in ONE pass over the image.
//!
//! The image is read once. A 24 GB capture cannot be read twice on a production endpoint
//! without the user noticing, and a second pass would also read a machine whose memory has
//! moved on since the first.
//!
//! Nothing is staged to disk. The endpoint's disk footprint is zero and its memory footprint
//! is one chunk, because a flagged workstation may not have 24 GB free and the image would
//! otherwise sit on a host the adversary controls.

use crate::manifest::{hex, Chunk, Encoding};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::io::Read;

/// 64 MiB: large enough that per-chunk overhead is noise against a multi-GB image, small
/// enough that a resume after a dropped link re-sends little. Also keeps the part count far
/// below the 10,000-part ceiling multipart upload imposes.
pub const CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// What one chunk became, handed to the shipper. `bytes` is empty for an elided zero chunk.
pub struct Encoded {
    pub meta: Chunk,
    pub bytes: Vec<u8>,
}

/// Streams the source, emitting encoded chunks through `sink` as they are produced.
///
/// `sink` returning an error aborts the pass — a failed upload should stop the read rather
/// than continue burning the endpoint's I/O for bytes nobody will receive.
pub struct Chunker {
    encoding: Encoding,
    sha: Sha256,
    leaves: Vec<[u8; 32]>,
    pub raw_size: u64,
    pub chunks: Vec<Chunk>,
}

impl Chunker {
    pub fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            sha: Sha256::new(),
            leaves: Vec::new(),
            raw_size: 0,
            chunks: Vec::new(),
        }
    }

    pub fn run<R: Read, F: FnMut(Encoded) -> Result<()>>(
        &mut self,
        mut src: R,
        mut sink: F,
    ) -> Result<()> {
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut index: u64 = 0;
        let mut offset: u64 = 0;

        loop {
            let n = read_full(&mut src, &mut buf)?;
            if n == 0 {
                break;
            }
            let raw = &buf[..n];

            // The custody hash is over the ORIGINAL bytes, so it is fed before any encoding.
            self.sha.update(raw);

            let leaf = blake3::hash(raw);
            self.leaves.push(*leaf.as_bytes());

            // An all-zero chunk is recorded and not sent. Memory images are full of them.
            let zero = is_all_zero(raw);
            let bytes = if zero {
                Vec::new()
            } else {
                match self.encoding {
                    Encoding::None => raw.to_vec(),
                    Encoding::Zstd => zstd::stream::encode_all(raw, ZSTD_LEVEL)?,
                }
            };

            let meta = Chunk {
                i: index,
                raw_off: offset,
                raw_len: n as u64,
                blake3: leaf.to_hex().to_string(),
                stored_len: bytes.len() as u64,
                zero,
            };
            self.chunks.push(meta.clone());
            sink(Encoded { meta, bytes })?;

            self.raw_size += n as u64;
            offset += n as u64;
            index += 1;
        }
        Ok(())
    }

    /// Content hashes, available once the pass completes.
    pub fn finish(self) -> (String, String, Vec<Chunk>, u64) {
        let sha256 = hex(&self.sha.finalize());
        let root = merkle_root(&self.leaves);
        (sha256, root, self.chunks, self.raw_size)
    }
}

/// Low, deliberately. Compression runs on a production endpoint, and the win on a memory image
/// comes from repeated kernel structures and near-zero pages rather than from a high level.
/// Level 3 gives most of the ratio at a fraction of the CPU an employee would feel.
const ZSTD_LEVEL: i32 = 3;

/// Binary Merkle over the raw chunk hashes. An odd node is promoted rather than duplicated —
/// duplicating the last leaf is the shape that admits second-preimage tricks.
fn merkle_root(leaves: &[[u8; 32]]) -> String {
    if leaves.is_empty() {
        return hex(blake3::hash(b"").as_bytes());
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut h = blake3::Hasher::new();
                h.update(&pair[0]);
                h.update(&pair[1]);
                next.push(*h.finalize().as_bytes());
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    hex(&level[0])
}

fn is_all_zero(b: &[u8]) -> bool {
    // Compares as words where alignment allows; a byte loop over 64 MiB is measurable on a
    // machine somebody is using.
    b.iter().all(|&x| x == 0)
}

/// `Read::read` is permitted to return short. A partial chunk mid-image would shift every
/// later offset and change the content hash, so fill or hit EOF.
fn read_full<R: Read>(src: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

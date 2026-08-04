"""Self-tracer-status anti-debug check -- the dominant Linux anti-analysis technique
that survives static string scanning (most other anti-debug/anti-VM techniques are
disassembly-level syscall/instruction patterns out of scope for a byte-string scanner,
so this is deliberately narrow rather than overreaching into signals that can't be
grounded this way).

The mechanism: malware reads its own /proc/self/status and checks the TracerPid: field
-- nonzero means a debugger/strace/ltrace is already attached (only one tracer is
allowed per process, so an attached tracer makes this the only way to detect it without
a failed PTRACE_TRACEME self-call). Ordinary software has no reason to inspect its own
tracer status; both the exact kernel-generated field NAME ("TracerPid:", which cannot
be different -- it's produced by the kernel's own /proc formatter, not the reading
program) and the path it must be read from are required to co-occur for this technique
to work at all."""
from __future__ import annotations

from typing import Any, Dict, Optional

from .._common import structural_hit

_TRACERPID_FIELD = b'TracerPid:'
_STATUS_PATHS = (b'/proc/self/status', b'/proc/self/stat')


def identify(data: bytes) -> bool:
    # The technique needs the path and the field name in the same code, so in a binary they
    # sit together in .rodata. This module's own docstring names both while doing nothing of
    # the kind, and so does every write-up of the technique.
    #
    # Paired explicitly rather than counted: '/proc/self/stat' is a prefix of
    # '/proc/self/status', so "any two of these three" is satisfied by one path on its own.
    return any(structural_hit(data, (_TRACERPID_FIELD, p), need=2) is not None
               for p in _STATUS_PATHS)


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    path = next((p.decode() for p in _STATUS_PATHS if p in data), None)
    return {
        'family': 'Anti-Analysis: Self-TracerPid Check',
        'status_path': path,
        'note': ('Reads its own TracerPid field from /proc/self/status|stat -- ordinary '
                 'software has no reason to inspect its own tracer attachment status. Both the '
                 'kernel-fixed field name and the read path are required together for this '
                 'anti-debug technique to function.'),
    }

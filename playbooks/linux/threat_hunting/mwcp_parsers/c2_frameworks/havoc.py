"""Havoc (Demon agent -- Linux/macOS builds since Havoc v2). The 0xDEADBEEF config
magic + a plausible size field is the wire-format structure the agent's own config
parser requires to bootstrap; the protocol field names are the fallback signal when
the magic isn't present (e.g. only a decoded/partial config blob was carved)."""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, Optional

from .._common import decode, in_text_run, structural_hit

_MAGIC = b'\xde\xad\xbe\xef'
_PROTO_FIELDS = (b'DemonID', b'SleepTime', b'Injection', b'encrypted_exchange_check')
_SLEEP_RE = re.compile(rb'(?:SleepTime|Sleep)\s*[=:]\s*(\d{1,6})', re.IGNORECASE)
_HOST_RE = re.compile(
    rb'(?:Teamserver|Host)\s*[=:]\s*[\x22\x27]?([a-zA-Z0-9\.\-]{4,100}:\d{2,5})', re.IGNORECASE)


def identify(data: bytes) -> bool:
    pos = data.find(_MAGIC)
    if pos != -1 and pos + 8 <= len(data) and not in_text_run(data, pos):
        try:
            size = struct.unpack_from('<I', data, pos + 4)[0]
            if 0 < size < 8192:
                return True
        except struct.error:
            pass
    # Without the magic the claim rests entirely on field names, which is what a write-up of
    # the wire format also contains. They have to sit together and out of running text.
    return structural_hit(data, _PROTO_FIELDS, need=2) is not None


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    sleep, jitter = None, None
    pos = data.find(_MAGIC)
    if pos != -1 and pos + 24 <= len(data):
        try:
            sleep = struct.unpack_from('<I', data, pos + 12)[0]
            jitter = struct.unpack_from('<I', data, pos + 16)[0]
        except struct.error:
            pass
    if sleep is None:
        m = _SLEEP_RE.search(data)
        if m:
            sleep = int(m.group(1))
    host_m = _HOST_RE.search(data)
    host = decode(host_m.group(1)) if host_m else ''
    if sleep is None and not host:
        return None
    return {'family': 'Havoc', 'teamserver': host, 'sleep_s': sleep, 'jitter': jitter}

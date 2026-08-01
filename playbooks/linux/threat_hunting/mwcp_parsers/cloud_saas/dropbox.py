"""Dropbox API as a C2/exfil channel. Requires BOTH the content-upload API endpoint
AND the Dropbox-API-Arg header -- a custom HTTP header the Dropbox API mandates for
every content-endpoint call (it carries the JSON call arguments the REST body can't,
since the body IS the raw file payload). No generic HTTP client emits this header;
it only exists because the Dropbox API protocol requires it."""
from __future__ import annotations

from typing import Any, Dict, Optional

_ENDPOINTS = (b'content.dropboxapi.com/2/files/upload', b'api.dropboxapi.com/2/files/')
_REQUIRED_HEADER = b'Dropbox-API-Arg'


from .._common import co_located, in_text_run


def identify(data: bytes) -> bool:
    # The header belongs to the request that carries it. Requiring only that both appear
    # somewhere in the region matched any buffer holding API documentation or an HTTP client
    # library alongside the endpoint string.
    for ep in _ENDPOINTS:
        i = data.find(ep)
        if i == -1 or in_text_run(data, i):
            continue
        if co_located(data, ep, _REQUIRED_HEADER):
            return True
    return False


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    endpoint = next((e.decode() for e in _ENDPOINTS if e in data), None)
    return {
        'family': 'SaaS C2: Dropbox API',
        'endpoint': endpoint,
        'note': ('Dropbox content-API endpoint co-occurring with the Dropbox-API-Arg header '
                 'the protocol requires for every content call -- API-mandated pairing, not an '
                 'artifact string.'),
    }

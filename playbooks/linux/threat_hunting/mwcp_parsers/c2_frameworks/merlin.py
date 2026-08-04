"""Merlin (Go, explicitly cross-platform -- ships Linux builds). Protocol-required
serialization keys used by the Merlin server's REST/gRPC interface; operators strip
"merlin"/"ne0nd0g" but cannot rename these without forking the server."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import decode, find_json_objects, structural_hit, values_near

_PROTO_FIELDS = (b'"psk"', b'"PSK"', b'"skew"', b'"maxRetry"', b'"proto"')
_JSON_ANCHOR = re.compile(rb'"(?:psk|PSK|maxRetry)"\s*:')
_URL_RE = re.compile(rb'https?://[^\s\x00\'"<>]{4,200}', re.IGNORECASE)


def identify(data: bytes) -> bool:
    # Serialization keys travel together inside one marshalled message; the same keys
    # quoted in a source file or an advisory are spread through running text.
    return structural_hit(data, _PROTO_FIELDS, need=2) is not None


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in find_json_objects(data, _JSON_ANCHOR):
        fields.update(obj)

    url = fields.get('url') or fields.get('URL', '')
    if not url:
        # Only a URL sitting beside the PSK/retry keys is part of this config; the first
        # URL in the region at large belongs to whatever else the process was doing.
        near = values_near(data, _URL_RE, _JSON_ANCHOR, limit=1)
        if near:
            url = decode(near[0])
    sleep = fields.get('sleep') or fields.get('Sleep')
    proto = fields.get('proto') or fields.get('Proto')
    if not url:
        return None
    return {'family': 'Merlin', 'c2_url': url, 'sleep_s': sleep, 'protocol': proto}

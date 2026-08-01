"""Pupy RAT (Python, explicitly cross-platform -- Linux is a first-class target, not a
cross-compile afterthought). Pupy's transport/config layer uses these module and RPC
names verbatim in its pickled/marshalled config and reflective-loader banner; an
operator can rebuild the payload but these package/RPC names are load-bearing (the
client can't dispatch without them)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import decode, find_json_objects

_MARKERS = (
    b'pupy.pupyimporter', b'PupyCredentials', b'rpyc.core', b'ReverseSlave',
    b'launcher_module', b'pupy_srv.py', b'dnscnc',
)
_CONF_ANCHOR = re.compile(rb'"?(?:launcher_args|transport|server)"?\s*:')
_HOST_RE = re.compile(rb'(?:server|host)["\')\s:=]{1,4}["\']?([a-zA-Z0-9\.\-]{4,100}:\d{2,5})', re.IGNORECASE)


from .._common import co_located, in_text_run


def identify(data: bytes) -> bool:
    """Two markers anywhere is not a deployment.

    The marker names appear together in documentation, in detection content, and in this
    parser's own source. They must sit close enough to be one embedded module set, outside a
    printable text run, and be accompanied by the configuration anchor that a live launcher
    actually carries.
    """
    hits = [m for m in _MARKERS if m in data]
    if len(hits) < 2:
        return False
    if not co_located(data, hits[0], hits[1], window=4096):
        return False
    # Accompanied by something a live launcher carries: a configuration anchor, or the
    # server endpoint itself. Requiring the anchor alone rejected real deployments that
    # write `server=host:port` rather than a JSON key.
    for pat in (_CONF_ANCHOR, _HOST_RE):
        m = pat.search(data)
        if m and not in_text_run(data, m.start()):
            return True
    return False


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in find_json_objects(data, _CONF_ANCHOR):
        fields.update(obj)
    server = fields.get('server', '')
    if not server:
        m = _HOST_RE.search(data)
        if m:
            server = decode(m.group(1))
    transport = fields.get('transport', '')
    dns_cnc = b'dnscnc' in data
    if not (server or dns_cnc):
        return None
    return {'family': 'Pupy', 'server': server, 'transport': transport,
            'dns_cnc': dns_cnc or None}

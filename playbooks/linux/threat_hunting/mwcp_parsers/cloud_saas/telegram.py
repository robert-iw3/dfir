"""Telegram Bot API as a C2/exfil channel. A Telegram bot token has an EXACT wire
format Telegram's own API enforces (numeric bot ID : 35-char secret) -- an operator
cannot use a malformed token and have the bot function at all. Combined with the
API-required endpoint path structure (api.telegram.org/bot<token>/<method>, where
<method> must be a real Bot API method the server recognizes)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_TOKEN_RE = re.compile(rb'(?<!\d)(\d{8,10}):([A-Za-z0-9_\-]{35})\b')
_ENDPOINT_RE = re.compile(
    rb'api\.telegram\.org/bot[\d]{8,10}:[A-Za-z0-9_\-]{35}/(sendMessage|sendDocument|'
    rb'getUpdates|sendPhoto|answerCallbackQuery)', re.IGNORECASE)


from .._common import co_located, in_text_run


def identify(data: bytes) -> bool:
    # The endpoint form carries the token inside the URL path, which is the protocol
    # requirement and the actual evidence. The previous `or 'api.telegram.org' in data`
    # fallback discarded that: a token-shaped string anywhere plus the hostname anywhere
    # matched, and both occur by chance in a large heap.
    em = _ENDPOINT_RE.search(data)
    if em:
        return not in_text_run(data, em.start())
    tm = _TOKEN_RE.search(data)
    if not tm or in_text_run(data, tm.start()):
        return False
    return co_located(data, _TOKEN_RE, b'api.telegram.org')


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    tm = _TOKEN_RE.search(data)
    em = _ENDPOINT_RE.search(data)
    return {
        'family': 'SaaS C2: Telegram Bot API',
        'bot_id': tm.group(1).decode(),
        'endpoint_method': em.group(1).decode() if em else None,
        'note': ('Bot-API-required token format (numeric ID:35-char secret) AND the '
                 'api.telegram.org endpoint co-occurring -- both are protocol requirements, '
                 'not artifact strings an operator chose.'),
    }

"""GitHub as a C2/exfil/dead-drop channel. Requires the GitHub REST API endpoint and a
GitHub-issued Personal Access Token, the two close enough together to form one request
rather than two unrelated strings in the same buffer."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import co_located, in_text_run

_ENDPOINT = b'api.github.com/repos/'

# Only GitHub's prefixed token formats. The classic 40-hex form was accepted here and is
# indistinguishable from any SHA-1 -- every git object id and content hash matches it. On a
# developer machine `api.github.com/repos/` and a commit hash co-occur constantly, so that
# alternative asserted a credential wherever ordinary development work sat in memory. The
# prefixed forms are issued and validated by GitHub and carry no such collision.
_PAT_RE = re.compile(
    rb'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b'
    rb'|\bgithub_pat_[A-Za-z0-9_]{60,}\b')


def identify(data: bytes) -> bool:
    m = _PAT_RE.search(data)
    if not m or _ENDPOINT not in data:
        return False
    # A token quoted in documentation or an example is not a configuration in use.
    if in_text_run(data, m.start()):
        return False
    return co_located(data, _ENDPOINT, _PAT_RE)


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    m = _PAT_RE.search(data)
    token_kind = m.group(0).split(b'_', 1)[0].decode()
    return {
        'family': 'SaaS C2: GitHub API',
        'token_format': token_kind,
        'note': ('GitHub REST API endpoint and a GitHub-issued token, co-located within one '
                 'request structure -- repo-as-dead-drop / gist-based C2 channel indicator. '
                 'Token prefixes are assigned by GitHub, not chosen by an operator.'),
    }

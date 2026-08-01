"""
Resolving a capture's Volatility symbol table, and asking for one when it is missing.

Neither end of the pipeline may reach the internet: the collector runs on a possibly
compromised endpoint, and the enclave has no egress by design. Acquiring debug symbols is
therefore an out-of-band act by an administrator, and this module is the boundary between
"analysis wants symbols" and "an administrator was told to go get them".

Nothing here downloads anything. It looks in the enclave's symbol store, and if the ISF is
absent it records a request carrying the exact requisites the collector captured.
"""
import hashlib
import json
import os

from django.conf import settings
from django.utils import timezone

from .models import SymbolRequest

SYMBOL_STORE = os.environ.get("IR_SYMBOLS_DIR", "/symbols")


def _key_from_context(ctx):
    """The store key for a capture's kernel.

    Prefers the build-id: it identifies a kernel build across distributions, which is what
    debuginfod resolves against. Falls back to distro + release when the collector could
    not read the ELF notes.
    """
    if not isinstance(ctx, dict):
        return ""
    if ctx.get("symbol_key"):
        return str(ctx["symbol_key"])
    if ctx.get("build_id"):
        return str(ctx["build_id"])
    release = ctx.get("kernel_release") or ctx.get("kernel") or ""
    distro = (ctx.get("os_release") or {}).get("ID", "linux")
    return f"{distro}-{release}" if release else ""


def find_isf(capture):
    """Path to the ISF for this capture's kernel, or "" when the enclave does not have it.

    Several candidate names are tried because the key recorded at collection and the name
    the table was acquired under do not always agree — a build-id from the endpoint, a
    distro-qualified name from the acquisition machine, or a bare kernel release read out
    of the image itself all describe the same kernel. Matching on only one of them means
    silently analyzing at reduced depth while a usable table sits in the store.
    """
    ctx = capture.symbol_context or {}
    release = ctx.get("kernel_release") or ctx.get("kernel") or ""
    distro = (ctx.get("os_release") or {}).get("ID", "")

    candidates = [
        _key_from_context(ctx),
        ctx.get("build_id", ""),
        f"{distro}-{release}" if distro and release else "",
        release,
    ]
    for key in [c for c in candidates if c]:
        for name in (f"{key}.json", f"{key}.json.xz"):
            path = os.path.join(SYMBOL_STORE, name)
            if os.path.isfile(path):
                return path
        # Volatility also accepts a directory of tables; a per-kernel subdirectory is valid.
        sub = os.path.join(SYMBOL_STORE, key)
        if os.path.isdir(sub):
            return sub

    # Last resort: a table whose filename ends with this kernel release. The release is
    # the discriminator that actually has to match — a prefix like the distro name does not.
    if release:
        try:
            for name in sorted(os.listdir(SYMBOL_STORE)):
                if name.endswith(f"{release}.json"):
                    return os.path.join(SYMBOL_STORE, name)
        except OSError:
            pass
    return ""


def request_symbols(capture):
    """Record that this kernel's ISF is missing, so an administrator can acquire it.

    Idempotent per kernel: many captures from one fleet share a build, and an admin should
    see one request with a waiting count, not one per capture.
    """
    ctx = capture.symbol_context or {}
    key = _key_from_context(ctx)
    if not key:
        return None

    now = timezone.now()
    req, created = SymbolRequest.objects.get_or_create(
        symbol_key=key,
        defaults={
            "kernel_release": ctx.get("kernel_release") or ctx.get("kernel", ""),
            "arch": ctx.get("arch", ""),
            "banner": ctx.get("banner", ""),
            "build_id": ctx.get("build_id", ""),
            "os_release": ctx.get("os_release", {}),
            "first_needed_at": now,
            "status": "needed",
        },
    )
    if not created and req.status == "fulfilled" and not find_isf(capture):
        # The store lost it, or the record was optimistic. Ask again rather than keep
        # reporting a capability the enclave does not currently have.
        req.status = "needed"
        req.fulfilled_at = None

    req.waiting_captures = _waiting_count(key)
    req.save()
    return req


def _waiting_count(key):
    from .models import MemoryCapture

    total = 0
    for cap in MemoryCapture.objects.exclude(retention_status="purged").only(
        "id", "symbol_context"
    ):
        if _key_from_context(cap.symbol_context) == key:
            total += 1
    return total


def mark_fulfilled(key, isf_path):
    """Called when an ISF lands in the store, so the request stops being outstanding."""
    req = SymbolRequest.objects.filter(symbol_key=key).first()
    if not req:
        return None
    digest = hashlib.sha256()
    try:
        with open(isf_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return req
    req.status = "fulfilled"
    req.fulfilled_at = timezone.now()
    req.isf_sha256 = digest.hexdigest()
    req.save()
    return req


def outstanding():
    """Requests an administrator still has to act on."""
    return SymbolRequest.objects.filter(status="needed")


def requisites_export():
    """The requisites an administrator carries to an internet-connected machine.

    Deliberately contains only kernel identity — no evidence, no hostnames, no case
    context. What leaves the enclave to enable symbol acquisition is the minimum that
    identifies a kernel build.
    """
    return {
        "generated_at": timezone.now().isoformat(),
        "requests": [
            {
                "symbol_key": r.symbol_key,
                "kernel_release": r.kernel_release,
                "arch": r.arch,
                "banner": r.banner,
                "build_id": r.build_id,
                "os_release": r.os_release,
                "waiting_captures": r.waiting_captures,
                "first_needed_at": r.first_needed_at,
            }
            for r in outstanding()
        ],
    }

import threading
import time

# In-process, in-memory staging for KeePass import previews. Replaces the
# instance/vault_import_<token>.json plaintext file that used to hold
# decrypted passwords/notes/custom fields between the upload and confirm
# steps (ADR-004 "Future implementations should prefer encrypted or
# non-persistent temporary state" — this is the non-persistent option).
#
# Lives only in this process's memory: a restart loses any in-progress
# import (the admin re-uploads the .kdbx), but nothing sensitive is ever
# written to disk or logged.

_lock = threading.Lock()
_staging = {}
_TTL_SECONDS = 30 * 60


def _purge_expired_locked():
    """Drop entries older than _TTL_SECONDS. Caller must hold _lock.
    Lazy: this only runs when store()/retrieve() are called, not on a
    timer — an expired entry's memory is reclaimed on the next staging
    operation (or when the process exits), not at the instant it turns
    stale."""
    now = time.time()
    expired = [
        token
        for token, entry in _staging.items()
        if now - entry["created_at"] > _TTL_SECONDS
    ]
    for token in expired:
        del _staging[token]


def store(token, data):
    with _lock:
        _purge_expired_locked()
        _staging[token] = {"data": data, "created_at": time.time()}


def retrieve(token):
    """Returns the staged data, or None if the token is unknown or has
    expired (expired is treated identically to never having existed)."""
    with _lock:
        _purge_expired_locked()
        entry = _staging.get(token)
        return entry["data"] if entry is not None else None


def discard(token):
    with _lock:
        _staging.pop(token, None)

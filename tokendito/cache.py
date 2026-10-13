# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Credential cache backed by the OS keychain, with a private file fallback.

Values are plain JSON-serialisable dicts. The cache never logs stored values; only
cache keys (``<backend>:<profile>``) are ever written to the logs.
"""

import hashlib
import json
import logging
import os
import re
import sys
import tempfile

import keyring
from keyring.backends import fail as keyring_fail
from keyring.backends import null as keyring_null
from keyring.errors import KeyringError
from keyring.errors import PasswordDeleteError
from platformdirs import user_cache_dir
from tokendito import __title__

logger = logging.getLogger(__name__)

# Windows Credential Manager limits a credential blob to 2560 bytes, and keyring stores
# the value as UTF-16. JSON output is ASCII, so 1000 characters is ~2000 bytes per chunk.
CHUNK_SIZE = 1000
MANIFEST_VERSION = 1
STORES = ("keyring", "file", "none")
DEFAULT_REFRESH_SKEW = 300
TRUE_VALUES = ("1", "true", "yes", "on")
KEYRING_ERRORS = (KeyringError, RuntimeError, OSError)


def cache_key(backend, profile):
    """Build the cache key for a backend and profile.

    :param backend: backend name, e.g. "aws"
    :param profile: tokendito profile name
    :return: cache key string "<backend>:<profile>"
    """
    return f"{backend}:{profile}"


def _loads_dict(text):
    """Deserialise a JSON object, returning None if it is invalid or not a dict."""
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    return value


def _to_bool(value):
    """Convert a config value (bool or string) into a boolean."""
    if isinstance(value, str):
        return value.strip().lower() in TRUE_VALUES
    return bool(value)


class NullStore:
    """A store that never persists anything."""

    name = "none"

    def get(self, key):
        """Return None, as nothing is ever stored."""
        return None

    def set(self, key, value):
        """Discard the value."""
        return None

    def delete(self, key):
        """Do nothing."""
        return None


class FileStore:
    """Store each entry as a private JSON file under the user cache directory."""

    name = "file"

    def __init__(self, cache_dir=None):
        """Initialise the store.

        :param cache_dir: directory to store entries in, defaults to the user cache dir.
        """
        self.cache_dir = cache_dir or user_cache_dir(__title__)

    def path(self, key):
        """Return the file path used for a key."""
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        return os.path.join(self.cache_dir, f"{safe}-{digest}.json")

    def _ensure_dir(self):
        os.makedirs(self.cache_dir, mode=0o700, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.cache_dir, 0o700)

    def get(self, key):
        """Return the stored dict for a key, or None if it is missing or unreadable."""
        try:
            with open(self.path(key), encoding="utf-8") as file:
                return _loads_dict(file.read())
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError) as err:
            logger.debug(f"Could not read cache entry '{key}': {err}")
            return None

    def set(self, key, value):
        """Atomically write a dict for a key with 0600 permissions."""
        data = json.dumps(value)
        self._ensure_dir()
        fd, tmp = tempfile.mkstemp(dir=self.cache_dir, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            if os.name == "posix":
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path(key))
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    def delete(self, key):
        """Remove the entry for a key, if present."""
        try:
            os.remove(self.path(key))
        except FileNotFoundError:
            pass
        except OSError as err:
            logger.warning(f"Could not delete cache entry '{key}': {err}")


def keyring_is_usable(backend=None):
    """Check whether a keyring backend can actually store secrets.

    :param backend: keyring backend, defaults to the active keyring.
    :return: True if the backend is usable, False otherwise.
    """
    try:
        backend = backend or keyring.get_keyring()
    except KEYRING_ERRORS:
        return False
    if isinstance(backend, (keyring_fail.Keyring, keyring_null.Keyring)):
        return False
    # A chainer with no viable backends behaves like the fail keyring.
    return getattr(backend, "backends", None) != []


class KeyringStore:
    """Store entries in the OS keychain, chunked to respect backend size limits.

    The entry ``<key>`` holds a small JSON manifest, and the serialised value is split
    across ``<key>#0`` .. ``<key>#n-1``. If no usable keyring is available, or the keyring
    fails at runtime, the store falls back to a ``FileStore``.
    """

    name = "keyring"

    def __init__(self, service_name=__title__, cache_dir=None):
        """Initialise the store.

        :param service_name: keyring service name entries are stored under.
        :param cache_dir: directory for the file fallback.
        """
        self.service_name = service_name
        self.cache_dir = cache_dir
        self.fallback = None
        self.backend = None
        try:
            self.backend = keyring.get_keyring()
        except KEYRING_ERRORS as err:
            logger.debug(f"Could not load keyring: {err}")
        if not keyring_is_usable(self.backend):
            self._use_fallback("no usable OS keyring backend was found")

    def _use_fallback(self, reason):
        if self.fallback is None:
            self.fallback = FileStore(self.cache_dir)
            logger.warning(
                f"Credential cache: {reason}, falling back to file store in "
                f"{self.fallback.cache_dir}"
            )
        return self.fallback

    def _call(self, method, key, *args):
        """Run an operation on the keyring, or on the file fallback if needed."""
        if self.fallback is None:
            try:
                return getattr(self, f"_keyring_{method}")(key, *args)
            except KEYRING_ERRORS as err:
                self._use_fallback(f"keyring error ({type(err).__name__})")
        return getattr(self.fallback, method)(key, *args)

    def get(self, key):
        """Return the stored dict for a key, or None if it is missing or corrupt."""
        return self._call("get", key)

    def set(self, key, value):
        """Store a dict for a key."""
        return self._call("set", key, value)

    def delete(self, key):
        """Remove the entry for a key, if present."""
        return self._call("delete", key)

    def _chunk_count(self, key):
        manifest = _loads_dict(self.backend.get_password(self.service_name, key))
        if manifest is None:
            return None
        chunks = manifest.get("chunks")
        if not isinstance(chunks, int) or isinstance(chunks, bool) or chunks < 0:
            return None
        return chunks

    def _keyring_get(self, key):
        chunks = self._chunk_count(key)
        if chunks is None:
            return None
        parts = []
        for index in range(chunks):
            part = self.backend.get_password(self.service_name, f"{key}#{index}")
            if part is None:
                logger.debug(f"Cache entry '{key}' is missing chunk {index}")
                return None
            parts.append(part)
        return _loads_dict("".join(parts))

    def _keyring_set(self, key, value):
        data = json.dumps(value)
        old_chunks = self._chunk_count(key) or 0
        parts = [data[i : i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
        for index, part in enumerate(parts):
            self.backend.set_password(self.service_name, f"{key}#{index}", part)
        manifest = {"version": MANIFEST_VERSION, "chunks": len(parts)}
        self.backend.set_password(self.service_name, key, json.dumps(manifest))
        self._delete_chunks(key, len(parts), old_chunks)

    def _keyring_delete(self, key):
        chunks = self._chunk_count(key) or 0
        self._delete_password(key)
        self._delete_chunks(key, 0, chunks)

    def _delete_chunks(self, key, start, end):
        for index in range(start, end):
            self._delete_password(f"{key}#{index}")

    def _delete_password(self, username):
        try:
            self.backend.delete_password(self.service_name, username)
        except PasswordDeleteError:
            pass


class CredentialCache:
    """Cache of JSON-serialisable credential dicts, keyed by ``cache_key()``."""

    def __init__(self, store="keyring", service_name=__title__, cache_dir=None):
        """Initialise the cache.

        :param store: one of "keyring", "file" or "none".
        :param service_name: keyring service name.
        :param cache_dir: directory for the file store (and keyring fallback).
        """
        self.service_name = service_name
        self.store = self._make_store(store, service_name, cache_dir)
        self.enabled = store != "none"
        self.refresh_skew = DEFAULT_REFRESH_SKEW

    @staticmethod
    def _make_store(store, service_name, cache_dir):
        if store == "keyring":
            return KeyringStore(service_name=service_name, cache_dir=cache_dir)
        if store == "file":
            return FileStore(cache_dir)
        if store == "none":
            return NullStore()
        logger.error(f"Invalid cache store '{store}', must be one of: {', '.join(STORES)}")
        sys.exit(1)

    @classmethod
    def from_config(cls, config):
        """Create a cache from the ``cache`` section of a Config object.

        Missing sections or keys use the defaults. A disabled cache uses ``NullStore``.
        ``refresh_skew`` (seconds) is exposed as an attribute for callers.

        :param config: Config object
        :return: CredentialCache
        """
        section = getattr(config, "cache", None) or {}
        enabled = _to_bool(section.get("enabled", False))
        store = section.get("store") or "keyring"
        service_name = section.get("service_name") or __title__
        cache = cls(store=store if enabled else "none", service_name=service_name)
        try:
            cache.refresh_skew = int(section.get("refresh_skew", DEFAULT_REFRESH_SKEW))
        except (TypeError, ValueError):
            logger.warning(f"Invalid cache refresh_skew, using {DEFAULT_REFRESH_SKEW}")
        return cache

    def get(self, key):
        """Return the cached dict for a key, or None if missing or unreadable."""
        try:
            value = self.store.get(key)
        except (TypeError, ValueError, OSError) as err:
            logger.debug(f"Could not read cache entry '{key}': {type(err).__name__}")
            return None
        logger.debug(f"Cache {'hit' if value is not None else 'miss'} for '{key}'")
        return value

    def set(self, key, value):
        """Store a JSON-serialisable dict for a key."""
        if not isinstance(value, dict):
            raise TypeError(f"Cache values must be dicts, got {type(value).__name__}")
        self.store.set(key, value)
        logger.debug(f"Cached credentials for '{key}' in {self.store.name} store")

    def delete(self, key):
        """Remove the cached entry for a key, if present."""
        self.store.delete(key)
        logger.debug(f"Removed cache entry '{key}'")

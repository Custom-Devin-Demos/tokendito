# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests for the credential cache module."""

import json
import os
import stat
from types import SimpleNamespace

import keyring
from keyring.backend import KeyringBackend
from keyring.backends import fail as keyring_fail
from keyring.backends import null as keyring_null
from keyring.errors import KeyringError
from keyring.errors import NoKeyringError
from keyring.errors import PasswordDeleteError
import pytest

WINDOWS_BLOB_LIMIT = 2560


class MemoryKeyring(KeyringBackend):
    """In-memory keyring that enforces the Windows Credential Manager blob size limit."""

    priority = 1

    def __init__(self):
        """Initialise the in-memory store."""
        super().__init__()
        self.store = {}

    def get_password(self, service, username):
        """Return a stored password."""
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        """Store a password, rejecting values over the Windows blob limit."""
        if len(password.encode("utf-16-le")) > WINDOWS_BLOB_LIMIT:
            raise KeyringError("blob too large")
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        """Delete a stored password."""
        if (service, username) not in self.store:
            raise PasswordDeleteError("not found")
        del self.store[(service, username)]


class BrokenKeyring(MemoryKeyring):
    """Keyring that fails at runtime, e.g. a locked keychain."""

    def set_password(self, service, username, password):
        """Fail to store a password."""
        raise KeyringError("locked")


@pytest.fixture
def fake_keyring():
    """Install an in-memory keyring so tests never touch the real OS keychain."""
    original = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(original)


@pytest.fixture
def set_keyring():
    """Install an arbitrary keyring backend, restoring the original afterwards."""
    original = keyring.get_keyring()
    yield keyring.set_keyring
    keyring.set_keyring(original)


def big_value(size=6000):
    """Return a dict whose JSON form is larger than one keyring chunk."""
    return {"backend": "aws", "data": {"SessionToken": "x" * size}, "expiration": None}


def test_cache_key():
    """Test cache key format."""
    from tokendito import cache

    assert cache.cache_key("aws", "default") == "aws:default"


def test_keyring_roundtrip(fake_keyring, tmp_path):
    """Test storing and retrieving a small value from the keyring."""
    from tokendito import cache

    store = cache.KeyringStore(service_name="pytest", cache_dir=str(tmp_path))
    store.set("aws:default", {"a": 1})

    assert store.fallback is None
    assert store.get("aws:default") == {"a": 1}
    assert json.loads(fake_keyring.store[("pytest", "aws:default")])["chunks"] == 1
    assert list(tmp_path.iterdir()) == []


def test_keyring_chunking(fake_keyring, tmp_path):
    """Test large values are chunked under the Windows limit and stale chunks removed."""
    from tokendito import cache

    store = cache.KeyringStore(service_name="pytest", cache_dir=str(tmp_path))
    value = big_value()
    store.set("aws:big", value)

    manifest = json.loads(fake_keyring.store[("pytest", "aws:big")])
    assert manifest["chunks"] > 1
    assert store.fallback is None
    assert store.get("aws:big") == value

    store.set("aws:big", {"small": True})
    assert store.get("aws:big") == {"small": True}
    assert set(fake_keyring.store) == {("pytest", "aws:big"), ("pytest", "aws:big#0")}


def test_keyring_delete(fake_keyring, tmp_path):
    """Test deleting removes the manifest and every chunk."""
    from tokendito import cache

    store = cache.KeyringStore(service_name="pytest", cache_dir=str(tmp_path))
    store.set("aws:big", big_value())
    store.set("aws:other", {"keep": 1})
    store.delete("aws:big")
    store.delete("aws:missing")

    assert store.get("aws:big") is None
    assert set(fake_keyring.store) == {("pytest", "aws:other"), ("pytest", "aws:other#0")}


@pytest.mark.parametrize(
    "entries",
    [
        {"k": "not json"},
        {"k": "[1, 2]"},
        {"k": '{"chunks": "two"}'},
        {"k": '{"chunks": true}'},
        {"k": '{"chunks": -1}'},
        {"k": '{"chunks": 2}', "k#0": '{"a": '},
        {"k": '{"chunks": 1}', "k#0": '{"a": '},
        {"k": '{"chunks": 1}', "k#0": '"string"'},
    ],
)
def test_keyring_corrupt(fake_keyring, tmp_path, entries):
    """Test corrupt or incomplete keyring entries return None."""
    from tokendito import cache

    for username, password in entries.items():
        fake_keyring.store[("pytest", username)] = password

    store = cache.KeyringStore(service_name="pytest", cache_dir=str(tmp_path))
    assert store.get("k") is None
    assert cache.CredentialCache(store="keyring", service_name="pytest").get("k") is None


@pytest.mark.parametrize("backend", [keyring_fail.Keyring, keyring_null.Keyring])
def test_keyring_unusable_fallback(set_keyring, tmp_path, caplog, backend):
    """Test fail/null keyrings fall back to the file store with a warning."""
    from tokendito import cache

    set_keyring(backend())
    store = cache.KeyringStore(service_name="pytest", cache_dir=str(tmp_path))
    store.set("aws:default", big_value())

    assert isinstance(store.fallback, cache.FileStore)
    assert "falling back to file store" in caplog.text
    assert store.get("aws:default") == big_value()
    assert len(list(tmp_path.glob("*.json"))) == 1
    store.delete("aws:default")
    assert store.get("aws:default") is None


def test_keyring_get_keyring_error(mocker, tmp_path, caplog):
    """Test an error loading the keyring falls back to the file store."""
    from tokendito import cache

    mocker.patch("keyring.get_keyring", side_effect=NoKeyringError("none"))
    store = cache.KeyringStore(service_name="pytest", cache_dir=str(tmp_path))

    assert isinstance(store.fallback, cache.FileStore)
    assert "falling back" in caplog.text


def test_keyring_runtime_error_fallback(set_keyring, tmp_path, caplog):
    """Test a keyring that fails at runtime falls back to the file store."""
    from tokendito import cache

    set_keyring(BrokenKeyring())
    store = cache.KeyringStore(service_name="pytest", cache_dir=str(tmp_path))
    assert store.fallback is None

    store.set("aws:default", {"a": 1})
    assert isinstance(store.fallback, cache.FileStore)
    assert "keyring error (KeyringError)" in caplog.text
    assert store.get("aws:default") == {"a": 1}


def test_keyring_is_usable(fake_keyring):
    """Test keyring usability detection."""
    from tokendito import cache

    assert cache.keyring_is_usable() is True
    assert cache.keyring_is_usable(keyring_fail.Keyring()) is False
    assert cache.keyring_is_usable(keyring_null.Keyring()) is False
    assert cache.keyring_is_usable(SimpleNamespace(backends=[])) is False
    assert cache.keyring_is_usable(SimpleNamespace(backends=[fake_keyring])) is True


def test_file_store_roundtrip(tmp_path):
    """Test file store set/get/delete and filename safety."""
    from tokendito import cache

    store = cache.FileStore(str(tmp_path / "cache"))
    assert store.get("aws:default") is None

    store.set("aws:default", {"a": 1})
    store.set("aws:default", {"a": 2})
    store.set("aws/default", {"b": 1})

    assert store.get("aws:default") == {"a": 2}
    assert store.get("aws/default") == {"b": 1}
    names = sorted(os.listdir(tmp_path / "cache"))
    assert len(names) == 2
    assert all(":" not in name and "/" not in name for name in names)

    store.delete("aws:default")
    store.delete("aws:default")
    assert store.get("aws:default") is None
    assert store.get("aws/default") == {"b": 1}


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_file_store_permissions(tmp_path):
    """Test the cache directory is 0700 and entries are 0600."""
    from tokendito import cache

    cache_dir = tmp_path / "cache"
    store = cache.FileStore(str(cache_dir))
    store.set("aws:default", {"a": 1})

    assert stat.S_IMODE(os.stat(cache_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(store.path("aws:default")).st_mode) == 0o600


@pytest.mark.parametrize("content", [b"not json", b"[1]", b"\xff\xfe\x00"])
def test_file_store_corrupt(tmp_path, content):
    """Test corrupt files return None."""
    from tokendito import cache

    store = cache.FileStore(str(tmp_path))
    with open(store.path("k"), "wb") as file:
        file.write(content)

    assert store.get("k") is None


def test_file_store_read_error(tmp_path, mocker):
    """Test unreadable files return None."""
    from tokendito import cache

    store = cache.FileStore(str(tmp_path))
    mocker.patch("builtins.open", side_effect=PermissionError("denied"))
    assert store.get("k") is None


def test_file_store_atomic_write_failure(tmp_path, mocker):
    """Test a failed write leaves neither a temp file nor a partial entry."""
    from tokendito import cache

    store = cache.FileStore(str(tmp_path))
    store.set("k", {"old": 1})
    mocker.patch("os.replace", side_effect=OSError("boom"))

    with pytest.raises(OSError):
        store.set("k", {"new": 1})
    assert os.listdir(tmp_path) == [os.path.basename(store.path("k"))]
    assert store.get("k") == {"old": 1}


def test_file_store_delete_error(tmp_path, mocker, caplog):
    """Test delete errors are logged, not raised."""
    from tokendito import cache

    store = cache.FileStore(str(tmp_path))
    mocker.patch("os.remove", side_effect=PermissionError("denied"))
    store.delete("k")
    assert "Could not delete cache entry 'k'" in caplog.text


def test_file_store_default_dir(mocker):
    """Test the file store defaults to the platformdirs user cache dir."""
    from tokendito import cache

    mocker.patch("tokendito.cache.user_cache_dir", return_value="/pytest/cache")
    assert cache.FileStore().cache_dir == "/pytest/cache"


def test_null_store():
    """Test the null store never stores anything."""
    from tokendito import cache

    cred_cache = cache.CredentialCache(store="none")
    cred_cache.set("k", {"a": 1})
    assert cred_cache.get("k") is None
    cred_cache.delete("k")
    assert cred_cache.enabled is False


def test_credential_cache(tmp_path, fake_keyring):
    """Test the CredentialCache wrapper for each store."""
    from tokendito import cache

    file_cache = cache.CredentialCache(store="file", cache_dir=str(tmp_path))
    assert isinstance(file_cache.store, cache.FileStore)
    file_cache.set("aws:p", {"a": 1})
    assert file_cache.get("aws:p") == {"a": 1}
    file_cache.delete("aws:p")
    assert file_cache.get("aws:p") is None

    kr_cache = cache.CredentialCache(service_name="pytest")
    assert isinstance(kr_cache.store, cache.KeyringStore)
    kr_cache.set("aws:p", big_value())
    assert kr_cache.get("aws:p") == big_value()
    assert kr_cache.enabled is True

    with pytest.raises(TypeError):
        kr_cache.set("aws:p", ["not", "a", "dict"])


def test_credential_cache_get_error(mocker):
    """Test unexpected store errors on read return None."""
    from tokendito import cache

    cred_cache = cache.CredentialCache(store="none")
    mocker.patch.object(cred_cache.store, "get", side_effect=ValueError("bad"))
    assert cred_cache.get("k") is None


def test_credential_cache_invalid_store():
    """Test an invalid store name exits."""
    from tokendito import cache

    with pytest.raises(SystemExit) as err:
        cache.CredentialCache(store="bogus")
    assert err.value.code == 1


def test_from_config_without_section():
    """Test from_config works when the config has no cache section."""
    from tokendito import cache
    from tokendito.config import Config

    for config in (SimpleNamespace(), Config()):
        cred_cache = cache.CredentialCache.from_config(config)
        assert isinstance(cred_cache.store, cache.NullStore)
        assert cred_cache.enabled is False
        assert cred_cache.refresh_skew == 300


@pytest.mark.parametrize(
    "section, store_type, skew",
    [
        ({"enabled": True, "store": "file"}, "FileStore", 300),
        ({"enabled": "true", "store": "keyring", "refresh_skew": "60"}, "KeyringStore", 60),
        ({"enabled": True, "store": "none", "refresh_skew": 10}, "NullStore", 10),
        ({"enabled": "false", "store": "file"}, "NullStore", 300),
        ({"enabled": True, "refresh_skew": "soon"}, "KeyringStore", 300),
    ],
)
def test_from_config_with_section(fake_keyring, section, store_type, skew):
    """Test from_config honours the cache section."""
    from tokendito import cache

    config = SimpleNamespace(cache=dict(section, service_name="pytest"))
    cred_cache = cache.CredentialCache.from_config(config)

    assert type(cred_cache.store).__name__ == store_type
    assert cred_cache.service_name == "pytest"
    assert cred_cache.refresh_skew == skew

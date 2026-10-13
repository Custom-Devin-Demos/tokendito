# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests for the tokendito.backends package."""

from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json

import pytest


@pytest.fixture
def sts_response():
    """Return an AssumeRoleWithSAML-like response."""
    return {
        "Credentials": {
            "AccessKeyId": "ASIAPYTEST",
            "SecretAccessKey": "pytest_secret_access_key",
            "SessionToken": "pytest_session_token",
            "Expiration": datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        }
    }


@pytest.fixture
def aws_config():
    """Return a Config object for the AWS backend."""
    from tokendito.config import Config

    pytest_config = Config()
    pytest_config.okta["org"] = "https://acme.okta.org"
    pytest_config.aws["profile"] = "pytest_profile"
    return pytest_config


def test_available_backends():
    """Test that only importable backends are listed."""
    from tokendito import backends

    available = backends.available_backends()
    assert "aws" in available
    assert available == sorted(available)
    for name in available:
        assert backends.get_backend(name).name == name


def test_get_backend_aws():
    """Test retrieving the AWS backend."""
    from tokendito import backends
    from tokendito.backends.aws import AWSBackend
    from tokendito.backends.base import CredentialBackend

    backend = backends.get_backend("aws")
    assert backend is AWSBackend
    assert issubclass(backend, CredentialBackend)
    assert backend.config_section == "aws"


def test_get_backend_unknown(caplog):
    """Test that unknown backends exit with an error listing available backends."""
    from tokendito import backends

    with pytest.raises(SystemExit) as err:
        backends.get_backend("pytest_unknown")
    assert err.value.code == 1
    assert "Backend 'pytest_unknown' is not available" in caplog.text
    assert "aws" in caplog.text


def test_get_backend_not_importable(mocker, caplog):
    """Test that a built-in backend whose module cannot be imported is unavailable."""
    from tokendito import backends

    mocker.patch.dict(backends._BUILTIN, {"pytest_missing": "tokendito.backends.pytest_missing"})
    assert "pytest_missing" not in backends.available_backends()
    with pytest.raises(SystemExit) as err:
        backends.get_backend("pytest_missing")
    assert err.value.code == 1
    assert "pytest_missing" in caplog.text


def test_register_backend(mocker):
    """Test the register_backend decorator."""
    from tokendito import backends
    from tokendito.backends.base import CredentialBackend
    from tokendito.backends.base import Credentials

    mocker.patch.dict(backends._REGISTRY)

    @backends.register_backend("pytest")
    class PytestBackend(CredentialBackend):
        config_section = "user"

        def validate(self):
            return []

        def authenticate(self):
            return Credentials(backend=self.name, profile="p", data={"k": "v"})

        def write(self, credentials):
            return None

    assert PytestBackend.name == "pytest"
    assert backends.get_backend("pytest") is PytestBackend
    assert "pytest" in backends.available_backends()

    backend = PytestBackend(config=None)
    creds = backend.authenticate()
    assert backend.credential_process_output(creds) == creds.to_dict()
    assert backend.display(creds) is None


def test_credential_backend_is_abstract():
    """Test that CredentialBackend cannot be instantiated."""
    from tokendito.backends.base import CredentialBackend

    with pytest.raises(TypeError):
        CredentialBackend(config=None)


def test_add_backend_arguments(mocker):
    """Test that backend modules can add their own arguments."""
    import argparse
    import types

    from tokendito import backends

    def add_arguments(parser):
        group = parser.add_argument_group("pytest")
        group.add_argument("--cache-pytest-hook", dest="cache_pytest_hook")

    module = types.SimpleNamespace(add_arguments=add_arguments)
    mocker.patch.dict(backends._BUILTIN, {"pytest_hook": "pytest_hook_module"})
    real_import = backends._import_backend_module
    mocker.patch(
        "tokendito.backends._import_backend_module",
        side_effect=lambda name: module if name == "pytest_hook" else real_import(name),
    )

    parser = argparse.ArgumentParser()
    called = backends.add_backend_arguments(parser)
    assert "pytest_hook" in called
    assert parser.parse_args(["--cache-pytest-hook", "pool"]).cache_pytest_hook == "pool"


def test_credentials_round_trip():
    """Test Credentials serialisation."""
    from tokendito.backends.base import Credentials

    expiration = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    creds = Credentials(backend="aws", profile="default", data={"a": 1}, expiration=expiration)
    as_dict = creds.to_dict()
    assert as_dict["expiration"] == "2030-01-02T03:04:05Z"
    assert json.loads(json.dumps(as_dict)) == as_dict

    restored = Credentials.from_dict(as_dict)
    assert restored == creds
    assert restored.expiration.tzinfo is not None

    no_expiry = Credentials(backend="gcp", profile="p", data={})
    assert no_expiry.to_dict()["expiration"] is None
    assert Credentials.from_dict(no_expiry.to_dict()) == no_expiry


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2030-01-02T03:04:05Z", datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        ("2030-01-02T03:04:05+00:00", datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        ("2030-01-02T05:04:05+02:00", datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        (datetime(2030, 1, 2, 3, 4, 5), datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        (None, None),
        ("", None),
    ],
)
def test_parse_expiration(value, expected):
    """Test expiration parsing and normalisation to UTC."""
    from tokendito.backends.base import parse_expiration

    assert parse_expiration(value) == expected


def test_credentials_is_expired():
    """Test the expiration check, including skew."""
    from tokendito.backends.base import Credentials

    now = datetime.now(timezone.utc)
    future = Credentials("aws", "p", {}, expiration=now + timedelta(seconds=600))
    past = Credentials("aws", "p", {}, expiration=now - timedelta(seconds=1))
    never = Credentials("aws", "p", {})

    assert future.is_expired() is False
    assert future.is_expired(skew_seconds=300) is False
    assert future.is_expired(skew_seconds=900) is True
    assert past.is_expired() is True
    assert never.is_expired(skew_seconds=10**6) is False


def test_aws_backend_authenticate(mocker, aws_config, sts_response):
    """Test the AWS backend authentication flow."""
    from tokendito.backends.aws import AWSBackend

    aws_config.okta["tile"] = "https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456"
    m_auth = mocker.patch("tokendito.aws.authenticate_to_roles", return_value="tiles")
    mocker.patch("tokendito.aws.select_assumeable_role", return_value=(sts_response, "role"))
    mocker.patch("tokendito.aws.assert_credentials", return_value={"Arn": "arn"})
    m_profile = mocker.patch("tokendito.user.set_profile_name")
    m_discover = mocker.patch("tokendito.user.discover_tiles")

    backend = AWSBackend(aws_config)
    assert backend.validate() == []
    creds = backend.authenticate()

    m_discover.assert_not_called()
    m_auth.assert_called_once_with(
        aws_config, ("https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456", "")
    )
    m_profile.assert_called_once_with(aws_config, "role")
    assert creds.backend == "aws"
    assert creds.profile == "default"
    assert creds.expiration == datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert creds.data["AccessKeyId"] == "ASIAPYTEST"
    assert creds.data["aws_profile"] == "pytest_profile"
    assert creds.data["role_name"] == "role"
    assert json.dumps(creds.to_dict())


def test_aws_backend_authenticate_discovers_tiles(mocker, aws_config, sts_response):
    """Test that tiles are discovered when no tile is configured."""
    from tokendito.backends.aws import AWSBackend

    m_discover = mocker.patch("tokendito.user.discover_tiles", return_value=("url", "label"))
    m_auth = mocker.patch("tokendito.aws.authenticate_to_roles", return_value="tiles")
    mocker.patch("tokendito.aws.select_assumeable_role", return_value=(sts_response, "role"))
    mocker.patch("tokendito.aws.assert_credentials", return_value={"UserId": "id"})

    AWSBackend(aws_config).authenticate()
    m_discover.assert_called_once_with("https://acme.okta.org")
    m_auth.assert_called_once_with(aws_config, ("url", "label"))


def test_aws_backend_authenticate_invalid_identity(mocker, aws_config, sts_response):
    """Test that an invalid identity exits."""
    from tokendito.backends.aws import AWSBackend

    aws_config.okta["tile"] = ("url", "label")
    mocker.patch("tokendito.aws.authenticate_to_roles", return_value="tiles")
    mocker.patch("tokendito.aws.select_assumeable_role", return_value=(sts_response, "role"))
    mocker.patch("tokendito.aws.assert_credentials", return_value={})

    with pytest.raises(SystemExit) as err:
        AWSBackend(aws_config).authenticate()
    assert err.value.code == 1


def test_aws_backend_invalid_response(aws_config):
    """Test that a response without credentials exits."""
    from tokendito.backends.aws import AWSBackend

    with pytest.raises(SystemExit) as err:
        AWSBackend(aws_config).credentials_from_response({}, "role")
    assert err.value.code == 1


def test_aws_backend_write_and_display(mocker, aws_config, sts_response):
    """Test that write and display reuse the existing user helpers."""
    from tokendito.backends.aws import AWSBackend

    m_write = mocker.patch("tokendito.user.set_local_credentials")
    m_display = mocker.patch("tokendito.user.display_selected_role")

    backend = AWSBackend(aws_config)
    creds = backend.credentials_from_response(sts_response, "role")
    backend.write(creds)
    backend.display(creds)

    m_write.assert_called_once_with(
        response=sts_response,
        role="pytest_profile",
        region=aws_config.aws["region"],
        output=aws_config.aws["output"],
    )
    m_display.assert_called_once_with(profile_name="pytest_profile", role_response=sts_response)

    # Without a configured AWS profile, the stored profile name is used
    aws_config.aws["profile"] = None
    backend.write(creds)
    assert m_write.call_args.kwargs["role"] == "pytest_profile"


def test_aws_backend_write_files(monkeypatch, tmpdir, aws_config, sts_response):
    """Test that credentials are written to the AWS files."""
    import configparser

    from tokendito.backends.aws import AWSBackend
    from tokendito.config import config

    monkeypatch.setitem(config.aws, "shared_credentials_file", str(tmpdir.join("credentials")))
    monkeypatch.setitem(config.aws, "config_file", str(tmpdir.join("config")))

    backend = AWSBackend(aws_config)
    backend.write(backend.credentials_from_response(sts_response, "role"))

    ini = configparser.RawConfigParser()
    ini.read(config.aws["shared_credentials_file"])
    assert ini.get("pytest_profile", "aws_access_key_id") == "ASIAPYTEST"
    assert ini.get("pytest_profile", "aws_session_token") == "pytest_session_token"


def test_aws_backend_credential_process_output(aws_config, sts_response):
    """Test the AWS credential_process v1 output."""
    from tokendito.backends.aws import AWSBackend

    backend = AWSBackend(aws_config)
    creds = backend.credentials_from_response(sts_response, "role")
    assert backend.credential_process_output(creds) == {
        "Version": 1,
        "AccessKeyId": "ASIAPYTEST",
        "SecretAccessKey": "pytest_secret_access_key",
        "SessionToken": "pytest_session_token",
        "Expiration": "2030-01-02T03:04:05Z",
    }

    # Round-trip through a cache-like JSON representation
    from tokendito.backends.base import Credentials

    restored = Credentials.from_dict(json.loads(json.dumps(creds.to_dict())))
    assert backend.credential_process_output(restored) == backend.credential_process_output(creds)

    creds.expiration = None
    assert "Expiration" not in backend.credential_process_output(creds)

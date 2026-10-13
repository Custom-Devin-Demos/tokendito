# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests for the Azure (Entra ID) federated token exchange backend."""

import base64
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json
import logging
import os
import sys
from urllib.parse import parse_qs

import pytest
import requests

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"


def make_jwt(claims):
    """Build an unsigned JWT with the given claims."""

    def encode(data):
        raw = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
        return raw.rstrip("=")

    return f"{encode({'alg': 'RS256', 'kid': 'pytest'})}.{encode(claims)}.c2lnbmF0dXJl"


@pytest.fixture
def okta_jwt():
    """Return an Okta-like access token for Entra ID."""
    return make_jwt(
        {
            "iss": "https://acme.okta.org/oauth2/default",
            "sub": "jane.doe@acme.com",
            "aud": "api://AzureADTokenExchange",
        }
    )


@pytest.fixture
def azure_config(tmpdir):
    """Return a Config object for the Azure backend."""
    from tokendito.config import Config

    pytest_config = Config()
    pytest_config.okta["org"] = "https://acme.okta.org"
    pytest_config.okta["oidc_authorization_server"] = "default"
    pytest_config.user["config_profile"] = "pytest_profile"
    pytest_config.user["config_dir"] = str(tmpdir)
    pytest_config.user["backend"] = "azure"
    pytest_config.azure["tenant_id"] = TENANT
    pytest_config.azure["client_id"] = CLIENT
    return pytest_config


@pytest.fixture
def backend(azure_config):
    """Return an AzureBackend instance."""
    from tokendito.backends.azure import AzureBackend

    return AzureBackend(azure_config)


@pytest.fixture
def mock_oidc(mocker, okta_jwt):
    """Mock okta.get_oidc_tokens."""
    return mocker.patch(
        "tokendito.okta.get_oidc_tokens",
        return_value={"id_token": "pytest_id_token", "access_token": okta_jwt, "expires_in": 3600},
    )


@pytest.fixture
def credentials(okta_jwt):
    """Return Azure Credentials."""
    from tokendito.backends.base import Credentials

    return Credentials(
        backend="azure",
        profile="pytest_profile",
        data={
            "access_token": "pytest_azure_access_token",
            "token_type": "Bearer",
            "tenant_id": TENANT,
            "client_id": CLIENT,
            "federated_token": okta_jwt,
        },
        expiration=datetime(2030, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc),
    )


def test_azure_backend_registered():
    """Test that the Azure backend is available through the registry."""
    from tokendito import backends
    from tokendito.backends.azure import AzureBackend

    assert "azure" in backends.available_backends()
    assert backends.get_backend("azure") is AzureBackend
    assert AzureBackend.name == "azure"
    assert AzureBackend.config_section == "azure"


def test_validate_ok(backend, caplog):
    """Test a valid configuration."""
    with caplog.at_level(logging.WARNING):
        assert backend.validate() == []
    assert "okta_oidc_authorization_server" not in caplog.text


def test_validate_missing(backend, caplog):
    """Test that missing settings are reported."""
    backend.config.azure["tenant_id"] = None
    backend.config.azure["client_id"] = ""
    backend.config.azure["authority_host"] = "http://login.example.com"
    backend.config.okta["oidc_authorization_server"] = None
    with caplog.at_level(logging.WARNING):
        messages = backend.validate()
    assert "azure_tenant_id is not set" in messages
    assert "azure_client_id is not set" in messages
    assert any("https://" in message for message in messages)
    assert len(messages) == 3
    assert "okta_oidc_authorization_server is not set" in caplog.text


def test_validate_merged_into_validate_configuration(backend):
    """Test that backend messages are merged into user.validate_configuration."""
    from tokendito import user

    backend.config.azure["tenant_id"] = None
    assert "azure_tenant_id is not set" in user.validate_configuration(backend.config, backend)


@pytest.mark.parametrize(
    "token, expected",
    [
        (make_jwt({"aud": "x", "sub": "y"}), {"aud": "x", "sub": "y"}),
        ("not-a-jwt", {}),
        ("a.!!!.c", {}),
        (make_jwt(["list"]), {}),
        (None, {}),
    ],
)
def test_decode_jwt_claims(token, expected):
    """Test unverified JWT claim decoding."""
    from tokendito.backends.azure import decode_jwt_claims

    assert decode_jwt_claims(token) == expected


@pytest.mark.parametrize(
    "claims, expected",
    [
        ({"aud": "api://AzureADTokenExchange"}, True),
        ({"aud": ["other", "api://AzureADTokenExchange"]}, True),
        ({"aud": "api://default"}, False),
        ({}, True),
    ],
)
def test_check_audience(claims, expected):
    """Test the audience check."""
    from tokendito.backends.azure import check_audience

    assert check_audience(claims, "api://AzureADTokenExchange") is expected


def test_authenticate(backend, mock_oidc, okta_jwt, requests_mock):
    """Test a successful token exchange."""
    requests_mock.post(
        TOKEN_URL,
        json={"token_type": "Bearer", "expires_in": 3599, "access_token": "pytest_azure_token"},
    )
    before = datetime.now(timezone.utc)
    creds = backend.authenticate()

    mock_oidc.assert_called_once_with(backend.config)
    body = parse_qs(requests_mock.last_request.text)
    assert body == {
        "grant_type": ["client_credentials"],
        "client_id": [CLIENT],
        "scope": ["https://management.azure.com/.default"],
        "client_assertion_type": ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"],
        "client_assertion": [okta_jwt],
    }
    assert creds.backend == "azure"
    assert creds.profile == "pytest_profile"
    assert creds.data == {
        "access_token": "pytest_azure_token",
        "token_type": "Bearer",
        "tenant_id": TENANT,
        "client_id": CLIENT,
        "federated_token": okta_jwt,
    }
    expected = before + timedelta(seconds=3599)
    assert abs((creds.expiration - expected).total_seconds()) < 5


def test_authenticate_custom_authority(backend, mock_oidc, requests_mock):
    """Test a custom authority host and a missing expires_in."""
    backend.config.azure["authority_host"] = "https://login.microsoftonline.us/"
    backend.config.azure["scope"] = "https://graph.microsoft.com/.default"
    url = f"https://login.microsoftonline.us/{TENANT}/oauth2/v2.0/token"
    requests_mock.post(url, json={"access_token": "pytest_azure_token", "expires_in": "bad"})

    creds = backend.authenticate()
    assert requests_mock.last_request.url == url
    assert "graph.microsoft.com" in parse_qs(requests_mock.last_request.text)["scope"][0]
    assert creds.data["token_type"] == "Bearer"
    assert not creds.is_expired(skew_seconds=3000)


def test_authenticate_audience_mismatch(backend, mocker, requests_mock, caplog):
    """Test that a wrong audience is reported, and the id_token used as a fallback."""
    token = make_jwt({"aud": "0oa_okta_client", "iss": "https://acme.okta.org"})
    mocker.patch("tokendito.okta.get_oidc_tokens", return_value={"id_token": token})
    requests_mock.post(TOKEN_URL, json={"access_token": "pytest_azure_token"})

    with caplog.at_level(logging.WARNING):
        creds = backend.authenticate()
    assert creds.data["federated_token"] == token
    assert "using the id_token" in caplog.text
    assert "does not match azure_audience" in caplog.text


def test_authenticate_aadsts70021(backend, mock_oidc, requests_mock, caplog):
    """Test that AADSTS errors are surfaced."""
    requests_mock.post(
        TOKEN_URL,
        status_code=400,
        json={
            "error": "invalid_request",
            "error_description": "AADSTS70021: No matching federated identity record found "
            "for presented assertion.",
            "error_codes": [70021],
            "trace_id": "pytest-trace",
            "correlation_id": "pytest-correlation",
        },
    )
    with pytest.raises(SystemExit) as err, caplog.at_level(logging.ERROR):
        backend.authenticate()
    assert err.value.code == 1
    assert "AADSTS70021: No matching federated identity record" in caplog.text
    assert "issuer, subject and audience" in caplog.text
    assert "pytest-trace" in caplog.text
    assert "pytest-correlation" in caplog.text


@pytest.mark.parametrize(
    "kwargs, text",
    [
        ({"status_code": 400, "json": {"error_codes": [700016], "error": "x"}}, "AADSTS700016"),
        ({"status_code": 500, "text": "Internal error"}, "Internal error"),
        ({"status_code": 200, "json": ["unexpected"]}, "unknown_error"),
        ({"status_code": 200, "json": {"token_type": "Bearer"}}, "unknown_error"),
        ({"exc": requests.exceptions.ConnectionError("boom")}, "boom"),
    ],
)
def test_authenticate_errors(backend, mock_oidc, requests_mock, caplog, kwargs, text):
    """Test error responses from Entra ID."""
    requests_mock.post(TOKEN_URL, **kwargs)
    with pytest.raises(SystemExit) as err, caplog.at_level(logging.ERROR):
        backend.authenticate()
    assert err.value.code == 1
    assert text in caplog.text


def test_write_default_token_file(backend, credentials, okta_jwt, tmpdir, caplog):
    """Test that the federated token is written to the default path with 0600 permissions."""
    with caplog.at_level(logging.INFO):
        backend.write(credentials)

    path = os.path.join(str(tmpdir), "azure", "pytest_profile.jwt")
    assert backend.token_file() == path
    with open(path) as file:
        assert file.read() == okta_jwt
    if sys.platform != "win32":
        assert os.stat(path).st_mode & 0o777 == 0o600

    assert "AZURE_FEDERATED_TOKEN_FILE" in caplog.text
    assert "AZURE_CLIENT_ID" in caplog.text
    assert TENANT in caplog.text
    assert "AZURE_AUTHORITY_HOST" in caplog.text
    assert f"az login --service-principal -u {CLIENT} -t {TENANT}" in caplog.text
    assert f'--federated-token "$(cat {path})"' in caplog.text


def test_write_custom_token_file_overwrites(backend, credentials, okta_jwt, tmpdir):
    """Test a custom token file, replacing an existing world-readable file."""
    path = tmpdir.join("sub", "token.jwt")
    path.write("old token content that is longer", ensure=True)
    os.chmod(str(path), 0o644)
    backend.config.azure["token_file"] = str(path)

    backend.write(credentials)
    assert path.read() == okta_jwt
    if sys.platform != "win32":
        assert os.stat(str(path)).st_mode & 0o777 == 0o600


def test_write_error(backend, credentials, mocker, caplog):
    """Test that write errors exit."""
    mocker.patch("os.open", side_effect=OSError("pytest denied"))
    with pytest.raises(SystemExit) as err:
        backend.write(credentials)
    assert err.value.code == 1
    assert "pytest denied" in caplog.text


@pytest.mark.parametrize(
    "os_name, prefix", [("posix", "export AZURE_CLIENT_ID='"), ("nt", "$env:")]
)
def test_env_export_lines(mocker, os_name, prefix):
    """Test the shell export lines for POSIX shells and PowerShell."""
    from tokendito.backends import azure

    mocker.patch.object(azure.os, "name", os_name)
    lines = azure.env_export_lines({"AZURE_CLIENT_ID": CLIENT})
    assert lines[0].startswith(prefix)
    assert CLIENT in lines[0]


def test_credential_process_output(backend, credentials):
    """Test the az account get-access-token style output."""
    output = backend.credential_process_output(credentials)
    local = credentials.expiration.astimezone()
    assert output == {
        "accessToken": "pytest_azure_access_token",
        "expiresOn": local.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "expires_on": int(credentials.expiration.timestamp()),
        "tokenType": "Bearer",
        "tenant": TENANT,
    }
    assert datetime.strptime(output["expiresOn"], "%Y-%m-%d %H:%M:%S.%f").microsecond == 678901
    assert json.loads(json.dumps(output)) == output


def test_credential_process_output_no_expiration(backend, credentials):
    """Test the output when the expiration is unknown."""
    credentials.expiration = None
    output = backend.credential_process_output(credentials)
    assert "expiresOn" not in output
    assert output["accessToken"] == "pytest_azure_access_token"


def test_display(backend, credentials, capsys, mocker):
    """Test the summary."""
    mocker.patch.dict("tokendito.config.config.user", {"quiet": False})
    backend.display(credentials)
    out = capsys.readouterr().out
    assert TENANT in out
    assert CLIENT in out
    assert "https://management.azure.com/.default" in out
    assert "2030-01-02T03:04:05Z" in out
    assert "pytest_azure_access_token" not in out


def test_credentials_round_trip(credentials):
    """Test that Azure credentials can be cached as JSON."""
    from tokendito.backends.base import Credentials

    restored = Credentials.from_dict(json.loads(json.dumps(credentials.to_dict())))
    assert restored.data == credentials.data
    assert restored.expiration == credentials.expiration.replace(microsecond=0)


def test_cli_arguments():
    """Test the Azure command line arguments."""
    from tokendito import user

    args = user.parse_cli_args(
        [
            "--backend",
            "azure",
            "--azure-tenant-id",
            TENANT,
            "--azure-client-id",
            CLIENT,
            "--azure-scope",
            "https://graph.microsoft.com/.default",
            "--azure-authority-host",
            "https://login.microsoftonline.us",
            "--azure-audience",
            "api://pytest",
            "--azure-token-file",
            "/tmp/pytest.jwt",
        ]
    )
    ret = user.process_arguments(args)
    assert ret.user["backend"] == "azure"
    assert ret.azure == {
        "tenant_id": TENANT,
        "client_id": CLIENT,
        "scope": "https://graph.microsoft.com/.default",
        "authority_host": "https://login.microsoftonline.us",
        "audience": "api://pytest",
        "token_file": "/tmp/pytest.jwt",
    }

    args = user.parse_cli_args([])
    assert args.azure_tenant_id is None
    assert user.process_arguments(args).azure == {}


def test_environment_variables(monkeypatch):
    """Test the TOKENDITO_AZURE_* environment variables."""
    from tokendito import user

    env = dict(
        TOKENDITO_USER_BACKEND="azure",
        TOKENDITO_AZURE_TENANT_ID=TENANT,
        TOKENDITO_AZURE_CLIENT_ID=CLIENT,
        TOKENDITO_AZURE_TOKEN_FILE="/tmp/pytest.jwt",
    )
    monkeypatch.setattr(os, "environ", env)
    ret = user.process_environment()
    assert ret.user["backend"] == "azure"
    assert ret.azure["tenant_id"] == TENANT
    assert ret.azure["client_id"] == CLIENT
    assert ret.azure["token_file"] == "/tmp/pytest.jwt"


def test_ini_file(tmpdir):
    """Test the azure_* ini keys."""
    from tokendito import user

    ini_file = tmpdir.join("tokendito.ini")
    ini_file.write(
        "[default]\n"
        "okta_org = https://acme.okta.org\n"
        "[azure-dev]\n"
        "user_backend = azure\n"
        "okta_oidc_authorization_server = default\n"
        f"azure_tenant_id = {TENANT}\n"
        f"azure_client_id = {CLIENT}\n"
        "azure_scope = https://graph.microsoft.com/.default\n"
    )
    ret = user.process_ini_file(str(ini_file), "azure-dev")
    assert ret.user["backend"] == "azure"
    assert ret.okta["org"] == "https://acme.okta.org"
    assert ret.azure["tenant_id"] == TENANT
    assert ret.azure["client_id"] == CLIENT
    assert ret.azure["scope"] == "https://graph.microsoft.com/.default"


@pytest.fixture
def restore_config():
    """Restore the global Config object after a test."""
    import copy

    from tokendito.config import config

    saved = {section: copy.deepcopy(getattr(config, section)) for section in config.get_sections()}
    yield config
    for section, values in saved.items():
        setattr(config, section, values)


def test_process_args_azure_flow(
    mocker, tmpdir, okta_jwt, requests_mock, monkeypatch, restore_config
):
    """Test the full process_args flow with the Azure backend."""
    from tokendito import user

    config = restore_config
    monkeypatch.setattr(os, "environ", {})
    config.user["quiet"] = False
    mocker.patch("tokendito.okta.access_control")
    mocker.patch(
        "tokendito.okta.get_oidc_tokens",
        return_value={"access_token": okta_jwt, "id_token": None, "expires_in": 3600},
    )
    requests_mock.post(TOKEN_URL, json={"access_token": "pytest_azure_token", "expires_in": 60})
    token_file = tmpdir.join("token.jwt")
    args = [
        "--config-file",
        str(tmpdir.join("missing.ini")),
        "--okta-org",
        "https://acme.okta.org",
        "--username",
        "pytest",
        "--password",
        "pytest_password",
        "--backend",
        "azure",
        "--okta-oidc-authorization-server",
        "default",
        "--azure-tenant-id",
        TENANT,
        "--azure-client-id",
        CLIENT,
        "--azure-token-file",
        str(token_file),
    ]
    user.process_args(user.parse_cli_args(args))
    assert token_file.read() == okta_jwt

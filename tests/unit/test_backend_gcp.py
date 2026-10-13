# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests for the GCP Workload Identity Federation backend."""

import base64
from datetime import datetime
from datetime import timezone
import json
import os
import sys
import urllib.parse

import pytest
import requests

STS_URL = "https://sts.googleapis.com/v1/token"
SA_EMAIL = "pytest@pytest-project.iam.gserviceaccount.com"
IAM_URL = (
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
    f"{SA_EMAIL}:generateAccessToken"
)
AUDIENCE = (
    "//iam.googleapis.com/projects/123456789/locations/global/"
    "workloadIdentityPools/pytest-pool/providers/pytest-provider"
)
SUBJECT_EXP = 1893456000  # 2030-01-01T00:00:00Z


def make_jwt(claims):
    """Build an unsigned JWT with the given claims."""

    def encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{encode({'alg': 'none'})}.{encode(claims)}.signature"


@pytest.fixture
def id_token():
    """Return an Okta-like id_token."""
    return make_jwt({"sub": "pytest", "exp": SUBJECT_EXP})


@pytest.fixture
def gcp_config(tmpdir):
    """Return a Config object for the GCP backend."""
    from tokendito.config import Config

    pytest_config = Config()
    pytest_config.okta["org"] = "https://acme.okta.org"
    pytest_config.user["backend"] = "gcp"
    pytest_config.user["config_profile"] = "pytest"
    pytest_config.user["config_dir"] = str(tmpdir)
    pytest_config.gcp.update(
        project_number="123456789", pool_id="pytest-pool", provider_id="pytest-provider"
    )
    return pytest_config


@pytest.fixture
def backend(gcp_config):
    """Return a GCPBackend instance."""
    from tokendito.backends.gcp import GCPBackend

    return GCPBackend(gcp_config)


@pytest.fixture
def oidc_tokens(mocker, id_token):
    """Mock okta.get_oidc_tokens."""
    tokens = {"id_token": id_token, "access_token": "pytest_okta_access", "expires_in": 3600}
    return mocker.patch("tokendito.okta.get_oidc_tokens", return_value=tokens)


@pytest.fixture
def sts_ok(requests_mock):
    """Mock a successful Google STS token exchange."""
    return requests_mock.post(
        STS_URL,
        json={
            "access_token": "pytest_federated_token",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )


def test_registry():
    """Test that the GCP backend is registered and its arguments are added."""
    from tokendito import backends
    from tokendito.backends.gcp import GCPBackend

    assert backends.get_backend("gcp") is GCPBackend
    assert GCPBackend.name == "gcp"
    assert GCPBackend.config_section == "gcp"
    assert "gcp" in backends.available_backends()


def test_validate_ok(backend):
    """Test a valid configuration."""
    assert backend.validate() == []


def test_validate_missing_keys(backend):
    """Test that the Workload Identity Pool settings are required."""
    for key in ("project_number", "pool_id", "provider_id"):
        backend.config.gcp[key] = None
    messages = backend.validate()
    assert len(messages) == 3
    assert any("gcp_project_number" in msg for msg in messages)
    assert any("gcp_pool_id" in msg for msg in messages)
    assert any("gcp_provider_id" in msg for msg in messages)


@pytest.mark.parametrize("lifetime", ["3600", 0, 43201, True, None])
def test_validate_token_lifetime(backend, lifetime):
    """Test validation of the token lifetime."""
    backend.config.gcp["token_lifetime"] = lifetime
    messages = backend.validate()
    assert len(messages) == 1
    assert "lifetime" in messages[0]


def test_validate_subject_token(backend):
    """Test validation of the subject token settings."""
    backend.config.gcp["subject_token"] = "pytest"
    assert "subject token" in backend.validate()[0]

    backend.config.gcp["subject_token"] = "access_token"
    assert "okta_oidc_authorization_server" in backend.validate()[0]

    backend.config.okta["oidc_authorization_server"] = "default"
    assert backend.validate() == []

    backend.config.okta["oidc_redirect_uri"] = None
    assert "okta_oidc_redirect_uri" in backend.validate()[0]


def test_validate_configuration_includes_backend(gcp_config, backend):
    """Test that backend validation is merged into validate_configuration."""
    from tokendito import user

    gcp_config.gcp["pool_id"] = None
    gcp_config.okta["username"] = "pytest"
    messages = user.validate_configuration(gcp_config, backend)
    assert any("gcp_pool_id" in msg for msg in messages)


def test_authenticate_sts(backend, oidc_tokens, sts_ok, id_token):
    """Test the STS token exchange without impersonation."""
    creds = backend.authenticate()

    oidc_tokens.assert_called_once_with(backend.config)
    body = urllib.parse.parse_qs(sts_ok.last_request.text)
    assert body["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert body["audience"] == [AUDIENCE]
    assert body["scope"] == ["https://www.googleapis.com/auth/cloud-platform"]
    assert body["requested_token_type"] == ["urn:ietf:params:oauth:token-type:access_token"]
    assert body["subject_token_type"] == ["urn:ietf:params:oauth:token-type:id_token"]
    assert body["subject_token"] == [id_token]

    assert creds.backend == "gcp"
    assert creds.profile == "pytest"
    assert creds.data["access_token"] == "pytest_federated_token"
    assert creds.data["subject_token"] == id_token
    assert creds.data["token_type"] == "Bearer"
    assert creds.data["subject_token_expiration"] == SUBJECT_EXP
    assert creds.data["service_account_email"] is None
    assert creds.expiration.tzinfo is not None
    assert not creds.is_expired()
    json.dumps(creds.to_dict())


def test_authenticate_masks_tokens(backend, oidc_tokens, sts_ok, id_token):
    """Test that the subject and access tokens are masked in logs."""
    from tokendito import user

    backend.authenticate()
    assert id_token in user.mask_items
    assert "pytest_federated_token" in user.mask_items


def test_authenticate_expiration_capped_by_subject_token(backend, mocker, sts_ok):
    """Test that the credentials expire no later than the subject token."""
    token = make_jwt({"exp": 1000})
    mocker.patch("tokendito.okta.get_oidc_tokens", return_value={"id_token": token})
    creds = backend.authenticate()
    assert creds.expiration == datetime.fromtimestamp(1000, tz=timezone.utc)
    assert creds.is_expired()


def test_authenticate_opaque_subject_token(backend, mocker, sts_ok):
    """Test that expires_in is used when the subject token is not a JWT."""
    mocker.patch(
        "tokendito.okta.get_oidc_tokens",
        return_value={"id_token": "pytest_opaque", "expires_in": 600},
    )
    now = int(datetime.now(timezone.utc).timestamp())
    creds = backend.authenticate()
    assert now + 590 <= creds.data["subject_token_expiration"] <= now + 610


def test_authenticate_access_token_subject(backend, oidc_tokens, sts_ok):
    """Test using the Okta access token as a JWT subject token."""
    backend.config.gcp["subject_token"] = "access_token"
    backend.config.gcp["scopes"] = "scope1,scope2"
    creds = backend.authenticate()
    body = urllib.parse.parse_qs(sts_ok.last_request.text)
    assert body["subject_token"] == ["pytest_okta_access"]
    assert body["subject_token_type"] == ["urn:ietf:params:oauth:token-type:jwt"]
    assert body["scope"] == ["scope1 scope2"]
    assert creds.data["subject_token_type"] == "urn:ietf:params:oauth:token-type:jwt"


def test_authenticate_missing_subject_token(backend, mocker, caplog):
    """Test that a missing Okta token is fatal."""
    mocker.patch("tokendito.okta.get_oidc_tokens", return_value={"access_token": "x"})
    with pytest.raises(SystemExit) as err:
        backend.authenticate()
    assert err.value.code == 1
    assert "id_token" in caplog.text


def test_authenticate_sts_error(backend, oidc_tokens, requests_mock, caplog):
    """Test that Google STS errors are reported."""
    requests_mock.post(
        STS_URL,
        status_code=400,
        json={
            "error": "invalid_grant",
            "error_description": "The audience in ID Token does not match the expected audience.",
        },
    )
    with pytest.raises(SystemExit) as err:
        backend.authenticate()
    assert err.value.code == 1
    assert "invalid_grant" in caplog.text
    assert "does not match the expected audience" in caplog.text


def test_authenticate_sts_no_access_token(backend, oidc_tokens, requests_mock, caplog):
    """Test an STS response without an access token."""
    requests_mock.post(STS_URL, json={"token_type": "Bearer"})
    with pytest.raises(SystemExit):
        backend.authenticate()
    assert "No access token" in caplog.text


def test_authenticate_impersonation(backend, oidc_tokens, sts_ok, requests_mock):
    """Test service account impersonation."""
    backend.config.gcp["service_account_email"] = SA_EMAIL
    backend.config.gcp["scopes"] = "https://www.googleapis.com/auth/devstorage.read_only"
    backend.config.gcp["token_lifetime"] = 1800
    iam = requests_mock.post(
        IAM_URL,
        json={"accessToken": "pytest_sa_token", "expireTime": "2029-06-01T12:00:00Z"},
    )
    creds = backend.authenticate()

    sts_body = urllib.parse.parse_qs(sts_ok.last_request.text)
    assert sts_body["scope"] == ["https://www.googleapis.com/auth/cloud-platform"]
    assert iam.last_request.headers["Authorization"] == "Bearer pytest_federated_token"
    assert iam.last_request.json() == {
        "scope": ["https://www.googleapis.com/auth/devstorage.read_only"],
        "lifetime": "1800s",
    }
    assert creds.data["access_token"] == "pytest_sa_token"
    assert creds.data["service_account_email"] == SA_EMAIL
    assert creds.expiration == datetime(2029, 6, 1, 12, 0, tzinfo=timezone.utc)


def test_authenticate_impersonation_error(backend, oidc_tokens, sts_ok, requests_mock, caplog):
    """Test that IAM Credentials errors are reported."""
    backend.config.gcp["service_account_email"] = SA_EMAIL
    requests_mock.post(
        IAM_URL,
        status_code=403,
        json={
            "error": {
                "code": 403,
                "message": "Permission 'iam.serviceAccounts.getAccessToken' denied",
                "status": "PERMISSION_DENIED",
            }
        },
    )
    with pytest.raises(SystemExit):
        backend.authenticate()
    assert "PERMISSION_DENIED" in caplog.text
    assert "getAccessToken" in caplog.text


def test_authenticate_impersonation_no_token(backend, oidc_tokens, sts_ok, requests_mock):
    """Test an IAM Credentials response without an access token."""
    backend.config.gcp["service_account_email"] = SA_EMAIL
    requests_mock.post(IAM_URL, json={})
    with pytest.raises(SystemExit):
        backend.authenticate()


def test_post_google_api_errors(requests_mock, caplog):
    """Test network errors, invalid JSON and non-JSON error responses."""
    from tokendito.backends import gcp

    requests_mock.post(STS_URL, exc=requests.exceptions.ConnectTimeout)
    with pytest.raises(SystemExit):
        gcp.post_google_api(STS_URL)

    requests_mock.post(STS_URL, text="not json")
    with pytest.raises(SystemExit):
        gcp.post_google_api(STS_URL)
    assert "Invalid JSON" in caplog.text

    requests_mock.post(STS_URL, status_code=500, text="pytest internal error")
    with pytest.raises(SystemExit):
        gcp.post_google_api(STS_URL)
    assert "HTTP 500: pytest internal error" in caplog.text

    requests_mock.post(STS_URL, status_code=502, json=["pytest"])
    with pytest.raises(SystemExit):
        gcp.post_google_api(STS_URL)
    assert "HTTP 502: ['pytest']" in caplog.text


@pytest.mark.parametrize(
    "scopes, expected",
    [
        (None, ["https://www.googleapis.com/auth/cloud-platform"]),
        ("a b", ["a", "b"]),
        ("a, b", ["a", "b"]),
        (["a", ""], ["a"]),
    ],
)
def test_parse_scopes(scopes, expected):
    """Test scope parsing."""
    from tokendito.backends.gcp import parse_scopes

    assert parse_scopes(scopes) == expected


@pytest.mark.parametrize("token", [None, "a", "a.b.c", make_jwt({"sub": "x"})])
def test_get_jwt_expiration_invalid(token):
    """Test that invalid JWTs have no expiration."""
    from tokendito.backends.gcp import get_jwt_expiration

    assert get_jwt_expiration(token) is None


def _credentials(backend, id_token, email=None):
    """Build GCP Credentials."""
    from tokendito.backends.base import Credentials

    return Credentials(
        backend="gcp",
        profile="pytest",
        data={
            "access_token": "pytest_access",
            "token_type": "Bearer",
            "subject_token": id_token,
            "subject_token_type": backend.subject_token_type,
            "subject_token_expiration": SUBJECT_EXP,
            "audience": backend.audience,
            "service_account_email": email,
        },
        expiration=datetime(2029, 1, 1, tzinfo=timezone.utc),
    )


def test_credential_process_output(backend, id_token):
    """Test the Google executable-sourced credential response."""
    output = backend.credential_process_output(_credentials(backend, id_token))
    assert output == {
        "version": 1,
        "success": True,
        "token_type": "urn:ietf:params:oauth:token-type:id_token",
        "id_token": id_token,
        "expiration_time": SUBJECT_EXP,
    }
    json.dumps(output)


def test_credential_process_output_from_cache(backend, id_token):
    """Test the executable response for credentials restored from a dictionary."""
    from tokendito.backends.base import Credentials

    creds = _credentials(backend, id_token)
    del creds.data["subject_token_expiration"]
    creds = Credentials.from_dict(creds.to_dict())
    output = backend.credential_process_output(creds)
    assert output["expiration_time"] == int(datetime(2029, 1, 1, tzinfo=timezone.utc).timestamp())


def test_write_default_path(backend, id_token, tmpdir, caplog):
    """Test the ADC external_account file contents and permissions."""
    import logging

    caplog.set_level(logging.INFO)
    backend.write(_credentials(backend, id_token))

    path = os.path.join(str(tmpdir), "gcp", "pytest.json")
    token_path = os.path.join(str(tmpdir), "gcp", "pytest.subject_token.json")
    with open(path) as file:
        adc = json.load(file)
    assert adc == {
        "type": "external_account",
        "audience": AUDIENCE,
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "token_url": STS_URL,
        "credential_source": {
            "executable": {
                "command": "tokendito --credential-process --profile pytest",
                "timeout_millis": 30000,
                "output_file": token_path,
            }
        },
    }
    with open(token_path) as file:
        assert json.load(file)["id_token"] == id_token

    if sys.platform != "win32":
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert os.stat(token_path).st_mode & 0o777 == 0o600

    assert f"export GOOGLE_APPLICATION_CREDENTIALS='{path}'" in caplog.text
    assert "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1" in caplog.text
    assert f"gcloud auth login --cred-file='{path}'" in caplog.text


def test_write_impersonation_custom_path(backend, id_token, tmpdir):
    """Test the ADC file with service account impersonation and a custom path."""
    path = os.path.join(str(tmpdir), "custom", "adc.json")
    backend.config.gcp["credentials_file"] = path
    backend.config.gcp["service_account_email"] = SA_EMAIL
    backend.config.gcp["token_lifetime"] = 1800

    # Existing files with wider permissions are tightened.
    os.makedirs(os.path.dirname(path))
    with open(path, "w") as file:
        file.write("{}")
    os.chmod(path, 0o644)

    backend.write(_credentials(backend, id_token, SA_EMAIL))
    with open(path) as file:
        adc = json.load(file)
    assert adc["service_account_impersonation_url"] == IAM_URL
    assert adc["service_account_impersonation"] == {"token_lifetime_seconds": 1800}
    assert adc["credential_source"]["executable"]["output_file"] == os.path.join(
        str(tmpdir), "custom", "adc.subject_token.json"
    )
    if sys.platform != "win32":
        assert os.stat(path).st_mode & 0o777 == 0o600


def test_credentials_file_default_config_dir(gcp_config):
    """Test the default credentials file when config_dir is not set."""
    from tokendito.backends.gcp import GCPBackend

    del gcp_config.user["config_dir"]
    default_dir = gcp_config.get_defaults()["user"]["config_dir"]
    assert GCPBackend(gcp_config).credentials_file == os.path.join(
        default_dir, "gcp", "pytest.json"
    )


def test_display(backend, id_token, capsys):
    """Test the credentials summary."""
    backend.display(_credentials(backend, id_token, SA_EMAIL))
    out = capsys.readouterr().out
    assert "profile 'pytest'" in out
    assert "pytest-pool (project 123456789)" in out
    assert "pytest-provider" in out
    assert f"service account {SA_EMAIL}" in out
    assert "2029-01-01T00:00:00Z" in out

    backend.display(_credentials(backend, id_token))
    assert "no impersonation" in capsys.readouterr().out


def test_cli_arguments():
    """Test that the GCP command line arguments map to the gcp section."""
    from tokendito import user

    args = user.parse_cli_args([])
    assert args.gcp_pool_id is None
    assert args.gcp_token_lifetime is None

    args = user.parse_cli_args(
        [
            "--backend",
            "gcp",
            "--gcp-project-number",
            "123456789",
            "--gcp-pool-id",
            "pytest-pool",
            "--gcp-provider-id",
            "pytest-provider",
            "--gcp-service-account-email",
            SA_EMAIL,
            "--gcp-scopes",
            "scope1 scope2",
            "--gcp-token-lifetime",
            "1200",
            "--gcp-credentials-file",
            "/tmp/pytest.json",
            "--gcp-subject-token",
            "access_token",
        ]
    )
    ret = user.process_arguments(args)
    assert ret.user["backend"] == "gcp"
    assert ret.gcp == {
        "project_number": "123456789",
        "pool_id": "pytest-pool",
        "provider_id": "pytest-provider",
        "service_account_email": SA_EMAIL,
        "scopes": "scope1 scope2",
        "token_lifetime": 1200,
        "credentials_file": "/tmp/pytest.json",
        "subject_token": "access_token",
    }

    with pytest.raises(SystemExit):
        user.parse_cli_args(["--gcp-token-lifetime", "pytest"])
    with pytest.raises(SystemExit):
        user.parse_cli_args(["--gcp-subject-token", "pytest"])


def test_ini_keys(tmpdir):
    """Test that gcp_* ini keys map to the gcp section."""
    from tokendito import user

    ini_file = tmpdir.join("tokendito.ini")
    ini_file.write(
        "[default]\n"
        "user_backend = gcp\n"
        "gcp_project_number = 123456789\n"
        "gcp_pool_id = pytest-pool\n"
        "gcp_provider_id = pytest-provider\n"
        "gcp_scopes = scope1\n"
        "gcp_token_lifetime = 900\n"
        "gcp_credentials_file = ~/pytest.json\n"
        "gcp_subject_token = access_token\n"
    )
    ret = user.coerce_config_types(user.process_ini_file(str(ini_file), "default"))
    assert ret.user["backend"] == "gcp"
    assert ret.gcp["project_number"] == "123456789"
    assert ret.gcp["provider_id"] == "pytest-provider"
    assert ret.gcp["token_lifetime"] == 900
    assert ret.gcp["subject_token"] == "access_token"


def test_env_keys(monkeypatch):
    """Test that TOKENDITO_GCP_* environment variables map to the gcp section."""
    from tokendito import user

    env = dict(
        TOKENDITO_GCP_PROJECT_NUMBER="123456789",
        TOKENDITO_GCP_PROVIDER_ID="pytest-provider",
        TOKENDITO_GCP_SERVICE_ACCOUNT_EMAIL=SA_EMAIL,
        TOKENDITO_GCP_TOKEN_LIFETIME="600",
        TOKENDITO_GCP_SUBJECT_TOKEN="id_token",
    )
    monkeypatch.setattr(os, "environ", env)
    ret = user.coerce_config_types(user.process_environment())
    assert ret.gcp["project_number"] == "123456789"
    assert ret.gcp["provider_id"] == "pytest-provider"
    assert ret.gcp["service_account_email"] == SA_EMAIL
    assert ret.gcp["token_lifetime"] == 600
    assert ret.gcp["subject_token"] == "id_token"


def test_process_args_flow(mocker, tmpdir, id_token, requests_mock, capsys):
    """Test the process_args flow with the real GCP backend."""
    from argparse import Namespace

    from tokendito import user
    from tokendito.config import config

    path = os.path.join(str(tmpdir), "flow.json")
    mocker.patch("tokendito.user.process_options")
    mocker.patch("tokendito.user.setup_logging")
    mocker.patch("tokendito.user.validate_basic_configuration", return_value=[])
    mocker.patch.dict(
        config.user,
        {"backend": "gcp", "use_device_token": False, "quiet": False, "config_profile": "flow"},
    )
    mocker.patch.dict(config.okta, {"org": "https://acme.okta.org/"})
    mocker.patch.dict(
        config.gcp,
        {
            "project_number": "123456789",
            "pool_id": "pytest-pool",
            "provider_id": "pytest-provider",
            "credentials_file": path,
        },
    )
    m_access = mocker.patch("tokendito.okta.access_control")
    mocker.patch(
        "tokendito.okta.get_oidc_tokens",
        return_value={"id_token": id_token, "access_token": "x", "expires_in": 3600},
    )
    mocker.patch("tokendito.user.HTTP_client.get_device_token", return_value=None)
    requests_mock.post(STS_URL, json={"access_token": "pytest_flow", "expires_in": 3600})

    user.process_args(Namespace(user_config_profile="flow"), False)

    m_access.assert_called_once_with(config)
    with open(path) as file:
        adc = json.load(file)
    assert adc["audience"] == AUDIENCE
    assert "--profile flow" in adc["credential_source"]["executable"]["command"]
    assert "pytest-provider" in capsys.readouterr().out

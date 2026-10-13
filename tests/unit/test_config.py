# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures for the Config class."""

import pytest


def test_config_object():
    """Test proper initialization of the Config object."""
    import json
    import sys

    from tokendito.config import Config

    # Test for invalid assignments to the object
    with pytest.raises(AttributeError):
        pytest_config = Config(pytest_attribute={})

    with pytest.raises(KeyError):
        pytest_config = Config(aws="pytest")

    with pytest.raises(ValueError):
        pytest_config = Config(aws={"pytest": "pytest"})

    # Test whether repr can be reused to create an object
    pytest_config = Config()
    args = json.loads(repr(pytest_config))
    pytest_config_2 = Config(**args)
    assert (pytest_config == pytest_config_2) is True

    # Test if passing arguments results in an object with new values
    pytest_config_aws = Config(aws={"profile": "pytest_aws"})
    pytest_config_okta = Config(okta={"username": "pytest_username"})
    pytest_config_mixed = Config(
        user={"config_profile": "pytest_user"}, okta={"password": "%pytest_!&%password^"}
    )
    assert (pytest_config == pytest_config_aws) is False

    # Check that an update copies the values correctly
    pytest_config.update(pytest_config_aws)
    assert pytest_config.aws["profile"] == "pytest_aws"

    # Check that an update does not overwrite all values
    pytest_config.update(pytest_config_okta)
    assert pytest_config.aws["profile"] == "pytest_aws"

    # Check that an update overwrites matching values only
    pytest_config.update(pytest_config_mixed)
    assert pytest_config.okta["username"] == "pytest_username"
    assert pytest_config.okta["password"] == "%pytest_!&%password^"
    assert pytest_config.user["config_profile"] == "pytest_user"

    # Check that default values from the original object are kept
    assert pytest_config.get_defaults()["aws"]["region"] == pytest_config.aws["region"]

    # Check that we set encoding correctly when there is no stdin
    sys.stdin = None
    pytest_config = Config()
    assert pytest_config.user["encoding"] == "utf-8"


def test_config_backend_sections():
    """Test that the backend related sections and keys exist with their defaults."""
    from tokendito.config import Config

    pytest_config = Config()
    assert Config.get_sections() == ["user", "aws", "okta", "gcp", "azure", "cache"]
    assert pytest_config.user["backend"] == "aws"
    assert pytest_config.okta["oidc_client_id"] is None
    assert pytest_config.okta["oidc_scopes"] == "openid profile"
    assert pytest_config.okta["oidc_authorization_server"] is None
    assert pytest_config.okta["oidc_redirect_uri"] == "http://localhost:8765/callback"
    assert pytest_config.gcp == {
        "project_number": None,
        "pool_id": None,
        "provider_id": None,
        "service_account_email": None,
        "scopes": "https://www.googleapis.com/auth/cloud-platform",
        "token_lifetime": 3600,
        "credentials_file": None,
    }
    assert pytest_config.azure == {
        "tenant_id": None,
        "client_id": None,
        "scope": "https://management.azure.com/.default",
        "authority_host": "https://login.microsoftonline.com",
        "audience": "api://AzureADTokenExchange",
        "token_file": None,
    }
    assert pytest_config.cache == {
        "enabled": False,
        "store": "keyring",
        "service_name": "tokendito",
        "refresh_skew": 300,
        "store_okta_password": False,
    }


def test_config_init_all_sections():
    """Test that partially initialised objects still contain every section."""
    from tokendito.config import Config

    pytest_config = Config(gcp={"pool_id": "pool"})
    for section in Config.get_sections():
        assert isinstance(getattr(pytest_config, section), dict)
    assert pytest_config.gcp == {"pool_id": "pool"}
    assert pytest_config.azure == {}

    merged = Config()
    merged.update(pytest_config)
    assert merged.gcp["pool_id"] == "pool"
    assert merged.gcp["token_lifetime"] == 3600

    with pytest.raises(ValueError):
        Config(cache={"pytest": "pytest"})

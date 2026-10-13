# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Azure backend: Okta OIDC JWT -> Entra ID (Azure AD) federated client credentials.

The Okta access token, issued by a custom authorization server with the audience
``api://AzureADTokenExchange``, is used as a ``client_assertion`` in an Entra ID
``client_credentials`` request. The Entra ID application must have a federated identity
credential whose issuer and subject match the Okta token.
"""

import base64
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json
import logging
import os
import sys

from platformdirs import user_config_dir
import requests
from tokendito import __title__
from tokendito import okta
from tokendito import user
from tokendito.backends import register_backend
from tokendito.backends.base import CredentialBackend
from tokendito.backends.base import Credentials
from tokendito.backends.base import format_expiration
from tokendito.http_client import HTTP_client

logger = logging.getLogger(__name__)

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

AADSTS_HINTS = {
    70021: "No federated identity credential on the Entra ID application matches the Okta "
    "token. Check that its issuer, subject and audience match the token claims.",
    700016: "The application (client) ID was not found in the tenant. Check azure_client_id "
    "and azure_tenant_id.",
    90002: "The tenant was not found. Check azure_tenant_id.",
    700024: "The Okta token is expired or not yet valid. Check the clock and try again.",
    50027: "The Okta token is not a valid JWT for Entra ID. Use an access token from a custom "
    "authorization server (okta_oidc_authorization_server).",
    70011: "The requested scope is invalid. Check azure_scope (e.g. "
    "https://management.azure.com/.default).",
}


def decode_jwt_claims(token):
    """Decode the claims of a JWT without verifying its signature.

    :param token: JWT string
    :return: dict of claims, or an empty dict if the token cannot be decoded.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except (AttributeError, IndexError, ValueError, TypeError) as err:
        logger.debug(f"Could not decode the Okta token claims: {err}")
        return {}
    return claims if isinstance(claims, dict) else {}


def check_audience(claims, audience):
    """Warn if the token audience does not contain the expected audience.

    :param claims: decoded JWT claims
    :param audience: expected audience
    :return: True if the audience matches or cannot be checked, False otherwise.
    """
    if not claims or not audience:
        return True
    aud = claims.get("aud")
    values = aud if isinstance(aud, list) else [aud]
    if audience in values:
        return True
    logger.warning(
        f"The Okta token audience '{aud}' does not match azure_audience '{audience}'. "
        "Entra ID will probably reject it. Configure the audience on the Okta custom "
        "authorization server."
    )
    return False


def format_aadsts_error(body, status_code):
    """Build a readable error message from an Entra ID error response.

    :param body: decoded JSON error response, or a dict with the raw text.
    :param status_code: HTTP status code
    :return: error message
    """
    error = body.get("error", "unknown_error")
    description = body.get("error_description", body.get("text", "")).strip()
    message = f"Entra ID token request failed ({status_code}): {error}: {description}"
    for code in body.get("error_codes") or []:
        if code in AADSTS_HINTS:
            message += f"\nHint (AADSTS{code}): {AADSTS_HINTS[code]}"
    for key in ("trace_id", "correlation_id"):
        if body.get(key):
            message += f"\n{key}: {body[key]}"
    return message


def _response_body(response):
    """Decode a JSON response body, falling back to the raw text.

    :param response: requests.Response
    :return: dict
    """
    try:
        body = response.json()
    except ValueError:
        return {"text": response.text}
    return body if isinstance(body, dict) else {"text": response.text}


def env_export_lines(variables):
    """Format shell commands to export environment variables.

    :param variables: dict of variable names and values
    :return: list of strings
    """
    if os.name == "nt":
        return [f'$env:{key} = "{value}"' for key, value in variables.items()]
    return [f"export {key}='{value}'" for key, value in variables.items()]


@register_backend("azure")
class AzureBackend(CredentialBackend):
    """Exchange an Okta OIDC token for an Entra ID access token."""

    name = "azure"
    config_section = "azure"

    @property
    def settings(self):
        """Return the azure configuration section."""
        return self.config.azure

    @property
    def profile(self):
        """Return the tokendito profile name."""
        return self.config.user.get("config_profile", "default")

    def validate(self):
        """Validate Azure-specific configuration.

        :return: list of error messages.
        """
        messages = []
        for key in ("tenant_id", "client_id", "scope", "authority_host", "audience"):
            if not self.settings.get(key):
                messages.append(f"azure_{key} is not set")
        host = self.settings.get("authority_host")
        if host and not str(host).startswith("https://"):
            messages.append(f"azure_authority_host must be an https:// URL, got '{host}'")
        if not self.config.okta.get("oidc_authorization_server"):
            logger.warning(
                "okta_oidc_authorization_server is not set. The Okta Org authorization server "
                f"cannot issue tokens with aud={self.settings.get('audience')}; "
                "configure a custom authorization server."
            )
        return messages

    def get_federated_token(self):
        """Get the Okta token used as the client assertion.

        :return: JWT string
        """
        tokens = okta.get_oidc_tokens(self.config)
        token = tokens.get("access_token")
        if not token:
            logger.warning("No Okta access token was returned, using the id_token instead.")
            token = tokens.get("id_token")
        user.add_sensitive_value_to_be_masked(token)

        claims = decode_jwt_claims(token)
        logger.debug(
            f"Okta token claims: iss={claims.get('iss')} sub={claims.get('sub')} "
            f"aud={claims.get('aud')}"
        )
        check_audience(claims, self.settings.get("audience"))
        return token

    def token_url(self):
        """Return the Entra ID v2.0 token endpoint of the tenant."""
        host = str(self.settings["authority_host"]).rstrip("/")
        return f"{host}/{self.settings['tenant_id']}/oauth2/v2.0/token"

    def request_access_token(self, federated_token):
        """Exchange the Okta token for an Entra ID access token. Exits on error.

        :param federated_token: Okta JWT
        :return: token response dict
        """
        url = self.token_url()
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.settings["client_id"],
            "scope": self.settings["scope"],
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": federated_token,
        }
        headers = {"accept": "application/json"}
        logger.debug(f"POST to {url}")
        try:
            response = HTTP_client.session.post(url, data=payload, headers=headers)
        except requests.RequestException as err:
            logger.error(f"Error during POST request to {url}. Error: {err}")
            sys.exit(1)

        body = _response_body(response)
        if not response.ok or "access_token" not in body:
            logger.error(format_aadsts_error(body, response.status_code))
            sys.exit(1)
        return body

    def authenticate(self):
        """Get an Okta token and exchange it with Entra ID.

        :return: Credentials object.
        """
        federated_token = self.get_federated_token()
        response = self.request_access_token(federated_token)
        access_token = response["access_token"]
        user.add_sensitive_value_to_be_masked(access_token)

        try:
            expires_in = int(response.get("expires_in", 3600))
        except (TypeError, ValueError):
            expires_in = 3600
        return Credentials(
            backend=self.name,
            profile=self.profile,
            data={
                "access_token": access_token,
                "token_type": response.get("token_type", "Bearer"),
                "tenant_id": self.settings["tenant_id"],
                "client_id": self.settings["client_id"],
                "federated_token": federated_token,
            },
            expiration=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
        )

    def token_file(self):
        """Return the path of the federated token file."""
        path = self.settings.get("token_file")
        if not path:
            config_dir = self.config.user.get("config_dir") or user_config_dir(
                appname=__title__, appauthor=False
            )
            path = os.path.join(config_dir, "azure", f"{self.profile}.jwt")
        return os.path.expanduser(path)

    def environment(self, credentials, token_file):
        """Return the azure-identity environment variables for the credentials.

        :param credentials: Credentials object.
        :param token_file: path of the federated token file.
        :return: dict
        """
        return {
            "AZURE_CLIENT_ID": credentials.data["client_id"],
            "AZURE_TENANT_ID": credentials.data["tenant_id"],
            "AZURE_FEDERATED_TOKEN_FILE": token_file,
            "AZURE_AUTHORITY_HOST": str(self.settings["authority_host"]).rstrip("/"),
        }

    def write(self, credentials):
        """Write the Okta token to the federated token file, readable only by the user.

        :param credentials: Credentials object.
        """
        path = self.token_file()
        user.create_directory(os.path.dirname(path))
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as file:
                file.write(credentials.data["federated_token"])
            os.chmod(path, 0o600)
        except OSError as err:
            logger.error(f"Cannot write the federated token file {path}: {err}")
            sys.exit(1)

        exports = "\n\t".join(env_export_lines(self.environment(credentials, path)))
        logger.info(
            f"Wrote the Okta federated token to {path}.\n"
            f"Use it with azure-identity (WorkloadIdentityCredential / "
            f"DefaultAzureCredential):\n\t{exports}\n"
            "Or with the Azure CLI:\n\t"
            f"az login --service-principal -u {credentials.data['client_id']} "
            f"-t {credentials.data['tenant_id']} --federated-token \"$(cat {path})\""
        )

    def display(self, credentials):
        """Print a short summary of the credentials.

        :param credentials: Credentials object.
        """
        expiration = format_expiration(credentials.expiration) or "unknown"
        user.print(
            f"\nGenerated Azure access token for profile '{credentials.profile}'.\n"
            f"\tTenant: {credentials.data['tenant_id']}\n"
            f"\tClient: {credentials.data['client_id']}\n"
            f"\tScope: {self.settings.get('scope')}\n"
            f"Token is valid until {expiration}."
        )

    def credential_process_output(self, credentials):
        """Return an ``az account get-access-token`` style JSON document.

        :param credentials: Credentials object.
        :return: dictionary
        """
        output = {
            "accessToken": credentials.data["access_token"],
            "tokenType": "Bearer",
            "tenant": credentials.data["tenant_id"],
        }
        if credentials.expiration is not None:
            local = credentials.expiration.astimezone()
            output["expiresOn"] = local.strftime("%Y-%m-%d %H:%M:%S.%f")
            output["expires_on"] = int(credentials.expiration.timestamp())
        return output


def add_arguments(parser):
    """Add the Azure backend command line arguments.

    :param parser: argparse.ArgumentParser
    """
    group = parser.add_argument_group("Azure backend")
    group.add_argument("--azure-tenant-id", dest="azure_tenant_id", help="Entra ID tenant ID.")
    group.add_argument(
        "--azure-client-id",
        dest="azure_client_id",
        help="Entra ID application (client) ID with the Okta federated identity credential.",
    )
    group.add_argument(
        "--azure-scope",
        dest="azure_scope",
        help="Scope to request. Defaults to https://management.azure.com/.default.",
    )
    group.add_argument(
        "--azure-authority-host",
        dest="azure_authority_host",
        help="Entra ID authority host. Defaults to https://login.microsoftonline.com.",
    )
    group.add_argument(
        "--azure-audience",
        dest="azure_audience",
        help="Expected audience of the Okta token. Defaults to api://AzureADTokenExchange.",
    )
    group.add_argument(
        "--azure-token-file",
        dest="azure_token_file",
        help="Federated token file to write. Defaults to <config dir>/azure/<profile>.jwt.",
    )

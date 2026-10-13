# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""GCP credential backend: Okta OIDC token -> GCP Workload Identity Federation.

The Okta subject token (id_token by default) is exchanged at the Google Security Token Service
for a federated access token. If a service account is configured, it is then impersonated with
the IAM Credentials ``generateAccessToken`` API.
"""

import base64
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json
import logging
import os
import sys

import requests
from tokendito import okta
from tokendito import user
from tokendito.backends import register_backend
from tokendito.backends.base import CredentialBackend
from tokendito.backends.base import Credentials
from tokendito.backends.base import format_expiration
from tokendito.http_client import HTTP_client

logger = logging.getLogger(__name__)

STS_TOKEN_URL = "https://sts.googleapis.com/v1/token"
IAM_CREDENTIALS_URL = (
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
    "{email}:generateAccessToken"
)
AUDIENCE = (
    "//iam.googleapis.com/projects/{project_number}/locations/global/"
    "workloadIdentityPools/{pool_id}/providers/{provider_id}"
)
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
SUBJECT_TOKEN_TYPES = {
    "id_token": "urn:ietf:params:oauth:token-type:id_token",
    "access_token": "urn:ietf:params:oauth:token-type:jwt",
}
REQUIRED_KEYS = ("project_number", "pool_id", "provider_id")
MAX_TOKEN_LIFETIME = 43200
EXECUTABLE_TIMEOUT_MILLIS = 30000


def parse_scopes(scopes):
    """Split a space or comma separated list of OAuth scopes.

    :param scopes: string, list or None.
    :return: list of scopes.
    """
    if not scopes:
        return [CLOUD_PLATFORM_SCOPE]
    if isinstance(scopes, str):
        scopes = scopes.replace(",", " ").split()
    return [scope for scope in scopes if scope]


def get_jwt_expiration(token):
    """Read the ``exp`` claim of a JWT without verifying it.

    :param token: JWT string.
    :return: expiration as unix seconds, or None.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return int(claims["exp"])
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return None


def google_error_message(response):
    """Build a readable error message from a Google API error response.

    :param response: requests.Response
    :return: string
    """
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}: {response.text}"
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        return f"HTTP {response.status_code} {error.get('status', '')}: {error.get('message', '')}"
    if error:
        return f"HTTP {response.status_code} {error}: {body.get('error_description', '')}"
    return f"HTTP {response.status_code}: {body}"


def post_google_api(url, **kwargs):
    """POST to a Google API with the shared HTTP session. Exits on error.

    :param url: URL to post to.
    :param kwargs: arguments passed to requests.Session.post.
    :return: JSON response, as a dictionary.
    """
    logger.debug(f"POST to {url}")
    try:
        response = HTTP_client.session.post(url, **kwargs)
    except requests.RequestException as err:
        logger.error(f"Error during POST request to {url}: {err}")
        sys.exit(1)

    if not response.ok:
        logger.error(f"Google API request to {url} failed: {google_error_message(response)}")
        sys.exit(1)

    try:
        return response.json()
    except ValueError as err:
        logger.error(f"Invalid JSON response from {url}: {err}")
        sys.exit(1)


def write_private_file(path, content):
    """Write a file readable only by the current user (0600).

    :param path: file path.
    :param content: string to write.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(content)
    os.chmod(path, 0o600)


@register_backend("gcp")
class GCPBackend(CredentialBackend):
    """Exchange an Okta OIDC token for GCP credentials via Workload Identity Federation."""

    name = "gcp"
    config_section = "gcp"

    @property
    def settings(self):
        """Return the gcp section of the configuration."""
        return self.config.gcp

    @property
    def profile(self):
        """Return the tokendito profile name."""
        return self.config.user.get("config_profile") or "default"

    @property
    def subject_token_kind(self):
        """Return which Okta token is used as subject token: id_token or access_token."""
        return self.settings.get("subject_token") or "id_token"

    @property
    def subject_token_type(self):
        """Return the STS subject token type URN."""
        return SUBJECT_TOKEN_TYPES.get(self.subject_token_kind, SUBJECT_TOKEN_TYPES["id_token"])

    @property
    def audience(self):
        """Return the Workload Identity Pool provider audience."""
        return AUDIENCE.format(**{key: self.settings.get(key) for key in REQUIRED_KEYS})

    @property
    def impersonation_url(self):
        """Return the service account impersonation URL, or None."""
        email = self.settings.get("service_account_email")
        if not email:
            return None
        return IAM_CREDENTIALS_URL.format(email=email)

    @property
    def credentials_file(self):
        """Return the path of the ADC external_account file."""
        path = self.settings.get("credentials_file")
        if path:
            return os.path.expanduser(path)
        config_dir = (
            self.config.user.get("config_dir") or self.config.get_defaults()["user"]["config_dir"]
        )
        return os.path.join(config_dir, "gcp", f"{self.profile}.json")

    @property
    def subject_token_file(self):
        """Return the path of the cached executable response, next to the credentials file."""
        base, _ = os.path.splitext(self.credentials_file)
        return f"{base}.subject_token.json"

    def validate(self):
        """Validate GCP-specific configuration.

        :return: list of error messages.
        """
        messages = [
            f"GCP {key.replace('_', ' ')} not set (gcp_{key})"
            for key in REQUIRED_KEYS
            if not self.settings.get(key)
        ]
        messages += self._validate_token_lifetime()
        messages += self._validate_subject_token()
        return messages

    def _validate_token_lifetime(self):
        """Validate gcp_token_lifetime.

        :return: list of error messages.
        """
        lifetime = self.settings.get("token_lifetime")
        if isinstance(lifetime, bool) or not isinstance(lifetime, int):
            return [f"GCP token lifetime must be an integer, got '{lifetime}'"]
        if not 1 <= lifetime <= MAX_TOKEN_LIFETIME:
            return [f"GCP token lifetime must be between 1 and {MAX_TOKEN_LIFETIME} seconds"]
        return []

    def _validate_subject_token(self):
        """Validate gcp_subject_token and the Okta OIDC settings it needs.

        :return: list of error messages.
        """
        kind = self.subject_token_kind
        if kind not in SUBJECT_TOKEN_TYPES:
            return [
                f"GCP subject token must be one of {', '.join(SUBJECT_TOKEN_TYPES)}, got '{kind}'"
            ]
        messages = []
        if not self.config.okta.get("oidc_redirect_uri"):
            messages.append("Okta OIDC redirect URI not set (okta_oidc_redirect_uri)")
        if kind == "access_token" and not self.config.okta.get("oidc_authorization_server"):
            messages.append(
                "Okta OIDC custom authorization server (okta_oidc_authorization_server) "
                "is required when gcp_subject_token is access_token"
            )
        return messages

    def get_subject_token(self):
        """Retrieve the Okta OIDC token used as STS subject token.

        :return: tuple of (token, expiration as unix seconds).
        """
        tokens = okta.get_oidc_tokens(self.config)
        token = tokens.get(self.subject_token_kind)
        if not token:
            logger.error(f"Okta did not return an {self.subject_token_kind} for the GCP backend.")
            sys.exit(1)
        user.add_sensitive_value_to_be_masked(token)

        expiration = get_jwt_expiration(token)
        if expiration is None:
            expires_in = int(tokens.get("expires_in") or 3600)
            expiration = int(datetime.now(timezone.utc).timestamp()) + expires_in
        return token, expiration

    def exchange_token(self, subject_token):
        """Exchange the subject token for a federated access token at Google STS.

        :param subject_token: Okta OIDC token.
        :return: STS JSON response.
        """
        scopes = parse_scopes(self.settings.get("scopes"))
        if self.impersonation_url:
            scopes = [CLOUD_PLATFORM_SCOPE]
        payload = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "audience": self.audience,
            "scope": " ".join(scopes),
            "requested_token_type": TOKEN_TYPE_ACCESS_TOKEN,
            "subject_token": subject_token,
            "subject_token_type": self.subject_token_type,
        }
        response = post_google_api(
            STS_TOKEN_URL, data=payload, headers={"accept": "application/json"}
        )
        if "access_token" not in response:
            logger.error(f"No access token in the Google STS response: {list(response.keys())}")
            sys.exit(1)
        user.add_sensitive_value_to_be_masked(response["access_token"])
        return response

    def impersonate(self, federated_token):
        """Impersonate the configured service account.

        :param federated_token: STS access token.
        :return: tuple of (access token, expiration datetime).
        """
        payload = {
            "scope": parse_scopes(self.settings.get("scopes")),
            "lifetime": f"{int(self.settings.get('token_lifetime'))}s",
        }
        headers = {
            "Authorization": f"Bearer {federated_token}",
            "accept": "application/json",
        }
        response = post_google_api(self.impersonation_url, json=payload, headers=headers)
        if "accessToken" not in response:
            logger.error(f"No access token in the IAM Credentials response: {list(response)}")
            sys.exit(1)
        user.add_sensitive_value_to_be_masked(response["accessToken"])
        return response["accessToken"], response.get("expireTime")

    def authenticate(self):
        """Get a GCP access token from the Okta session.

        :return: Credentials object.
        """
        subject_token, subject_expiration = self.get_subject_token()
        sts = self.exchange_token(subject_token)
        access_token = sts["access_token"]
        now = datetime.now(timezone.utc)
        expiration = now + timedelta(seconds=int(sts.get("expires_in") or 3600))

        email = self.settings.get("service_account_email")
        if email:
            access_token, expire_time = self.impersonate(access_token)
            expiration = expire_time or expiration

        credentials = Credentials(
            backend=self.name,
            profile=self.profile,
            data={
                "access_token": access_token,
                "token_type": sts.get("token_type", "Bearer"),
                "subject_token": subject_token,
                "subject_token_type": self.subject_token_type,
                "subject_token_expiration": subject_expiration,
                "audience": self.audience,
                "service_account_email": email,
            },
            expiration=expiration,
        )
        subject_expiry = datetime.fromtimestamp(subject_expiration, tz=timezone.utc)
        credentials.expiration = min(credentials.expiration, subject_expiry)
        return credentials

    def external_account_config(self):
        """Build the ADC external_account configuration.

        :return: dictionary
        """
        command = f"tokendito --credential-process --profile {self.profile}"
        adc = {
            "type": "external_account",
            "audience": self.audience,
            "subject_token_type": self.subject_token_type,
            "token_url": STS_TOKEN_URL,
            "credential_source": {
                "executable": {
                    "command": command,
                    "timeout_millis": EXECUTABLE_TIMEOUT_MILLIS,
                    "output_file": self.subject_token_file,
                }
            },
        }
        if self.impersonation_url:
            adc["service_account_impersonation_url"] = self.impersonation_url
            adc["service_account_impersonation"] = {
                "token_lifetime_seconds": int(self.settings.get("token_lifetime"))
            }
        return adc

    def write(self, credentials):
        """Write the ADC file and the cached subject token, both 0600.

        :param credentials: Credentials object.
        """
        path = self.credentials_file
        write_private_file(path, json.dumps(self.external_account_config(), indent=2) + "\n")
        output = self.credential_process_output(credentials)
        write_private_file(self.subject_token_file, json.dumps(output, indent=2) + "\n")
        logger.info(f"Wrote GCP external account credentials to {path}")
        logger.info(
            "Use them with:\n"
            f"\texport GOOGLE_APPLICATION_CREDENTIALS='{path}'\n"
            "\texport GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1\n"
            "OR\n"
            f"\tgcloud auth login --cred-file='{path}'"
        )

    def display(self, credentials):
        """Print a summary of the generated GCP credentials.

        :param credentials: Credentials object.
        """
        email = credentials.data.get("service_account_email")
        identity = f"service account {email}" if email else "federated identity (no impersonation)"
        msg = (
            f"\nGenerated GCP credentials for profile '{credentials.profile}'.\n"
            f"\tPool:     {self.settings.get('pool_id')}"
            f" (project {self.settings.get('project_number')})\n"
            f"\tProvider: {self.settings.get('provider_id')}\n"
            f"\tIdentity: {identity}\n"
            f"\tADC file: {self.credentials_file}\n\n"
            f"Credentials are valid until {format_expiration(credentials.expiration)}."
        )
        print(msg)

    def credential_process_output(self, credentials):
        """Return a Google executable-sourced credential response.

        :param credentials: Credentials object.
        :return: dictionary
        """
        expiration = credentials.data.get("subject_token_expiration")
        if expiration is None and credentials.expiration is not None:
            expiration = int(credentials.expiration.timestamp())
        return {
            "version": 1,
            "success": True,
            "token_type": credentials.data.get("subject_token_type", self.subject_token_type),
            "id_token": credentials.data["subject_token"],
            "expiration_time": expiration,
        }


def add_arguments(parser):
    """Add the GCP backend command line arguments.

    :param parser: argparse.ArgumentParser
    """
    group = parser.add_argument_group("GCP backend")
    group.add_argument(
        "--gcp-project-number",
        dest="gcp_project_number",
        help="GCP project number of the Workload Identity Pool.",
    )
    group.add_argument("--gcp-pool-id", dest="gcp_pool_id", help="Workload Identity Pool ID.")
    group.add_argument(
        "--gcp-provider-id", dest="gcp_provider_id", help="Workload Identity Pool provider ID."
    )
    group.add_argument(
        "--gcp-service-account-email",
        dest="gcp_service_account_email",
        help="Service account to impersonate. Defaults to no impersonation.",
    )
    group.add_argument(
        "--gcp-scopes",
        dest="gcp_scopes",
        help="Space separated OAuth scopes for the access token. "
        f"Defaults to {CLOUD_PLATFORM_SCOPE}.",
    )
    group.add_argument(
        "--gcp-token-lifetime",
        dest="gcp_token_lifetime",
        type=int,
        help="Impersonated access token lifetime, in seconds. Defaults to 3600.",
    )
    group.add_argument(
        "--gcp-credentials-file",
        dest="gcp_credentials_file",
        help="Path of the ADC external_account file. Defaults to "
        "<user_config_dir>/gcp/<profile>.json.",
    )
    group.add_argument(
        "--gcp-subject-token",
        dest="gcp_subject_token",
        choices=sorted(SUBJECT_TOKEN_TYPES),
        help="Okta token used as the STS subject token. Defaults to id_token.",
    )

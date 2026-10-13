# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""AWS credential backend: Okta SAML -> STS AssumeRoleWithSAML -> ~/.aws/credentials."""

import logging
import sys

from tokendito import aws
from tokendito import user
from tokendito.backends import register_backend
from tokendito.backends.base import CredentialBackend
from tokendito.backends.base import Credentials
from tokendito.backends.base import format_expiration

logger = logging.getLogger(__name__)


@register_backend("aws")
class AWSBackend(CredentialBackend):
    """Wrap the existing tokendito AWS SAML -> STS flow."""

    name = "aws"
    config_section = "aws"

    def validate(self):
        """Validate AWS-specific configuration.

        The quiet-mode role ARN check is kept in ``user.validate_quiet_configuration``
        for backwards compatibility.

        :return: list of error messages.
        """
        return []

    def _resolve_tiles(self):
        """Set ``okta.tile`` to the tile(s) to use, discovering them if needed."""
        tile = self.config.okta["tile"]
        if isinstance(tile, str) and tile:
            self.config.okta["tile"] = (tile, "")
        elif not tile:
            self.config.okta["tile"] = user.discover_tiles(self.config.okta["org"])

    def authenticate(self):
        """Discover tiles, assume a role via SAML and verify the credentials.

        :return: Credentials object.
        """
        self._resolve_tiles()

        auth_tiles = aws.authenticate_to_roles(self.config, self.config.okta["tile"])
        role_response, role_name = aws.select_assumeable_role(auth_tiles)

        identity = aws.assert_credentials(role_response=role_response)
        if "Arn" not in identity and "UserId" not in identity:
            logger.error(
                f"There was an error retrieving and verifying AWS credentials: {role_response}"
            )
            sys.exit(1)

        user.set_profile_name(self.config, role_name)
        return self.credentials_from_response(role_response, role_name)

    def credentials_from_response(self, role_response, role_name=None):
        """Convert an AssumeRoleWithSAML response into a Credentials object.

        :param role_response: STS response dictionary.
        :param role_name: name of the assumed role.
        :return: Credentials object.
        """
        try:
            sts = role_response["Credentials"]
            data = {
                "AccessKeyId": sts["AccessKeyId"],
                "SecretAccessKey": sts["SecretAccessKey"],
                "SessionToken": sts["SessionToken"],
            }
        except (KeyError, TypeError) as err:
            logger.error(f"Could not retrieve credentials: {err}")
            sys.exit(1)

        data["aws_profile"] = self.config.aws["profile"]
        data["role_name"] = role_name
        for value in (data["SecretAccessKey"], data["SessionToken"]):
            user.add_sensitive_value_to_be_masked(value)

        return Credentials(
            backend=self.name,
            profile=self.config.user.get("config_profile", "default"),
            data=data,
            expiration=sts.get("Expiration"),
        )

    def _profile_name(self, credentials):
        """Return the AWS profile name to write the credentials to."""
        return (
            self.config.aws["profile"] or credentials.data.get("aws_profile") or credentials.profile
        )

    @staticmethod
    def _role_response(credentials):
        """Rebuild an STS-like response dictionary from Credentials."""
        sts = {
            "AccessKeyId": credentials.data["AccessKeyId"],
            "SecretAccessKey": credentials.data["SecretAccessKey"],
            "SessionToken": credentials.data["SessionToken"],
        }
        if credentials.expiration is not None:
            sts["Expiration"] = credentials.expiration
        return {"Credentials": sts}

    def write(self, credentials):
        """Write the credentials to the AWS shared credentials and config files.

        :param credentials: Credentials object.
        """
        user.set_local_credentials(
            response=self._role_response(credentials),
            role=self._profile_name(credentials),
            region=self.config.aws["region"],
            output=self.config.aws["output"],
        )

    def display(self, credentials):
        """Print how to use the generated AWS profile.

        :param credentials: Credentials object.
        """
        user.display_selected_role(
            profile_name=self._profile_name(credentials),
            role_response=self._role_response(credentials),
        )

    def credential_process_output(self, credentials):
        """Return the AWS ``credential_process`` version 1 JSON document.

        :param credentials: Credentials object.
        :return: dictionary
        """
        output = {
            "Version": 1,
            "AccessKeyId": credentials.data["AccessKeyId"],
            "SecretAccessKey": credentials.data["SecretAccessKey"],
            "SessionToken": credentials.data["SessionToken"],
        }
        expiration = format_expiration(credentials.expiration)
        if expiration:
            output["Expiration"] = expiration
        return output

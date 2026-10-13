# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Base classes shared by all tokendito credential backends."""

from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _to_utc(value):
    """Normalise a datetime to tz-aware UTC. Naive datetimes are assumed to be UTC.

    :param value: datetime or None
    :return: tz-aware UTC datetime, or None
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def format_expiration(value):
    """Format a datetime as an ISO-8601 UTC string ending in "Z".

    :param value: datetime or None
    :return: string such as "2024-01-01T00:00:00Z", or None
    """
    value = _to_utc(value)
    if value is None:
        return None
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_expiration(value):
    """Parse an ISO-8601 string (or datetime) into a tz-aware UTC datetime.

    :param value: ISO-8601 string, datetime or None
    :return: tz-aware UTC datetime, or None
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return _to_utc(value)
    text = str(value).strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    return _to_utc(datetime.fromisoformat(text))


@dataclass
class Credentials:
    """Credentials produced by a backend.

    :param backend: backend name ("aws", "gcp", "azure").
    :param profile: tokendito profile name.
    :param data: backend-specific secret material. Must be JSON-serialisable.
    :param expiration: tz-aware UTC expiration time, or None if unknown.
    """

    backend: str
    profile: str
    data: dict
    expiration: Optional[datetime] = None

    def __post_init__(self):
        """Normalise the expiration to tz-aware UTC."""
        self.expiration = parse_expiration(self.expiration)

    def is_expired(self, skew_seconds: int = 0) -> bool:
        """Check whether the credentials are expired, or will be within skew_seconds.

        Credentials without an expiration are never considered expired.

        :param skew_seconds: number of seconds before the real expiration to consider
            the credentials as expired.
        :return: True if expired.
        """
        if self.expiration is None:
            return False
        now = datetime.now(timezone.utc)
        return now + timedelta(seconds=int(skew_seconds)) >= self.expiration

    def to_dict(self) -> dict:
        """Return a JSON-safe representation, with the expiration as ISO-8601 "Z".

        :return: dictionary
        """
        return {
            "backend": self.backend,
            "profile": self.profile,
            "data": dict(self.data),
            "expiration": format_expiration(self.expiration),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Credentials":
        """Create a Credentials object from the output of to_dict().

        :param d: dictionary
        :return: Credentials object
        """
        return cls(
            backend=d["backend"],
            profile=d["profile"],
            data=dict(d.get("data") or {}),
            expiration=parse_expiration(d.get("expiration")),
        )


class CredentialBackend(ABC):
    """Abstract base class for credential backends.

    A backend is selected with the ``user.backend`` setting. ``user.process_args`` calls
    ``validate()`` before contacting Okta, then ``authenticate()`` after
    ``okta.access_control(config)``, then ``write()`` and ``display()``.
    """

    name: str = ""
    config_section: str = ""

    def __init__(self, config):
        """Create a backend instance.

        :param config: tokendito Config object.
        """
        self.config = config

    @abstractmethod
    def validate(self) -> list[str]:
        """Validate backend-specific configuration.

        :return: list of configuration error messages (empty if valid).
        """

    @abstractmethod
    def authenticate(self) -> Credentials:
        """Obtain credentials. Called after ``okta.access_control(config)``.

        :return: Credentials object.
        """

    @abstractmethod
    def write(self, credentials: Credentials) -> None:
        """Persist the credentials to the native tool files.

        :param credentials: Credentials object.
        """

    def display(self, credentials: Credentials) -> None:
        """Log a short summary of the credentials.

        :param credentials: Credentials object.
        """
        expiration = format_expiration(credentials.expiration) or "unknown"
        logger.info(
            f"Generated {credentials.backend} credentials for profile "
            f"'{credentials.profile}', valid until {expiration}."
        )

    def credential_process_output(self, credentials: Credentials) -> dict:
        """Return the JSON document printed by ``--credential-process``.

        :param credentials: Credentials object.
        :return: dictionary
        """
        return credentials.to_dict()

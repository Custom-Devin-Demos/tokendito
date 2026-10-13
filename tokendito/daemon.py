# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Credential process and daemon modes.

``--credential-process`` prints the credentials of a single profile as one JSON document on
stdout, serving them from the credential cache while they are fresh. ``--daemon`` keeps
running, and refreshes the credentials of one or more profiles before they expire.
"""

import contextlib
import json
import logging
import os
import signal
import sys
import time

from tokendito import user
from tokendito.backends.base import Credentials
from tokendito.backends.base import format_expiration
from tokendito.cache import cache_key
from tokendito.cache import CredentialCache
from tokendito.config import config

logger = logging.getLogger(__name__)

BACKOFF_INITIAL = 30
BACKOFF_MAX = 900
DEFAULT_REFRESH_INTERVAL = 3600
MIN_REFRESH_INTERVAL = 60
SLEEP_STEP = 1.0
RETAINED_OKTA_KEYS = ("username", "password")


def main(args):
    """Run the credential process or daemon mode selected on the command line.

    :param args: argparse namespace.
    :return: process exit code.
    """
    if args.credential_process:
        if args.multi_profiles:
            logger.error("--credential-process supports a single --profile, not --multi-profiles.")
            return 1
        return credential_process(args)
    return Daemon(args).run()


def okta_password_key(username):
    """Build the cache key under which an Okta password is stored.

    :param username: Okta username.
    :return: cache key string "okta:<username>".
    """
    return f"okta:{username}"


def load_okta_password(cache, conf=config):
    """Load the Okta password from the cache, if opted in and not already configured.

    :param cache: CredentialCache.
    :param conf: Config object.
    :return: True if a password was loaded.
    """
    if conf.cache.get("store_okta_password") is not True or conf.okta.get("password"):
        return False
    username = conf.okta.get("username")
    if not username:
        return False
    password = (cache.get(okta_password_key(username)) or {}).get("password")
    if not password:
        return False
    user.add_sensitive_value_to_be_masked(password)
    conf.okta["password"] = password
    logger.debug(f"Loaded the Okta password for {username} from the credential cache")
    return True


def save_okta_password(cache, conf=config):
    """Store the Okta password in the cache. Only done when explicitly opted in.

    :param cache: CredentialCache.
    :param conf: Config object.
    :return: True if the password was stored.
    """
    if conf.cache.get("store_okta_password") is not True:
        return False
    username = conf.okta.get("username")
    password = conf.okta.get("password")
    if not username or not password:
        return False
    if not cache.enabled:
        logger.warning("cache_store_okta_password requires cache_enabled, password not stored.")
        return False
    cache.set(okta_password_key(username), {"password": password})
    return True


def get_cached_credentials(cache, key, skew_seconds):
    """Return cached credentials if they are present and fresh.

    :param cache: CredentialCache.
    :param key: cache key.
    :param skew_seconds: credentials expiring within this many seconds are not used.
    :return: Credentials, or None.
    """
    entry = cache.get(key)
    if entry is None:
        return None
    try:
        credentials = Credentials.from_dict(entry)
    except (AttributeError, KeyError, TypeError, ValueError) as err:
        logger.debug(f"Ignoring invalid cache entry '{key}': {type(err).__name__}")
        return None
    if credentials.is_expired(skew_seconds):
        logger.debug(f"Cached credentials for '{key}' are expired or about to expire")
        return None
    for value in credentials.data.values():
        if isinstance(value, str):
            user.add_sensitive_value_to_be_masked(value)
    return credentials


@contextlib.contextmanager
def non_interactive():
    """Send anything printed to stderr, and make sure no input can be requested."""
    stdin = sys.stdin
    with open(os.devnull, encoding="utf-8") as devnull:
        sys.stdin = devnull
        try:
            with contextlib.redirect_stdout(sys.stderr):
                yield
        finally:
            sys.stdin = stdin


def get_process_credentials(args):
    """Return credentials for --credential-process, from the cache or by authenticating.

    :param args: argparse namespace.
    :return: tuple of (CredentialBackend instance, Credentials).
    """
    backend = user.load_backend(args)
    cache = CredentialCache.from_config(config)
    key = cache_key(backend.name, config.user["config_profile"])

    credentials = get_cached_credentials(cache, key, cache.refresh_skew)
    if credentials is not None:
        logger.debug(f"Using cached credentials for '{key}'")
        return backend, credentials

    load_okta_password(cache)
    credentials = user.authenticate_backend(args, backend)
    user.save_device_token(args)
    save_okta_password(cache)
    cache.set(key, credentials.to_dict())
    return backend, credentials


def credential_process(args, stdout=None):
    """Print the credentials of a profile as a single JSON document.

    Logs go to stderr, input is never requested, and the native tool files are not written.

    :param args: argparse namespace.
    :param stdout: stream to write the JSON document to, defaults to sys.stdout.
    :return: process exit code.
    """
    stdout = stdout or sys.stdout
    args.user_quiet = True
    with non_interactive():
        backend, credentials = get_process_credentials(args)
        output = backend.credential_process_output(credentials)
    stdout.write(f"{json.dumps(output)}\n")
    stdout.flush()
    return 0


def backoff_delay(failures):
    """Compute the exponential backoff delay after a number of consecutive failures.

    :param failures: number of consecutive failures, starting at 1.
    :return: delay in seconds.
    """
    return min(BACKOFF_MAX, BACKOFF_INITIAL * 2 ** (max(failures, 1) - 1))


class Daemon:
    """Refresh the credentials of one or more profiles before they expire."""

    def __init__(self, args, clock=time.time, sleep=time.sleep, max_iterations=None):
        """Create the daemon.

        :param args: argparse namespace.
        :param clock: function returning the current time as epoch seconds.
        :param sleep: function sleeping for a number of seconds.
        :param max_iterations: stop after this many refreshes (after the initial ones).
        """
        self.args = args
        self.multi = bool(args.multi_profiles)
        self.profiles = list(args.multi_profiles or [args.user_config_profile])
        self.clock = clock
        self.sleep = sleep
        if max_iterations is None:
            max_iterations = getattr(args, "daemon_max_iterations", None)
        self.max_iterations = max_iterations
        self.schedule = {}
        self.failures = {}
        self.okta_secrets = {}
        self.okta_authenticated = False
        self.stopping = False

    def stop(self, signum=None, frame=None):
        """Request a clean shutdown. A second request interrupts immediately.

        :param signum: signal number.
        :param frame: current stack frame.
        """
        if self.stopping:
            raise KeyboardInterrupt
        logger.info("Shutdown requested, stopping after the current operation.")
        self.stopping = True

    def run(self):
        """Run until stopped.

        :return: process exit code.
        """
        previous = self._install_signal_handlers()
        try:
            return self._run()
        except KeyboardInterrupt:
            logger.info("Interrupted, daemon stopped.")
            return 0
        finally:
            self._restore_signal_handlers(previous)

    def _run(self):
        for profile in self.profiles:
            if self.stopping:
                return 0
            if not self.refresh(profile):
                logger.error(f"Could not obtain the initial credentials for profile '{profile}'.")
                return 1

        iterations = 0
        while not self.stopping and not self._reached_max_iterations(iterations):
            profile = min(self.schedule, key=self.schedule.get)
            self.wait_until(self.schedule[profile])
            if self.stopping:
                break
            self.refresh(profile)
            iterations += 1
        logger.info("Daemon stopped.")
        return 0

    def _reached_max_iterations(self, iterations):
        return self.max_iterations is not None and iterations >= self.max_iterations

    def wait_until(self, deadline):
        """Sleep until a deadline, waking up regularly to honour shutdown requests.

        :param deadline: epoch seconds.
        """
        while not self.stopping:
            remaining = deadline - self.clock()
            if remaining <= 0:
                return
            self.sleep(min(remaining, SLEEP_STEP))

    def refresh(self, profile):
        """Obtain, write and cache the credentials of a profile, and schedule the next refresh.

        Failures are logged and retried later with exponential backoff.

        :param profile: tokendito profile name.
        :return: True on success.
        """
        try:
            credentials, skew = self._obtain(profile)
        except (Exception, SystemExit) as err:
            return self._failed(profile, err)
        self.failures.pop(profile, None)
        self.schedule[profile] = self.next_refresh_time(credentials, skew)
        logger.info(
            f"Refreshed {credentials.backend} credentials for profile '{profile}', valid until "
            f"{format_expiration(credentials.expiration) or 'unknown'}. Next refresh in "
            f"{int(self.schedule[profile] - self.clock())}s."
        )
        return True

    def next_refresh_time(self, credentials, skew):
        """Compute when credentials should be refreshed.

        :param credentials: Credentials.
        :param skew: seconds before the expiration to refresh at.
        :return: epoch seconds.
        """
        now = self.clock()
        if credentials.expiration is None:
            return now + DEFAULT_REFRESH_INTERVAL
        return max(credentials.expiration.timestamp() - skew, now + MIN_REFRESH_INTERVAL)

    def _failed(self, profile, err):
        failures = self.failures.get(profile, 0) + 1
        self.failures[profile] = failures
        delay = backoff_delay(failures)
        self.schedule[profile] = self.clock() + delay
        reason = "authentication failed" if isinstance(err, SystemExit) else repr(err)
        logger.warning(
            f"Could not refresh credentials for profile '{profile}' ({reason}), "
            f"attempt {failures}. Retrying in {delay}s."
        )
        return False

    def _prepare_config(self, profile):
        config.set_defaults()
        config.okta.update(self.okta_secrets)
        self.args.user_config_profile = profile
        if self.multi:
            self.args.aws_profile = profile

    def _obtain(self, profile):
        self._prepare_config(profile)
        backend = user.load_backend(self.args)
        cache = CredentialCache.from_config(config)
        load_okta_password(cache)

        credentials = self._authenticate(backend)

        self.okta_secrets = {
            key: config.okta[key] for key in RETAINED_OKTA_KEYS if config.okta.get(key)
        }
        save_okta_password(cache)
        user.save_device_token(self.args)
        backend.write(credentials)
        cache.set(cache_key(backend.name, profile), credentials.to_dict())
        return credentials, cache.refresh_skew

    def _authenticate(self, backend):
        if self.okta_authenticated:
            try:
                return user.authenticate_backend(self.args, backend, skip_auth=True)
            except (Exception, SystemExit) as err:
                reason = "" if isinstance(err, SystemExit) else f" ({err!r})"
                logger.info(f"Okta session may have expired{reason}, authenticating again.")
                self.okta_authenticated = False
        credentials = user.authenticate_backend(self.args, backend, skip_auth=False)
        self.okta_authenticated = True
        return credentials

    def _install_signal_handlers(self):
        previous = {}
        for name in ("SIGINT", "SIGTERM"):
            signum = getattr(signal, name, None)
            if signum is None:
                continue
            try:
                previous[signum] = signal.signal(signum, self.stop)
            except (OSError, ValueError) as err:
                logger.debug(f"Could not install a {name} handler: {err}")
        return previous

    @staticmethod
    def _restore_signal_handlers(previous):
        for signum, handler in previous.items():
            if handler is None:
                continue
            try:
                signal.signal(signum, handler)
            except (OSError, ValueError) as err:
                logger.debug(f"Could not restore the handler for signal {signum}: {err}")

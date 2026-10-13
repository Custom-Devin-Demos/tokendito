# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests for the credential process and daemon modes."""

from argparse import Namespace
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import json
import signal
import sys

import pytest

NOW = 1_800_000_000.0


class FakeCache:
    """In-memory replacement for CredentialCache. Never touches the keychain."""

    def __init__(self, enabled=True, refresh_skew=300):
        """Create an empty cache."""
        self.enabled = enabled
        self.refresh_skew = refresh_skew
        self.data = {}

    def get(self, key):
        """Return a stored value."""
        return self.data.get(key)

    def set(self, key, value):
        """Store a value."""
        if self.enabled:
            self.data[key] = value

    def delete(self, key):
        """Remove a value."""
        self.data.pop(key, None)


class FakeClock:
    """Clock advanced by a fake sleep function."""

    def __init__(self, now=NOW):
        """Start the clock."""
        self.now = now
        self.sleeps = []

    def time(self):
        """Return the current fake time."""
        return self.now

    def sleep(self, seconds):
        """Advance the fake time."""
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def reset_config():
    """Reset the config singleton around each test."""
    from tokendito.config import config

    config.set_defaults()
    yield
    config.set_defaults()


@pytest.fixture
def fake_cache(mocker):
    """Patch CredentialCache.from_config to return an in-memory cache."""
    cache = FakeCache()
    mocker.patch("tokendito.daemon.CredentialCache.from_config", return_value=cache)
    return cache


def make_credentials(profile="default", expiration=None, backend="aws"):
    """Build a Credentials object."""
    from tokendito.backends.base import Credentials

    return Credentials(
        backend=backend,
        profile=profile,
        data={"AccessKeyId": "AKIA", "SecretAccessKey": "secret", "SessionToken": "token"},
        expiration=expiration,
    )


def make_backend(mocker, name="aws"):
    """Build a mocked backend."""
    backend = mocker.Mock()
    backend.name = name
    backend.credential_process_output.side_effect = lambda creds: {
        "Version": 1,
        "AccessKeyId": creds.data["AccessKeyId"],
    }
    return backend


def in_seconds(seconds, now=None):
    """Return a UTC datetime some seconds from now."""
    base = datetime.now(timezone.utc) if now is None else datetime.fromtimestamp(now, timezone.utc)
    return base + timedelta(seconds=seconds)


def cp_args(profile="default", **kwargs):
    """Build a namespace for --credential-process."""
    values = dict(
        credential_process=True,
        daemon=False,
        multi_profiles=None,
        user_config_profile=profile,
        user_quiet=False,
        aws_profile=None,
        daemon_max_iterations=None,
    )
    values.update(kwargs)
    return Namespace(**values)


@pytest.fixture
def cp_env(mocker, fake_cache):
    """Patch the user pipeline used by --credential-process."""
    from tokendito.config import config

    backend = make_backend(mocker)

    def load_backend(args):
        config.user["config_profile"] = args.user_config_profile
        config.user["quiet"] = args.user_quiet
        return backend

    mocks = Namespace(
        backend=backend,
        cache=fake_cache,
        load=mocker.patch("tokendito.user.load_backend", side_effect=load_backend),
        auth=mocker.patch(
            "tokendito.user.authenticate_backend",
            side_effect=lambda *a, **k: make_credentials(expiration=in_seconds(3600)),
        ),
        save_token=mocker.patch("tokendito.user.save_device_token"),
    )
    return mocks


def test_credential_process_cache_miss(cp_env, capsys):
    """Test that a cache miss authenticates, caches, and prints the backend output."""
    from tokendito import daemon
    from tokendito.config import config

    args = cp_args("dev")
    assert daemon.credential_process(args) == 0

    assert args.user_quiet is True
    assert config.user["quiet"] is True
    cp_env.auth.assert_called_once()
    cp_env.save_token.assert_called_once_with(args)
    cp_env.backend.write.assert_not_called()
    assert set(cp_env.cache.data) == {"aws:dev"}
    assert cp_env.cache.data["aws:dev"]["data"]["AccessKeyId"] == "AKIA"
    out = capsys.readouterr().out
    assert json.loads(out) == {"Version": 1, "AccessKeyId": "AKIA"}


def test_credential_process_cache_hit(cp_env, capsys):
    """Test that fresh cached credentials are served without authenticating."""
    from tokendito import daemon

    cached = make_credentials("dev", expiration=in_seconds(3600))
    cached.data["AccessKeyId"] = "CACHED"
    cp_env.cache.data["aws:dev"] = cached.to_dict()

    assert daemon.credential_process(cp_args("dev")) == 0

    cp_env.auth.assert_not_called()
    cp_env.backend.write.assert_not_called()
    assert json.loads(capsys.readouterr().out)["AccessKeyId"] == "CACHED"


@pytest.mark.parametrize(
    "entry",
    [
        make_credentials("dev", expiration=in_seconds(-10)).to_dict(),
        make_credentials("dev", expiration=in_seconds(100)).to_dict(),
        {"garbage": True},
    ],
    ids=["expired", "within-refresh-skew", "invalid"],
)
def test_credential_process_cache_expired(cp_env, capsys, entry):
    """Test that expired, nearly expired or invalid cache entries are refreshed."""
    from tokendito import daemon

    cp_env.cache.data["aws:dev"] = entry

    assert daemon.credential_process(cp_args("dev")) == 0

    cp_env.auth.assert_called_once()
    assert json.loads(capsys.readouterr().out)["AccessKeyId"] == "AKIA"
    assert "backend" in cp_env.cache.data["aws:dev"]


def test_credential_process_cache_disabled(cp_env, capsys):
    """Test that a disabled cache always authenticates and stores nothing."""
    from tokendito import daemon

    cp_env.cache.enabled = False
    assert daemon.credential_process(cp_args()) == 0
    assert daemon.credential_process(cp_args()) == 0

    assert cp_env.auth.call_count == 2
    assert cp_env.cache.data == {}


def test_credential_process_stdout_purity(cp_env, capsys):
    """Test that only the JSON document is written to stdout."""
    import builtins
    import logging

    from tokendito import daemon

    def noisy(*args, **kwargs):
        builtins.print("this goes to stderr")
        logging.getLogger("tokendito.pytest").warning("a log line")
        return make_credentials(expiration=in_seconds(3600))

    cp_env.auth.side_effect = noisy

    assert daemon.credential_process(cp_args()) == 0

    captured = capsys.readouterr()
    assert captured.out.count("\n") == 1
    assert json.loads(captured.out) == {"Version": 1, "AccessKeyId": "AKIA"}
    assert "this goes to stderr" in captured.err
    assert sys.stdout is not None


def test_credential_process_never_prompts(cp_env, capsys):
    """Test that a required prompt fails with an error on stderr instead of reading input."""
    from tokendito import daemon
    from tokendito import user

    cp_env.auth.side_effect = lambda *a, **k: user.get_input("Enter your code: ")
    stdin = sys.stdin

    with pytest.raises(SystemExit) as err:
        daemon.credential_process(cp_args())

    assert err.value.code == 1
    assert capsys.readouterr().out == ""
    assert sys.stdin is stdin


def test_credential_process_rejects_multi_profiles(mocker):
    """Test that --credential-process only accepts a single profile."""
    from tokendito import daemon

    m_cp = mocker.patch("tokendito.daemon.credential_process")
    assert daemon.main(cp_args(multi_profiles=["a", "b"])) == 1
    m_cp.assert_not_called()


def test_main_dispatch(mocker):
    """Test that main selects the right mode."""
    from tokendito import daemon

    mocker.patch("tokendito.daemon.credential_process", return_value=0)
    m_daemon = mocker.patch("tokendito.daemon.Daemon")
    m_daemon.return_value.run.return_value = 0

    assert daemon.main(cp_args()) == 0
    daemon.credential_process.assert_called_once()
    m_daemon.assert_not_called()

    assert daemon.main(cp_args(credential_process=False, daemon=True)) == 0
    m_daemon.return_value.run.assert_called_once()


def test_cmd_interface_dispatch(mocker):
    """Test that the CLI flags select the daemon module."""
    from tokendito import user

    m_main = mocker.patch("tokendito.daemon.main", return_value=0)
    m_process = mocker.patch("tokendito.user.process_args")

    with pytest.raises(SystemExit) as err:
        user.cmd_interface(["--credential-process", "--profile", "dev"])
    assert err.value.code == 0
    assert m_main.call_args.args[0].credential_process is True
    assert m_main.call_args.args[0].user_config_profile == "dev"

    m_main.return_value = 3
    with pytest.raises(SystemExit) as err:
        user.cmd_interface(["--daemon", "--multi-profiles", "a", "--multi-profiles", "b"])
    assert err.value.code == 3
    assert m_main.call_args.args[0].daemon is True
    m_process.assert_not_called()


def test_cli_flags():
    """Test parsing of the credential process and daemon flags."""
    from tokendito import user

    args = user.parse_cli_args([])
    assert args.credential_process is False
    assert args.daemon is False
    assert args.daemon_max_iterations is None

    args = user.parse_cli_args(["--daemon", "--daemon-max-iterations", "2"])
    assert args.daemon is True
    assert args.daemon_max_iterations == 2

    with pytest.raises(SystemExit):
        user.parse_cli_args(["--daemon", "--credential-process"])


def test_okta_password_not_persisted_by_default(cp_env, capsys):
    """Test that the Okta password is never stored unless opted in."""
    from tokendito import daemon
    from tokendito.config import config

    def auth(*args, **kwargs):
        config.okta["username"] = "jane"
        config.okta["password"] = "hunter2"
        return make_credentials(expiration=in_seconds(3600))

    cp_env.auth.side_effect = auth

    assert daemon.credential_process(cp_args()) == 0

    assert "okta:jane" not in cp_env.cache.data
    assert "hunter2" not in json.dumps(cp_env.cache.data)


def test_okta_password_opt_in(fake_cache):
    """Test storing and loading the Okta password when opted in."""
    from tokendito import daemon
    from tokendito.config import config

    config.okta["username"] = "jane"
    config.okta["password"] = "hunter2"
    assert daemon.save_okta_password(fake_cache) is False

    config.cache["store_okta_password"] = True
    assert daemon.save_okta_password(fake_cache) is True
    assert fake_cache.data == {"okta:jane": {"password": "hunter2"}}

    # A configured password takes precedence
    config.okta["password"] = "configured"
    assert daemon.load_okta_password(fake_cache) is False
    assert config.okta["password"] == "configured"

    config.okta["password"] = ""
    assert daemon.load_okta_password(fake_cache) is True
    assert config.okta["password"] == "hunter2"

    config.okta["password"] = ""
    config.okta["username"] = "john"
    assert daemon.load_okta_password(fake_cache) is False
    config.okta["username"] = ""
    assert daemon.load_okta_password(fake_cache) is False

    config.cache["store_okta_password"] = False
    config.okta["username"] = "jane"
    assert daemon.load_okta_password(fake_cache) is False


def test_okta_password_requires_enabled_cache():
    """Test that opting in without an enabled cache does not store the password."""
    from tokendito import daemon
    from tokendito.config import config

    cache = FakeCache(enabled=False)
    config.cache["store_okta_password"] = True
    config.okta["username"] = "jane"
    config.okta["password"] = "hunter2"
    assert daemon.save_okta_password(cache) is False
    config.okta["password"] = ""
    assert daemon.save_okta_password(cache) is False


def test_credential_process_uses_stored_password(cp_env, capsys):
    """Test that an opted-in stored password is loaded before authenticating."""
    from tokendito import daemon
    from tokendito.config import config

    cp_env.cache.data["okta:jane"] = {"password": "hunter2"}
    seen = {}

    def load_backend(args):
        config.user["config_profile"] = args.user_config_profile
        config.okta["username"] = "jane"
        config.cache["store_okta_password"] = True
        return cp_env.backend

    def auth(*args, **kwargs):
        seen["password"] = config.okta["password"]
        return make_credentials(expiration=in_seconds(3600))

    cp_env.load.side_effect = load_backend
    cp_env.auth.side_effect = auth

    assert daemon.credential_process(cp_args()) == 0
    assert seen["password"] == "hunter2"


def test_backoff_delay():
    """Test the exponential backoff with cap."""
    from tokendito import daemon

    assert daemon.backoff_delay(0) == daemon.BACKOFF_INITIAL
    assert daemon.backoff_delay(1) == daemon.BACKOFF_INITIAL
    assert daemon.backoff_delay(2) == daemon.BACKOFF_INITIAL * 2
    assert daemon.backoff_delay(3) == daemon.BACKOFF_INITIAL * 4
    assert daemon.backoff_delay(100) == daemon.BACKOFF_MAX


def daemon_args(profiles=None, profile="default", max_iterations=None):
    """Build a namespace for --daemon."""
    return cp_args(
        profile,
        credential_process=False,
        daemon=True,
        multi_profiles=profiles,
        daemon_max_iterations=max_iterations,
    )


@pytest.fixture
def daemon_env(mocker, fake_cache):
    """Patch the user pipeline used by the daemon, with per-profile lifetimes."""
    from tokendito.config import config

    clock = FakeClock()
    backend = make_backend(mocker)
    env = Namespace(
        clock=clock,
        cache=fake_cache,
        backend=backend,
        lifetimes={},
        calls=[],
        failures=[],
    )

    def load_backend(args):
        config.user["config_profile"] = args.user_config_profile
        return backend

    def auth(args, backend, skip_auth=False):
        profile = args.user_config_profile
        env.calls.append((profile, skip_auth, clock.now))
        if env.failures:
            failure = env.failures.pop(0)
            if failure is not None:
                raise failure
        lifetime = env.lifetimes.get(profile, 3600)
        return make_credentials(profile, expiration=in_seconds(lifetime, clock.now))

    env.load = mocker.patch("tokendito.user.load_backend", side_effect=load_backend)
    env.auth = mocker.patch("tokendito.user.authenticate_backend", side_effect=auth)
    env.save_token = mocker.patch("tokendito.user.save_device_token")
    return env


def make_daemon(env, args, max_iterations=None):
    """Create a Daemon with the fake clock."""
    from tokendito import daemon

    return daemon.Daemon(
        args, clock=env.clock.time, sleep=env.clock.sleep, max_iterations=max_iterations
    )


def test_daemon_refresh_scheduling(daemon_env):
    """Test that profiles are refreshed at expiration - refresh_skew, earliest first."""
    daemon_env.lifetimes = {"a": 3600, "b": 1800}
    args = daemon_args(["a", "b"])

    assert make_daemon(daemon_env, args, max_iterations=3).run() == 0

    times = [(profile, int(at - NOW)) for profile, _, at in daemon_env.calls]
    assert times == [("a", 0), ("b", 0), ("b", 1500), ("b", 3000), ("a", 3300)]
    # One Okta login, then the session is reused
    assert [skip for _, skip, _ in daemon_env.calls] == [False, True, True, True, True]
    assert daemon_env.backend.write.call_count == 5
    assert set(daemon_env.cache.data) == {"aws:a", "aws:b"}
    assert args.aws_profile == "a"
    assert max(daemon_env.clock.sleeps) <= 1.0


def test_daemon_max_iterations_from_args(daemon_env):
    """Test that the hidden --daemon-max-iterations flag is honoured."""
    from tokendito import daemon

    instance = daemon.Daemon(
        daemon_args(max_iterations=0), clock=daemon_env.clock.time, sleep=daemon_env.clock.sleep
    )
    assert instance.max_iterations == 0
    assert instance.run() == 0
    assert len(daemon_env.calls) == 1


def test_daemon_refresh_intervals(daemon_env):
    """Test the refresh time of credentials without, or with a short, expiration."""
    from tokendito import daemon

    instance = make_daemon(daemon_env, daemon_args())
    assert instance.next_refresh_time(make_credentials(), 300) == NOW + 3600
    short = make_credentials(expiration=in_seconds(120, NOW))
    assert instance.next_refresh_time(short, 300) == NOW + daemon.MIN_REFRESH_INTERVAL


def test_daemon_okta_session_expired(daemon_env):
    """Test that Okta authentication is redone when the session can no longer be used."""
    daemon_env.failures = [None, SystemExit(1)]

    assert make_daemon(daemon_env, daemon_args(), max_iterations=1).run() == 0

    assert [(int(at - NOW), skip) for _, skip, at in daemon_env.calls] == [
        (0, False),
        (3300, True),
        (3300, False),
    ]


def test_daemon_backoff_on_failures(daemon_env):
    """Test that transient failures are retried with exponential backoff."""
    from tokendito import daemon

    error = ConnectionError("pytest")
    # Initial login OK. The first refresh fails with the reused session and with a new Okta
    # login, the next three full logins fail, then the fifth refresh succeeds.
    daemon_env.failures = [None] + [error] * 5

    assert make_daemon(daemon_env, daemon_args(), max_iterations=5).run() == 0

    full_auth = [int(at - NOW) for _, skip, at in daemon_env.calls if not skip]
    initial = daemon.BACKOFF_INITIAL
    assert full_auth == [
        0,
        3300,
        3300 + initial,
        3300 + 3 * initial,
        3300 + 7 * initial,
        3300 + 15 * initial,
    ]
    assert daemon_env.backend.write.call_count == 2
    assert daemon_env.calls[-1][1] is False


def test_daemon_initial_failure_exits(daemon_env):
    """Test that failing to obtain the initial credentials stops the daemon."""
    daemon_env.failures = [SystemExit(1)]

    assert make_daemon(daemon_env, daemon_args(["a", "b"])).run() == 1
    assert len(daemon_env.calls) == 1


def test_daemon_does_not_persist_password(daemon_env):
    """Test that the daemon keeps the password in memory only, by default."""
    from tokendito.config import config

    seen = []

    def load_backend(args):
        seen.append(config.okta["password"])
        config.user["config_profile"] = args.user_config_profile
        config.okta["username"] = "jane"
        if not config.okta["password"]:
            config.okta["password"] = "hunter2"
        return daemon_env.backend

    daemon_env.load.side_effect = load_backend

    assert make_daemon(daemon_env, daemon_args(), max_iterations=1).run() == 0

    assert seen == ["", "hunter2"]
    assert "hunter2" not in json.dumps(daemon_env.cache.data)


def test_daemon_stores_password_when_opted_in(daemon_env):
    """Test that the daemon stores the password in the cache when opted in."""
    from tokendito.config import config

    def load_backend(args):
        config.user["config_profile"] = args.user_config_profile
        config.cache["store_okta_password"] = True
        config.okta["username"] = "jane"
        config.okta["password"] = config.okta["password"] or "hunter2"
        return daemon_env.backend

    daemon_env.load.side_effect = load_backend

    assert make_daemon(daemon_env, daemon_args(), max_iterations=0).run() == 0
    assert daemon_env.cache.data["okta:jane"] == {"password": "hunter2"}


def test_daemon_signal_handling(daemon_env):
    """Test that SIGINT/SIGTERM handlers request a clean shutdown and are restored."""
    from tokendito import daemon

    before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    instance = make_daemon(daemon_env, daemon_args())
    installed = {}

    def sleep(seconds):
        for sig in before:
            installed[sig] = signal.getsignal(sig)
        installed[signal.SIGTERM](signal.SIGTERM, None)
        daemon_env.clock.sleep(seconds)

    instance.sleep = sleep

    assert instance.run() == 0
    assert all(handler == instance.stop for handler in installed.values())
    assert instance.stopping is True
    assert len(daemon_env.calls) == 1
    assert {sig: signal.getsignal(sig) for sig in before} == before
    assert isinstance(instance, daemon.Daemon)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal delivery")
def test_daemon_real_signal(daemon_env):
    """Test shutdown on a real SIGTERM."""
    instance = make_daemon(daemon_env, daemon_args())
    instance.sleep = lambda seconds: signal.raise_signal(signal.SIGTERM)

    assert instance.run() == 0
    assert instance.stopping is True


def test_daemon_second_signal_interrupts(daemon_env):
    """Test that a second shutdown request interrupts immediately."""
    instance = make_daemon(daemon_env, daemon_args())
    instance.stop()
    with pytest.raises(KeyboardInterrupt):
        instance.stop()


def test_daemon_keyboard_interrupt(daemon_env):
    """Test that KeyboardInterrupt (e.g. Ctrl+C on Windows) stops the daemon cleanly."""
    instance = make_daemon(daemon_env, daemon_args())

    def sleep(seconds):
        raise KeyboardInterrupt

    instance.sleep = sleep
    assert instance.run() == 0


def test_daemon_stop_before_start(daemon_env):
    """Test that a daemon stopped before running does not authenticate."""
    instance = make_daemon(daemon_env, daemon_args())
    instance.stopping = True
    assert instance.run() == 0
    assert daemon_env.calls == []


def test_daemon_signal_install_failure(mocker, daemon_env):
    """Test that the daemon still runs when signal handlers cannot be installed."""
    mocker.patch("tokendito.daemon.signal.signal", side_effect=ValueError("not main thread"))
    assert make_daemon(daemon_env, daemon_args(), max_iterations=0).run() == 0

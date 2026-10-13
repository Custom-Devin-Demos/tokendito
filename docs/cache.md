# Credential cache

Tokendito can cache the credentials it obtains so that repeated invocations (for example
`tokendito --credential-process` being called by the AWS CLI, `gcloud`, or the Azure SDKs) do not
need to re-authenticate with Okta every time. Caching is **disabled by default**.

The cache is implemented in `tokendito/cache.py`. It stores one JSON document per
`<backend>:<profile>` key (for example `aws:my_prod_okta_tile`). Each document is the
backend-specific credential material plus its expiration time. Entries are considered fresh until
`refresh_skew` seconds before they expire, at which point tokendito re-authenticates and replaces
them.

## Configuration

Add the following keys to a profile in `tokendito.ini` (see [tokendito.ini.md](tokendito.ini.md)):

| INI key | Environment variable | Default | Description |
|---|---|---|---|
| `cache_enabled` | `TOKENDITO_CACHE_ENABLED` | `false` | Enable the credential cache. |
| `cache_store` | `TOKENDITO_CACHE_STORE` | `keyring` | Where to store entries: `keyring`, `file` or `none`. |
| `cache_service_name` | `TOKENDITO_CACHE_SERVICE_NAME` | `tokendito` | Service name entries are stored under in the OS keychain. |
| `cache_refresh_skew` | `TOKENDITO_CACHE_REFRESH_SKEW` | `300` | Seconds before expiry at which cached credentials are refreshed. |

Example:

```ini
[default]
okta_org = https://acme.okta.com/
okta_username = jane.doe@acme.com
cache_enabled = true
cache_store = keyring
cache_refresh_skew = 300
```

## Stores

### `keyring` (default)

Entries are stored in the operating system's credential store via the
[keyring](https://pypi.org/project/keyring/) library, under the service name `cache_service_name`
(default `tokendito`) with the cache key as the account/user name:

| OS | Where the data lives |
|---|---|
| macOS | The login **Keychain** (visible in *Keychain Access*, search for `tokendito`). |
| Windows | **Windows Credential Manager** (*Control Panel → Credential Manager → Windows Credentials*). |
| Linux | The **Secret Service** API (GNOME Keyring, KeePassXC, ...) or **KWallet**, whichever is available on the D-Bus session. |

Windows Credential Manager limits each credential to 2560 bytes, so values are split into chunks:
the entry `<key>` holds a small manifest (`{"version": 1, "chunks": n}`) and the JSON payload is
stored in entries `<key>#0` ... `<key>#n-1`. This is done on every OS so that entries behave the
same everywhere.

If no usable keyring is available (for example on a headless Linux host with no Secret Service,
where keyring selects its `fail` or `null` backend), or the keyring returns an error at runtime
(for example a locked keychain), tokendito logs a warning and falls back to the `file` store
described below. You can also select a specific keyring backend using keyring's own
configuration, such as the `PYTHON_KEYRING_BACKEND` environment variable.

### `file`

Entries are stored as one JSON file per key in the user cache directory reported by
[platformdirs](https://github.com/platformdirs/platformdirs) for `tokendito`:

| OS | Default directory |
|---|---|
| macOS | `~/Library/Caches/tokendito` |
| Windows | `%LOCALAPPDATA%\tokendito\Cache` |
| Linux | `$XDG_CACHE_HOME/tokendito` (usually `~/.cache/tokendito`) |

File names are derived from the cache key with unsafe characters replaced, plus a short hash
(for example `aws_default-1a2b3c4d5e6f.json`). On POSIX systems the directory is set to mode
`0700` and each file to `0600`. Files are written atomically (to a temporary file that is then
renamed), so a reader never sees a partially written entry.

### `none`

Nothing is stored. This is what is used when `cache_enabled` is `false`.

## Security notes

* The cache contains live, short-lived cloud credentials. Anyone who can read it can use those
  credentials until they expire. Prefer the `keyring` store, which is protected by your OS login.
* The `file` store relies solely on file system permissions. On Windows the file inherits the ACL
  of your user profile directory. Do not point it at shared or synced directories.
* Your Okta password is never written to the cache.
* Cached values are never written to the logs; only cache keys (`<backend>:<profile>`) are logged,
  at debug level.
* Corrupt or unreadable entries are ignored (treated as a cache miss) and overwritten on the next
  successful authentication.
* To clear the cache, delete the `tokendito` entries from your OS keychain, or remove the cache
  directory listed above.

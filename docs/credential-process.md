# credential_process and daemon mode

Tokendito can act as an on-demand credential source for cloud CLIs and SDKs
(`--credential-process`), or keep credentials fresh in the background (`--daemon`). Both modes
work with every [backend](README.md#cloud-backends) and are usually combined with the
[credential cache](cache.md).

## `--credential-process`

```
tokendito --credential-process --profile <tokendito profile>
```

- Prints exactly one JSON document on stdout: the backend's `credential_process_output()`
  (the AWS `credential_process` v1 format for `aws`, the Google executable-sourced response for
  `gcp`, an `az account get-access-token` style document for `azure`).
- All logs go to stderr. Nothing else is ever written to stdout.
- Implies `--quiet`, and never reads input: stdin is replaced with an empty stream, so anything that
  would need a prompt (missing username or password, a TOTP code, a role selection) fails with an
  error on stderr and a non-zero exit code instead of hanging.
- Does not write the native tool files (`~/.aws/credentials`, the ADC file, the token file).
- With `cache_enabled = true`, credentials are served from the cache under the key
  `<backend>:<profile>` while they are valid for more than `cache_refresh_skew` seconds.
  Otherwise tokendito authenticates to Okta, calls the backend, stores the result in the cache
  and prints it. Enabling the cache is strongly recommended, as tools may call the credential
  process frequently.
- Only a single `--profile` is supported; `--multi-profiles` is rejected.

### AWS

In `~/.aws/config`:

```ini
[profile prod]
credential_process = tokendito --credential-process --profile prod
region = us-east-1
```

`aws --profile prod sts get-caller-identity` then calls tokendito whenever the AWS SDK needs
credentials. The tokendito profile must set `aws_role_arn` (quiet mode requirement).

### GCP

The `gcp` backend writes an `external_account` [Application Default Credentials][adc] file whose
`credential_source.executable.command` is `tokendito --credential-process --profile <profile>`.
Google client libraries only run executables when explicitly allowed:

```
export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1
export GOOGLE_APPLICATION_CREDENTIALS=<user_config_dir>/gcp/<profile>.json  # gcp_credentials_file
gcloud auth application-default print-access-token
```

Run `tokendito --profile <profile>` (or `--daemon`) once to create the file. See
[backends/gcp.md](backends/gcp.md).

[adc]: https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers#executable-sourced-credentials

### Azure

```
export AZURE_ACCESS_TOKEN="$(tokendito --credential-process --profile azure-dev | jq -r .accessToken)"
curl -H "Authorization: Bearer ${AZURE_ACCESS_TOKEN}" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

See [backends/azure.md](backends/azure.md) for using the federated token file with
`azure-identity`.

## `--daemon`

```
tokendito --daemon --profile prod
tokendito --daemon --multi-profiles prod --multi-profiles dev
```

The daemon:

1. Authenticates to Okta once and obtains the credentials of every profile. Each profile is
   written to its native files (`backend.write()`) and stored in the cache (if enabled). If the
   initial credentials cannot be obtained, the daemon exits with status 1.
2. Sleeps until the earliest `expiration - cache_refresh_skew` (credentials without an expiration
   are refreshed hourly, and refreshes are never scheduled less than 60 seconds apart), then
   refreshes that profile, reusing the Okta session. Each refresh is logged at `INFO`.
3. When the Okta session can no longer be used, authenticates to Okta again. Use
   `--use-device-token` so re-authentication does not trigger a new MFA challenge where your Okta
   policy allows it.
4. Retries failures with exponential backoff (30 seconds, doubling, capped at 15 minutes) without
   exiting.
5. Stops cleanly on `SIGINT`/`SIGTERM` (Ctrl+C on Windows) after the current operation. A second
   signal interrupts immediately.

The Okta username and password are kept in memory for re-authentication. They are never
written to disk unless you opt in with `cache_store_okta_password` (see below). With
`--multi-profiles`, each profile name is also used as the AWS profile name, as in the normal
multi-profile mode.

The daemon may prompt for missing values (for example the password) when started from a
terminal. When it runs as a service there is no terminal, so configure it for
[non-interactive use](#non-interactive-requirements) and use `--quiet`.

### systemd (Linux) user unit

`~/.config/systemd/user/tokendito.service`:

```ini
[Unit]
Description=tokendito credential refresh
After=network-online.target

[Service]
ExecStart=%h/.local/bin/tokendito --daemon --quiet --use-device-token --profile prod
Restart=on-failure
RestartSec=60

[Install]
WantedBy=default.target
```

```
systemctl --user daemon-reload
systemctl --user enable --now tokendito.service
journalctl --user -u tokendito -f
```

A Secret Service keyring (GNOME Keyring, KWallet) must be unlocked for the `keyring` cache
store to work from a user unit; otherwise the cache falls back to the `file` store.

### launchd (macOS) agent

`~/Library/LaunchAgents/com.github.tokendito.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.github.tokendito</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/tokendito</string>
    <string>--daemon</string>
    <string>--quiet</string>
    <string>--use-device-token</string>
    <string>--profile</string>
    <string>prod</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardErrorPath</key>
  <string>/tmp/tokendito.log</string>
</dict>
</plist>
```

```
launchctl load ~/Library/LaunchAgents/com.github.tokendito.plist
```

## Non-interactive requirements

Both modes need everything that would otherwise be prompted for to be configured, as in
`--quiet` mode:

- `okta_org` (or `okta_tile`) and `okta_username`.
- The Okta password: from `TOKENDITO_OKTA_PASSWORD`, or stored in the keychain with
  `cache_store_okta_password = true`.
- `okta_mfa`, set to a factor that does not need typing: Okta Verify push, or a TOTP factor with
  `okta_mfa_response`. Combine with `user_use_device_token = true` to limit MFA challenges.
- For AWS, `aws_role_arn`, so no role selection is needed.

## Storing the Okta password

With `cache_enabled = true` and `cache_store_okta_password = true`, `--credential-process` and
`--daemon` store the Okta password in the credential cache under the key `okta:<username>` after
a successful login, and load it from there when no password is configured. This is **off by
default**.

**Risk:** anything able to read your keychain entries for the `cache_service_name` service (or,
with the `file` store or the keyring fallback, your user's cache directory) can recover your Okta
password, not just short-lived cloud credentials. Only enable this on machines you trust, prefer
the `keyring` store, and pair it with an MFA factor. Remove the entry with your OS keychain tool
(service `tokendito`, account `okta:<username>`) to revoke it.

To seed the stored password without typing it on the command line:

```
read -rs TOKENDITO_OKTA_PASSWORD && export TOKENDITO_OKTA_PASSWORD
tokendito --credential-process --profile prod > /dev/null
unset TOKENDITO_OKTA_PASSWORD
```

## Cache keys

| Key | Value |
|---|---|
| `<backend>:<profile>` (e.g. `aws:prod`) | `Credentials.to_dict()` of the profile's last credentials. |
| `okta:<username>` | `{"password": ...}`, only with `cache_store_okta_password = true`. |

## Configuration

| INI key | Environment variable | Default | Description |
|---|---|---|---|
| `cache_store_okta_password` | `TOKENDITO_CACHE_STORE_OKTA_PASSWORD` | `false` | Store the Okta password in the credential cache. Requires `cache_enabled`. |

The other cache keys are described in [cache.md](cache.md).

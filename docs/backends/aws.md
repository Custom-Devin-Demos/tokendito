# AWS backend

The AWS backend is the default tokendito backend. It is selected when `user_backend` is not set,
or set to `aws`, and behaves exactly like previous tokendito releases:

1. Authenticate to Okta (`okta.access_control`), including MFA and OIE authorization code + PKCE.
2. Discover the AWS tiles assigned to the user (or use `okta_tile`).
3. Retrieve the SAML assertion for each tile and list the roles it contains.
4. Call STS `AssumeRoleWithSAML` for the selected role (`aws_role_arn`, or interactive selection).
5. Verify the credentials with STS `GetCallerIdentity`.
6. Write the credentials to `aws_shared_credentials_file` and the region/output to `aws_config_file`
   under the `aws_profile` profile (interactive prompt if not set).

## Selecting the backend

The backend is chosen with the `user.backend` setting:

| Source | Example |
| ------ | ------- |
| Command line | `tokendito --backend aws` |
| Environment variable | `TOKENDITO_USER_BACKEND=aws` |
| [tokendito.ini](../tokendito.ini.md) | `user_backend = aws` |

Valid values are `aws`, `gcp` and `azure`. If a backend is not installed or unknown, tokendito
exits with an error listing the available backends.

## Configuration

| Key | Default | Description |
| --- | ------- | ----------- |
| `aws_profile` | (prompt) | AWS profile name to write to. |
| `aws_role_arn` | (prompt) | IAM role to assume. Required in `--quiet` mode. |
| `aws_region` | `us-east-1` | Region written to the AWS config file. |
| `aws_output` | `json` | Output format written to the AWS config file. |
| `aws_shared_credentials_file` | `~/.aws/credentials` | AWS credentials file. |
| `aws_config_file` | `~/.aws/config` | AWS config file. |

Example profile:

``` ini
[engineer]
user_backend = aws
okta_tile = https://acme.okta.com/home/amazon_aws/b07384d113edec49eaa6/123
okta_username = jane.doe@acme.com
okta_mfa = push
aws_role_arn = arn:aws:iam::123456789000:role/engineer
aws_profile = engineer
```

## credential_process output

For use with the AWS CLI/SDK [`credential_process`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)
setting (see [credential-process.md](../credential-process.md)), the AWS backend produces the
version 1 JSON document:

``` json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2030-01-02T03:04:05Z"
}
```

## Writing a backend

Backends live in `tokendito/backends/`, subclass `tokendito.backends.base.CredentialBackend` and
register themselves with `@tokendito.backends.register_backend("<name>")`. `user.process_args`
calls, in order:

1. `backend.validate()` -> list of configuration errors, merged with the generic validation.
2. `okta.access_control(config)` (skipped for subsequent `--multi-profiles` profiles).
3. `backend.authenticate()` -> `Credentials(backend, profile, data, expiration)`.
4. `backend.write(credentials)` to persist to the native tool files.
5. `backend.display(credentials)`.

OIDC based backends can call `okta.get_oidc_tokens(config)` after `access_control` to obtain
`{"id_token", "access_token", "expires_in"}` from the Okta session, using the `okta_oidc_*` keys.

A backend module may define a module-level `add_arguments(parser)` function, which is called while
the command line parser is built. Argument `dest` values must be `<section>_<key>` where
`<section>` is a configuration section (`user`, `aws`, `okta`, `gcp`, `azure`, `cache`), so they
are merged into the configuration like the built-in arguments.

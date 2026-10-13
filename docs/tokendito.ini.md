Tokendito uses [platformdirs](https://github.com/platformdirs/platformdirs) to manage the location of the user configuration file `tokendito.ini`. That file may contain different profiles, as:

```
[default]
okta_org = https://acme.okta.com/
okta_username = jane.doe@acme.com
okta_mfa = push
login_timeout = 0

[my_prod_okta_tile]
okta_tile = https://acme.okta.com/home/amazon_aws/b07384d113edec49f00d/272?fromHome=true

[my_dev_okta_tile]
okta_tile = https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123
okta_username = jane.doe@acme.com
login_timeout = 0
```

To select a given profile, use the `--profile $name` option, otherwise the default profile will be selected. In the above tokendito.ini file, using `--profile my_dev_okta_tile` would select the configuration values for the `[my_dev_okta_tile]` profile.

To authenticate to multiple profiles in a single invocation, use `--multi-profiles` (can be repeated):

```
tokendito --multi-profiles my_prod_okta_tile --multi-profiles my_dev_okta_tile
```

This will authenticate once and then iterate through each profile, writing AWS credentials to `~/.aws/credentials` using the tokendito profile name as the AWS profile name (e.g. `my_prod_okta_tile`, `my_dev_okta_tile`). See the [multi-profile usage](README.md#multi-profile-usage) section for more details.

The `login_timeout` option controls how long tokendito will wait for username and password input before timing out. Once the user starts typing, the timeout is disabled. The default is 0 (disabled). Set to a positive value (in seconds) to enable timeout.

## Backend, OIDC, cloud and cache keys

Keys use the `<section>_<key>` format, and can also be set with `TOKENDITO_<SECTION>_<KEY>`
environment variables. See [Cloud backends](README.md#cloud-backends).

| Key | Default | Description |
| --- | ------- | ----------- |
| `user_backend` | `aws` | Credential backend: `aws`, `gcp` or `azure`. CLI `--backend`. See [backends/aws.md](backends/aws.md). |
| `okta_oidc_client_id` | (none) | Okta OIDC native app client ID. Falls back to the client ID discovered by tokendito. |
| `okta_oidc_scopes` | `openid profile` | Space separated scopes requested from Okta. |
| `okta_oidc_authorization_server` | (none) | Custom authorization server ID (e.g. `default`), needed for a custom `aud`. Empty uses the Org authorization server. |
| `okta_oidc_redirect_uri` | `http://localhost:8765/callback` | Redirect URI registered on the OIDC app. It is not followed; the code is read from the `Location` header. |
| `gcp_project_number` | (none) | GCP project number of the Workload Identity Pool. See [backends/gcp.md](backends/gcp.md). |
| `gcp_pool_id` | (none) | Workload Identity Pool ID. |
| `gcp_provider_id` | (none) | Workload Identity Pool provider ID. |
| `gcp_service_account_email` | (none) | If set, impersonate this service account. |
| `gcp_scopes` | `https://www.googleapis.com/auth/cloud-platform` | OAuth scopes for the GCP access token. |
| `gcp_token_lifetime` | `3600` | Access token lifetime, in seconds. |
| `gcp_credentials_file` | `<user_config_dir>/gcp/<profile>.json` | Where to write the ADC `external_account` file. |
| `gcp_subject_token` | `id_token` | Okta token sent to Google STS: `id_token`, or `access_token` (custom authorization server only, sent as a `jwt`). |
| `azure_tenant_id` | (none) | Entra ID tenant ID. See [backends/azure.md](backends/azure.md). |
| `azure_client_id` | (none) | Entra ID application (client) ID with the federated credential. |
| `azure_scope` | `https://management.azure.com/.default` | Scope requested from Entra ID. |
| `azure_authority_host` | `https://login.microsoftonline.com` | Entra ID authority host. |
| `azure_audience` | `api://AzureADTokenExchange` | Audience of the Okta token. |
| `azure_token_file` | `<user_config_dir>/azure/<profile>.jwt` | Where to write the federated token. |
| `cache_enabled` | `false` | Enable the credential cache. See [cache.md](cache.md). |
| `cache_store` | `keyring` | `keyring`, `file` or `none`. |
| `cache_service_name` | `tokendito` | Keyring service name. |
| `cache_refresh_skew` | `300` | Seconds before expiration at which credentials are refreshed. |

Example:

```
[gcp-dev]
user_backend = gcp
okta_org = https://acme.okta.com/
okta_oidc_client_id = 0oa1example
okta_oidc_authorization_server = default
gcp_project_number = 123456789012
gcp_pool_id = okta-pool
gcp_provider_id = okta
```

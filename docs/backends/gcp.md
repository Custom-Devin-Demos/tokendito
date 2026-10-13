# GCP backend

The GCP backend (`user_backend = gcp`) turns an Okta login into Google Cloud credentials with
[Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation).
No service account keys are created or stored.

1. Authenticate to Okta (`okta.access_control`), including MFA.
2. Get an OIDC token for the Okta OIDC application from the existing Okta session
   (`okta.get_oidc_tokens`, authorization code + PKCE). The `id_token` is used by default.
3. Exchange it at the Google Security Token Service
   (`POST https://sts.googleapis.com/v1/token`, RFC 8693 token exchange) for a federated access
   token. The audience is the Workload Identity Pool provider:
   `//iam.googleapis.com/projects/<gcp_project_number>/locations/global/workloadIdentityPools/<gcp_pool_id>/providers/<gcp_provider_id>`.
4. If `gcp_service_account_email` is set, impersonate that service account with the IAM
   Credentials `generateAccessToken` API, with a lifetime of `gcp_token_lifetime` seconds.
5. Write an [`external_account`](https://google.aip.dev/auth/4117) Application Default
   Credentials (ADC) file to `gcp_credentials_file`, plus the cached Okta token next to it.

Google API errors (for example an audience or issuer mismatch) are logged with the error
returned by Google, and tokendito exits with status 1.

## Configuration

| Key | Default | Description |
| --- | ------- | ----------- |
| `gcp_project_number` | (required) | Project **number** (not ID) that owns the Workload Identity Pool. |
| `gcp_pool_id` | (required) | Workload Identity Pool ID. |
| `gcp_provider_id` | (required) | Workload Identity Pool OIDC provider ID. |
| `gcp_service_account_email` | (none) | Service account to impersonate. Without it, the federated token is used directly. |
| `gcp_scopes` | `https://www.googleapis.com/auth/cloud-platform` | Space (or comma) separated OAuth scopes. |
| `gcp_token_lifetime` | `3600` | Impersonated access token lifetime in seconds (1 - 43200; above 3600 needs the `iam.allowServiceAccountCredentialLifetimeExtension` org policy). |
| `gcp_credentials_file` | `<user_config_dir>/gcp/<profile>.json` | Path of the ADC `external_account` file. |
| `gcp_subject_token` | `id_token` | Okta token sent to Google STS: `id_token`, or `access_token` (custom authorization server only, sent as `urn:ietf:params:oauth:token-type:jwt`). |
| `okta_oidc_client_id` | (discovered) | Client ID of the Okta OIDC application below. |
| `okta_oidc_scopes` | `openid profile` | Add `email` if you map the email claim. |
| `okta_oidc_authorization_server` | (none) | Custom authorization server ID, e.g. `default`. Empty uses the Org authorization server. |
| `okta_oidc_redirect_uri` | `http://localhost:8765/callback` | Must be registered on the Okta app. It is never opened. |

Each key can also be set with `TOKENDITO_GCP_<KEY>` environment variables, or on the command line:

```
GCP backend:
  --gcp-project-number GCP_PROJECT_NUMBER
  --gcp-pool-id GCP_POOL_ID
  --gcp-provider-id GCP_PROVIDER_ID
  --gcp-service-account-email GCP_SERVICE_ACCOUNT_EMAIL
  --gcp-scopes GCP_SCOPES
  --gcp-token-lifetime GCP_TOKEN_LIFETIME
  --gcp-credentials-file GCP_CREDENTIALS_FILE
  --gcp-subject-token {access_token,id_token}
```

## Okta setup

1. In the Okta Admin Console, go to **Applications > Create App Integration** and pick
   **OIDC - OpenID Connect** and **Native Application**.
2. Grant type: **Authorization Code** (PKCE is used; no client secret is needed).
3. Sign-in redirect URI: `http://localhost:8765/callback` (or your `okta_oidc_redirect_uri`).
   tokendito reads the code from the redirect and never starts a local listener.
4. Assign the app to the users or groups who should get GCP access.
5. Note the **Client ID** (e.g. `0oa1b2c3d4e5f6g7h8i9`) and set it as `okta_oidc_client_id`.

The issuer and audience used in GCP depend on the authorization server:

| Authorization server | `okta_oidc_authorization_server` | Issuer | `aud` of the `id_token` |
| -------------------- | -------------------------------- | ------ | ----------------------- |
| Org (default) | (empty) | `https://acme.okta.com` | the Client ID |
| Custom, e.g. `default` | `default` | `https://acme.okta.com/oauth2/default` | the Client ID |

Use a [custom authorization server](https://developer.okta.com/docs/concepts/auth-servers/) if
you need a custom audience or custom claims: set `gcp_subject_token = access_token`, and the
access token's `aud` (the authorization server's audience, e.g. `api://gcp`) becomes the allowed
audience in GCP. Access tokens from the Org authorization server cannot be validated by third
parties, so `access_token` requires `okta_oidc_authorization_server`.

## GCP setup

``` sh
PROJECT_ID=my-project
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')

# 1. Workload Identity Pool
gcloud iam workload-identity-pools create okta-pool \
  --project="$PROJECT_ID" --location=global --display-name="Okta"

# 2. OIDC provider trusting Okta
gcloud iam workload-identity-pools providers create-oidc okta \
  --project="$PROJECT_ID" --location=global --workload-identity-pool=okta-pool \
  --issuer-uri="https://acme.okta.com" \
  --allowed-audiences="0oa1b2c3d4e5f6g7h8i9" \
  --attribute-mapping="google.subject=assertion.sub,attribute.email=assertion.email"
```

- `--issuer-uri` must match the issuer from the table above exactly (no trailing `/`).
- `--allowed-audiences` is the Okta Client ID for `id_token`, or the custom authorization server
  audience for `access_token`.
- `google.subject=assertion.sub` maps the Okta user ID (`00u...`). Mapping `attribute.email`
  requires the `email` claim, so add `email` to `okta_oidc_scopes`. You can also add an
  `--attribute-condition`, e.g. `"assertion.email.endsWith('@acme.com')"`.

Then grant access, either by impersonating a service account (recommended):

``` sh
gcloud iam service-accounts add-iam-policy-binding \
  okta-engineer@"$PROJECT_ID".iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/okta-pool/attribute.email/jane.doe@acme.com"
```

or by granting roles directly to the federated principal
(`principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/okta-pool/subject/00u...`)
and leaving `gcp_service_account_email` empty. Not every Google API supports federated
identities directly; see
[supported products](https://cloud.google.com/iam/docs/federated-identity-supported-services).

## Example profile

``` ini
[gcp-engineer]
user_backend = gcp
okta_org = https://acme.okta.com
okta_username = jane.doe@acme.com
okta_mfa = push
okta_oidc_client_id = 0oa1b2c3d4e5f6g7h8i9
okta_oidc_scopes = openid profile email
gcp_project_number = 123456789012
gcp_pool_id = okta-pool
gcp_provider_id = okta
gcp_service_account_email = okta-engineer@my-project.iam.gserviceaccount.com
gcp_token_lifetime = 3600
```

``` sh
tokendito --profile gcp-engineer
```

## Using the credentials

tokendito writes an `external_account` ADC file (mode `0600`) such as:

``` json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/okta-pool/providers/okta",
  "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "executable": {
      "command": "tokendito --credential-process --profile gcp-engineer",
      "timeout_millis": 30000,
      "output_file": "/home/jane/.config/tokendito/gcp/gcp-engineer.subject_token.json"
    }
  },
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/okta-engineer@my-project.iam.gserviceaccount.com:generateAccessToken",
  "service_account_impersonation": {"token_lifetime_seconds": 3600}
}
```

Google client libraries and `gcloud` perform the STS exchange (and impersonation) themselves from
this file. They first read the cached Okta token in `output_file` (also `0600`, written by
tokendito); once it expires they run `tokendito --credential-process`
(see [credential-process.md](../credential-process.md)) to get a fresh one.
Executable credential sources are disabled by default in Google libraries, so set
`GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`:

``` sh
export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1
export GOOGLE_APPLICATION_CREDENTIALS=~/.config/tokendito/gcp/gcp-engineer.json

# Application Default Credentials (client libraries, terraform, ...)
python -c 'import google.auth; print(google.auth.default())'

# gcloud
gcloud auth login --cred-file="$GOOGLE_APPLICATION_CREDENTIALS"
gcloud storage ls --project my-project
```

## credential_process output

`tokendito --credential-process` with the GCP backend prints a Google
[executable-sourced credential](https://google.aip.dev/auth/4117#determining-the-subject-token-in-executable-sourced-credentials)
response containing the Okta token:

``` json
{
  "version": 1,
  "success": true,
  "token_type": "urn:ietf:params:oauth:token-type:id_token",
  "id_token": "eyJraWQiOi...",
  "expiration_time": 1893456000
}
```

`token_type` is `urn:ietf:params:oauth:token-type:jwt` when `gcp_subject_token = access_token`.
`expiration_time` is the `exp` claim of the Okta token, in Unix seconds.

## Troubleshooting

| Google error | Cause |
| ------------ | ----- |
| `invalid_grant: The audience in ID Token ... does not match the expected audience` | `--allowed-audiences` does not contain the Okta Client ID (or custom AS audience). |
| `invalid_grant: ... issuer ... does not match` | `--issuer-uri` differs from the token `iss` (Org vs custom authorization server, trailing `/`). |
| `invalid_target` | Wrong `gcp_project_number`, `gcp_pool_id` or `gcp_provider_id`, or the pool/provider is disabled. |
| `PERMISSION_DENIED: Permission 'iam.serviceAccounts.getAccessToken' denied` | Missing `roles/iam.workloadIdentityUser` binding for the federated principal on the service account. |

# Azure backend

The Azure backend exchanges an Okta token for a Microsoft Entra ID (Azure AD) access token,
using [workload identity federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation).
No client secret or certificate is stored on the machine.

1. Authenticate to Okta (`okta.access_control`), including MFA.
2. Get an access token from an Okta **custom authorization server** whose audience is
   `api://AzureADTokenExchange` (authorization code + PKCE, reusing the Okta session).
3. `POST {azure_authority_host}/{azure_tenant_id}/oauth2/v2.0/token` with
   `grant_type=client_credentials`, `client_id`, `scope`,
   `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and
   `client_assertion=<Okta token>`.
4. Write the Okta token to `azure_token_file` (permissions `0600`), so that the Azure CLI and the
   Azure SDKs can perform the same exchange themselves.

Entra ID accepts the Okta token when the application has a federated identity credential whose
**issuer**, **subject** and **audience** match the `iss`, `sub` and `aud` claims of the token.

## Okta setup

1. **Authorization server**: in the Okta admin console, go to *Security > API > Authorization
   Servers > Add Authorization Server*:
   - Audience: `api://AzureADTokenExchange`
   - Note the *Issuer* (e.g. `https://acme.okta.com/oauth2/aus1example`) and the server ID
     (`aus1example`, or `default` for the default custom authorization server if you set its
     audience to `api://AzureADTokenExchange`).
   - Add an *Access Policy* assigned to the application below, with a rule allowing the
     *Authorization Code* grant and the `openid` / `profile` scopes.
   The Okta Org authorization server cannot issue tokens with a custom audience, so
   `okta_oidc_authorization_server` must be set.
2. **Application**: create an *OIDC - Native Application* with the *Authorization Code* grant
   (PKCE), the sign-in redirect URI `http://localhost:8765/callback` (or your
   `okta_oidc_redirect_uri`; it is never actually opened), and assign it to the users who need
   Azure access. Use its client ID as `okta_oidc_client_id`.
3. **Claims**: for user sign-ins, the `sub` claim of the access token is the user's Okta login
   (e.g. `jane.doe@acme.com`) and `iss` is the authorization server issuer. These are the values
   that Entra ID matches. Run tokendito with `--loglevel DEBUG` to see the `iss`, `sub` and `aud`
   claims of the token it obtained.

## Entra ID setup

1. Create an application registration and its service principal:

   ``` sh
   az ad app create --display-name tokendito-okta
   az ad sp create --id <appId>
   ```

2. Add a federated identity credential that trusts the Okta token. Create `credential.json`:

   ``` json
   {
     "name": "okta-jane-doe",
     "issuer": "https://acme.okta.com/oauth2/aus1example",
     "subject": "jane.doe@acme.com",
     "audiences": ["api://AzureADTokenExchange"],
     "description": "tokendito via Okta"
   }
   ```

   ``` sh
   az ad app federated-credential create --id <appId> --parameters credential.json
   ```

   The issuer must match the Okta `iss` claim exactly (no trailing slash), and the subject the
   `sub` claim. Each user (subject) needs its own federated identity credential, and an
   application supports a limited number of them, so consider one application per team or role.
   The same can be done in the Azure portal, under *App registrations > your app > Certificates &
   secrets > Federated credentials > Add credential > Other issuer*.

3. Grant the service principal access to your resources, for example:

   ``` sh
   az role assignment create --assignee <appId> --role Reader \
     --scope /subscriptions/<subscriptionId>
   ```

## Configuration

| Key | Command line | Default | Description |
| --- | ------------ | ------- | ----------- |
| `user_backend` | `--backend` | `aws` | Set to `azure`. |
| `azure_tenant_id` | `--azure-tenant-id` | (required) | Entra ID tenant ID (or domain). |
| `azure_client_id` | `--azure-client-id` | (required) | Application (client) ID with the federated credential. |
| `azure_scope` | `--azure-scope` | `https://management.azure.com/.default` | Scope requested from Entra ID. |
| `azure_authority_host` | `--azure-authority-host` | `https://login.microsoftonline.com` | Authority host, e.g. `https://login.microsoftonline.us` for Azure Government. |
| `azure_audience` | `--azure-audience` | `api://AzureADTokenExchange` | Expected `aud` of the Okta token. tokendito warns if the token does not match. |
| `azure_token_file` | `--azure-token-file` | `<user_config_dir>/azure/<profile>.jwt` | Where the Okta token is written. |
| `okta_oidc_client_id` | `--okta-oidc-client-id` | (discovered) | Okta OIDC application client ID. |
| `okta_oidc_authorization_server` | `--okta-oidc-authorization-server` | (none) | Okta custom authorization server ID. Required for this backend. |

Every key can also be set with an environment variable, e.g. `TOKENDITO_AZURE_TENANT_ID`.
See [tokendito.ini](../tokendito.ini.md).

Example profile:

``` ini
[azure-dev]
user_backend = azure
okta_org = https://acme.okta.com/
okta_username = jane.doe@acme.com
okta_mfa = push
okta_oidc_client_id = 0oa1example
okta_oidc_authorization_server = aus1example
azure_tenant_id = 11111111-2222-3333-4444-555555555555
azure_client_id = aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

``` txt
tokendito --profile azure-dev
```

## Using the credentials

tokendito prints the commands to use the token file. With the Azure CLI:

``` sh
az login --service-principal -u <azure_client_id> -t <azure_tenant_id> \
  --federated-token "$(cat ~/.config/tokendito/azure/azure-dev.jwt)"
az account show
```

With the Azure SDKs (`azure-identity`), `WorkloadIdentityCredential` and
`DefaultAzureCredential` read these environment variables:

``` sh
export AZURE_CLIENT_ID='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
export AZURE_TENANT_ID='11111111-2222-3333-4444-555555555555'
export AZURE_FEDERATED_TOKEN_FILE="$HOME/.config/tokendito/azure/azure-dev.jwt"
export AZURE_AUTHORITY_HOST='https://login.microsoftonline.com'
```

``` python
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient

for sub in SubscriptionClient(DefaultAzureCredential()).subscriptions.list():
    print(sub.subscription_id, sub.display_name)
```

On Windows, tokendito prints PowerShell `$env:NAME = "value"` lines instead of `export`.

The token file is only valid for the lifetime of the Okta access token (one hour by default,
configurable in the authorization server access policy). Run tokendito again to refresh it.

`credential_process_output` returns the same JSON shape as `az account get-access-token`:

``` json
{
  "accessToken": "eyJ0eXAi...",
  "expiresOn": "2030-01-02 03:04:05.000000",
  "expires_on": 1893553445,
  "tokenType": "Bearer",
  "tenant": "11111111-2222-3333-4444-555555555555"
}
```

## Troubleshooting

Entra ID errors are reported with their `AADSTS` code, trace ID and correlation ID:

| Error | Meaning |
| ----- | ------- |
| `AADSTS70021` | No federated identity credential matches the token. Compare its issuer, subject and audience with the token claims (`--loglevel DEBUG`). |
| `AADSTS700016` | Application not found in the tenant. Check `azure_client_id` and `azure_tenant_id`. |
| `AADSTS90002` | Tenant not found. Check `azure_tenant_id`. |
| `AADSTS700024` | The Okta token is expired or not yet valid. Check the system clock. |
| `AADSTS50027` | Invalid JWT. Use an access token from a custom authorization server. |
| `AADSTS70011` | Invalid scope. Check `azure_scope`. |

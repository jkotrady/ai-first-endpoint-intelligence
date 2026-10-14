# Local identity provider lab

T013 is in progress. The pilot still uses its existing password/TOTP login.
This separate lab does not migrate users or grant customer access.

On the project Linux amd64 host:

```sh
python3 scripts/bootstrap-identity.py
python3 tools/identity/start_lab.py
```

Pinned inputs and SHA-256 hashes are in
`outputs/identity-toolchain-2026-10-14.json`. The bootstrap extracts Keycloak
26.8.1 and a private Java 25 runtime beneath `work/identity/`; it does not
replace the system Java installation. The launcher binds only to
`http://127.0.0.1:9080` and imports the `forensics-lab` realm. Ctrl+C stops it.

The bootstrap admin is `lab-admin`; its generated password is in the
owner-only `work/private/identity-lab-admin.txt`. Read that file locally.
Never commit it or copy it into tickets. Development H2 storage and HTTP
loopback mode are not a production deployment.

The application client is public with authorization code flow and required
PKCE S256. Its only callback is `http://127.0.0.1:8080/auth/oidc/callback`.
That application route is implemented behind the opt-in configuration below. Direct password grants,
implicit flow and service accounts are disabled. The source realm template has no application users. A private local test user
was subsequently provisioned on this development host. Discovery, signing JWKS and advertised S256
were checked against a running provider on 14 October 2026. Login, MFA,
recovery and application logout have not been exercised through OIDC.

The optional integration below implements state/nonce/PKCE, token validation,
explicit subject mapping and local TOTP/session handling. Provider browser
acceptance, recovery and provider-wide revocation remain outstanding.

References used for the provider selection:
[Keycloak downloads](https://www.keycloak.org/downloads),
[OpenJDK quickstart](https://www.keycloak.org/getting-started/getting-started-zip),
[OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers).

## Optional application integration (14 October)

The application now implements `/auth/oidc/start`, `/auth/oidc/callback` and
`/auth/oidc/confirm`. It is disabled unless explicitly configured. Existing
password/TOTP login continues to work. Do not start a second console instance
against the same state directory; stop the running console before changing
its startup flags.

1. Start the provider as above. Create the intended user in the provider using
   its administration interface and obtain that user's stable ID (the `sub`
   for this realm). On this development host a dedicated `oidc-lab-tester` was already created
   and explicitly mapped to the initial local tester. Its generated credentials
   are in owner-only `work/private/oidc-lab-tester.json`; do not copy them into
   chat or Git. The mapping is in owner-only `work/private/oidc.json`.
2. Copy `tools/identity/oidc.example.json` to `work/private/oidc.json` and set
   permissions to `0600`. Replace the subject placeholder with the verified
   provider user ID and the value with the existing local Forensics username.
   The local user must already have TOTP configured. Never link accounts by
   matching their email or display name. This file grants no new customer
   permissions; those remain on the existing local account.
3. Start the console with:

   ```sh
   work/bin/forensics-console --state work/pilot --oidc-config work/private/oidc.json
   ```

4. Open `http://127.0.0.1:8080/portal` and select **Prihlásiť sa cez organizáciu**.
   Authenticate with the provider, then enter the existing **Forensics** TOTP
   code. No application session is created until this second step succeeds.
   `localhost:8080` is not the canonical host for this OIDC flow.

The server uses authorization code + S256 PKCE with independent random state,
nonce and a browser-binding HttpOnly/Lax cookie. Pending flows expire after
five minutes; post-provider TOTP challenges after three. The callback consumes
its flow once. Signature (RS256), exact issuer, audience/authorized party,
expiry, issued-at, nonce and fresh auth-time are checked. Provider calls are
bounded in size/time, stay on the configured issuer origin and reject HTTP
redirects. Plain HTTP providers are allowed only with an explicit flag for
`127.0.0.1:9080`; other issuers require HTTPS. This is still a loopback pilot,
not a production HTTPS/reverse-proxy deployment.

ID/access tokens, authorization codes, PKCE verifiers and provider claims are
not persisted in the application state. Only an explicitly mapped local user
can continue. The local TOTP counter is persisted against reuse; successful
login rotates the browser's existing app session. Password and OIDC logins
both use existing customer authorization. `Odhlásiť všade` revokes all of the
user's application sessions and pending OIDC factor challenges. It does not
log out Keycloak or revoke the provider account; no back-channel logout or
provider revocation synchronization is implemented yet.

`go.mod`/`go.sum` pin go-oidc v3.21.0, oauth2 v0.36.0 and go-jose v4.1.4.
`python3 scripts/bootstrap.py` downloads/verifies these modules; ordinary
`scripts/go.sh` commands stay offline after bootstrap.

Automated signed-token tests cover successful mapped identity → TOTP → tenant
API → logout, plus invalid signature/issuer/audience/nonce/time/subject,
missing browser binding, duplicate/replayed state, TOTP replay, expiry,
limits, storage failure and cross-user session revocation. A separate opt-in
probe connects the real provider discovery to application configuration:

```sh
FORENSICS_OIDC_LAB=1 ./scripts/go.sh test -race ./internal/pilot -run TestOIDCLocalProviderDiscovery -count=1
```

The real provider probe is **not** an end-to-end provider login test. Browser
acceptance is still pending, as are MFA recovery, production identity policy
and provider logout/revocation. No existing tester was migrated.

# Fork extensions: review and upgrade notes (2026-11-07)

Reviewed fork head: `2188c42050fe808f19d585be5facde989aaf0e0d`.
Merged upstream `develop`: `ea7e7468dfa65237008a05e0b2a9c3d407fe8278`
(222 upstream commits; upstream version 2.16.0). The fork's five custom commits
are preserved in the merge history.

## Review findings and changes

The original fork should not be treated as safe to deploy with untrusted IdP
users or untrusted proxy-host managers. These findings were confirmed in the
fork's changes and addressed by this branch:

| Severity | Finding in the original implementation | Change |
| --- | --- | --- |
| High | Forward auth applied only to the generated default `/`, leaving custom locations unprotected. The built-in asset-cache regex location also bypassed auth. | Apply forward auth to every generated proxy location, including a custom `/`; disable shared asset caching on forward-auth hosts. |
| High | Selecting Authelia without `AUTHELIA_UPSTREAM_URL` silently rendered a host without authentication. | Validate the configured upstream before saving and rendering; reject missing or unsafe URLs. |
| High | `satisfy any` access lists could allow an IP check to bypass the auth subrequest. | Require `satisfy all` when forward auth is selected. |
| High | OIDC associated every login by email without requiring `email_verified`, and did not enforce the recorded issuer/subject binding. An IdP permitting unverified or reassigned email addresses could lead to account takeover. | Resolve existing identities by exact issuer and subject. Require verified email for new identities. First-time email linking is an explicit, default-off migration setting. |
| High | OIDC state/PKCE was not bound to the browser starting the login, and the frontend accepted a bearer token directly from a URL fragment. | Bind state to a Secure, HttpOnly, SameSite=Lax `__Host-` cookie. Exchange a browser-bound, single-use, 60-second server result through a same-origin POST. Never place local JWTs in callback URLs. |
| High | OIDC issued a full local JWT even when local 2FA was enabled. | Return the existing 2FA challenge and reuse the normal verification UI/API. |
| High | IdP users were automatically created with management permissions by default. | Disable auto-creation by default; opt-in new users receive hidden resource permissions and no admin role. Create user, permissions and identity binding in one transaction. |
| Medium | State expiry was checked only when another authorization was started; the pending-state map was unbounded. | Enforce expiry on consumption, consume once, and cap each state/result store at 1,000 entries. |
| Medium | Redirect origins fell back to untrusted Host/forwarded headers. | Require a canonical HTTPS `OIDC_BASE_URL`; retain PKCE and add nonce/ID-token checks. |
| Medium | The SQLite auth migration manually rebuilt the table with `INSERT ... SELECT *`, risking loss of indexes or future schema additions. | Use Knex's column alteration and verify preservation of existing rows and indexes. Already-applied migrations are not re-run. |
| Hardening | Workflow checkout retained credentials and granted write access to repository contents. | Use `contents: read` and `persist-credentials: false`. Image publishing is otherwise preserved. |

The upstream merge also brings authentication rate limits, authentication-oracle
fixes, certificate permissions, token revocation after password changes, per-path
access lists, dependency updates and other upstream changes.

The new raw proxy-configuration field follows upstream's administrator-only
advanced-configuration boundary, enforced on both create and update. Non-admin
users also cannot smuggle Nginx syntax through typed proxy host/domain/path
fields. Complex location expressions remain available to administrators.
This is not an audit of every upstream route or of a running deployment.

## Custom proxy directives

As an administrator, edit a Proxy Host and open its advanced/settings tab.
**Custom proxy location configuration** accepts Nginx location-context directives:

```nginx
proxy_set_header X-Example "value";
proxy_set_header X-Request-ID $request_id;
proxy_read_timeout 60s;
proxy_send_timeout 60s;
```

The API field is `proxy_config` (`proxyConfig` in frontend models), limited to
32,768 characters. It defaults to an empty string for existing rules and applies
to the generated default location and all generated custom paths. The existing
`advanced_config` remains server-context configuration; per-path
`advanced_config` remains available for path-specific settings.

Use actual directives such as `proxy_set_header`; `proxy_set_xxxx` is not a
literal Nginx directive. This field is Nginx configuration, not a shell-command
runner. Do not repeat built-in headers such as `Host`, `X-Forwarded-*`,
`X-Real-IP`, WebSocket headers, or the selected auth provider's identity headers:
Nginx may send duplicate headers rather than override them. Do not repeat
single-value directives already set by a generated location. On unprotected
hosts, the separate built-in asset-cache location retains its own settings.
Manually authored `location` blocks in server advanced configuration must be
configured separately; automatic inheritance only covers generated locations.

The existing configure flow runs `nginx -t` before reloading. Invalid
configuration marks that host offline and retains a `.conf.err` for diagnosis;
it does not validate that an administrator's otherwise valid directives are
appropriate for the application. Raw Nginx configuration is a privileged
capability and must remain restricted to trusted administrators.

## OIDC upgrade configuration

Keep password login available while checking SSO. Configure the IdP callback as
`https://npm.example.com/api/oidc/callback` and set:

```yaml
environment:
  OIDC_ISSUER_URL: https://idp.example.com
  OIDC_CLIENT_ID: npm
  OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
  OIDC_BASE_URL: https://npm.example.com
  OIDC_SCOPE: openid email profile
  OIDC_AUTO_CREATE_USERS: "false"
  OIDC_ALLOW_EMAIL_LINKING: "false"
```

`OIDC_BASE_URL` must be an HTTPS origin with no path/query/fragment. The browser
must use that same canonical origin. Trusted existing `(issuer, subject)`
bindings continue to work. No secrets are exposed through `/tokens/oidc/config`.

To bind an existing local user for the first time, an operator who trusts the
IdP's verified-email ownership policy may temporarily opt in to
`OIDC_ALLOW_EMAIL_LINKING=true`, then turn it off after linking. It does not
replace an existing identity binding. Providers that omit `email_verified: true`
cannot link/create a new user through this flow. Operators may separately opt in
to `OIDC_AUTO_CREATE_USERS=true`; an administrator must grant the new user's
resource permissions afterward.

OIDC state remains single-instance, in memory. Restarting during a login or
routing the callback to another instance requires starting a new login. State
expires after 10 minutes and the post-callback result after 60 seconds.

Forward-auth examples:

```yaml
environment:
  AUTHELIA_UPSTREAM_URL: http://authelia:9091/api/authz/auth-request
  OAUTH2PROXY_UPSTREAM_URL: http://oauth2-proxy:4180
```

OAuth2Proxy's URL is an origin without a path/query. Its default is
`http://127.0.0.1:4180`; Authelia has no default. The IdP and auth services still
need their normal redirect allowlists, TLS and session-cookie settings.
Before upgrading, back up the database and persistent data. The new migration
adds `proxy_host.proxy_config` and retains existing rules. MySQL/PostgreSQL
migration execution and a live IdP login have not been exercised in this task.

## Validation and remaining limitations

- Backend: 14 security/DDL regression tests pass: `cd backend && yarn test:security`.
  Covers browser binding, replay/expiry, email linking, issuer/subject binding,
  transaction rollback, local 2FA, admin permissions, injection checks, templates,
  actual Express HTTP routes and full SQLite fresh-install/upgrade migrations.
- Frontend: locale compilation, TypeScript/Vite production build and 57 Vitest
  tests pass, including StrictMode callback behavior and rejecting URL credentials.
- `cd backend && node test/nginx-integration.mjs`: official `nginx:stable-alpine`
  (Nginx 1.30.6 during verification), 12 path scenarios / 24 HTTP checks, custom
  header delivery, access-list interaction and invalid-directive rejection pass.
  Auth services are local test doubles, not live Authelia/OAuth2Proxy instances.
- Chromium: the real built form accepts multiline directives and submits the
  correct `proxy_config` JSON field without page errors. API responses are stubbed;
  backend persistence and template generation are verified separately.
- API schema validation and `git diff --check` pass. The installed upstream
  Biome 2.6.4 executable was truncated and crashed; changed code was checked with
  Biome 2.4.15 and a compatible copy of the repository rules instead. The project
  dependency versions were not downgraded.

Production dependency audit on 2026-11-07 found no frontend advisories, but two
remain in the upstream backend lockfile:

| Severity | Dependency path | Advisory |
| --- | --- | --- |
| High | `proxy-agent > pac-proxy-agent > get-uri > basic-ftp@5.3.1` | [Directory-list parser CPU DoS](https://github.com/advisories/GHSA-c475-qrg2-pj4r); advisory lists fix >=6.2.1. |
| Moderate | `archiver > readdir-glob > minimatch@10.2.6` | [Glob-parts amplification DoS](https://github.com/advisories/GHSA-g3hv-75wg-m249); advisory lists fix >=11.0.1. |

The vulnerable operations require attacker-controlled FTP directory listings or
glob patterns, respectively; their reachability in a deployment has not been
established here. Both fixes cross the parents' declared major-version ranges.
This branch leaves those upstream dependency constraints intact rather than
forcing unverified major overrides. Follow up with compatible parent-package
updates and targeted tests. The full NPM Docker image, complete Cypress suite,
production configuration and a real IdP have not been tested, so passing these
checks is not a blanket security certification.

# Nginx security update (2026-11-20)

This fork uses **OpenResty**, not the standalone Nginx image. The latest
OpenResty release is 1.31.8.1. Its Nginx 1.31.8 core predates the November
Nginx 1.31.9 security release. Merely rebuilding against a floating
`nginxproxymanager/nginx-full:certbot-node` tag does not fix the whole set.

## Sources and scope

- [Nginx security advisories](https://nginx.org/en/security_advisories.html)
- [Nginx 1.31.9 changes](https://nginx.org/en/CHANGES)
- [OpenResty releases](https://openresty.org/en/download.html)
- [NPM base-image HTTP/2 backports](https://github.com/NginxProxyManager/docker-nginx-full/pull/44)

The base is pinned to the multi-platform image index
`nginxproxymanager/nginx-full:certbot-node@sha256:160438ca30f5d290dcc878f9fe32ecb142739a477bd6a508b852cc5a31f22dec`.
Its amd64/arm64 BuildKit provenance identifies upstream base-image revision
`38654e0736c19578e0045678480622e48473878c`. It includes the two HTTP/2
backports, but not all of the other November fixes.

Both production and development builds recompile the official OpenResty
1.31.8.1 source bundle with the vendored, unmodified
[Nginx 1.31.8 → 1.31.9 diff](https://github.com/nginx/nginx/compare/release-1.31.8...release-1.31.9).
The release commits are `140aa942711868a8daeb95810bc9a81f272ada72`
and `c2c44702c2fbc572e4cfb0a52331061d7fcaca16`, respectively.
Only `src/*` is applied, excluding `src/core/nginx.h`. This preserves
OpenResty's own version header and its existing source changes while applying
all other upstream source changes in that release, including prerequisite
changes and related correctness fixes. Patch application fails the build on
conflicts; it never silently skips a hunk. The input patch has SHA-256
`b558e870b82621bc6a4edc665a55bfa2ec0073b5884abcb14864a5802edf6ed7`.

This includes the November fixes for:

| Area | CVEs |
| --- | --- |
| HTTP/2 | CVE-2026-123007, CVE-2026-123633 |
| Resolver | CVE-2026-123634 |
| HTTP/3 | CVE-2026-121810 |
| TLS request-body reading | CVE-2026-118899 |
| Mail proxy | CVE-2026-113425 |
| PROXY protocol v2 | CVE-2026-120993 |
| `alias` with `try_files` | CVE-2026-125283 |
| Stream client certificates and SNI | CVE-2026-120967 |
| Stream TLS preread | CVE-2026-123640 |

The builder retains the base's configure options and bundled OpenResty
modules, links against its existing LuaJIT installation, and rebuilds both
GeoIP2 dynamic modules from pinned commit
`445df24ef3781e488cee3dfe8a1e111997fc1dfe`. Only the Nginx executable and
matching `.so` modules are copied into the runtime base. Build dependencies
and downloaded source stay in the builder stage. The source archives are
SHA-256 checked in `docker/scripts/build-nginx-security`.

`nginx -V` reports **openresty/1.31.8.1 (npm-nginx-1.31.9-backport)**.
This is a fork backport, not an official OpenResty 1.31.9 release. Scanners
that inspect only the version string may still flag these CVEs; retain the
image digest, source patch and build provenance as evidence. This update
does not imply that unrelated application or OS dependencies have no CVEs.

## Build and verify

Build the frontend as in `.github/workflows/docker-publish.yml`, then:

```sh
docker buildx build --load --platform linux/amd64 -f docker/Dockerfile -t npm-security:local .
docker run --rm --entrypoint nginx npm-security:local -V
python3 test/host-header-smoke.py npm-security:local
```

The smoke test boots a disposable NPM container with a fresh SQLite database,
checks manager health and the generated Nginx configuration, exercises HTTP
and HTTPS default/custom locations, port-preserving Host/Origin/Referer
forwarding and cache isolation, verifies Lua execution, and sends 24
multiplexed HTTP/2 requests. It uses a local TLS backend and test certificates;
it is not a live IdP, ACME-provider or production deployment test. It verifies
runtime compatibility, not a proof that every vulnerability is unexploitable.
The publish workflow requires this test before pushing amd64/arm64 images.

Local validation on 2026-11-20 passed: complete amd64 image build, frontend
locale/TypeScript/Vite production build, 42 proxy smoke checks, 24 multiplexed
HTTP/2 requests, Lua over HTTP and HTTPS, all 15 backend security tests and API
schema validation (with development dependencies installed in a disposable
container). Both Dockerfiles passed BuildKit checks. The cloud build used the
environment's CA through a temporary BuildKit secret; no CA was added to the
repository or runtime image. Arm64 is built by the publish workflow; it was not
executed locally.

For deployment, back up `/data` and `/etc/letsencrypt`, retain the previous
image digest for rollback, then pull and recreate the existing Compose service
using the new published image. A pull alone does not replace a running
container. Verify `nginx -V`, `nginx -t`, manager health, HTTPS proxying and
your real SSO/certificate renewal setup afterward.

Before this update, GHCR `latest` resolved to
`ghcr.io/arnotho/nginx-proxy-manager@sha256:271a9921a349eeaf2b0f93579bfdf56fc1836c83a213658b92deb0562a3251cd`.
This records the previous published artifact, not the image currently running
on any server; inspect your deployment before selecting a rollback image.

When an official OpenResty release incorporating these fixes becomes available,
replace this temporary rebuild with a verified, pinned NPM base that contains
that release, remove the backport stage/patch, and repeat the runtime checks.

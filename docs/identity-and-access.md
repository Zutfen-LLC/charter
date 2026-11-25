# Identity, project isolation and role separation (C03, #3)

Synthetic data only. Authorization is enforced by the control plane on every request; the client is untrusted.

## Authentication
- `Authorization: Bearer <JWT>` is the only credential. Tokens must be **RS256**, signed by a key in the configured issuer's JWKS; `alg: none`, HS*, unknown `kid` and `crit` headers are refused.
- The token must match the configured **issuer** (exact), **audience**, and **tenant claim** (`tid`) equal to `CHARTER_OIDC_TENANT_ID`; `exp`/`iat`/`nbf` are checked (30 s leeway) and `exp - iat` may not exceed 1 h.
- Identity is the validated **(issuer, tenant, subject)**. It is mapped to a pre-provisioned user via `identities`; unknown subjects are refused (403), never auto-created. **Email and other claims, headers and query parameters are never used for identity.** A validly signed token for another tenant is refused (401).
- Failures return a generic 401; detail goes to the server log only.

## Configuration
| Variable | Meaning |
| --- | --- |
| `CHARTER_OIDC_TENANT_ID` | Required tenant claim value (Entra tenant id of the designated test tenant) |
| `CHARTER_OIDC_AUDIENCE` | Application (client) id / API URI the token is issued for |
| `CHARTER_OIDC_ISSUER`, `CHARTER_OIDC_JWKS_URL` | Default to Entra v2 (`https://login.microsoftonline.com/<tid>/v2.0` and `/<tid>/discovery/v2.0/keys`); set both explicitly for another IdP |

With none set, only `/healthz` and `/readyz` are served. The JWKS fetch is the only outbound call and goes only to the configured URL. No tenant ids or secrets are committed. Entra live testing needs a designated test tenant and is **not exercised in CI**; it is a recorded gap until run (users must be provisioned with `identities.subject` = the token's `sub`).

CI and local tests use `internal/oidc/syntheticidp`, an in-process IdP that serves a real JWKS over HTTP and mints valid and forged tokens. It has no authentication of its own and is test-only.

## Authorization model
Matches [role-matrix.md](contracts/role-matrix.md): **project_member** (per project) is the only way to read workspace content; **tenant_admin**, **records_officer**, **export_reviewer** and **operator** are disjoint tenant capabilities with **no implicit read-through** (an admin or records officer who is not a project member gets 404 on that project's artifacts, lists and search).
- Every route is registered through one wrapper that authenticates first (`TestEveryRouteRequiresAuthentication` checks each route returns 401 without a valid token).
- Project data queries filter by `tenant_id` **and** membership in SQL (lists, search, direct IDs, artifact content URLs). Non-member and nonexistent are indistinguishable (404).
- Composite foreign keys make cross-tenant rows impossible even if application code is wrong.
- Role-gated routes re-read the role from the database. Holds/exports (`POST /v1/holds`, `/v1/exports`, `/approve`) enforce authorization now and return **501** after the check: the operations land in #7/#8. Admins cannot grant themselves `records_officer`/`export_reviewer`, and the last `tenant_admin` cannot be removed. Role/membership/disable changes are written to an append-only `audit_log`.
- `POST /v1/projects/{id}/model-calls` is an authorization stub (no adapter until #5).

## Revocation: propagation bound
| Path | Bound |
| --- | --- |
| Project membership, role, user disable (control-plane change) | **Immediate for the next request.** No authorization decision is cached; each request reads committed state. A still-valid token ("cached session") gains nothing. |
| Request already in flight | Model calls re-check membership and account status **after the work and before releasing output**; if revoked, output is discarded and 403 returned. The window is the work duration, capped by `WorkTimeout` (default 60 s). Bytes already streamed before a revocation cannot be recalled; streaming (not in this slice) must re-check per chunk. |
| IdP-side revocation (user disabled at Entra, key withdrawn) | **Not immediate.** An already-issued token stays valid until `exp` (≤ 1 h by `MaxLifetime`, typically shorter); a withdrawn signing key is honoured for at most the JWKS cache TTL (5 min). To cut access at once, disable the user or remove membership in Charter. |

## Not covered
No interactive login/session flow (bearer tokens only), no UI, no SCIM/automatic provisioning, no break-glass, no multi-tenant-per-instance issuer trust (one configured tenant per instance), and no live Entra test in CI.

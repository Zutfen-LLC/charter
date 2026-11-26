# Identity, project isolation and role separation (C03, #3)

Synthetic data only. Authorization is enforced by the control plane on every request; the client is untrusted.

## Authentication
`Authorization: Bearer <JWT>` is the only credential. Identity is the validated **(issuer, tenant, subject)**, mapped to a **pre-provisioned** user through `identities`. Unknown subjects get 403 and are never auto-created. Email and other claims, headers, cookies and query parameters are never used for identity. Validation failures return a generic 401; detail goes to the server log.

### Accepted token profile
A delegated-user **access token for this API**:
- JWS **RS256** signed by a key in the configured issuer's JWKS. Header `typ` absent, `JWT` or `at+jwt`; no `crit`. `none`, HS*, unknown `kid` refused.
- `iss` exact; `aud` equals the configured audience as a string **or a one-element array**. A **multi-audience token is refused** (it was minted for other relying parties as well and could be replayed against them).
- The tenant claim (`tid`) equals `CHARTER_OIDC_TENANT_ID`. A validly signed token for another tenant is refused.
- `exp` and `iat` are required, `nbf` optional but **validated if present**. All must be JSON numbers in (0, 9999-12-31]; strings, null, booleans, negatives, zero and overflow are rejected rather than ignored. `exp > iat`, `exp - iat <= 1h`, `nbf < exp`; `exp`/`nbf`/`iat` are checked with 30 s leeway.
- **Delegated-user purpose is proven positively.** `scp` must be present, a JSON string of single-space-separated scope tokens, and contain **exactly** `CHARTER_OIDC_REQUIRED_SCOPE`. Missing, empty, non-string, malformed (leading/trailing/double spaces, tabs, newlines, quotes, commas), substring (`charter.access.admin`) and case-different values are refused. ID tokens and app-only (client-credentials) tokens carry no delegated `scp` and are therefore refused whatever other claims they have (`roles` alone never suffices). Tokens with a `nonce` or an `idtyp` other than `user` are additionally refused as defense in depth, but nothing depends on those being present. A token carrying other scopes in addition to the required one, or user app `roles`, is accepted.
- **There is no permissive fallback:** the server will not start, and `oidc.NewVerifier` returns an error, without a valid required scope.

### Designated Entra test tenant: required registration (not yet verified live)
The profile follows Microsoft's documented v2.0 access-token format. For it to hold, the tenant needs:
1. A **dedicated API app registration** for Charter (separate from any client/SPA/native registration). Its `aud` is the audience you set in `CHARTER_OIDC_AUDIENCE`; no client may use it for sign-in ID tokens.
2. The API registration's manifest sets `accessTokenAcceptedVersion` to `2`, so tokens carry `iss` `https://login.microsoftonline.com/<tenant-id>/v2.0` and `ver` `2.0`.
3. A **delegated** scope exposed by that API (for example `charter.access`; set `CHARTER_OIDC_REQUIRED_SCOPE=charter.access`, the scope *name*, which is what appears in `scp`, not the `api://` URI). Clients request `api://<api-app>/charter.access`.
4. **Token lifetime ≤ 1 hour.** Entra's default access-token lifetime is a random 60-90 minutes, which this verifier rejects (`exp - iat <= 1h`). Assign a token-lifetime policy to the API (e.g. 30-60 min). Shorter lifetimes also shorten the IdP-side revocation bound below.
5. Users are provisioned in Charter with `identities.subject` equal to the token's `sub`. Entra `sub` is pairwise per application, so it differs between the API and any other app.

**Live Entra compatibility has not been demonstrated.** None of the above has been exercised against a real tenant; CI uses only the synthetic IdP, whose default tokens mirror this profile (`scp`, `ver`, `tid`, `typ` JWT). It is a recorded gap until run against the designated test tenant.

### Configuration (`CHARTER_OIDC_*`)
| Variable | Meaning |
| --- | --- |
| `TENANT_ID` | Required tenant claim value (Entra tenant id) |
| `AUDIENCE` | API audience the token is issued for |
| `ISSUER`, `JWKS_URL` | Both unset: Entra v2 defaults derived from the tenant id. Otherwise **both** must be set. |
| `REQUIRED_SCOPE` | **Required.** One scope name that must appear exactly in `scp` (no default) |
| `INSECURE_LOOPBACK_FIXTURE` | `true` allows plain-HTTP issuer/JWKS on **loopback hosts only**, for local fixtures; default off |

If any setting is present, startup **fails** unless the whole configuration validates: issuer and JWKS URL must be clean absolute **https** URLs (no userinfo, fragment or query), Entra issuer/JWKS paths must match the tenant id, and a partial configuration is an error, never silently "no auth". With none set, only `/healthz` and `/readyz` are served. No tenant ids or secrets are committed.

### JWKS fetching
The only outbound call identity makes, to the configured URL. https only (loopback http only with the fixture flag, enforced in the fetcher as well as in config); **redirects are not followed**; 5 s timeout and 1 MiB cap per fetch; one refresh at a time and no lock held during I/O, so a slow IdP never delays requests whose key is cached. Keys are served only while younger than the 5 min TTL; **expired keys are never used as a fallback**. Every refresh attempt (empty cache, expired cache, unknown `kid`) is throttled to one per 15 s whether or not it succeeded, so an unavailable IdP or `kid` flooding cannot amplify into outbound requests; callers within the window fail closed without network I/O.

## Authorization model
Per [role-matrix.md](contracts/role-matrix.md): **project_member** (per project) is the only way to read workspace content. **tenant_admin, records_officer, export_reviewer, operator** are separate tenant capabilities with **no implicit read-through** (404 on a project's artifacts, lists, search and model calls without membership). One person may hold several explicitly granted roles.
- Every route is registered through one wrapper that authenticates first. Coverage is checked against a **hand-written route table independent of the registry**, with a source check that nothing registers on the mux outside the wrapper and the two health routes, and across methods incl. HEAD.
- Identifiers are **canonicalized to lowercase at the store boundary** (`store.CanonicalID`) for every identifier-bearing operation, in Go comparisons and SQL alike, so no UUID spelling changes a decision. This covers **the `Principal` too**: its user and tenant ids are canonicalized (and must be UUIDs) in every store operation, so a noncanonical principal cannot defeat the self-grant comparison. A malformed principal is refused by every administrative mutation (`ErrForbidden`, no audit row) and returns nothing from reads. Audit rows hold canonical ids only.
- Every read is filtered in SQL by tenant, project membership **and an active user** (lists, search, direct ids, artifact content URLs). A `Principal` resolved before a disable returns nothing afterwards. Non-member and nonexistent are indistinguishable (404). Composite foreign keys prevent cross-tenant rows.
- **Administrative mutations** (membership, roles, disable) share one protocol: lock the tenant row (`FOR NO KEY UPDATE`) → re-verify the actor is still an **active** `tenant_admin` → check invariants → mutate and write the audit row in one transaction. So a concurrently revoked or deactivated administrator cannot commit, and the tenant always keeps **at least one active `tenant_admin`** (disabled admins keep role rows but do not count; applies to role revocation and to disabling). Nobody can self-grant `records_officer`/`export_reviewer`. Only actual changes are audited. The audit log is append-only.
- **Verified authorization stubs, not functional behavior:** `POST /v1/holds`, `/v1/holds/{id}/release`, `/v1/exports`, `/v1/exports/{id}/approve` enforce roles and then return **501**; `POST /v1/projects/{id}/model-calls` enforces membership and the release gate below and records evidence ([evidence capture](evidence-capture.md)), but still has **no real model adapter** (#5). Holds, export and routing belong to #5–#8.

## Revocation: propagation and in-flight behavior
| Path | Guarantee |
| --- | --- |
| Membership, role, user disable (control-plane change) | **Effective for every request that starts after the change commits.** No authorization decision is cached; every request reads committed state. A still-valid token gains nothing. |
| Model call in flight | Work runs on the request goroutine under `WorkTimeout` (default 60 s). **That deadline is cooperative**: the handler cannot preempt `Work` and starts no background goroutine, so actual execution is bounded only by the adapter's own enforced timeouts (#5). The release path is: (1) drop output if the work context is already done; (2) **one authoritative query "user active AND project member"** on its own context bounded by `ReleaseCheckTimeout` (default 2 s) so cancellation can neither abort it into an allow nor leave it unbounded; (3) **final gate immediately before writing the response**: drop the output if the work context expired (504) or was cancelled (503) while the query ran. The linearization point is the query's read: revocations committed before it are honoured, later ones are not reflected in that response. Any failure, including an unavailable or too-slow database, returns no output (503). Output the adapter already sent to a provider cannot be recalled; ADR 0001 R1/R2 attach to this same gate: the intent is durable before dispatch and the output is durable before the gate runs (#4). |
| IdP-side revocation (user disabled or session revoked at the IdP) | **Not immediate.** An already-issued token is accepted until `exp + 30 s` leeway, and `exp - iat <= 1 h`, so at most **1 h 30 s**. A withdrawn signing key is honoured for at most the **5 min** JWKS TTL (it does not extend a token's own bound). To cut access at once, disable the user or remove membership in Charter. |

## Not covered
No interactive login/session flow (bearer tokens only), no UI, no SCIM, no break-glass, one trusted tenant per instance, no HTTP server read/write timeouts beyond header timeout (a streaming design in #5 must add them), and **no live Entra test**. Test-database and CI results demonstrate the synthetic IdP only.

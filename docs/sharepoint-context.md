# C06: Permission-bound document excerpts

## Implementation invariants (pre-change design)

- Only the authenticated model-call route can request an external excerpt. Client input is an opaque document ID, expected provider-native version, and byte range, never a URL, credential, provider response, identity assertion, or cached permission. Workspace IDs remain distinct. Membership precedes any connector operation. The server owns one tenant/project/site/library scope and an authenticated user-to-delegated-subject mapping.
- Connector output is not prompt context unless a fresh delegated read proves authorization and exact version/bytes. Revalidate the same binding before disclosure intent, at final dispatch, at initial release, at recorder delivery (including replay), and at the HTTP write. No permission cache, subset fallback, or identity substitution. Cancellation and current membership checks remain mandatory. External ACL visibility and the interval between the last external response and the subsequent local action cannot be made atomic by Charter.
- Contributed content and its derivative outputs exist only in scoped turn evidence and the original actor's authorized response. Workspace list, search, direct artifact/content lookup and workspace reuse continue to query only workspace artifacts; no API publishes an excerpt or derivative there. Holds/exports do not become content routes in C06. There is no share/write/import endpoint. Copying content manually after lawful delivery is outside this control boundary.
- Ordered source bindings contribute to a new request fingerprint version only for external-source turns. The request and excerpt objects are sealed before provider work, and acknowledged intent and exact-version storage checks remain authoritative. Replay is scoped to the original custodian and selection and can return only the verified original output; a fresh delegated read is authorization/version proof, never historical reconstruction. Recovery must not contact the connector or model. Evidence reconstruction does not concern current access and uses retained bytes only.
- External-source turns use C05 governance exclusively. Pre-dispatch refusal is not a billable call; post-dispatch refusal does not remove incurred obligations. Existing configuration and retained network isolation do not gain any authority to contact Microsoft.

## Serving and retention semantics

`POST /v1/projects/{id}/model-calls` adds optional `sharepoint_sources`, e.g.
`[{"document_id":"opaque-id","version":"1.0","offset":0,"length":32}]`.
The positions are zero-based UTF-8 byte offsets, not character indexes; a range
that splits a code point is refused. The contract places legacy `artifact_ids`
first, then the external selections in the order submitted. Both are bounded;
there is no enumeration, path-based lookup, search, sharing, save-as-artifact,
or transitive derivative reuse endpoint. An evidence turn UUID is not a
workspace artifact ID. The external binding is restricted even if the response
contains none of the input text. Workspace membership remains mandatory and
no tenant role confers source access.

The required version is the current native version at each check. Charter does
not try another version when it changes. Stable item IDs, not names, select the
item, so an in-library rename may preserve access if the binding still verifies;
a move out of scope or a recreated item with a different stable identity does
not. A later valid request with new binding under an already admitted key is a
conflict for that custodian. A request that cannot verify the original binding
returns no output, even if the key and historical evidence are otherwise valid.
A repeated key under a different custodian is a separate key namespace, not
a right to replay the first custodian's output. Replaying never charges for or
invokes a model. It reads historical output, not freshly produced output.

`source_binding_version: 1` is an additive mandatory extension when an external
source participates. The v3 fingerprint binds the ordered sources, digest,
length, identity, version, validator, document digest, selector and (if specified) registry
model without binding the timestamp of a fresh observation. `context_sealed`
keeps the original decision and observation; `output_recorded` and
`response_released` bind the exact sealed source list by digest. Offline full
verification compares the recorded source objects against the actual canonical
request. `response_released` remains authorization, not client receipt. No
successful current delivery may be inferred from an old record. Historical C03–
C05 evidence and fingerprints are unmodified. The retained profile keeps its
existing signed receipt/version references and coordination authority. Only
excerpts are preserved, not whole external documents or the library.

## Separate live smoke procedure — not authorized or run here

Prerequisite: separate approval of the exact synthetic tenant, test users,
SharePoint site and library, registered client/API, read-only delegated scope,
Graph/Entra/download destination allowlist, credential custody, and an adapter
built and reviewed against `internal/sharepoint.Transport`. The standard
executable installs no Microsoft transport or credentials. Keep the retained
synthetic deployment disconnected and use a separate synthetic environment;
use the in-process model only. Stop rather than broadening the scope, adding
an application permission or using an operator's account to make a test pass.

1. Pre-provision the Charter tenant/project/users and stable Microsoft identity
   mappings. Use an identity-bound server-side broker over a validated
   Charter-audience assertion for Microsoft on-behalf-of delegation (Microsoft
   Learn: *Microsoft identity platform and OAuth 2.0 On-Behalf-Of flow*).
   Verify tenant, delegated principal and minimum read scope at the broker and
   establish equality with the server mapping. Refuse an incoming Graph token,
   app-only token, subject mismatch or consent/claims failure; never forward
   the inbound Charter authorization header to Graph or download endpoints.
2. Create versioned synthetic UTF-8 documents under the configured library.
   Give two same-project identities unequal source permissions. Establish a
   separate reference byte digest out of band. Fetch the stable DriveItem ID's
   metadata and provider-native DriveItemVersion ID in the configured drive;
   require a matching version-bound read. Do not use `Last-Modified`, the ETag
   or a numeric conversion as the native version. Use read-only fixed paths.
3. Before using any version download redirect, require separately approved
   exact HTTPS endpoints, reject proxy/DNS/network escapes, userinfo, and
   further redirects, and never forward credentials or retain the download URL.
   Graph version content may return a preauthenticated redirect (Microsoft
   Learn: *Download a previous version*). The transport contract additionally requires authoritative exact-version content
   digest attestation. If the approved provider flow cannot establish that
   proof or cannot bind it to the delegated version and validator, stop; latest-content fallback
   is not qualification. Check cancellation, deadlines, size ceilings and that
   rejecting an unapproved redirect causes zero requests to its destination.
4. Submit one authorized request and compare exact excerpt, version, validator,
   full rendered request digest, accepted destination and derivative evidence.
   Submit the same selector as the denied user; demand zero model calls.
   Revoke access with the approved synthetic operator, record the first upstream
   refusal and the first Charter refusal, and exercise pre-dispatch, release,
   delivery and replay refusal. Never include credentials or signed URLs in
   evidence. Restore only fixture authorization where the approval permits it.
5. Edit the source, test the stale and new version against the same key, rename
   or move the item, delete it, and recreate a different item at the same name.
   Test connector unavailability and verify historical objects without a
   Microsoft connection. Require no new provider call, charge or retained
   mutation from replay/recovery. Record failures, cleanup or restore the
   synthetic fixture as approved, and report exact signed evidence locations.

External ACL propagation (including cached upstream behavior) is the external
system's responsibility; fresh Charter checks do not prove globally instant ACL
visibility. Checks and an outbound write cannot form a single transaction across
systems. With multiple sources checks are sequential and cannot establish an
atomic snapshot of all provider ACLs. A decision can change after the final
check, and already transmitted bytes or response data cannot be recalled.

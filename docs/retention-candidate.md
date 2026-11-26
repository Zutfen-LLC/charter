# Retention candidate: persistence and recovery

PostgreSQL remains the default and does not claim retention. Explicit `CHARTER_EVIDENCE_BACKEND=s3-object-lock` is a separate synthetic-only deployment. Startup requires a fresh signed storage-native qualification for the selected installation and current live readback of its pinned authority version. The Go/Python offline profile and simulated transport tests are not qualification.

## Authority

- PostgreSQL remains authoritative for live authorization and paired ownership/drain locks, not the retention evidence catalog. The candidate uses an owner-session transaction to check PostgreSQL durability and serialize remote writes, then checks both physical sessions again before returning success. It does not create a PostgreSQL evidence index. The existing PostgreSQL profile and tables are unchanged.
- A signed `charter.retained-commit.v1` record in COMPLIANCE storage is the commitment. Its slot key, tenant, project, turn, sequence, event hash, exact event version, all declared evidence object versions, and exact preceding marker version are bound to the signed content. Admission instead binds a domain-separated digest of tenant/project/custodian/idempotency key and the request fingerprint. Only a pinned independent Charter signing public key can authenticate a commit. Storage credentials alone cannot mint a commit. If the signing key is lost, independent read-only verification still works with the public key; writing does not.
- Event and object bytes are separate from commit records. An upload without a valid commitment is a retained orphan, not an event. Orphans are not automatically deleted. Listing is discovery, not authority: every relevant version is fetched using its own version ID, and bytes and retention are verified before use. There is no latest-version GET and no ETag digest shortcut.
- The implementation performs exhaustive bounded namespace scans for this synthetic pilot. An incomplete scan, missing predecessor, signature conflict, unverified retention, invalid bound bytes or a second signed version in the same slot blocks progress. An unsigned version cannot substitute an authentic marker. Assuming a trusted complete listing endpoint, index loss or workspace mutation cannot hide or redirect the chain. The scheme is not external anchoring and cannot prove completeness against an endpoint that falsifies inventory or loss of the whole deployment.

## Cross-store failure windows

| Failure point | Result |
| --- | --- |
| PostgreSQL session/durability unavailable before work | No receipt; no storage write is attempted. |
| Object/event staging succeeds but commit marker does not | Retained orphan. No logical admission/event. When its bytes are found, retry may reuse the exact verified version. |
| Staging PUT response lost | Exact-key version inventory plus SHA-256, length and protection resolves only an unambiguous candidate. No guessing or latest selection. |
| Conditional commit PUT response lost | Read all versions of the slot; use the unique signed record only after exact readback. An ambiguous admission never authorizes a new provider call: it returns the stored turn as an existing turn. |
| Commit marker written then PostgreSQL coordination commit fails | Return failure, do not delete. The S3 commitment remains authoritative for restart. No PG rows are required to reconstruct it. |
| PostgreSQL coordination succeeds but S3 rejects or is unavailable | No new commitment and no successful receipt. No hidden PostgreSQL-only fallback. |
| Both PG sessions fail while a remote request is in flight | A late remote write is not revocable. The candidate requires atomic conditional creation of a marker slot at the storage receiver. A lost final fence withholds success. A replacement never redispatches. |
| Intent acknowledgment exists without provider acceptance | Conservatively unknown, reserved-max settlement on recovery. |
| Output acknowledgment exists but policy or storage fails afterward | No output is returned. If release authorization was committed, recovery completes it and permits only a freshly authorized delivery replay. |

Gate readbacks run before last-mile authorization, cancellation and ownership checks. No storage writes sit between the last delivery check and output. The retained profile adds fresh authorization before dispatch as well. An exact-version readback must verify active COMPLIANCE protection at or beyond the signed deployment floor. New objects inherit the locked bucket's default rather than giving the runtime credential permission to set or mutate retention. PostgreSQL and storage are verified on readiness; mandatory storage is not a fallback tier.

The database owner binds the synthetic database to this profile and deployment, separately from provisioning. A legacy database with evidence already present cannot be relabeled by startup. The profile has no mutable authoritative PostgreSQL index to rebuild: a fresh read-only instance supplied with the trusted public key, deployment namespace and qualified storage can reconstruct from commit/version inventory without opening PostgreSQL. Workspace authorization remains a separate dependency for live delivery.

## No holds or purge

A current COMPLIANCE period can be extended, never shortened. An extension does not model a Charter hold. Multiple future holds are independent claims, and purge still needs the reviewed hold-epoch interlock. Expiry does not authorize deletion; no lifecycle, purge, or storage administration is exposed by Charter.

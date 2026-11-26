# Verifier profiles

Charter records `payload.evidence_profile = "charter-postgres-v1"` on new turn admissions. The profile applies to the whole turn, including resumed recovery after an upgrade. It uses the existing 1.0 event envelope; no golden event bytes or hashes change.

- **Structural** (`VerifyStructure` or Python `verify_turn` with no object map): checks structure, the hash chain, lifecycle, and the indicated profile. It does not check object bytes.
- **Legacy compatibility with object verification** (`VerifyFull` or `verify_turn` with an object map): checks every object a historical log actually declares. Historical admissions may have only `input_summary`; a successful check of those logs is not proof of exact input. Historical acknowledgements may omit `storage_level` and use an opaque receipt identifier. If a PostgreSQL storage level is present, its receipt must bind to the recorded target.
- **Complete current profile** (`VerifyCurrentFull` or Python `verify_current_full`): requires the caller to select current verification independently of log contents. An absent, changed, or unrecognized profile marker cannot downgrade this call. All declared objects must match in digest and byte count, including the exact original input.

The current profile checks user admission against the stated custodian, requires service actors for subsequent events (including startup recovery), and requires all three destination identifiers (provider, endpoint, model) in the allow policy, disclosure intent, and provider acceptance when present. Its acknowledgement must bind the immediately preceding intent or output, that event's hash, the PostgreSQL durable storage class, and the deterministic event receipt. Successful completion requires usage settlement. An unknown disclosure requires `reserved_max` settlement for the entire reservation before interruption.

A deterministic database receipt is not an independent attestation of a database's behavior. A verifier cannot prove provenance against someone authorized to recompute an entire unauthenticated chain, nor does verifying these PostgreSQL logs prove retention, immutability, or WORM. Replay also compares the stored exact input reference to the submitted bytes; compatibility-only summaries cannot authorize delivery.

## Retention candidate profile

`charter-s3-compliance-v1` uses explicit `VerifyRetentionFull` (Go) or `verify_retention_full` (Python). The caller must select this profile independently; removing it or replacing it with the PostgreSQL profile cannot downgrade that check. Conversely, PostgreSQL current-profile verification still requires `charter-postgres-v1`.

The acknowledgment adds `retained_receipt` and declares `s3:object-lock:COMPLIANCE`. The containing event hashes the receipt fields as usual. The receipt ID is SHA-256 over `CHARTER-RETAINED-RECEIPT-v1`, a NUL byte, and canonical receipt JSON. The receipt binds the deployment, tenant, acknowledged event identity and sequence, bucket, key, exact non-null version, SHA-256 of the full canonical event bytes, byte count, mode and timestamp. The explicit full verifier also checks the exact input and every declared object. The shared synthetic fixtures are not real storage receipts.

Offline receipt validation checks shape and internal binding. It cannot authenticate the S3 endpoint, verify whether that version ever existed, prove that an administrator was prevented from deleting the version, or prove an external anchor. Those require separate protected-version readback and a qualification run for the actual deployment and runtime credentials. A correctly formed receipt cannot substitute for those checks.

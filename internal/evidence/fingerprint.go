package evidence

// Fingerprint is the deterministic identity of a request for idempotency: it
// binds tenant, project, matter, custodian, the exact input (hash and length)
// and the ORDERED source selection (id, version, content hash and length).
// Volatile values (request id, timestamps, the idempotency key itself) are
// excluded. Two requests with the same key are the same request only if their
// fingerprints are equal.
func Fingerprint(r Request) (string, error) {
	srcs := make([]any, 0, len(r.Sources))
	for _, s := range r.Sources {
		srcs = append(srcs, s.descriptor(true, false))
	}
	identity := map[string]any{
		"v": 1, "tenant_id": r.TenantID, "project_id": r.ProjectID, "matter_id": r.MatterID,
		"custodian_id": r.CustodianID, "input": ref(r.Input), "sources": srcs}
	if r.ModelID != "" {
		identity["v"] = 2
		identity["model_id"] = r.ModelID
	}
	if r.external() {
		identity["v"] = 3
		identity["model_id"] = r.ModelID
	}
	c, err := Canonical(identity)
	if err != nil {
		return "", err
	}
	return SHA256(c), nil
}

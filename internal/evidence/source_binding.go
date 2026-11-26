package evidence

import "context"

// ExternalSource is the serving process's observation of a delegated, exact
// source read. Version is provider-native; it is never a workspace ordinal.
type ExternalSource struct {
	ConnectorID, ExternalTenantID, SiteID, LibraryID  string
	DocumentID, ProviderVersion, ETag, DocumentSHA256 string
	DelegatedSubject, CustodianID, ObservedAt         string
	Offset, Length                                    int
}

func (s ExternalSource) fields(observation bool) map[string]any {
	m := map[string]any{
		"connector_id": s.ConnectorID, "provider": "sharepoint", "external_tenant_id": s.ExternalTenantID,
		"site_id": s.SiteID, "library_id": s.LibraryID, "document_id": s.DocumentID,
		"provider_version": s.ProviderVersion, "etag": s.ETag, "document_sha256": s.DocumentSHA256, "delegated_subject": s.DelegatedSubject,
		"custodian_id": s.CustodianID, "offset": s.Offset, "length": s.Length, "extraction": "utf8-byte-range-v1",
	}
	if observation {
		m["decision"], m["observed_at"] = "allow", s.ObservedAt
	}
	return m
}

func (s Source) descriptor(includeLength, observation bool) map[string]any {
	m := map[string]any{"source_id": s.ID, "version": s.Version, "sha256": SHA256(s.Bytes)}
	if includeLength || s.External != nil {
		m["bytes"] = len(s.Bytes)
	}
	if s.External != nil {
		m["external"] = s.External.fields(observation)
	}
	return m
}

func (r Request) external() bool {
	for _, s := range r.Sources {
		if s.External != nil {
			return true
		}
	}
	return false
}

func (r Request) checkAccess(ctx context.Context, membership func(context.Context) error) error {
	if err := r.AuthorizeSources(ctx); err != nil {
		return err
	}
	return membership(ctx)
}

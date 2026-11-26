package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/sharepoint"
	"github.com/Zutfen-LLC/charter/internal/store"
)

func (a *Auth) externalSources(ctx context.Context, p store.Principal, project string, selections []sharepoint.Selection) ([]evidence.Source, func(context.Context) error, error) {
	read := func(ctx context.Context, selection sharepoint.Selection) (evidence.Source, error) {
		s, err := a.SharePoint.Read(ctx, p.TenantID, project, p.UserID, selection)
		switch {
		case errors.Is(err, sharepoint.ErrDenied):
			return evidence.Source{}, &gateError{http.StatusNotFound, "not found"}
		case errors.Is(err, sharepoint.ErrMismatch):
			return evidence.Source{}, &gateError{http.StatusConflict, "source version could not be verified"}
		case err != nil:
			return evidence.Source{}, &gateError{http.StatusServiceUnavailable, "source verification unavailable"}
		}
		return evidence.Source{ID: s.DocumentID, Bytes: s.Bytes, External: &evidence.ExternalSource{
			ConnectorID: s.Scope.ConnectorID, ExternalTenantID: s.Scope.ExternalTenantID, SiteID: s.Scope.SiteID,
			LibraryID: s.Scope.LibraryID, DocumentID: s.DocumentID, ProviderVersion: s.Version, ETag: s.ETag, DocumentSHA256: s.DocumentSHA256,
			DelegatedSubject: s.Subject, CustodianID: p.UserID, Offset: s.Offset, Length: s.Length,
			ObservedAt: s.ObservedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		}}, nil
	}
	selections = append([]sharepoint.Selection(nil), selections...)
	sources := make([]evidence.Source, 0, len(selections))
	for _, sel := range selections {
		s, err := read(ctx, sel)
		if err != nil {
			return nil, nil, err
		}
		sources = append(sources, s)
	}
	authorize := func(ctx context.Context) error {
		for i, sel := range selections {
			fresh, err := read(ctx, sel)
			if err != nil {
				return err
			}
			x, y := *sources[i].External, *fresh.External
			x.ObservedAt, y.ObservedAt = "", ""
			if x != y || !bytes.Equal(sources[i].Bytes, fresh.Bytes) {
				return &gateError{http.StatusConflict, "source version could not be verified"}
			}
		}
		return workContextErr(ctx)
	}
	return sources, authorize, nil
}

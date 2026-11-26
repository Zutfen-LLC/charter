package sharepoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrDenied      = errors.New("sharepoint: denied")
	ErrUnavailable = errors.New("sharepoint: unavailable")
	ErrMismatch    = errors.New("sharepoint: snapshot mismatch")
)

const (
	MaxSourceBytes  = 8 << 20
	MaxExcerptBytes = 64 << 10
	ReadTimeout     = 10 * time.Second
)

type Scope struct {
	ConnectorID, TenantID, ProjectID, ExternalTenantID, SiteID, LibraryID string
	Delegates                                                             map[string]string
}
type Selection struct {
	DocumentID string `json:"document_id"`
	Version    string `json:"version"`
	Offset     int    `json:"offset"`
	Length     int    `json:"length"`
}
type Snapshot struct {
	Scope                                              Scope
	Subject, DocumentID, Version, ETag, DocumentSHA256 string
	Offset, Length                                     int
	Bytes                                              []byte
	ObservedAt                                         time.Time
}
type Metadata struct{ TenantID, SiteID, LibraryID, DocumentID, Version, ETag, ContentSHA256, DelegatedSubject string }
type Document struct {
	Metadata
	Content []byte
}

// Transport must use the supplied delegated subject, enforce provider ACLs on every operation,
// bind all requests to the configured scope, and provide no caller-controlled URL surface.
// Implementations must use approved egress and protect delegated credentials at rest/in transit.
// Metadata must attest the digest of the exact native version's bytes, not a
// hash inferred from an ETag or from a differently authorized fetch. ReadVersion
// must return authoritative metadata for the bytes actually read (never an echo
// of the caller's expectation). Apply MaxSourceBytes while reading from the
// wire, with cooperative cancellation; no fallback to a different version.
type Transport interface {
	Metadata(context.Context, Scope, string, string) (Metadata, error)
	ReadVersion(context.Context, Scope, string, Metadata) (Document, error)
}
type Connector struct {
	scope     Scope
	transport Transport
}

func New(scope Scope, transport Transport) (*Connector, error) {
	if transport == nil || !validID(scope.ConnectorID) || !validID(scope.TenantID) || !validID(scope.ProjectID) || !validID(scope.ExternalTenantID) || !validID(scope.SiteID) || !validID(scope.LibraryID) || len(scope.Delegates) == 0 {
		return nil, ErrDenied
	}
	d := make(map[string]string, len(scope.Delegates))
	subjects := map[string]bool{}
	for u, s := range scope.Delegates {
		if !validID(u) || !validID(s) || subjects[s] {
			return nil, ErrDenied
		}
		d[u] = s
		subjects[s] = true
	}
	scope.Delegates = d
	return &Connector{scope, transport}, nil
}
func validID(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

// Synthetic reports whether the transport is the concrete no-network fake.
func (c *Connector) Synthetic() bool {
	if c == nil {
		return false
	}
	_, ok := c.transport.(*Fake)
	return ok
}

func (c *Connector) Read(ctx context.Context, tenant, project, user string, sel Selection) (Snapshot, error) {
	if c == nil || c.transport == nil || ctx == nil || !validID(tenant) || !validID(project) || !validID(user) || tenant != c.scope.TenantID || project != c.scope.ProjectID {
		return Snapshot{}, ErrDenied
	}
	subject, ok := c.scope.Delegates[user]
	if !ok || !validID(sel.DocumentID) || !validID(sel.Version) || sel.Offset < 0 || sel.Length <= 0 || sel.Length > MaxExcerptBytes || sel.Offset > MaxSourceBytes-sel.Length {
		return Snapshot{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	scope := c.scope
	scope.Delegates = nil
	before, err := c.transport.Metadata(ctx, scope, subject, sel.DocumentID)
	if err != nil {
		return Snapshot{}, transportError(err)
	}
	if !matches(scope, before, sel.DocumentID, subject) {
		return Snapshot{}, ErrDenied
	}
	if before.Version != sel.Version {
		return Snapshot{}, ErrMismatch
	}
	doc, err := c.transport.ReadVersion(ctx, scope, subject, before)
	if err != nil {
		return Snapshot{}, transportError(err)
	}
	if doc.Metadata != before || len(doc.Content) > MaxSourceBytes || digest(doc.Content) != before.ContentSHA256 || !utf8.Valid(doc.Content) || sel.Offset+sel.Length > len(doc.Content) {
		return Snapshot{}, ErrMismatch
	}
	excerpt := doc.Content[sel.Offset : sel.Offset+sel.Length]
	if !utf8.Valid(excerpt) {
		return Snapshot{}, ErrMismatch
	}
	after, err := c.transport.Metadata(ctx, scope, subject, sel.DocumentID)
	if err != nil {
		return Snapshot{}, transportError(err)
	}
	if !matches(scope, after, sel.DocumentID, subject) {
		return Snapshot{}, ErrDenied
	}
	if before != after {
		return Snapshot{}, ErrMismatch
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrUnavailable
	}
	return Snapshot{Scope: scope, Subject: subject, DocumentID: sel.DocumentID, Version: after.Version, ETag: after.ETag, DocumentSHA256: after.ContentSHA256, Offset: sel.Offset, Length: len(excerpt), Bytes: append([]byte(nil), excerpt...), ObservedAt: time.Now().UTC()}, nil
}
func matches(s Scope, m Metadata, id, subject string) bool {
	return m.DelegatedSubject == subject && m.TenantID == s.ExternalTenantID && m.SiteID == s.SiteID && m.LibraryID == s.LibraryID && m.DocumentID == id && validID(m.Version) && validID(m.ETag)
}
func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func transportError(err error) error {
	switch {
	case errors.Is(err, ErrDenied):
		return ErrDenied
	case errors.Is(err, ErrMismatch):
		return ErrMismatch
	default:
		return ErrUnavailable
	}
}

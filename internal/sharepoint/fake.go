package sharepoint

import (
	"context"
	"sync"
	"sync/atomic"
)

// Fake is a deterministic, shared, mutable Transport for tests; maps and counters are concurrency-safe.
type Fake struct {
	mu            sync.RWMutex
	docs          map[string]Document
	acl           map[string]map[string]bool
	outage        error
	BeforeRead    func()
	AfterRead     func()
	MetadataCalls atomic.Int64
	ReadCalls     atomic.Int64
}

func NewFake() *Fake { return &Fake{docs: map[string]Document{}, acl: map[string]map[string]bool{}} }
func (f *Fake) Put(d Document) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d.Content = append([]byte(nil), d.Content...)
	d.ContentSHA256 = digest(d.Content)
	f.docs[d.DocumentID] = d
}
func (f *Fake) Grant(id, subject string, allowed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acl[id] == nil {
		f.acl[id] = map[string]bool{}
	}
	f.acl[id][subject] = allowed
}
func (f *Fake) SetOutage(err error) { f.mu.Lock(); f.outage = err; f.mu.Unlock() }
func (f *Fake) Metadata(ctx context.Context, s Scope, subject, id string) (Metadata, error) {
	f.MetadataCalls.Add(1)
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.outage != nil {
		return Metadata{}, f.outage
	}
	d, ok := f.docs[id]
	if !ok || d.TenantID != s.ExternalTenantID || d.SiteID != s.SiteID || d.LibraryID != s.LibraryID || !f.acl[id][subject] {
		return Metadata{}, ErrDenied
	}
	d.DelegatedSubject = subject
	return d.Metadata, nil
}
func (f *Fake) Delete(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.docs, id)
	delete(f.acl, id)
}
func (f *Fake) ReadVersion(ctx context.Context, s Scope, subject string, expected Metadata) (Document, error) {
	f.ReadCalls.Add(1)
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	if f.BeforeRead != nil {
		f.BeforeRead()
	}
	f.mu.RLock()
	outage := f.outage
	d, ok := f.docs[expected.DocumentID]
	allowed := f.acl[expected.DocumentID][subject]
	f.mu.RUnlock()
	if outage != nil {
		return Document{}, outage
	}
	if !ok || !allowed || d.TenantID != s.ExternalTenantID || d.SiteID != s.SiteID || d.LibraryID != s.LibraryID {
		return Document{}, ErrDenied
	}
	d.DelegatedSubject = subject
	if d.Metadata != expected || len(d.Content) > MaxSourceBytes {
		return Document{}, ErrMismatch
	}
	d.Content = append([]byte(nil), d.Content...)
	if f.AfterRead != nil {
		f.AfterRead()
	}
	return d, nil
}

var _ Transport = (*Fake)(nil)

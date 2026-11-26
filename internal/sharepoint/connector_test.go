package sharepoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Connector, *Fake) {
	t.Helper()
	f := NewFake()
	f.Put(Document{Metadata: Metadata{TenantID: "ext", SiteID: "site", LibraryID: "lib", DocumentID: "doc", Version: "v1", ETag: "e1"}, Content: []byte("hello world")})
	f.Grant("doc", "subject", true)
	c, e := New(Scope{ConnectorID: "c", TenantID: "t", ProjectID: "p", ExternalTenantID: "ext", SiteID: "site", LibraryID: "lib", Delegates: map[string]string{"user": "subject"}}, f)
	if e != nil {
		t.Fatal(e)
	}
	return c, f
}
func TestReadExactPermissionBoundExcerpt(t *testing.T) {
	c, _ := fixture(t)
	got, e := c.Read(context.Background(), "t", "p", "user", Selection{DocumentID: "doc", Version: "v1", Offset: 6, Length: 5})
	if e != nil || string(got.Bytes) != "world" || got.Subject != "subject" || got.Scope.Delegates != nil {
		t.Fatalf("snapshot=%+v err=%v", got, e)
	}
}
func TestReadDeniedBeforeTransport(t *testing.T) {
	c, f := fixture(t)
	_, e := c.Read(context.Background(), "t", "other", "user", Selection{DocumentID: "doc", Version: "v1", Length: 5})
	if !errors.Is(e, ErrDenied) || f.MetadataCalls.Load() != 0 {
		t.Fatalf("err=%v calls=%d", e, f.MetadataCalls.Load())
	}
}
func TestReadRejectsChangedVersion(t *testing.T) {
	c, f := fixture(t)
	f.AfterRead = func() {
		f.Put(Document{Metadata: Metadata{TenantID: "ext", SiteID: "site", LibraryID: "lib", DocumentID: "doc", Version: "v2", ETag: "e2"}, Content: []byte("hello world")})
	}
	_, e := c.Read(context.Background(), "t", "p", "user", Selection{DocumentID: "doc", Version: "v1", Offset: 0, Length: 5})
	if !errors.Is(e, ErrMismatch) {
		t.Fatalf("err=%v", e)
	}
}
func TestReadOutageUnavailable(t *testing.T) {
	c, f := fixture(t)
	f.SetOutage(errors.New("down"))
	_, e := c.Read(context.Background(), "t", "p", "user", Selection{DocumentID: "doc", Version: "v1", Length: 5})
	if !errors.Is(e, ErrUnavailable) {
		t.Fatalf("err=%v", e)
	}
}

func TestC06ContentChangedWithSameClaimedVersionDuringFetch(t *testing.T) {
	c, f := fixture(t)
	reading, changed := make(chan struct{}), make(chan struct{})
	f.BeforeRead = func() { close(reading); <-changed }
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-reading
		f.Put(Document{Metadata: Metadata{TenantID: "ext", SiteID: "site", LibraryID: "lib", DocumentID: "doc", Version: "v1", ETag: "e1"}, Content: []byte("hello WORLD")})
		close(changed)
	}()
	_, err := c.Read(context.Background(), "t", "p", "user", Selection{DocumentID: "doc", Version: "v1", Length: 5})
	wg.Wait()
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("changed document accepted: %v", err)
	}
}

func TestC06DeleteRecreateScopeAndCancellation(t *testing.T) {
	c, f := fixture(t)
	read := func(id string) error {
		_, e := c.Read(context.Background(), "t", "p", "user", Selection{DocumentID: id, Version: "v1", Length: 1})
		return e
	}
	if err := read("doc"); err != nil {
		t.Fatal(err)
	}
	f.Delete("doc")
	f.Put(Document{Metadata: Metadata{TenantID: "ext", SiteID: "site", LibraryID: "lib", DocumentID: "new-id", Version: "v1", ETag: "e1"}, Content: []byte("replacement")})
	f.Grant("new-id", "subject", true)
	if !errors.Is(read("doc"), ErrDenied) || read("new-id") != nil {
		t.Fatal("deleted document fell back or recreated positive control failed")
	}
	for _, m := range []Metadata{{TenantID: "other", SiteID: "site", LibraryID: "lib"}, {TenantID: "ext", SiteID: "site", LibraryID: "other"}} {
		m.DocumentID = "foreign"
		m.Version = "v1"
		m.ETag = "e1"
		f.Put(Document{Metadata: m, Content: []byte("foreign")})
		f.Grant("foreign", "subject", true)
		if !errors.Is(read("foreign"), ErrDenied) {
			t.Fatalf("foreign scope accepted: %+v", m)
		}
	}
	before := f.MetadataCalls.Load()
	if !errors.Is(read("https://example.invalid/doc"), ErrDenied) || f.MetadataCalls.Load() != before {
		t.Fatal("URL escaped identifier validation")
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := c.Read(ctx, "t", "p", "user", Selection{DocumentID: "new-id", Version: "v1", Length: 1}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired operation got %v", err)
	}
}

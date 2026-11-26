//go:build retention_drill

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/sharepoint"
)

// startC06Retained runs the same fenced startup, recovery and HTTP handler as
// the normal binary, but composes the in-memory connector. There is no network
// configuration or alternate governance path for the fixture.
func startC06Retained(ctx context.Context, c config.Config, connector *sharepoint.Connector, client *http.Client, addr string) (func() error, error) {
	run, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- serveWithSharePoint(run, c, connector) }()
	var once sync.Once
	var result error
	stop := func() error { once.Do(func() { cancel(); result = <-done }); return result }
	for i := 0; i < 70; i++ {
		select {
		case err := <-done:
			cancel()
			return nil, fmt.Errorf("C06 retained serving stopped before readiness: %v", err)
		default:
		}
		probe, cancelProbe := context.WithTimeout(ctx, time.Second)
		r, _ := http.NewRequestWithContext(probe, http.MethodGet, addr+"/readyz", nil)
		response, e := client.Do(r)
		if e == nil {
			_ = response.Body.Close()
		}
		cancelProbe()
		if e == nil && response.StatusCode == 200 {
			return stop, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = stop()
	return nil, errors.New("C06 retained serving did not become ready")
}

func c06RetainedSource(tenant, project, actor string) (*sharepoint.Connector, *sharepoint.Fake, error) {
	f := sharepoint.NewFake()
	f.Put(sharepoint.Document{Metadata: sharepoint.Metadata{TenantID: "synthetic-ms-tenant", SiteID: "synthetic-site", LibraryID: "synthetic-library", DocumentID: "sp-original-doc", Version: "1.0", ETag: "synthetic-etag-1"}, Content: []byte("prefix: exact retained source")})
	f.Grant("sp-original-doc", "synthetic-delegate", true)
	c, err := sharepoint.New(sharepoint.Scope{ConnectorID: "synthetic-connector", TenantID: tenant, ProjectID: project, ExternalTenantID: "synthetic-ms-tenant", SiteID: "synthetic-site", LibraryID: "synthetic-library", Delegates: map[string]string{actor: "synthetic-delegate"}}, f)
	return c, f, err
}

func checkC06Retained(evs []evidence.Event, objs map[string][]byte, output string) error {
	if errs := evidence.VerifyRetentionFull(evs, objs); len(errs) != 0 {
		return fmt.Errorf("C06 retained verification: %v", errs)
	}
	original := []byte("exact retained source")
	excerpt := evidence.SHA256(original)
	if !bytes.Equal(objs[excerpt], original) {
		return errors.New("missing exact retained source bytes")
	}
	for _, ev := range evs {
		if ev["type"] != "context_sealed" {
			continue
		}
		p := ev["payload"].(map[string]any)
		rq := p["request_sha256"].(string)
		sources := p["sources"].([]any)
		source := sources[0].(map[string]any)
		identity := source["external"].(map[string]any)
		if source["sha256"] != excerpt || identity["provider_version"] != "1.0" || identity["etag"] != "synthetic-etag-1" || identity["delegated_subject"] != "synthetic-delegate" || identity["library_id"] != "synthetic-library" ||
			!bytes.Contains(objs[rq], original) || output != "synthetic c04 response for "+rq {
			return errors.New("source identity, sealed request or original output mismatch")
		}
		return nil
	}
	return errors.New("missing C06 context seal")
}

func modifyRetainedSource(f *sharepoint.Fake) {
	f.Put(sharepoint.Document{Metadata: sharepoint.Metadata{TenantID: "synthetic-ms-tenant", SiteID: "synthetic-site", LibraryID: "synthetic-library", DocumentID: "sp-original-doc", Version: "2.0", ETag: "synthetic-etag-2"}, Content: []byte("prefix: edited retained source")})
}
func deleteRetainedSource(f *sharepoint.Fake) { f.Delete("sp-original-doc") }

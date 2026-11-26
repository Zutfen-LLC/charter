package s3transport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{Endpoint: srv.URL, Region: "test-region", Bucket: "test-bucket", AccessKeyID: "fixture", SecretAccessKey: "fixture-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateRejectsNullVersionAsAmbiguous(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("x-amz-version-id", "null") })
	v, err := c.Create(context.Background(), "k", []byte("x"), time.Now().Add(time.Minute))
	var ae *AmbiguousError
	if v != "" || !errors.As(err, &ae) {
		t.Fatalf("version=%q err=%v", v, err)
	}
}

func TestListVersionsEnumeratesAllPagesIncludingDeleteMarkers(t *testing.T) {
	var runs atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/xml")
		switch runs.Add(1) {
		case 1:
			if r.URL.Query().Get("prefix") != "tx/" || r.URL.Query().Has("key-marker") {
				w.WriteHeader(500)
				return
			}
			fmt.Fprint(w, `<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>tx/k</NextKeyMarker><NextVersionIdMarker>v2</NextVersionIdMarker><Version><Key>tx/k</Key><VersionId>v2</VersionId></Version></ListVersionsResult>`)
		case 2:
			if r.URL.Query().Get("key-marker") != "tx/k" || r.URL.Query().Get("version-id-marker") != "v2" {
				w.WriteHeader(500)
				return
			}
			fmt.Fprint(w, `<ListVersionsResult><IsTruncated>false</IsTruncated><DeleteMarker><Key>tx/k</Key><VersionId>d1</VersionId></DeleteMarker><Version><Key>tx/k</Key><VersionId>v1</VersionId></Version></ListVersionsResult>`)
		default:
			w.WriteHeader(500)
		}
	})
	refs, err := c.Versions(context.Background(), "tx/")
	if err != nil || len(refs) != 3 || refs[0].VersionID != "v2" || refs[1].VersionID != "v1" || !refs[2].DeleteMarker || refs[2].VersionID != "d1" {
		t.Fatalf("refs=%v err=%v", refs, err)
	}
}

func TestListingRejectsTruncationWithoutVersionCursor(t *testing.T) {
	var runs atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/xml")
		if runs.Add(1) == 1 {
			fmt.Fprint(w, `<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>tx/k</NextKeyMarker><Version><Key>tx/k</Key><VersionId>v2</VersionId></Version></ListVersionsResult>`)
			return
		}
		fmt.Fprint(w, `<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>`)
	})
	if refs, err := c.Versions(context.Background(), "tx/"); err == nil || len(refs) != 0 || runs.Load() != 1 {
		t.Fatalf("accepted incomplete cursor: refs=%v count=%d err=%v", refs, runs.Load(), err)
	}
}

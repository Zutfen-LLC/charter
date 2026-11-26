package s3transport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigRejectsNonLoopbackHTTP(t *testing.T) {
	_, err := New(Config{Endpoint: "http://example.com", Region: "us-east-1", Bucket: "bucket-name", AccessKeyID: "a", SecretAccessKey: "s"})
	if err == nil {
		t.Fatal("expected insecure endpoint rejection")
	}
}

func TestCreateUsesConditionalPutAndRequiresVersionID(t *testing.T) {
	var gotMethod, gotConditional, gotMode, gotVersioning string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotConditional = r.Header.Get("If-None-Match")
		gotMode = r.Header.Get("X-Amz-Object-Lock-Mode")
		if strings.Contains(r.URL.RawQuery, "versioning") {
			gotVersioning = "checked"
		}
		w.Header().Set("ETag", `"not-a-digest"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket-name", AccessKeyID: "a", SecretAccessKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Create(context.Background(), "key", []byte("x"), time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("missing version id must fail")
	}
	if gotMethod != "PUT" || gotConditional != "*" || gotMode != "COMPLIANCE" {
		t.Fatalf("request method=%q conditional=%q mode=%q", gotMethod, gotConditional, gotMode)
	}
	_ = gotVersioning
}

func TestReadUsesExactVersionForGetAndRetention(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		if strings.Contains(r.URL.RawQuery, "retention") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>COMPLIANCE</Mode><RetainUntilDate>2030-01-02T03:04:05Z</RetainUntilDate></Retention>`))
			return
		}
		w.Header().Set("x-amz-version-id", "v-7")
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket-name", AccessKeyID: "a", SecretAccessKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Read(context.Background(), "obj", "v-7")
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Data) != "payload" || v.ID != "v-7" || v.Mode != "COMPLIANCE" || v.Until.IsZero() {
		t.Fatalf("unexpected version %#v", v)
	}
	if len(requests) != 2 || !strings.Contains(requests[0], "versionId=v-7") || !strings.Contains(requests[1], "versionId=v-7") {
		t.Fatalf("wire requests %#v", requests)
	}
}
func TestNewRejectsDirtyEndpointsAndBuckets(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:9000", "https://host/path", "https://host/?x=1"} {
		if _, err := New(Config{Endpoint: endpoint, Region: "r", Bucket: "valid-bucket", AccessKeyID: "a", SecretAccessKey: "s"}); err == nil {
			t.Errorf("accepted endpoint %q", endpoint)
		}
	}
	for _, bucket := range []string{"UPPER-BUCKET", "bad..bucket", "-bad-bucket", "192.168.1.1"} {
		if _, err := New(Config{Endpoint: "https://host", Region: "r", Bucket: bucket, AccessKeyID: "a", SecretAccessKey: "s"}); err == nil {
			t.Errorf("accepted bucket %q", bucket)
		}
	}
}
func TestCreateSendsExplicitSHA256AndRejectsOversizeBeforePut(t *testing.T) {
	var checksum string
	puts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		puts++
		checksum = r.Header.Get("x-amz-checksum-sha256")
		w.Header().Set("x-amz-version-id", "v1")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket-name", AccessKeyID: "a", SecretAccessKey: "s"})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("x")
	sum := sha256.Sum256(body)
	if _, err = c.Create(context.Background(), "key", body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if checksum != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("checksum header %q", checksum)
	}
	if _, err = c.Create(context.Background(), "key", make([]byte, maxObjectBytes+1), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("oversize accepted")
	}
	if puts != 1 {
		t.Fatalf("PUT count %d", puts)
	}
}

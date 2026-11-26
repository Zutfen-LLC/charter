package routing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLocalHTTPRedirectIsNotFollowed(t *testing.T) {
	nextCalls := 0
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalls++; _, _ = w.Write([]byte(`{"output":"bad"}`)) }))
	defer next.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, next.URL, http.StatusFound) }))
	defer redirect.Close()
	m := Model{ID: "local-http", Kind: KindLocalHTTP, Class: ClassLocal, Endpoint: redirect.URL, MaxRequestBytes: 20, MaxOutputBytes: 100}
	out, err := (HTTPAdapter{Timeout: time.Second}).Invoke(context.Background(), m, []byte("{}"))
	if err == nil || out.ModelOutcome.Complete || nextCalls != 0 {
		t.Fatalf("redirect followed or accepted: out=%+v next=%d err=%v", out, nextCalls, err)
	}
}

func TestEndpointRequiresLiteralLoopbackAndDefaultPolicyDenies(t *testing.T) {
	if err := validateEndpoint("http://localhost:8000/infer"); err == nil {
		t.Fatal("localhost alias accepted")
	}
	if err := validateEndpoint("http://192.168.1.2:8000/infer"); err == nil {
		t.Fatal("LAN endpoint accepted")
	}
	if _, err := DefaultConfig().Resolve("det-a"); err == nil {
		t.Fatal("empty default policy did not deny")
	}
	if err := validateEndpoint("https://127.0.0.1:8000/infer"); err == nil {
		t.Fatal("TLS endpoint accepted")
	}
}

package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
)

// jwksEnv wraps the synthetic IdP's JWKS behind a counting, switchable front so
// tests can assert exactly how many outbound requests happen. Time is fake.
type jwksEnv struct {
	t     *testing.T
	idp   *syntheticidp.IdP
	front *httptest.Server
	hits  atomic.Int64
	fail  atomic.Bool
	gate  chan struct{} // when non-nil, JWKS responses block until it is closed
	began chan struct{} // receives one value per request that reached the gate
	mu    sync.Mutex
	now   time.Time
	f     *oidc.JWKSFetcher
	v     *oidc.Verifier
}

func newJWKSEnv(t *testing.T) *jwksEnv {
	t.Helper()
	e := &jwksEnv{t: t, now: time.Unix(1_900_000_000, 0)}
	e.idp = syntheticidp.New(aud, tid)
	t.Cleanup(e.idp.Server.Close)
	e.idp.Now = e.clock
	e.front = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		if e.gate != nil {
			e.began <- struct{}{}
			<-e.gate
		}
		if e.fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		resp, err := http.Get(e.idp.JWKSURL())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		buf := make([]byte, 1<<16)
		n, _ := resp.Body.Read(buf)
		_, _ = w.Write(buf[:n])
	}))
	t.Cleanup(e.front.Close)
	e.f = newFetcher(e.front.URL, e.clock)
	var err error
	e.v, err = oidc.NewVerifier(oidc.Config{Issuer: e.idp.Issuer, Audience: aud, TenantID: tid, RequiredScope: scope, Keys: e.f, Now: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *jwksEnv) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
func (e *jwksEnv) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}
func (e *jwksEnv) verify(tok string) error {
	_, err := e.v.Verify(context.Background(), tok)
	return err
}
func (e *jwksEnv) wantHits(n int64) {
	e.t.Helper()
	if got := e.hits.Load(); got != n {
		e.t.Fatalf("outbound JWKS requests = %d, want %d", got, n)
	}
}

func TestInitialFetchFailureIsThrottled(t *testing.T) {
	e := newJWKSEnv(t)
	e.fail.Store(true)
	tok := e.idp.Token("s")
	for i := 0; i < 25; i++ {
		if e.verify(tok) == nil {
			t.Fatal("verified with no keys")
		}
	}
	e.wantHits(1) // one attempt, then fail fast within MinRefresh
	e.advance(16 * time.Second)
	_ = e.verify(tok)
	e.wantHits(2)
	// Recovery once the IdP is back and the throttle window has passed.
	e.fail.Store(false)
	e.advance(16 * time.Second)
	if err := e.verify(tok); err != nil {
		t.Fatalf("no recovery: %v", err)
	}
	e.wantHits(3)
}

func TestConcurrentVerificationWhileIdPDown(t *testing.T) {
	e := newJWKSEnv(t)
	e.fail.Store(true)
	tok := e.idp.Token("s")
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.verify(tok) == nil {
				t.Error("verified with IdP down")
			}
		}()
	}
	wg.Wait()
	e.wantHits(1)
}

func TestExpiredCacheNeverServedAndRefreshFailureThrottled(t *testing.T) {
	e := newJWKSEnv(t)
	tok := e.idp.Token("s")
	if err := e.verify(tok); err != nil {
		t.Fatal(err)
	}
	e.wantHits(1)
	e.advance(5*time.Minute + time.Second) // cache expired
	e.fail.Store(true)
	for i := 0; i < 20; i++ {
		if e.verify(tok) == nil {
			t.Fatal("expired cached key served as fallback")
		}
	}
	e.wantHits(2) // exactly one refresh attempt
	e.advance(16 * time.Second)
	_ = e.verify(tok)
	e.wantHits(3)
	e.fail.Store(false)
	e.advance(16 * time.Second)
	if err := e.verify(tok); err != nil {
		t.Fatalf("no recovery after IdP returns: %v", err)
	}
}

func TestUnknownKidFloodIsBoundedAndRotationStillWorks(t *testing.T) {
	e := newJWKSEnv(t)
	if err := e.verify(e.idp.Token("s")); err != nil {
		t.Fatal(err)
	}
	e.wantHits(1)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	flood := func() { // well-formed RS256 tokens with unknown key ids reach the key source
		for i := 0; i < 300; i++ {
			e.verify(e.idp.Mint(syntheticidp.Claims{Subject: "s", Kid: "nope-" + strconv.Itoa(i), SignWith: attacker}))
		}
	}
	flood()
	e.wantHits(1) // inside MinRefresh: no refetch at all
	e.advance(16 * time.Second)
	flood()
	e.wantHits(2) // past MinRefresh: one refetch for the whole flood
	flood()
	e.wantHits(2)

	// Legitimate rotation is picked up after the throttle window.
	e.idp.AddKey("k2")
	rotated := e.idp.Mint(syntheticidp.Claims{Subject: "s", Kid: "k2"})
	if e.verify(rotated) == nil {
		t.Fatal("rotation should wait for the throttle window")
	}
	e.advance(16 * time.Second)
	if err := e.verify(rotated); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
}

func TestKeyWithdrawalBoundedByTTL(t *testing.T) {
	e := newJWKSEnv(t)
	tok := e.idp.Token("s")
	if err := e.verify(tok); err != nil {
		t.Fatal(err)
	}
	e.idp.AddKey("k2")
	e.idp.RemoveKey("k1")
	e.advance(time.Minute)
	if err := e.verify(tok); err != nil {
		t.Fatalf("within TTL the cached key validates (documented bound): %v", err)
	}
	e.advance(4*time.Minute + 2*time.Second)
	if e.verify(tok) == nil {
		t.Fatal("withdrawn key still validates after TTL")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	idp := syntheticidp.New(aud, tid)
	defer idp.Server.Close()
	var second atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		http.Redirect(w, r, idp.JWKSURL(), http.StatusFound) // would hand out valid keys
	}))
	defer target.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/keys", http.StatusFound)
	}))
	defer front.Close()
	v, _ := oidc.NewVerifier(oidc.Config{Issuer: idp.Issuer, Audience: aud, TenantID: tid, RequiredScope: scope, Keys: newFetcher(front.URL, time.Now)})
	if _, err := v.Verify(context.Background(), idp.Token("s")); err == nil {
		t.Fatal("verified using keys obtained through a redirect")
	}
	if n := second.Load(); n != 0 {
		t.Fatalf("redirect destination received %d requests", n)
	}
}

func TestPlainHTTPJWKSRefusedWithoutFixtureOptIn(t *testing.T) {
	idp := syntheticidp.New(aud, tid)
	defer idp.Server.Close()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	f := &oidc.JWKSFetcher{URL: srv.URL + "/keys"} // no fixture opt-in
	v, _ := oidc.NewVerifier(oidc.Config{Issuer: idp.Issuer, Audience: aud, TenantID: tid, RequiredScope: scope, Keys: f})
	if _, err := v.Verify(context.Background(), idp.Token("s")); err == nil {
		t.Fatal("verified")
	}
	if hits.Load() != 0 {
		t.Fatalf("made %d plaintext requests to the IdP URL", hits.Load())
	}
}

// A slow or hung refresh (triggered by an unknown kid) must not stall
// verification of tokens whose keys are already cached.
func TestSlowRefreshDoesNotBlockCachedKeyVerification(t *testing.T) {
	e := newJWKSEnv(t)
	good := e.idp.Token("s")
	if err := e.verify(good); err != nil {
		t.Fatal(err)
	}
	e.advance(16 * time.Second) // refresh allowed again
	e.gate, e.began = make(chan struct{}), make(chan struct{}, 8)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	unknown := e.idp.Mint(syntheticidp.Claims{Subject: "s", Kid: "unknown", SignWith: attacker})
	done := make(chan struct{})
	go func() { e.verify(unknown); close(done) }()
	<-e.began // the refresh is now in flight and hung at the IdP

	fast := make(chan error, 1)
	go func() { fast <- e.verify(good) }()
	select {
	case err := <-fast:
		if err != nil {
			t.Errorf("cached-key verification failed during a refresh: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("cached-key verification blocked behind an in-flight JWKS refresh")
	}
	close(e.gate)
	<-done
}

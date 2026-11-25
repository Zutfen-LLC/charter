package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// JWKSFetcher loads signing keys from one configured JWKS URL. It is the only
// outbound call identity makes.
//
// Trust and bounds:
//   - HTTPS only. Plain HTTP is accepted solely for loopback hosts and only when
//     AllowLoopbackHTTP is set (synthetic test fixtures); never for real IdPs.
//   - Redirects are never followed: a response other than 200 (including 3xx)
//     is a failure, so the request cannot be steered to another host.
//   - Each fetch has a hard timeout and a 1 MiB body cap, and uses its own
//     context (a caller cancelling must not poison the shared cache state).
//     Only one refresh runs at a time and no lock is held during network I/O:
//     requests whose key is cached are never delayed by a slow refresh.
//   - Cached keys are served only while younger than TTL. Expired keys are
//     dropped and never used as a fallback when a refresh fails.
//   - ALL refresh attempts, successful or failed, and whether triggered by an
//     empty cache, an expired cache or an unknown kid, are throttled to one per
//     MinRefresh. Within the window callers fail fast without network I/O, so an
//     unavailable IdP or kid-flooding cannot turn into request amplification.
//
// Revocation bound: a key withdrawn at the IdP validates tokens for at most TTL.
// Rotation: a new key is picked up on the first unknown-kid request after
// MinRefresh has elapsed since the previous attempt.
type JWKSFetcher struct {
	URL               string
	TTL               time.Duration // default 5m
	MinRefresh        time.Duration // default 15s
	Timeout           time.Duration // per fetch; default 5s
	AllowLoopbackHTTP bool          // fixtures only
	Now               func() time.Time

	mu          sync.Mutex
	inflight    chan struct{} // closed when the in-flight refresh finishes
	client      *http.Client
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	attempted   bool
	lastAttempt time.Time
	lastErr     error
}

var errUnknownKey = errors.New("unknown key id")

func (f *JWKSFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *JWKSFetcher) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	ttl, minR := f.TTL, f.MinRefresh
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	if minR == 0 {
		minR = 15 * time.Second
	}
	for {
		f.mu.Lock()
		now := f.now()
		fresh := f.keys != nil && now.Sub(f.fetchedAt) < ttl
		if !fresh {
			f.keys = nil // expired keys are never served
		}
		if fresh {
			if k, ok := f.keys[kid]; ok {
				f.mu.Unlock()
				return k, nil // cache hits never wait on a refresh
			}
		}
		if wait := f.inflight; wait != nil {
			// One refresh at a time. Callers that need its outcome wait for it
			// (bounded by their own context and the fetch timeout), then re-evaluate.
			f.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		// A fetch is needed (no keys, expired keys, or unknown kid). Throttle.
		if f.attempted && now.Sub(f.lastAttempt) < minR {
			err := errUnknownKey
			if f.lastErr != nil {
				err = fmt.Errorf("jwks refresh throttled after failure: %w", f.lastErr)
			}
			f.mu.Unlock()
			return nil, err
		}
		f.attempted, f.lastAttempt = true, now
		done := make(chan struct{})
		f.inflight = done
		f.mu.Unlock()

		keys, err := f.fetch() // no lock held during network I/O

		f.mu.Lock()
		f.inflight = nil
		if err != nil {
			f.lastErr = err
		} else {
			f.lastErr, f.keys, f.fetchedAt = nil, keys, now
		}
		var k *rsa.PublicKey
		if err == nil {
			k = keys[kid]
		}
		f.mu.Unlock()
		close(done)
		if err != nil {
			return nil, err
		}
		if k == nil {
			return nil, errUnknownKey
		}
		return k, nil
	}
}

// checkURL enforces the transport policy before any network I/O.
func (f *JWKSFetcher) checkURL() error {
	u, err := url.Parse(f.URL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("jwks: invalid URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if f.AllowLoopbackHTTP && IsLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return errors.New("jwks: URL must be https")
}

// IsLoopbackHost reports whether host is localhost or a loopback IP literal.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (f *JWKSFetcher) fetch() (map[string]*rsa.PublicKey, error) {
	if err := f.checkURL(); err != nil {
		return nil, err
	}
	timeout := f.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if f.client == nil {
		f.client = &http.Client{
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty, Kid, Use, Alg, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || pub.E < 3 {
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no usable keys")
	}
	return out, nil
}

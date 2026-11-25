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
	"net/http"
	"sync"
	"time"
)

// JWKSFetcher loads signing keys from a JWKS URL. This is the only outbound
// call identity makes, and only to the configured IdP URL.
//
// Cache behaviour is part of the revocation bound: a key removed at the IdP
// keeps validating tokens for at most TTL. An unknown kid triggers one refetch
// (rate-limited by MinRefresh) so key rotation works without opening a path for
// kid-spraying to hammer the IdP. A failed refresh fails closed once the cache
// has expired.
type JWKSFetcher struct {
	URL        string
	Client     *http.Client
	TTL        time.Duration // default 5m
	MinRefresh time.Duration // default 15s
	Now        func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
}

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
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	fresh := f.keys != nil && now.Sub(f.fetchedAt) < ttl
	if fresh {
		if k, ok := f.keys[kid]; ok {
			return k, nil
		}
	}
	if f.keys != nil && now.Sub(f.lastTry) < minR && fresh {
		return nil, errors.New("unknown key id")
	}
	f.lastTry = now
	keys, err := f.fetch(ctx)
	if err != nil {
		if !fresh {
			f.keys = nil // fail closed: do not keep serving expired keys
		}
		return nil, err
	}
	f.keys, f.fetchedAt = keys, now
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown key id")
}

func (f *JWKSFetcher) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	c := f.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
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

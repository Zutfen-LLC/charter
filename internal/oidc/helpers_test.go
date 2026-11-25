package oidc_test

import (
	"time"

	"github.com/Zutfen-LLC/charter/internal/oidc"
)

// newFetcher builds a fetcher for a local fixture server (explicit loopback opt-in).
func newFetcher(url string, now func() time.Time) *oidc.JWKSFetcher {
	return &oidc.JWKSFetcher{URL: url + "/keys", Now: now, AllowLoopbackHTTP: true}
}

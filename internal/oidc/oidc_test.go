package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
)

const aud, tid = "charter-test", "tenant-a"

func setup(t *testing.T) (*syntheticidp.IdP, *oidc.Verifier) {
	t.Helper()
	idp := syntheticidp.New(aud, tid)
	t.Cleanup(idp.Server.Close)
	v, err := oidc.NewVerifier(oidc.Config{Issuer: idp.Issuer, Audience: aud, TenantID: tid,
		Keys: &oidc.JWKSFetcher{URL: idp.JWKSURL()}})
	if err != nil {
		t.Fatal(err)
	}
	return idp, v
}

func TestValidToken(t *testing.T) {
	idp, v := setup(t)
	id, err := v.Verify(context.Background(), idp.Token("sub-1"))
	if err != nil || id.Subject != "sub-1" || id.TenantID != tid || id.Issuer != idp.Issuer {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestRejectsForgedAndMisissuedTokens(t *testing.T) {
	idp, v := setup(t)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]string{
		"wrong tenant (validly signed)": idp.Mint(syntheticidp.Claims{Subject: "s", Tenant: "tenant-b"}),
		"missing tenant claim":          idp.Mint(syntheticidp.Claims{Subject: "s", TenantClaim: "other_claim"}),
		"wrong issuer":                  idp.Mint(syntheticidp.Claims{Subject: "s", Issuer: "https://evil.example"}),
		"wrong audience":                idp.Mint(syntheticidp.Claims{Subject: "s", Audience: "someone-else"}),
		"expired":                       idp.Mint(syntheticidp.Claims{Subject: "s", IssuedAt: time.Now().Add(-time.Hour), Lifetime: 10 * time.Minute}),
		"issued in the future":          idp.Mint(syntheticidp.Claims{Subject: "s", IssuedAt: time.Now().Add(time.Hour)}),
		"lifetime too long":             idp.Mint(syntheticidp.Claims{Subject: "s", Lifetime: 24 * time.Hour}),
		"empty subject":                 idp.Mint(syntheticidp.Claims{}),
		"alg none":                      idp.Mint(syntheticidp.Claims{Subject: "s", Alg: "none"}),
		"alg HS256":                     idp.Mint(syntheticidp.Claims{Subject: "s", Alg: "HS256"}),
		"unknown kid":                   idp.Mint(syntheticidp.Claims{Subject: "s", Kid: "nope", SignWith: attacker}),
		"attacker key, valid kid":       idp.Mint(syntheticidp.Claims{Subject: "s", SignWith: attacker}),
		"garbage":                       "not.a.jwt",
		"empty":                         "",
	}
	for name, tok := range cases {
		if _, err := v.Verify(context.Background(), tok); !errors.Is(err, oidc.ErrInvalidToken) {
			t.Errorf("%s: want ErrInvalidToken, got %v", name, err)
		}
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	idp, v := setup(t)
	good := idp.Token("alice")
	other := idp.Token("bob")
	// Splice bob's payload under alice's signature.
	var gp, op []string
	gp, op = split(good), split(other)
	forged := gp[0] + "." + op[1] + "." + gp[2]
	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("spliced token accepted")
	}
}

func split(s string) []string {
	var out []string
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[last:i])
			last = i + 1
		}
	}
	return append(out, s[last:])
}

func TestEmailClaimIsNeverIdentity(t *testing.T) {
	idp, v := setup(t)
	id, err := v.Verify(context.Background(), idp.Mint(syntheticidp.Claims{Subject: "mallory", Email: "alice@example.test"}))
	if err != nil || id.Subject != "mallory" {
		t.Fatalf("%+v %v", id, err)
	}
}

// Documents the IdP-side revocation bound: a withdrawn signing key keeps
// validating tokens until the JWKS cache TTL elapses, then fails closed.
func TestJWKSCacheBoundsKeyRevocation(t *testing.T) {
	idp := syntheticidp.New(aud, tid)
	defer idp.Server.Close()
	now := time.Now()
	clock := func() time.Time { return now }
	f := &oidc.JWKSFetcher{URL: idp.JWKSURL(), TTL: 5 * time.Minute, Now: clock}
	v, _ := oidc.NewVerifier(oidc.Config{Issuer: idp.Issuer, Audience: aud, TenantID: tid, Keys: f, Now: clock})
	idp.Now = clock

	tok := idp.Token("s")
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	idp.AddKey("k2")
	idp.RemoveKey("k1")
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("within TTL the cached key still validates (documented bound): %v", err)
	}
	now = now.Add(5*time.Minute + time.Second)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("token signed by a withdrawn key still accepted after the cache TTL")
	}
}

func TestJWKSRotationPicksUpNewKey(t *testing.T) {
	idp := syntheticidp.New(aud, tid)
	defer idp.Server.Close()
	now := time.Now()
	clock := func() time.Time { return now }
	idp.Now = clock
	v, _ := oidc.NewVerifier(oidc.Config{Issuer: idp.Issuer, Audience: aud, TenantID: tid, Now: clock,
		Keys: &oidc.JWKSFetcher{URL: idp.JWKSURL(), Now: clock}})
	if _, err := v.Verify(context.Background(), idp.Token("s")); err != nil {
		t.Fatal(err)
	}
	idp.AddKey("k2")
	tok := idp.Mint(syntheticidp.Claims{Subject: "s", Kid: "k2"})
	// Unknown-kid refetches are rate limited so kid-spraying cannot hammer the IdP.
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("refetch should be rate limited immediately after a fetch")
	}
	now = now.Add(16 * time.Second)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("new key not discovered after the refresh interval: %v", err)
	}
}

func TestJWKSUnreachableFailsClosed(t *testing.T) {
	idp, v := setup(t)
	tok := idp.Token("s")
	idp.Server.Close()
	// Never fetched before in this verifier: no cache, must refuse.
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("accepted token with no reachable keys")
	}
}

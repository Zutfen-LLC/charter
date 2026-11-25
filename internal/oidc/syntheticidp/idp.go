// Package syntheticidp is an in-process OIDC identity provider for tests and
// CI. It mints RS256 tokens and serves a JWKS. It performs no authentication of
// its own and must never be wired into a production configuration.
package syntheticidp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

type IdP struct {
	Server   *httptest.Server
	Issuer   string
	Audience string
	TenantID string
	Now      func() time.Time
	// Scope is the delegated scope (scp) carried by default tokens, mirroring a
	// delegated-user access token for the API. Default "charter.access".
	Scope string

	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
}

// New starts a synthetic IdP. Close it with idp.Server.Close().
func New(audience, tenantID string) *IdP {
	idp := &IdP{Audience: audience, TenantID: tenantID, Now: time.Now, Scope: "charter.access", keys: map[string]*rsa.PrivateKey{}}
	idp.Server = httptest.NewServer(http.HandlerFunc(idp.serve))
	idp.Issuer = idp.Server.URL
	idp.AddKey("k1")
	return idp
}

func (i *IdP) JWKSURL() string { return i.Server.URL + "/keys" }

// AddKey creates a signing key published in the JWKS.
func (i *IdP) AddKey(kid string) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	i.mu.Lock()
	i.keys[kid] = k
	i.mu.Unlock()
	return k
}

// RemoveKey withdraws a key from the JWKS (simulates IdP-side key revocation).
func (i *IdP) RemoveKey(kid string) {
	i.mu.Lock()
	delete(i.keys, kid)
	i.mu.Unlock()
}

func (i *IdP) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/keys" {
		http.NotFound(w, r)
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	var ks []map[string]string
	for kid, k := range i.keys {
		ks = append(ks, map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": ks})
}

// Claims for a token. Zero values are filled with valid defaults by Token;
// negative tests override individual fields via Extra / the With* helpers.
type Claims struct {
	Subject     string
	Issuer      string // default idp issuer
	Audience    string // default idp audience
	Tenant      string // default idp tenant
	TenantClaim string // default "tid"
	Email       string // never trusted by Charter; included to test spoofing
	IssuedAt    time.Time
	Lifetime    time.Duration // default 10m
	Extra       map[string]any
	Kid         string          // default "k1"
	Alg         string          // default RS256; "none"/"HS256" for forgery tests
	SignWith    *rsa.PrivateKey // attacker key for forgery tests

	// Fixture controls for negative claim tests (the token is still signed).
	Omit        []string                   // claims to delete from the payload
	Raw         map[string]json.RawMessage // exact JSON values overriding claims
	Typ         string                     // header typ; default "JWT"; "-" omits it
	HeaderExtra map[string]any
}

// Token mints a signed token for subject sub with valid defaults.
func (i *IdP) Token(sub string) string { return i.Mint(Claims{Subject: sub}) }

func (i *IdP) Mint(c Claims) string {
	if c.Issuer == "" {
		c.Issuer = i.Issuer
	}
	if c.Audience == "" {
		c.Audience = i.Audience
	}
	if c.Tenant == "" {
		c.Tenant = i.TenantID
	}
	if c.TenantClaim == "" {
		c.TenantClaim = "tid"
	}
	if c.Kid == "" {
		c.Kid = "k1"
	}
	if c.Alg == "" {
		c.Alg = "RS256"
	}
	if c.Lifetime == 0 {
		c.Lifetime = 10 * time.Minute
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = i.Now()
	}
	pl := map[string]any{"iss": c.Issuer, "aud": c.Audience, "sub": c.Subject, c.TenantClaim: c.Tenant,
		"iat": c.IssuedAt.Unix(), "nbf": c.IssuedAt.Unix(), "exp": c.IssuedAt.Add(c.Lifetime).Unix()}
	if i.Scope != "" {
		pl["scp"] = i.Scope
		pl["ver"] = "2.0"
	}
	if c.Email != "" {
		pl["email"] = c.Email
	}
	for k, v := range c.Extra {
		pl[k] = v
	}
	for _, k := range c.Omit {
		delete(pl, k)
	}
	for k, v := range c.Raw {
		pl[k] = v
	}
	hdr := map[string]any{"alg": c.Alg, "kid": c.Kid}
	if c.Typ == "" {
		hdr["typ"] = "JWT"
	} else if c.Typ != "-" {
		hdr["typ"] = c.Typ
	}
	for k, v := range c.HeaderExtra {
		hdr[k] = v
	}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(pl)
	signing := b64(hb) + "." + b64(pb)
	switch c.Alg {
	case "RS256":
		key := c.SignWith
		if key == nil {
			i.mu.Lock()
			key = i.keys[c.Kid]
			i.mu.Unlock()
		}
		sum := sha256.Sum256([]byte(signing))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			panic(err)
		}
		return signing + "." + b64(sig)
	default: // unsigned / wrong-alg forgery attempts
		return signing + "."
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

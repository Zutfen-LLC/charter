// Package oidc validates OpenID Connect ID/access tokens (RS256 only) and
// extracts the identity facts Charter may trust: issuer, subject and tenant.
//
// Trust rules:
//   - Only the signature, issuer, audience, time and tenant claims of a token
//     verified against the configured issuer's keys are believed.
//   - Email, name and similar claims are never returned or used for identity.
//   - The tenant claim must equal the single configured tenant; a validly signed
//     token for another tenant is refused.
package oidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidToken is returned for every validation failure. Callers must not
// distinguish causes to clients; the wrapped detail is for server logs only.
var ErrInvalidToken = errors.New("invalid token")

// KeySource returns the public key for a key ID.
type KeySource interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// Config configures a Verifier. Issuer, Audience, TenantID and Keys are required.
type Config struct {
	Issuer      string
	Audience    string
	TenantID    string // required value of the tenant claim
	TenantClaim string // claim name; default "tid" (Entra)
	Keys        KeySource
	Leeway      time.Duration // clock skew allowance; default 30s
	// MaxLifetime bounds exp-iat so a long-lived token cannot extend the
	// revocation-propagation bound. Default 1h.
	MaxLifetime time.Duration
	Now         func() time.Time
}

// Identity is the only product of a successful validation.
type Identity struct {
	Issuer   string
	Subject  string
	TenantID string
	Expires  time.Time
}

type Verifier struct{ c Config }

func NewVerifier(c Config) (*Verifier, error) {
	if c.Issuer == "" || c.Audience == "" || c.TenantID == "" || c.Keys == nil {
		return nil, errors.New("oidc: issuer, audience, tenant id and key source are required")
	}
	if c.TenantClaim == "" {
		c.TenantClaim = "tid"
	}
	if c.Leeway == 0 {
		c.Leeway = 30 * time.Second
	}
	if c.MaxLifetime == 0 {
		c.MaxLifetime = time.Hour
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Verifier{c}, nil
}

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, a...))
}

func (v *Verifier) Verify(ctx context.Context, token string) (Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 16<<10 {
		return Identity{}, bad("malformed")
	}
	hdrB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Identity{}, bad("header encoding")
	}
	var hdr struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(hdrB, &hdr); err != nil {
		return Identity{}, bad("header json")
	}
	if hdr.Alg != "RS256" || hdr.Kid == "" || len(hdr.Crit) != 0 {
		return Identity{}, bad("unsupported header alg=%q", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, bad("signature encoding")
	}
	key, err := v.c.Keys.Key(ctx, hdr.Kid)
	if err != nil || key == nil {
		return Identity{}, bad("key lookup: %v", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return Identity{}, bad("signature")
	}

	// Signature is valid; only now parse the claims.
	payB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Identity{}, bad("payload encoding")
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payB, &claims); err != nil {
		return Identity{}, bad("payload json")
	}
	str := func(name string) string {
		var s string
		_ = json.Unmarshal(claims[name], &s)
		return s
	}
	num := func(name string) (time.Time, bool) {
		var f float64
		if err := json.Unmarshal(claims[name], &f); err != nil || f <= 0 {
			return time.Time{}, false
		}
		return time.Unix(int64(f), 0), true
	}
	if str("iss") != v.c.Issuer {
		return Identity{}, bad("issuer")
	}
	if !audienceMatches(claims["aud"], v.c.Audience) {
		return Identity{}, bad("audience")
	}
	sub := str("sub")
	if sub == "" || len(sub) > 256 {
		return Identity{}, bad("subject")
	}
	if tid := str(v.c.TenantClaim); tid == "" || tid != v.c.TenantID {
		return Identity{}, bad("tenant")
	}
	now := v.c.Now()
	exp, ok := num("exp")
	if !ok || !now.Before(exp.Add(v.c.Leeway)) {
		return Identity{}, bad("expired or missing exp")
	}
	iat, ok := num("iat")
	if !ok || iat.After(now.Add(v.c.Leeway)) {
		return Identity{}, bad("iat missing or in future")
	}
	if exp.Sub(iat) > v.c.MaxLifetime {
		return Identity{}, bad("lifetime exceeds %s", v.c.MaxLifetime)
	}
	if nbf, ok := num("nbf"); ok && nbf.After(now.Add(v.c.Leeway)) {
		return Identity{}, bad("not yet valid")
	}
	return Identity{Issuer: v.c.Issuer, Subject: sub, TenantID: v.c.TenantID, Expires: exp}, nil
}

func audienceMatches(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

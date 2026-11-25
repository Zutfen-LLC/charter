// Package oidc validates OpenID Connect ID/access tokens (RS256 only) and
// extracts the identity facts Charter may trust: issuer, subject and tenant.
//
// Trust rules:
//   - Only the signature, issuer, audience, time and tenant claims of a token
//     verified against the configured issuer's keys are believed.
//   - Email, name and similar claims are never returned or used for identity.
//   - The tenant claim must equal the single configured tenant; a validly signed
//     token for another tenant is refused.
//
// Accepted token profile (a delegated-user access token for this API):
//   - JWS RS256; header typ absent, "JWT" or "at+jwt"; no crit header.
//   - aud is the configured audience, as a string or a one-element array. A
//     multi-audience token is refused: it was issued for other relying parties
//     too and could be replayed against them (and vice versa).
//   - exp and iat are required NumericDates; nbf is optional but, if present,
//     must be valid. All are JSON numbers in (0, year 9999]. exp > iat, exp-iat
//     <= MaxLifetime, nbf < exp. Malformed values are rejected, never ignored.
//   - POSITIVE delegated-API evidence is mandatory: the token must carry an scp
//     claim, a string of single-space-separated scope tokens, one of which is
//     EXACTLY Config.RequiredScope. Missing, empty, non-string, malformed
//     (leading/trailing/double spaces, tabs, newlines, quotes), substring or
//     case-different scp is refused. This is what rejects ID tokens and app-only
//     (client-credentials) tokens, which carry no delegated scp; it does not
//     depend on the absence of nonce or the presence of optional claims.
//   - Defense in depth: tokens with a nonce or an idtyp other than "user" are
//     also refused. The audience must be a dedicated API audience that no client
//     uses for ID tokens.
//   - There is no permissive fallback: NewVerifier fails without a valid
//     RequiredScope.
//
// Live compatibility with a Microsoft Entra tenant has NOT been demonstrated;
// the profile above is derived from the documented v2.0 access-token format.
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
	"math"
	"strconv"
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
	// RequiredScope is the delegated API scope that must appear exactly in scp.
	// Required; see ValidScopeToken.
	RequiredScope string
	Leeway        time.Duration // clock skew allowance; default 30s
	// MaxLifetime bounds exp-iat so a long-lived token cannot extend the
	// revocation-propagation bound. A token is accepted until exp+Leeway, so
	// the IdP-side bound is MaxLifetime+Leeway. Default 1h.
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
	if !ValidScopeToken(c.RequiredScope) {
		return nil, errors.New("oidc: a valid required delegated scope is mandatory (no permissive fallback)")
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
		Typ  json.RawMessage `json:"typ"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(hdrB, &hdr); err != nil {
		return Identity{}, bad("header json")
	}
	if hdr.Alg != "RS256" || hdr.Kid == "" || len(hdr.Crit) != 0 {
		return Identity{}, bad("unsupported header alg=%q", hdr.Alg)
	}
	if len(hdr.Typ) != 0 {
		var typ string
		if json.Unmarshal(hdr.Typ, &typ) != nil || !(strings.EqualFold(typ, "JWT") || strings.EqualFold(typ, "at+jwt")) {
			return Identity{}, bad("unsupported typ")
		}
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
	if _, ok := claims["nonce"]; ok {
		return Identity{}, bad("ID-token artifact (nonce) in access token")
	}
	if _, ok := claims["idtyp"]; ok && str("idtyp") != "user" {
		return Identity{}, bad("not a user token (idtyp)")
	}
	if err := requireScope(claims["scp"], v.c.RequiredScope); err != nil {
		return Identity{}, err
	}

	exp, err := numericDate(claims, "exp", true)
	if err != nil {
		return Identity{}, err
	}
	iat, err := numericDate(claims, "iat", true)
	if err != nil {
		return Identity{}, err
	}
	nbf, err := numericDate(claims, "nbf", false)
	if err != nil {
		return Identity{}, err
	}
	if !exp.After(iat) {
		return Identity{}, bad("exp is not after iat")
	}
	if exp.Sub(iat) > v.c.MaxLifetime {
		return Identity{}, bad("lifetime exceeds %s", v.c.MaxLifetime)
	}
	now := v.c.Now()
	if !now.Before(exp.Add(v.c.Leeway)) {
		return Identity{}, bad("expired")
	}
	if iat.After(now.Add(v.c.Leeway)) {
		return Identity{}, bad("iat in the future")
	}
	if !nbf.IsZero() {
		if !nbf.Before(exp) {
			return Identity{}, bad("nbf not before exp")
		}
		if nbf.After(now.Add(v.c.Leeway)) {
			return Identity{}, bad("not yet valid")
		}
	}
	return Identity{Issuer: v.c.Issuer, Subject: sub, TenantID: v.c.TenantID, Expires: exp}, nil
}

// maxNumericDate is 9999-12-31T23:59:59Z; larger values are treated as overflow.
const maxNumericDate = 253402300799

// numericDate parses a JWT NumericDate. A claim that is present must be a JSON
// number in (0, maxNumericDate]; strings, null, booleans, arrays, objects,
// non-positive, non-finite and overflowing values are all errors. An absent
// optional claim returns the zero time.
func numericDate(claims map[string]json.RawMessage, name string, required bool) (time.Time, error) {
	raw, present := claims[name]
	if !present {
		if required {
			return time.Time{}, bad("%s missing", name)
		}
		return time.Time{}, nil
	}
	if len(raw) == 0 || !(raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9') {
		return time.Time{}, bad("%s is not a number", name)
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > maxNumericDate {
		return time.Time{}, bad("%s out of range", name)
	}
	sec := math.Floor(f)
	return time.Unix(int64(sec), int64((f-sec)*1e9)), nil
}

// ValidScopeToken reports whether s is a single scope token: 1-128 printable
// ASCII characters excluding space, double quote, backslash and comma (RFC 6749
// scope-token, minus comma which is never used as a separator here).
func ValidScopeToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' || c == ',' {
			return false
		}
	}
	return true
}

// requireScope demands scp to be a JSON string of single-space-separated valid
// scope tokens containing want exactly.
func requireScope(raw json.RawMessage, want string) error {
	var scp string
	if len(raw) == 0 || json.Unmarshal(raw, &scp) != nil || raw[0] != '"' {
		return bad("scp missing or not a string")
	}
	found := false
	for _, tok := range strings.Split(scp, " ") {
		if !ValidScopeToken(tok) {
			return bad("scp malformed")
		}
		if tok == want {
			found = true
		}
	}
	if !found {
		return bad("required delegated scope missing")
	}
	return nil
}

// audienceMatches accepts the audience as a string or a one-element array.
func audienceMatches(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil && len(many) == 1 {
		return many[0] == want
	}
	return false
}

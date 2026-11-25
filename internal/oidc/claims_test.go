package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
)

func raw(s string) json.RawMessage { return json.RawMessage(s) }

// Every case is a signed token: the failure must come from claim validation,
// not from a bad signature.
func TestClaimValidationNegativeFixtures(t *testing.T) {
	idp, v := setup(t)
	now := time.Now()
	nowS := fmt.Sprint(now.Unix())
	futureS := fmt.Sprint(now.Add(5 * time.Minute).Unix())
	cases := map[string]syntheticidp.Claims{
		// Temporal claims present but malformed must be rejected, not ignored.
		"exp as string":         {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`"` + futureS + `"`)}},
		"exp null":              {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`null`)}},
		"exp bool":              {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`true`)}},
		"exp array":             {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`[1]`)}},
		"exp object":            {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`{}`)}},
		"exp zero":              {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`0`)}},
		"exp negative":          {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`-5`)}},
		"exp overflow 1e30":     {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`1e30`)}},
		"exp beyond year 9999":  {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(`999999999999`)}},
		"exp missing":           {Subject: "s", Omit: []string{"exp"}},
		"iat as string":         {Subject: "s", Raw: map[string]json.RawMessage{"iat": raw(`"` + nowS + `"`)}},
		"iat null":              {Subject: "s", Raw: map[string]json.RawMessage{"iat": raw(`null`)}},
		"iat negative":          {Subject: "s", Raw: map[string]json.RawMessage{"iat": raw(`-1`)}},
		"iat overflow":          {Subject: "s", Raw: map[string]json.RawMessage{"iat": raw(`1e30`)}},
		"iat missing":           {Subject: "s", Omit: []string{"iat"}},
		"nbf as string":         {Subject: "s", Raw: map[string]json.RawMessage{"nbf": raw(`"` + nowS + `"`)}},
		"nbf null":              {Subject: "s", Raw: map[string]json.RawMessage{"nbf": raw(`null`)}},
		"nbf bool":              {Subject: "s", Raw: map[string]json.RawMessage{"nbf": raw(`false`)}},
		"nbf negative":          {Subject: "s", Raw: map[string]json.RawMessage{"nbf": raw(`-1`)}},
		"nbf overflow":          {Subject: "s", Raw: map[string]json.RawMessage{"nbf": raw(`1e30`)}},
		"nbf in the future":     {Subject: "s", Raw: map[string]json.RawMessage{"nbf": raw(futureS)}},
		"nbf after exp":         {Subject: "s", Raw: map[string]json.RawMessage{"nbf": raw(fmt.Sprint(now.Add(20 * time.Minute).Unix()))}},
		"exp before iat":        {Subject: "s", Raw: map[string]json.RawMessage{"iat": raw(futureS), "exp": raw(nowS)}, Lifetime: time.Minute},
		"exp equal iat":         {Subject: "s", Raw: map[string]json.RawMessage{"exp": raw(nowS), "iat": raw(nowS)}},
		"iat far in the future": {Subject: "s", IssuedAt: now.Add(2 * time.Hour)},
		"lifetime over max":     {Subject: "s", Lifetime: 2 * time.Hour},
		"expired beyond leeway": {Subject: "s", IssuedAt: now.Add(-time.Hour), Lifetime: 10 * time.Minute},
		// Audience / token profile.
		"multi audience":          {Subject: "s", Raw: map[string]json.RawMessage{"aud": raw(`["` + aud + `","https://other-api.example"]`)}},
		"audience number":         {Subject: "s", Raw: map[string]json.RawMessage{"aud": raw(`7`)}},
		"audience missing":        {Subject: "s", Omit: []string{"aud"}},
		"audience empty array":    {Subject: "s", Raw: map[string]json.RawMessage{"aud": raw(`[]`)}},
		"id token (nonce)":        {Subject: "s", Extra: map[string]any{"nonce": "n-0S6_WzA2Mj"}},
		"app-only token (idtyp)":  {Subject: "s", Extra: map[string]any{"idtyp": "app"}},
		"foreign typ header":      {Subject: "s", Typ: "secevent+jwt"},
		"typ JWE":                 {Subject: "s", Typ: "JWE"},
		"critical header":         {Subject: "s", HeaderExtra: map[string]any{"crit": []string{"exp"}}},
		"subject not a string":    {Subject: "s", Raw: map[string]json.RawMessage{"sub": raw(`123`)}},
		"subject empty":           {Subject: "s", Raw: map[string]json.RawMessage{"sub": raw(`""`)}},
		"tenant claim not string": {Subject: "s", Raw: map[string]json.RawMessage{"tid": raw(`123`)}},
	}
	for name, c := range cases {
		tok := idp.Mint(c)
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClaimValidationPositiveControls(t *testing.T) {
	idp, v := setup(t)
	now := time.Now()
	cases := map[string]syntheticidp.Claims{
		"plain":                   {Subject: "s"},
		"typ at+jwt":              {Subject: "s", Typ: "at+jwt"},
		"typ absent":              {Subject: "s", Typ: "-"},
		"single-element aud list": {Subject: "s", Raw: map[string]json.RawMessage{"aud": raw(`["` + aud + `"]`)}},
		"fractional NumericDate":  {Subject: "s", Raw: map[string]json.RawMessage{"iat": raw(fmt.Sprintf("%d.25", now.Unix())), "exp": raw(fmt.Sprintf("%d.75", now.Add(10*time.Minute).Unix()))}},
		"nbf omitted":             {Subject: "s", Omit: []string{"nbf"}},
		"nbf = iat":               {Subject: "s"},
		"idtyp user":              {Subject: "s", Extra: map[string]any{"idtyp": "user"}},
		"within leeway expired":   {Subject: "s", IssuedAt: now.Add(-10*time.Minute - 10*time.Second), Lifetime: 10 * time.Minute},
		"unrelated claims":        {Subject: "s", Email: "x@example.test", Extra: map[string]any{"scp": "access_as_user charter.access", "ver": "2.0", "oid": "abc"}},
	}
	for name, c := range cases {
		if _, err := v.Verify(context.Background(), idp.Mint(c)); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
	_ = oidc.ErrInvalidToken
}

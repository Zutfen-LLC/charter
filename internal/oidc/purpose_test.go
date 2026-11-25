package oidc_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
)

const scope = "charter.access"

func purposeVerifier(t *testing.T) (*syntheticidp.IdP, *oidc.Verifier) {
	t.Helper()
	idp := syntheticidp.New(aud, tid)
	t.Cleanup(idp.Server.Close)
	v, err := oidc.NewVerifier(oidc.Config{Issuer: idp.Issuer, Audience: aud, TenantID: tid, RequiredScope: scope,
		Keys: &oidc.JWKSFetcher{URL: idp.JWKSURL(), AllowLoopbackHTTP: true}})
	if err != nil {
		t.Fatal(err)
	}
	return idp, v
}

func scp(v string) map[string]json.RawMessage {
	b, _ := json.Marshal(v)
	return map[string]json.RawMessage{"scp": b}
}

// Signed fixtures: every rejection comes from token-purpose validation, not
// from signature, issuer, audience, tenant or time checks.
func TestDelegatedScopeIsRequiredPositively(t *testing.T) {
	idp, v := purposeVerifier(t)
	rejected := map[string]syntheticidp.Claims{
		"missing scp":                           {Subject: "s", Omit: []string{"scp"}},
		"empty scp":                             {Subject: "s", Raw: scp("")},
		"only blanks":                           {Subject: "s", Raw: scp("   ")},
		"incorrect scope":                       {Subject: "s", Raw: scp("other.scope")},
		"substring (suffix longer)":             {Subject: "s", Raw: scp("charter.access.admin")},
		"substring (prefix longer)":             {Subject: "s", Raw: scp("xcharter.access")},
		"substring (truncated)":                 {Subject: "s", Raw: scp("charter")},
		"case differs":                          {Subject: "s", Raw: scp("Charter.Access")},
		"scp as array":                          {Subject: "s", Raw: map[string]json.RawMessage{"scp": json.RawMessage(`["charter.access"]`)}},
		"scp as number":                         {Subject: "s", Raw: map[string]json.RawMessage{"scp": json.RawMessage(`5`)}},
		"scp null":                              {Subject: "s", Raw: map[string]json.RawMessage{"scp": json.RawMessage(`null`)}},
		"scp object":                            {Subject: "s", Raw: map[string]json.RawMessage{"scp": json.RawMessage(`{"charter.access":true}`)}},
		"leading space":                         {Subject: "s", Raw: scp(" charter.access")},
		"trailing space":                        {Subject: "s", Raw: scp("charter.access ")},
		"double space separator":                {Subject: "s", Raw: scp("openid  charter.access")},
		"tab separator":                         {Subject: "s", Raw: scp("openid\tcharter.access")},
		"newline separator":                     {Subject: "s", Raw: scp("openid\ncharter.access")},
		"comma separated":                       {Subject: "s", Raw: scp("openid,charter.access")},
		"app-only token, roles only":            {Subject: "s", Omit: []string{"scp"}, Extra: map[string]any{"roles": []string{"Charter.Admin"}}},
		"ID-token-shaped, no scope":             {Subject: "s", Omit: []string{"scp"}, Extra: map[string]any{"name": "Alice Example", "preferred_username": "alice@example.test", "oid": "00000000-0000-0000-0000-0000000000aa"}},
		"ID-token-shaped with scp of other API": {Subject: "s", Raw: scp("User.Read"), Extra: map[string]any{"name": "Alice Example"}},
	}
	for name, c := range rejected {
		if _, err := v.Verify(context.Background(), idp.Mint(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	accepted := map[string]syntheticidp.Claims{
		"exact scope (default fixture)":    {Subject: "s"},
		"exact scope explicit":             {Subject: "s", Raw: scp("charter.access")},
		"multiple scopes, required last":   {Subject: "s", Raw: scp("openid profile charter.access")},
		"multiple scopes, required first":  {Subject: "s", Raw: scp("charter.access offline_access")},
		"multiple scopes, required middle": {Subject: "s", Raw: scp("openid charter.access email")},
		"scopes plus user app roles":       {Subject: "s", Raw: scp("charter.access"), Extra: map[string]any{"roles": []string{"Charter.Reader"}}},
		"explicit idtyp user":              {Subject: "s", Extra: map[string]any{"idtyp": "user"}},
	}
	for name, c := range accepted {
		if _, err := v.Verify(context.Background(), idp.Mint(c)); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}

// There is no permissive fallback: a verifier cannot be built without an
// explicit delegated scope, so tokens without positive scope evidence can never
// pass by misconfiguration.
func TestVerifierCannotBeBuiltWithoutRequiredScope(t *testing.T) {
	idp := syntheticidp.New(aud, tid)
	defer idp.Server.Close()
	for _, bad := range []string{"", " ", "a b", "a\"b", `a\b`, "a\tb"} {
		_, err := oidc.NewVerifier(oidc.Config{Issuer: idp.Issuer, Audience: aud, TenantID: tid, RequiredScope: bad,
			Keys: &oidc.JWKSFetcher{URL: idp.JWKSURL(), AllowLoopbackHTTP: true}})
		if err == nil {
			t.Errorf("verifier built with RequiredScope %q", bad)
		}
	}
}

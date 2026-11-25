package config

import "testing"

func TestOIDCValidateRequiresExplicitDelegatedScope(t *testing.T) {
	base := OIDC{TenantID: guid, Audience: "api-client-id"}.EntraDefaults()
	if err := base.Validate(); err == nil {
		t.Fatal("entra runtime config without a required scope must fail closed")
	}
	for _, bad := range []string{"", " ", "a b", " charter.access", "charter.access ", "a\"b", `a\b`, "a\tb", "a\nb", "a,b"} {
		o := base
		o.RequiredScope = bad
		if err := o.Validate(); err == nil {
			t.Errorf("scope %q accepted", bad)
		}
	}
	o := base
	o.RequiredScope = "charter.access"
	if err := o.Validate(); err != nil {
		t.Fatalf("complete configuration rejected: %v", err)
	}
	// Custom (non-Entra) IdP is held to the same rule: no permissive fallback.
	c := OIDC{TenantID: "t1", Audience: "a", Issuer: "https://idp.example.test", JWKSURL: "https://idp.example.test/keys"}
	if err := c.Validate(); err == nil {
		t.Fatal("custom IdP without scope accepted")
	}
	c.RequiredScope = "charter.access"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

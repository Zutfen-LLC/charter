package config

import (
	"strings"
	"testing"
)

const guid = "11111111-2222-3333-4444-555555555555"

func TestOIDCValidate(t *testing.T) {
	ok := func(o OIDC) OIDC { return o.EntraDefaults() }
	valid := ok(OIDC{TenantID: guid, Audience: "api://charter-test"})
	if err := valid.Validate(); err != nil {
		t.Fatalf("entra defaults should validate: %v", err)
	}
	if valid.Issuer != "https://login.microsoftonline.com/"+guid+"/v2.0" ||
		valid.JWKSURL != "https://login.microsoftonline.com/"+guid+"/discovery/v2.0/keys" {
		t.Fatalf("entra defaults: %+v", valid)
	}
	custom := OIDC{TenantID: "t1", Audience: "a", Issuer: "https://idp.example.test", JWKSURL: "https://idp.example.test/keys"}
	if err := custom.Validate(); err != nil {
		t.Fatalf("custom https IdP: %v", err)
	}

	bad := map[string]OIDC{
		"missing audience":          ok(OIDC{TenantID: guid}),
		"missing tenant id":         {Audience: "a", Issuer: "https://idp.example.test", JWKSURL: "https://idp.example.test/keys"},
		"only jwks url":             {JWKSURL: "https://idp.example.test/keys"},
		"only issuer":               {Issuer: "https://idp.example.test"},
		"custom missing jwks":       {TenantID: "t1", Audience: "a", Issuer: "https://idp.example.test"},
		"custom missing issuer":     {TenantID: "t1", Audience: "a", JWKSURL: "https://idp.example.test/keys"},
		"http issuer":               {TenantID: "t1", Audience: "a", Issuer: "http://idp.example.test", JWKSURL: "https://idp.example.test/keys"},
		"http jwks":                 {TenantID: "t1", Audience: "a", Issuer: "https://idp.example.test", JWKSURL: "http://idp.example.test/keys"},
		"http loopback no optin":    {TenantID: "t1", Audience: "a", Issuer: "http://127.0.0.1:9", JWKSURL: "http://127.0.0.1:9/keys"},
		"ftp scheme":                {TenantID: "t1", Audience: "a", Issuer: "https://idp.example.test", JWKSURL: "ftp://idp.example.test/keys"},
		"userinfo in jwks":          {TenantID: "t1", Audience: "a", Issuer: "https://idp.example.test", JWKSURL: "https://u:p@idp.example.test/keys"},
		"fragment in jwks":          {TenantID: "t1", Audience: "a", Issuer: "https://idp.example.test", JWKSURL: "https://idp.example.test/keys#x"},
		"no host":                   {TenantID: "t1", Audience: "a", Issuer: "https://idp.example.test", JWKSURL: "https:///keys"},
		"entra issuer wrong tenant": {TenantID: guid, Audience: "a", Issuer: "https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0", JWKSURL: "https://login.microsoftonline.com/" + guid + "/discovery/v2.0/keys"},
		"entra jwks wrong tenant":   {TenantID: guid, Audience: "a", Issuer: "https://login.microsoftonline.com/" + guid + "/v2.0", JWKSURL: "https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/discovery/v2.0/keys"},
		"tenant id with slash":      ok(OIDC{TenantID: guid + "/x", Audience: "a"}),
	}
	for name, o := range bad {
		if err := o.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Plain HTTP is allowed only for loopback hosts and only with the explicit fixture opt-in.
	fixture := OIDC{TenantID: "t1", Audience: "a", Issuer: "http://127.0.0.1:9", JWKSURL: "http://127.0.0.1:9/keys", AllowInsecureLoopback: true}
	if err := fixture.Validate(); err != nil {
		t.Errorf("loopback fixture with opt-in: %v", err)
	}
	fixture.JWKSURL = "http://idp.example.test/keys"
	if err := fixture.Validate(); err == nil {
		t.Error("opt-in must not allow non-loopback plain HTTP")
	}
}

func TestOIDCLoadReadsEnvAndInsecureOptInIsExplicit(t *testing.T) {
	for _, k := range []string{"CHARTER_OIDC_ISSUER", "CHARTER_OIDC_AUDIENCE", "CHARTER_OIDC_TENANT_ID", "CHARTER_OIDC_JWKS_URL", "CHARTER_OIDC_REQUIRED_SCOPE", "CHARTER_OIDC_INSECURE_LOOPBACK_FIXTURE"} {
		t.Setenv(k, "")
	}
	if Load().OIDC.Configured() {
		t.Fatal("empty env must be unconfigured")
	}
	if Load().OIDC.AllowInsecureLoopback {
		t.Fatal("insecure loopback must default off")
	}
	t.Setenv("CHARTER_OIDC_INSECURE_LOOPBACK_FIXTURE", "true")
	t.Setenv("CHARTER_OIDC_REQUIRED_SCOPE", "charter.access")
	o := Load().OIDC
	if !o.AllowInsecureLoopback || o.RequiredScope != "charter.access" {
		t.Fatalf("%+v", o)
	}
	if !strings.Contains(o.Validate().Error(), "tenant") { // configured-but-incomplete is an error
		t.Fatalf("opt-in alone must not count as a valid config: %v", o.Validate())
	}
}

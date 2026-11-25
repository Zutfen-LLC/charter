package main

import (
	"testing"

	"github.com/Zutfen-LLC/charter/internal/config"
)

const guid = "11111111-2222-3333-4444-555555555555"

// The runtime wiring must refuse to produce a verifier from incomplete
// token-purpose configuration.
func TestBuildVerifierFailsClosed(t *testing.T) {
	complete := config.OIDC{TenantID: guid, Audience: "api-client-id", RequiredScope: "charter.access"}
	if v, err := buildVerifier(complete); err != nil || v == nil {
		t.Fatalf("complete config: %v", err)
	}
	for name, o := range map[string]config.OIDC{
		"no scope":          {TenantID: guid, Audience: "api-client-id"},
		"blank scope":       {TenantID: guid, Audience: "api-client-id", RequiredScope: " "},
		"multi-word scope":  {TenantID: guid, Audience: "api-client-id", RequiredScope: "a b"},
		"no audience":       {TenantID: guid, RequiredScope: "charter.access"},
		"no tenant":         {Audience: "api-client-id", RequiredScope: "charter.access"},
		"only scope":        {RequiredScope: "charter.access"},
		"only fixture flag": {AllowInsecureLoopback: true},
	} {
		if _, err := buildVerifier(o); err == nil {
			t.Errorf("%s: verifier built from incomplete configuration", name)
		}
	}
}

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/testdb"
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

// Startup refuses unsafe runtime configuration and accepts the real, restricted
// serving logins. Real PostgreSQL, real login roles.
func TestOpenServingRefusesUnsafeConfigurationAndAcceptsRestrictedLogins(t *testing.T) {
	owner := testdb.New(t)
	c := testdb.Runtime(t, owner)
	ownerURL := c.OwnerURL
	ctx := context.Background()
	good := config.Config{DatabaseURL: c.WorkspaceURL, EvidenceDatabaseURL: c.EvidenceURL}
	s, err := openServing(ctx, good)
	if err != nil {
		t.Fatalf("restricted logins rejected: %v", err)
	}
	s.Close()
	for name, cfg := range map[string]struct {
		c    config.Config
		want string
	}{
		"migration credentials present": {config.Config{DatabaseURL: c.WorkspaceURL, EvidenceDatabaseURL: c.EvidenceURL, MigrateDatabaseURL: ownerURL}, "migration credentials"},
		"missing evidence login":        {config.Config{DatabaseURL: c.WorkspaceURL}, "both required"},
		"same login for both":           {config.Config{DatabaseURL: c.WorkspaceURL, EvidenceDatabaseURL: c.WorkspaceURL}, "different credentials"},
		"owner as workspace login":      {config.Config{DatabaseURL: ownerURL, EvidenceDatabaseURL: c.EvidenceURL}, "unsafe workspace"},
		"owner as evidence login":       {config.Config{DatabaseURL: c.WorkspaceURL, EvidenceDatabaseURL: ownerURL}, "unsafe evidence"},
		"swapped logins":                {config.Config{DatabaseURL: c.EvidenceURL, EvidenceDatabaseURL: c.WorkspaceURL}, "unsafe"},
	} {
		s, err := openServing(ctx, cfg.c)
		if err == nil {
			s.Close()
			t.Errorf("%s: unsafe configuration accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), cfg.want) {
			t.Errorf("%s: error %q does not mention %q", name, err, cfg.want)
		}
	}
	// An unmigrated database is refused by the serving process, which cannot
	// migrate it.
	if _, err := owner.Exec(ctx, `DELETE FROM schema_migrations WHERE version = '0005_runtime_roles.sql'`); err != nil {
		t.Fatal(err)
	}
	if s, err := openServing(ctx, good); err == nil || !strings.Contains(err.Error(), "not migrated") {
		if s != nil {
			s.Close()
		}
		t.Fatalf("unmigrated database accepted: %v", err)
	}
}

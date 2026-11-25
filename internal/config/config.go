// Package config reads server settings from the environment.
package config

import "os"

// Evidence backend kinds. Only the test fixture exists in the pilot scaffold.
const EvidenceBackendTestFixture = "test-fixture"

// OIDC settings. Entra mode needs the designated test tenant's id; nothing
// tenant-specific is committed to the repository.
type OIDC struct {
	Issuer   string // exact issuer; Entra v2: https://login.microsoftonline.com/<tenant-id>/v2.0
	Audience string // application (client) id or api:// URI the token is minted for
	TenantID string // required value of the tenant claim
	JWKSURL  string // Entra v2: https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
}

type Config struct {
	Addr            string
	DatabaseURL     string
	EvidenceBackend string
	OIDC            OIDC
}

func Load() Config {
	return Config{
		Addr:            get("CHARTER_ADDR", "127.0.0.1:8080"),
		DatabaseURL:     os.Getenv("CHARTER_DATABASE_URL"),
		EvidenceBackend: get("CHARTER_EVIDENCE_BACKEND", EvidenceBackendTestFixture),
		OIDC: OIDC{
			Issuer:   os.Getenv("CHARTER_OIDC_ISSUER"),
			Audience: os.Getenv("CHARTER_OIDC_AUDIENCE"),
			TenantID: os.Getenv("CHARTER_OIDC_TENANT_ID"),
			JWKSURL:  os.Getenv("CHARTER_OIDC_JWKS_URL"),
		},
	}
}

func get(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// EntraDefaults fills Issuer and JWKSURL for a Microsoft Entra tenant when
// unset, so a test tenant needs only CHARTER_OIDC_TENANT_ID and _AUDIENCE.
func (o OIDC) EntraDefaults() OIDC {
	if o.TenantID == "" {
		return o
	}
	if o.Issuer == "" {
		o.Issuer = "https://login.microsoftonline.com/" + o.TenantID + "/v2.0"
	}
	if o.JWKSURL == "" {
		o.JWKSURL = "https://login.microsoftonline.com/" + o.TenantID + "/discovery/v2.0/keys"
	}
	return o
}

// Configured reports whether identity is configured at all.
func (o OIDC) Configured() bool {
	return o.TenantID != "" || o.Issuer != "" || o.Audience != "" || o.JWKSURL != ""
}

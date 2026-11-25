// Package config reads server settings from the environment.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/Zutfen-LLC/charter/internal/oidc"
)

// Evidence backend kinds. Both names select the PostgreSQL append-only evidence
// tables; NEITHER is retention-enforced storage (docs/evidence-capture.md).
// "test-fixture" is kept as an alias so existing environments keep working.
const (
	EvidenceBackendTestFixture    = "test-fixture"
	EvidenceBackendPostgresAppend = "postgres-append-only"
)

// OIDC settings. Entra mode needs the designated test tenant's id; nothing
// tenant-specific is committed to the repository.
type OIDC struct {
	Issuer   string // exact issuer; Entra v2: https://login.microsoftonline.com/<tenant-id>/v2.0
	Audience string // application (client) id or api:// URI the token is minted for
	TenantID string // required value of the tenant claim
	JWKSURL  string // Entra v2: https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
	// RequiredScope is the delegated API scope (a single scope name such as
	// "charter.access", not the api:// URI) that must appear exactly in the
	// token's scp claim. Required; there is no default.
	RequiredScope string
	// AllowInsecureLoopback permits plain-HTTP issuer/JWKS URLs on loopback
	// hosts ONLY, for synthetic fixtures. It defaults off and never relaxes
	// anything for non-loopback hosts.
	AllowInsecureLoopback bool
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
		EvidenceBackend: get("CHARTER_EVIDENCE_BACKEND", EvidenceBackendPostgresAppend),
		OIDC: OIDC{
			Issuer:   os.Getenv("CHARTER_OIDC_ISSUER"),
			Audience: os.Getenv("CHARTER_OIDC_AUDIENCE"),
			TenantID: os.Getenv("CHARTER_OIDC_TENANT_ID"),
			JWKSURL:  os.Getenv("CHARTER_OIDC_JWKS_URL"),

			RequiredScope:         os.Getenv("CHARTER_OIDC_REQUIRED_SCOPE"),
			AllowInsecureLoopback: truthy(os.Getenv("CHARTER_OIDC_INSECURE_LOOPBACK_FIXTURE")),
		},
	}
}

func get(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func truthy(v string) bool { return v == "1" || strings.EqualFold(v, "true") }

const entraHost = "login.microsoftonline.com"

// EntraDefaults fills Issuer and JWKSURL for a Microsoft Entra tenant, but only
// when BOTH are unset: setting just one is a partial configuration that
// Validate rejects rather than something to paper over.
func (o OIDC) EntraDefaults() OIDC {
	if o.TenantID == "" || o.Issuer != "" || o.JWKSURL != "" {
		return o
	}
	o.Issuer = "https://" + entraHost + "/" + o.TenantID + "/v2.0"
	o.JWKSURL = "https://" + entraHost + "/" + o.TenantID + "/discovery/v2.0/keys"
	return o
}

// Configured reports whether any identity setting is present. A server with any
// OIDC setting must pass Validate; it never silently falls back to "no auth".
func (o OIDC) Configured() bool {
	return o.TenantID != "" || o.Issuer != "" || o.Audience != "" || o.JWKSURL != "" ||
		o.RequiredScope != "" || o.AllowInsecureLoopback
}

var tenantIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)

// Validate rejects incomplete, inconsistent or unsafe identity configuration.
// Call it on the result of EntraDefaults.
func (o OIDC) Validate() error {
	switch {
	case o.TenantID == "":
		return errors.New("oidc: tenant id (CHARTER_OIDC_TENANT_ID) is required")
	case !tenantIDRe.MatchString(o.TenantID):
		return errors.New("oidc: tenant id has invalid characters")
	case o.Audience == "":
		return errors.New("oidc: audience (CHARTER_OIDC_AUDIENCE) is required")
	case !oidc.ValidScopeToken(o.RequiredScope):
		return errors.New("oidc: a single valid delegated scope name (CHARTER_OIDC_REQUIRED_SCOPE) is required")
	case o.Issuer == "" || o.JWKSURL == "":
		return errors.New("oidc: issuer and JWKS URL must be set together (or both left unset for Entra defaults)")
	}
	iss, err := o.checkURL("issuer", o.Issuer)
	if err != nil {
		return err
	}
	jwks, err := o.checkURL("JWKS URL", o.JWKSURL)
	if err != nil {
		return err
	}
	issEntra, jwksEntra := iss.Hostname() == entraHost, jwks.Hostname() == entraHost
	if issEntra != jwksEntra {
		return errors.New("oidc: issuer and JWKS URL must both be Entra or both be non-Entra")
	}
	if issEntra {
		if iss.Path != "/"+o.TenantID+"/v2.0" {
			return errors.New("oidc: Entra issuer does not match the configured tenant id")
		}
		if !strings.HasPrefix(jwks.Path, "/"+o.TenantID+"/") {
			return errors.New("oidc: Entra JWKS URL does not match the configured tenant id")
		}
	}
	return nil
}

func (o OIDC) checkURL(what, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, fmt.Errorf("oidc: %s is not a clean absolute URL", what)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !o.AllowInsecureLoopback || !oidc.IsLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("oidc: %s must use https (plain http is allowed only for loopback fixtures with CHARTER_OIDC_INSECURE_LOOPBACK_FIXTURE)", what)
		}
	default:
		return nil, fmt.Errorf("oidc: %s must use https", what)
	}
	return u, nil
}

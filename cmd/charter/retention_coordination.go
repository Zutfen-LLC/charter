package main

import (
	"context"
	"crypto/tls"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var coordinationID = regexp.MustCompile(`^[1-9][0-9]{0,19}:[1-9][0-9]{0,9}:sha256:[0-9a-f]{64}$`)
var errCoordination = errors.New("retained coordination authority mismatch")

func authorityBody(deployment, coordination string) []byte {
	return []byte("Charter C04 synthetic coordination authority v2\n" + deployment + "\n" + coordination + "\n")
}

// Pin the separately provisioned PostgreSQL TLS key before authentication,
// then check the actual cluster/database catalogs on each authenticated
// connection. This covers workspace reconnects and both non-reconnecting
// fence sessions, rather than checking only one session borrowed at startup.
func openRetainedCoordinationPool(ctx context.Context, dsn string, signed qualificationStatement) (*pgxpool.Pool, error) {
	c, err := labDSN(dsn)
	if err != nil {
		return nil, err
	}
	if c.ConnConfig.TLSConfig == nil || len(c.ConnConfig.Fallbacks) != 0 || !coordinationID.MatchString(signed.Coordination) {
		return nil, errors.New("retained coordination requires pinned PostgreSQL TLS without fallback")
	}
	catalogID, spki, _ := strings.Cut(signed.Coordination, ":sha256:")
	c.ConnConfig.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The qualification signer pins the exact server public key, not a
		// hostname or a CA. VerifyConnection replaces PKI verification.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errCoordination
			}
			leaf := cs.PeerCertificates[0]
			now := time.Now()
			if evidence.SHA256(leaf.RawSubjectPublicKeyInfo) != "sha256:"+spki || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
				return errCoordination
			}
			return nil
		},
	}
	c.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var actual, bound string
		var primaryPublic bool
		err := conn.QueryRow(ctx, `SELECT c.system_identifier::text || ':' || d.oid::text,
		   NOT pg_catalog.pg_is_in_recovery() AND pg_catalog.current_schema() = 'public', `+databaseBindingSQL+`
		   FROM pg_catalog.pg_control_system() c CROSS JOIN pg_catalog.pg_database d
		   WHERE d.datname = pg_catalog.current_database()`).Scan(&actual, &primaryPublic, &bound)
		if err != nil || !primaryPublic || actual != catalogID || bound != evidence.RetentionProfile+":"+signed.Deployment {
			return errCoordination
		}
		return nil
	}
	return pgxpool.NewWithConfig(ctx, c)
}

// Read the database-level setting from the catalog; a session GUC/role
// override is not an ownership assertion.
const databaseBindingSQL = `COALESCE((SELECT substring(v FROM length('charter.evidence_binding=')+1)
   FROM pg_catalog.pg_db_role_setting s
   JOIN pg_catalog.pg_database d ON d.oid=s.setdatabase
   CROSS JOIN pg_catalog.unnest(s.setconfig) v
   WHERE d.datname=pg_catalog.current_database() AND s.setrole=0 AND starts_with(v,'charter.evidence_binding=')), '')`

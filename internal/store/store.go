// Package store holds identity resolution and authorization queries.
//
// Every query that touches tenant or project data takes the caller's Principal
// and filters by principal.TenantID and project membership *in SQL*, so a
// handler bug cannot return another project's rows. Nothing here caches an
// authorization decision: each call reads committed state, so a revocation is
// visible to the very next call.
package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Roles (docs/contracts/role-matrix.md). project_member is per project.
const (
	RoleTenantAdmin    = "tenant_admin"
	RoleRecordsOfficer = "records_officer"
	RoleExportReviewer = "export_reviewer"
	RoleOperator       = "operator"
)

var tenantRoles = map[string]bool{RoleTenantAdmin: true, RoleRecordsOfficer: true, RoleExportReviewer: true, RoleOperator: true}

func ValidRole(r string) bool { return tenantRoles[r] }

var (
	ErrNotProvisioned = errors.New("identity not provisioned or user disabled")
	ErrNotFound       = errors.New("not found")
	ErrForbidden      = errors.New("forbidden")
)

// Principal is the authenticated caller, resolved from the database. Its
// TenantID and UserID are the only tenant/user values handlers may use.
type Principal struct {
	UserID   string
	TenantID string
	Roles    map[string]bool
}

func (p Principal) Has(role string) bool { return p.Roles[role] }

// canon returns the Principal with canonical lowercase ids. A Principal whose
// ids are not UUIDs is malformed and every store operation refuses it (fail
// closed). Principals from Resolve are already canonical; this protects against
// ones constructed or carried elsewhere, so no id spelling can change a
// comparison done in Go (self-grant) or in SQL.
func (p Principal) canon() (Principal, bool) {
	u, ok1 := CanonicalID(p.UserID)
	t, ok2 := CanonicalID(p.TenantID)
	if !ok1 || !ok2 {
		return p, false
	}
	p.UserID, p.TenantID = u, t
	return p, true
}

type Store struct{ DB *pgxpool.Pool }

// Resolve maps a validated (issuer, idp tenant, subject) to an active user.
// Unknown identities and disabled users are refused; nothing is auto-created.
func (s *Store) Resolve(ctx context.Context, issuer, idpTenant, subject string) (Principal, error) {
	var p Principal
	err := s.DB.QueryRow(ctx, `
		SELECT u.id::text, u.tenant_id::text
		FROM tenants t
		JOIN identities i ON i.tenant_id = t.id AND i.subject = $3
		JOIN users u ON u.id = i.user_id AND u.tenant_id = t.id
		WHERE t.issuer = $1 AND t.idp_tenant_id = $2 AND u.disabled_at IS NULL`,
		issuer, idpTenant, subject).Scan(&p.UserID, &p.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrNotProvisioned
	}
	if err != nil {
		return Principal{}, err
	}
	rows, err := s.DB.Query(ctx, `SELECT role FROM tenant_roles WHERE user_id=$1 AND tenant_id=$2`, p.UserID, p.TenantID)
	if err != nil {
		return Principal{}, err
	}
	defer rows.Close()
	p.Roles = map[string]bool{}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return Principal{}, err
		}
		p.Roles[r] = true
	}
	return p, rows.Err()
}

// IsMember reports whether the principal is an active member of the project
// (and the project is in the principal's tenant). Roles confer no membership.
func (s *Store) IsMember(ctx context.Context, p Principal, projectID string) (bool, error) {
	p, okp := p.canon()
	projectID, valid := CanonicalID(projectID)
	if !okp || !valid {
		return false, nil
	}
	var ok bool
	err := s.DB.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM project_members m JOIN users u ON u.id = m.user_id AND u.tenant_id = m.tenant_id
		  WHERE m.project_id=$1 AND m.user_id=$2 AND m.tenant_id=$3 AND u.disabled_at IS NULL)`,
		projectID, p.UserID, p.TenantID).Scan(&ok)
	return ok, err
}

// HasRole re-reads a tenant role from the database (not from Principal.Roles).
func (s *Store) HasRole(ctx context.Context, p Principal, role string) (bool, error) {
	p, okp := p.canon()
	if !okp {
		return false, nil
	}
	var ok bool
	err := s.DB.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM tenant_roles r JOIN users u ON u.id=r.user_id
		  WHERE r.user_id=$1 AND r.tenant_id=$2 AND r.role=$3 AND u.disabled_at IS NULL)`,
		p.UserID, p.TenantID, role).Scan(&ok)
	return ok, err
}

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Artifact struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Title     string `json:"title"`
	Body      string `json:"body,omitempty"`
}

// ListProjects returns only projects the principal is an active member of. Like
// every read below it re-checks that the user is still active, so a Principal
// resolved before a disable cannot read anything afterwards.
func (s *Store) ListProjects(ctx context.Context, p Principal) ([]Project, error) {
	p, okp := p.canon()
	if !okp {
		return nil, ErrForbidden
	}
	rows, err := s.DB.Query(ctx, `
		SELECT pr.id::text, pr.name FROM projects pr
		JOIN project_members m ON m.project_id = pr.id AND m.tenant_id = pr.tenant_id
		JOIN users u ON u.id = m.user_id AND u.tenant_id = m.tenant_id AND u.disabled_at IS NULL
		WHERE m.user_id=$1 AND pr.tenant_id=$2 ORDER BY pr.name`, p.UserID, p.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		var x Project
		if err := rows.Scan(&x.ID, &x.Name); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ListArtifacts lists artifacts of one project the principal belongs to,
// optionally filtered by a substring query. A project the caller is not in
// yields an empty list indistinguishable from an empty project.
func (s *Store) ListArtifacts(ctx context.Context, p Principal, projectID, q string) ([]Artifact, error) {
	if _, okp := p.canon(); !okp {
		return nil, ErrForbidden
	}
	projectID, valid := CanonicalID(projectID)
	if !valid {
		return []Artifact{}, nil
	}
	return s.artifacts(ctx, p, &projectID, q)
}

// Search searches across every project the principal belongs to.
func (s *Store) Search(ctx context.Context, p Principal, q string) ([]Artifact, error) {
	return s.artifacts(ctx, p, nil, q)
}

func (s *Store) artifacts(ctx context.Context, p Principal, projectID *string, q string) ([]Artifact, error) {
	p, okp := p.canon()
	if !okp {
		return nil, ErrForbidden
	}
	rows, err := s.DB.Query(ctx, `
		SELECT a.id::text, a.project_id::text, a.title FROM artifacts a
		JOIN project_members m ON m.project_id = a.project_id AND m.tenant_id = a.tenant_id
		JOIN users u ON u.id = m.user_id AND u.tenant_id = m.tenant_id AND u.disabled_at IS NULL
		WHERE m.user_id=$1 AND a.tenant_id=$2
		  AND ($3::uuid IS NULL OR a.project_id = $3::uuid)
		  AND ($4 = '' OR a.title ILIKE '%' || $4 || '%' OR a.body ILIKE '%' || $4 || '%')
		ORDER BY a.created_at, a.id LIMIT 200`,
		p.UserID, p.TenantID, projectID, escapeLike(q))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Artifact{}
	for rows.Next() {
		var a Artifact
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Title); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetArtifact returns an artifact only if the principal is a member of its
// project; otherwise ErrNotFound (same as nonexistent, to avoid an oracle).
func (s *Store) GetArtifact(ctx context.Context, p Principal, id string) (Artifact, error) {
	p, okp := p.canon()
	if !okp {
		return Artifact{}, ErrForbidden
	}
	id, valid := CanonicalID(id)
	if !valid {
		return Artifact{}, ErrNotFound
	}
	var a Artifact
	err := s.DB.QueryRow(ctx, `
		SELECT a.id::text, a.project_id::text, a.title, a.body FROM artifacts a
		JOIN project_members m ON m.project_id = a.project_id AND m.tenant_id = a.tenant_id
		JOIN users u ON u.id = m.user_id AND u.tenant_id = m.tenant_id AND u.disabled_at IS NULL
		WHERE a.id=$1 AND m.user_id=$2 AND a.tenant_id=$3`, id, p.UserID, p.TenantID).
		Scan(&a.ID, &a.ProjectID, &a.Title, &a.Body)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	return a, err
}

func escapeLike(q string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
}

// CanonicalID returns the canonical lowercase hyphenated form of a UUID
// (ADR 0001 identifiers are lowercase) and false if s is not a UUID. Every
// identifier-bearing operation canonicalizes at its boundary, so comparisons in
// Go and in SQL always see one spelling: 'ABC…' and 'abc…' are the same id.
func CanonicalID(s string) (string, bool) {
	if len(s) != 36 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return "", false
			}
		case !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'):
			return "", false
		}
	}
	return strings.ToLower(s), true
}

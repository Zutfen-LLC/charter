package store

import "context"

// Provisioning helpers for synthetic fixtures and a future admin CLI. They are
// not exposed over HTTP: creating tenants and identities is an out-of-band,
// operator-level action in the pilot.

func (s *Store) CreateTenant(ctx context.Context, issuer, idpTenant, name string) (string, error) {
	var id string
	err := s.DB.QueryRow(ctx, `INSERT INTO tenants(issuer, idp_tenant_id, name) VALUES ($1,$2,$3) RETURNING id::text`,
		issuer, idpTenant, name).Scan(&id)
	return id, err
}

// CreateUser creates a user and binds it to an IdP subject.
func (s *Store) CreateUser(ctx context.Context, tenantID, subject, displayName string) (string, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var id string
	if err := tx.QueryRow(ctx, `INSERT INTO users(tenant_id, display_name) VALUES ($1,$2) RETURNING id::text`, tenantID, displayName).Scan(&id); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identities(tenant_id, subject, user_id) VALUES ($1,$2,$3)`, tenantID, subject, id); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

func (s *Store) CreateProject(ctx context.Context, tenantID, name string) (string, error) {
	var id string
	err := s.DB.QueryRow(ctx, `INSERT INTO projects(tenant_id, name) VALUES ($1,$2) RETURNING id::text`, tenantID, name).Scan(&id)
	return id, err
}

func (s *Store) CreateArtifact(ctx context.Context, tenantID, projectID, title, body string) (string, error) {
	var id string
	err := s.DB.QueryRow(ctx, `INSERT INTO artifacts(tenant_id, project_id, title, body) VALUES ($1,$2,$3,$4) RETURNING id::text`,
		tenantID, projectID, title, body).Scan(&id)
	return id, err
}

// SeedMember and SeedRole bypass authorization; fixtures only.
func (s *Store) SeedMember(ctx context.Context, tenantID, projectID, userID string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO project_members(project_id, tenant_id, user_id) VALUES ($1,$2,$3)`, projectID, tenantID, userID)
	return err
}

func (s *Store) SeedRole(ctx context.Context, tenantID, userID, role string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO tenant_roles(tenant_id, user_id, role) VALUES ($1,$2,$3)`, tenantID, userID, role)
	return err
}

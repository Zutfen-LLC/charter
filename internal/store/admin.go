package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// AddMember adds a user to a project. The actor must be a tenant_admin in the
// project's tenant (re-checked here against the database). All three ids must
// belong to the actor's tenant; composite foreign keys enforce this again.
func (s *Store) AddMember(ctx context.Context, actor Principal, projectID, userID string) error {
	return s.changeMember(ctx, actor, projectID, userID, true)
}

func (s *Store) RemoveMember(ctx context.Context, actor Principal, projectID, userID string) error {
	return s.changeMember(ctx, actor, projectID, userID, false)
}

func (s *Store) changeMember(ctx context.Context, actor Principal, projectID, userID string, add bool) error {
	if !validUUID(projectID) || !validUUID(userID) {
		return ErrNotFound
	}
	return s.inTx(ctx, actor, RoleTenantAdmin, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id=$1 AND tenant_id=$2)
			AND EXISTS (SELECT 1 FROM users WHERE id=$3 AND tenant_id=$2)`, projectID, actor.TenantID, userID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		action := "project_member.remove"
		if add {
			action = "project_member.add"
			if _, err := tx.Exec(ctx, `INSERT INTO project_members(project_id, tenant_id, user_id, added_by)
				VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, projectID, actor.TenantID, userID, actor.UserID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `DELETE FROM project_members WHERE project_id=$1 AND user_id=$2 AND tenant_id=$3`,
			projectID, userID, actor.TenantID); err != nil {
			return err
		}
		return audit(ctx, tx, actor, action, map[string]string{"project_id": projectID, "user_id": userID})
	})
}

// GrantRole / RevokeRole manage tenant roles. Separation of duties: nobody may
// grant themselves records_officer or export_reviewer, and the last
// tenant_admin cannot be removed.
func (s *Store) GrantRole(ctx context.Context, actor Principal, userID, role string) error {
	if !validUUID(userID) || !ValidRole(role) {
		return ErrNotFound
	}
	if userID == actor.UserID && (role == RoleRecordsOfficer || role == RoleExportReviewer) {
		return ErrForbidden
	}
	return s.inTx(ctx, actor, RoleTenantAdmin, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO tenant_roles(tenant_id, user_id, role, granted_by)
			SELECT $1, id, $3, $4 FROM users WHERE id=$2 AND tenant_id=$1
			ON CONFLICT DO NOTHING`, actor.TenantID, userID, role, actor.UserID)
		if err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id=$1 AND tenant_id=$2)`, userID, actor.TenantID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return audit(ctx, tx, actor, "tenant_role.grant", map[string]string{"user_id": userID, "role": role})
	})
}

func (s *Store) RevokeRole(ctx context.Context, actor Principal, userID, role string) error {
	if !validUUID(userID) || !ValidRole(role) {
		return ErrNotFound
	}
	return s.inTx(ctx, actor, RoleTenantAdmin, func(tx pgx.Tx) error {
		if role == RoleTenantAdmin {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_roles WHERE tenant_id=$1 AND role=$2`, actor.TenantID, role).Scan(&n); err != nil {
				return err
			}
			if n <= 1 {
				return ErrForbidden
			}
		}
		tag, err := tx.Exec(ctx, `DELETE FROM tenant_roles WHERE user_id=$1 AND tenant_id=$2 AND role=$3`, userID, actor.TenantID, role)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit(ctx, tx, actor, "tenant_role.revoke", map[string]string{"user_id": userID, "role": role})
	})
}

// DisableUser blocks all access for a user immediately (workspace access only;
// evidence custodian attribution is unaffected by design).
func (s *Store) DisableUser(ctx context.Context, actor Principal, userID string) error {
	if !validUUID(userID) {
		return ErrNotFound
	}
	return s.inTx(ctx, actor, RoleTenantAdmin, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET disabled_at = now() WHERE id=$1 AND tenant_id=$2 AND disabled_at IS NULL`, userID, actor.TenantID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return audit(ctx, tx, actor, "user.disable", map[string]string{"user_id": userID})
	})
}

// inTx runs fn in a transaction after re-verifying, inside that transaction,
// that the actor still holds the role (a stale Principal cannot act).
func (s *Store) inTx(ctx context.Context, actor Principal, role string, fn func(pgx.Tx) error) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_roles r JOIN users u ON u.id=r.user_id
		WHERE r.user_id=$1 AND r.tenant_id=$2 AND r.role=$3 AND u.disabled_at IS NULL)`,
		actor.UserID, actor.TenantID, role).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func audit(ctx context.Context, tx pgx.Tx, actor Principal, action string, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log(tenant_id, actor_id, action, detail) VALUES ($1,$2,$3,$4)`,
		actor.TenantID, actor.UserID, action, b)
	return err
}

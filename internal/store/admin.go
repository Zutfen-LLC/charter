package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// Administrative mutations share one protocol (see inTx):
//
//  1. begin a transaction;
//  2. take the tenant-scoped lock (the tenants row, FOR NO KEY UPDATE), which
//     serializes every administrative mutation within a tenant;
//  3. only then re-verify, from committed state, that the actor is still an
//     active tenant_admin;
//  4. check invariants against that same state;
//  5. mutate and write the audit row in the same transaction.
//
// Because step 3 and 4 run after the lock, a concurrent revocation or
// deactivation committed first is always visible to the later transaction.

// AddMember adds a user to a project; RemoveMember removes one. Both are
// idempotent and audit only an actual change.
func (s *Store) AddMember(ctx context.Context, actor Principal, projectID, userID string) error {
	return s.changeMember(ctx, actor, projectID, userID, true)
}

func (s *Store) RemoveMember(ctx context.Context, actor Principal, projectID, userID string) error {
	return s.changeMember(ctx, actor, projectID, userID, false)
}

func (s *Store) changeMember(ctx context.Context, actor Principal, projectID, userID string, add bool) error {
	projectID, ok1 := CanonicalID(projectID)
	userID, ok2 := CanonicalID(userID)
	if !ok1 || !ok2 {
		return ErrNotFound
	}
	return s.inTx(ctx, actor, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id=$1 AND tenant_id=$2)
			AND EXISTS (SELECT 1 FROM users WHERE id=$3 AND tenant_id=$2)`, projectID, actor.TenantID, userID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		var changed int64
		action := "project_member.remove"
		if add {
			action = "project_member.add"
			tag, err := tx.Exec(ctx, `INSERT INTO project_members(project_id, tenant_id, user_id, added_by)
				VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, projectID, actor.TenantID, userID, actor.UserID)
			if err != nil {
				return err
			}
			changed = tag.RowsAffected()
		} else {
			tag, err := tx.Exec(ctx, `DELETE FROM project_members WHERE project_id=$1 AND user_id=$2 AND tenant_id=$3`,
				projectID, userID, actor.TenantID)
			if err != nil {
				return err
			}
			changed = tag.RowsAffected()
		}
		if changed == 0 {
			return nil
		}
		return audit(ctx, tx, actor, action, map[string]string{"project_id": projectID, "user_id": userID})
	})
}

// GrantRole / RevokeRole manage tenant roles. Separation of duties: nobody may
// grant themselves records_officer or export_reviewer (compared on canonical
// ids, so no UUID spelling matters), and the tenant must always keep at least
// one ACTIVE tenant_admin.
func (s *Store) GrantRole(ctx context.Context, actor Principal, userID, role string) error {
	userID, valid := CanonicalID(userID)
	if !valid || !ValidRole(role) {
		return ErrNotFound
	}
	if userID == actor.UserID && (role == RoleRecordsOfficer || role == RoleExportReviewer) {
		return ErrForbidden
	}
	return s.inTx(ctx, actor, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id=$1 AND tenant_id=$2)`, userID, actor.TenantID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		tag, err := tx.Exec(ctx, `INSERT INTO tenant_roles(tenant_id, user_id, role, granted_by)
			VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, actor.TenantID, userID, role, actor.UserID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return audit(ctx, tx, actor, "tenant_role.grant", map[string]string{"user_id": userID, "role": role})
	})
}

func (s *Store) RevokeRole(ctx context.Context, actor Principal, userID, role string) error {
	userID, valid := CanonicalID(userID)
	if !valid || !ValidRole(role) {
		return ErrNotFound
	}
	return s.inTx(ctx, actor, func(tx pgx.Tx) error {
		if role == RoleTenantAdmin {
			if err := requireOtherActiveAdmin(ctx, tx, actor.TenantID, userID); err != nil {
				return err
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
	userID, valid := CanonicalID(userID)
	if !valid {
		return ErrNotFound
	}
	return s.inTx(ctx, actor, func(tx pgx.Tx) error {
		if err := requireOtherActiveAdmin(ctx, tx, actor.TenantID, userID); err != nil {
			return err
		}
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

// requireOtherActiveAdmin enforces "at least one active tenant_admin remains":
// if target is currently an ACTIVE tenant_admin, some other active tenant_admin
// must exist. Disabled admins keep their role rows but do not count. Must run
// under the tenant lock.
func requireOtherActiveAdmin(ctx context.Context, tx pgx.Tx, tenantID, target string) error {
	var targetIsActiveAdmin bool
	var others int
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(bool_or(r.user_id = $2), false),
		       count(*) FILTER (WHERE r.user_id <> $2)
		FROM tenant_roles r JOIN users u ON u.id = r.user_id AND u.tenant_id = r.tenant_id
		WHERE r.tenant_id=$1 AND r.role='tenant_admin' AND u.disabled_at IS NULL`, tenantID, target).Scan(&targetIsActiveAdmin, &others)
	if err != nil {
		return err
	}
	if targetIsActiveAdmin && others == 0 {
		return ErrForbidden
	}
	return nil
}

// inTx runs fn in a transaction under the tenant-scoped lock, after
// re-verifying (inside that lock) that the actor is still an active
// tenant_admin. A stale Principal therefore cannot commit anything.
func (s *Store) inTx(ctx context.Context, actor Principal, fn func(pgx.Tx) error) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT true FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, actor.TenantID).Scan(&locked); err != nil {
		if err == pgx.ErrNoRows {
			return ErrForbidden
		}
		return err
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_roles r JOIN users u ON u.id=r.user_id AND u.tenant_id=r.tenant_id
		WHERE r.user_id=$1 AND r.tenant_id=$2 AND r.role=$3 AND u.disabled_at IS NULL)`,
		actor.UserID, actor.TenantID, RoleTenantAdmin).Scan(&ok); err != nil {
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

package app

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// dbScope is the row-level security context of one transaction (migration 004).
// A transaction that declares no scope matches no policy, so it reads and changes nothing.
type dbScope struct{ name, organization string }

var (
	ownerScope     = dbScope{name: "owner"}
	loginScope     = dbScope{name: "login"}
	bootstrapScope = dbScope{name: "bootstrap"}
	retentionScope = dbScope{name: "retention"}
)

func tenantScope(organization string) dbScope { return dbScope{"tenant", organization} }

// retentionTenantScope confines retention deletes to one organization's activity rows.
func retentionTenantScope(organization string) dbScope { return dbScope{"retention", organization} }

func (p principal) scope() dbScope {
	if p.Role == "product_owner" {
		return ownerScope
	}
	return tenantScope(p.OrganizationID)
}

func (d devicePrincipal) scope() dbScope { return tenantScope(d.OrganizationID) }

// setScope binds tx to s. set_config(...,true) is transaction-local, so the scope
// never survives on a pooled connection after commit or rollback.
func setScope(ctx context.Context, tx pgx.Tx, s dbScope) error {
	switch {
	case s.name == "tenant" && s.organization != "", s.name == "retention":
	case (s.name == "owner" || s.name == "login" || s.name == "bootstrap") && s.organization == "":
	default:
		return errors.New("invalid database scope")
	}
	_, err := tx.Exec(ctx, "SELECT set_config('app.scope',$1,true),set_config('app.organization_id',$2,true)", s.name, s.organization)
	return err
}

// beginScoped starts a transaction already bound to s; callers still defer Rollback.
func beginScoped(ctx context.Context, db *pgxpool.Pool, s dbScope) (pgx.Tx, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if err = setScope(ctx, tx, s); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

// inScope runs fn in one transaction bound to s and commits only if fn succeeds.
// Handlers send their response afterwards so a slow client never holds a pooled connection.
func inScope(ctx context.Context, db *pgxpool.Pool, s dbScope, fn func(pgx.Tx) error) error {
	tx, err := beginScoped(ctx, db, s)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

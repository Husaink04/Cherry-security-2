package app

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

const SchemaVersion = 4

func CheckSchema(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return fmt.Errorf("database unavailable")
	}
	var version int
	if err := db.QueryRow(ctx, "SELECT coalesce(max(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	if version != SchemaVersion {
		return fmt.Errorf("schema version %d incompatible with required version %d", version, SchemaVersion)
	}
	return nil
}

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 8
	cfg.MinConns = 0
	return pgxpool.NewWithConfig(ctx, cfg)
}
func Migrate(ctx context.Context, db *pgxpool.Pool) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(472903114)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); err != nil {
		return err
	}
	var version int
	if err = tx.QueryRow(ctx, "SELECT coalesce(max(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	if version > SchemaVersion {
		return fmt.Errorf("unsupported database schema version %d", version)
	}
	files := []string{"migrations/001_initial.sql", "migrations/002_ingestion_watermark.sql", "migrations/003_native_agent.sql", "migrations/004_row_level_security.sql"}
	for next := version + 1; next <= SchemaVersion; next++ {
		script, readErr := migrations.ReadFile(files[next-1])
		if readErr != nil {
			return readErr
		}
		if _, err = tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", next); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// GrantRuntimeRole gives the API role table access in the current schema plus the narrow
// pre-tenant lookups from migration 004; row-level security still decides which rows it reaches.
// Identifiers come from the server, never from requests, and are quoted.
func GrantRuntimeRole(ctx context.Context, db *pgxpool.Pool, role string) error {
	var schema string
	if err := db.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		return err
	}
	s, r := pgx.Identifier{schema}.Sanitize(), pgx.Identifier{role}.Sanitize()
	_, err := db.Exec(ctx, "GRANT USAGE ON SCHEMA "+s+" TO "+r+"; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA "+s+" TO "+r+"; GRANT EXECUTE ON FUNCTION auth_login(text),auth_session(text),auth_device(text),claim_enrollment_key(text),is_product_owner(text) TO "+r)
	return err
}

// CheckRuntimeRole refuses a database role that would silently skip row-level security.
func CheckRuntimeRole(ctx context.Context, db *pgxpool.Pool) error {
	var bypass bool
	if err := db.QueryRow(ctx, "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user").Scan(&bypass); err != nil {
		return err
	}
	if bypass {
		return errors.New("runtime database role bypasses row-level security")
	}
	return nil
}

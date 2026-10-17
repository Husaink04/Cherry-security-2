package app

import (
	"context"
	"embed"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

const SchemaVersion = 3

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
	files := []string{"migrations/001_initial.sql", "migrations/002_ingestion_watermark.sql", "migrations/003_native_agent.sql"}
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

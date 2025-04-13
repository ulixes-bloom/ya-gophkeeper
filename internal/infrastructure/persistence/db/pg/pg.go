// Package pg provides an abstraction layer for interacting with a PostgreSQL database.
package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// postgresDB represents a PostgreSQL database connection.
type postgresDB struct {
	db *sql.DB
}

// New initializes a new postgresDB instance and applies migrations.
func New(ctx context.Context, db *sql.DB, migrationsPath string) (*postgresDB, error) {
	newPG := &postgresDB{db: db}
	if err := newPG.runMigrations(migrationsPath); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}
	return newPG, nil
}

// Shutdown gracefully closes the database connection.
func (pg *postgresDB) Shutdown() error {
	if err := pg.db.Close(); err != nil {
		return fmt.Errorf("failed to close db: %w", err)
	}

	return nil
}

// runMigrations applies database migrations from the given path.
func (pg *postgresDB) runMigrations(migrationsPath string) error {
	// Initialize the migration driver for PostgreSQL.
	driver, err := postgres.WithInstance(pg.db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Create a new migration instance.
	m, err := migrate.NewWithDatabaseInstance(fmt.Sprint("file://", migrationsPath), "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create a new migration instance: %w", err)
	}

	// Apply migrations; ignore "no change" errors.
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	return nil
}

// isUniqueViolation checks if an error is a unique constraint violation.
func isUniqueViolation(err error, constraint string) bool {
	if pgError, ok := err.(*pgconn.PgError); ok {
		return pgError.Code == pgerrcode.UniqueViolation &&
			pgError.ConstraintName == constraint
	}
	return false
}

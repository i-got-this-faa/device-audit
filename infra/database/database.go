// Package database owns the controller's PostgreSQL connection and versioned
// schema migrations. It does not persist controller records yet.
package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	// advisoryLockKey serializes migrations across controller processes.
	advisoryLockKey int64 = 0x6465766963656175
	migrationTable        = "schema_migrations"
	pingTimeout           = 10 * time.Second
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

var managedTransaction = regexp.MustCompile(`(?im)^\s*(BEGIN|COMMIT|ROLLBACK)\s*;`)

// Migration is one ordered forward-only schema change.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Status reports the current schema version and any embedded migrations that
// have not been applied.
type Status struct {
	Version int
	Pending []string
}

// Open connects to the selected PostgreSQL database and verifies the connection.
// An empty URL or unavailable database is an explicit error, never a memory fallback.
func Open(ctx context.Context, databaseURL string) (*sql.DB, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, errors.New("database URL is required for durable storage")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	pingContext, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := db.PingContext(pingContext); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return db, nil
}

// Migrate applies the embedded forward-only migrations and returns the final
// schema version. A failed migration rolls back that migration and leaves the
// previous version in place.
func Migrate(ctx context.Context, db *sql.DB) (int, error) {
	return MigrateFS(ctx, db, embeddedMigrations)
}

// MigrateFS applies migrations from the supplied filesystem. Tests use it to
// exercise upgrades and injected failures without changing the embedded set.
func MigrateFS(ctx context.Context, db *sql.DB, files fs.FS) (int, error) {
	migrations, err := loadMigrations(files)
	if err != nil {
		return 0, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return 0, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		unlockContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(unlockContext, "SELECT pg_advisory_unlock($1)", advisoryLockKey)
	}()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+migrationTable+` (
		version integer PRIMARY KEY,
		name text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return 0, fmt.Errorf("create migration ledger: %w", err)
	}

	applied, err := appliedMigrations(ctx, conn)
	if err != nil {
		return 0, err
	}
	current := 0
	for version := range applied {
		if version > current {
			current = version
		}
	}
	for _, migration := range migrations {
		if appliedName, ok := applied[migration.Version]; ok {
			if appliedName != migration.Name {
				return current, fmt.Errorf("migration %03d was applied as %q but is now %q", migration.Version, appliedName, migration.Name)
			}
			continue
		}
		if migration.Version < current {
			return current, fmt.Errorf("migration %s is older than applied version %d", migration.Name, current)
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return current, fmt.Errorf("begin migration %s: %w", migration.Name, err)
		}
		if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
			_ = tx.Rollback()
			return current, fmt.Errorf("apply migration %s: %w", migration.Name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+migrationTable+` (version, name) VALUES ($1, $2)`, migration.Version, migration.Name); err != nil {
			_ = tx.Rollback()
			return current, fmt.Errorf("record migration %s: %w", migration.Name, err)
		}
		if err := tx.Commit(); err != nil {
			return current, fmt.Errorf("commit migration %s: %w", migration.Name, err)
		}
		current = migration.Version
	}
	return current, nil
}

// CurrentStatus reads the applied version and lists embedded migrations that
// still need to run. It is read-only.
func CurrentStatus(ctx context.Context, db *sql.DB) (Status, error) {
	migrations, err := loadMigrations(embeddedMigrations)
	if err != nil {
		return Status{}, err
	}
	applied, err := appliedMigrations(ctx, db)
	if err != nil {
		return Status{}, err
	}
	var status Status
	for version := range applied {
		if version > status.Version {
			status.Version = version
		}
	}
	for _, migration := range migrations {
		if _, ok := applied[migration.Version]; !ok {
			status.Pending = append(status.Pending, migration.Name)
		}
	}
	return status, nil
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func appliedMigrations(ctx context.Context, db queryer) (map[int]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT version, name FROM `+migrationTable)
	if err != nil {
		return nil, fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()
	applied := make(map[int]string)
	for rows.Next() {
		var version int
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			return nil, fmt.Errorf("scan migration ledger: %w", err)
		}
		applied[version] = name
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read migration ledger: %w", err)
	}
	return applied, nil
}

func loadMigrations(files fs.FS) ([]Migration, error) {
	paths, err := fs.Glob(files, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if len(paths) == 0 {
		return nil, errors.New("no migrations found")
	}
	migrations := make([]Migration, 0, len(paths))
	seen := make(map[int]string)
	for _, migrationPath := range paths {
		version, name, err := parseMigrationName(migrationPath)
		if err != nil {
			return nil, err
		}
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %03d: %q and %q", version, previous, name)
		}
		body, err := fs.ReadFile(files, migrationPath)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		if strings.TrimSpace(string(body)) == "" {
			return nil, fmt.Errorf("migration %s is empty", name)
		}
		if managedTransaction.Match(body) {
			return nil, fmt.Errorf("migration %s must not manage its own transaction", name)
		}
		seen[version] = name
		migrations = append(migrations, Migration{Version: version, Name: name, SQL: string(body)})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

func parseMigrationName(path string) (int, string, error) {
	base := path[strings.LastIndex(path, "/")+1:]
	stem, ok := strings.CutSuffix(base, ".sql")
	if !ok {
		return 0, "", fmt.Errorf("migration %q must end in .sql", base)
	}
	number, name, ok := strings.Cut(stem, "_")
	if !ok || number == "" || name == "" {
		return 0, "", fmt.Errorf("migration %q must be named NNN_name.sql", base)
	}
	version, err := strconv.Atoi(number)
	if err != nil || version < 1 || len(number) != 3 {
		return 0, "", fmt.Errorf("migration %q must start with a three-digit positive version", base)
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return 0, "", fmt.Errorf("migration %q must use lowercase letters, digits and underscores", base)
		}
	}
	return version, stem, nil
}

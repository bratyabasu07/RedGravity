package persistence

import (
	"context"
	"fmt"
	"redgravity/internal/config"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB represents database connection pooling
type DB struct {
	pool *pgxpool.Pool
}

// NewDB creates a new database connection pool and initializes schema
func NewDB(cfg *config.DatabaseConfig) (*DB, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name, cfg.SSLMode,
	)

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Set connection pool settings
	config.MaxConns = 20
	config.MinConns = 5
	config.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test connection
	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	fmt.Println("[DB] Connected to PostgreSQL using pgxpool")

	db := &DB{pool: pool}
	if err := db.initSchema(); err != nil {
		return nil, err
	}

	return db, nil
}

// initSchema initializes database schema and migrations
func (db *DB) initSchema() error {
	ctx := context.Background()

	// 1. Create migrations table if not exists
	_, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// 2. Define schema versions
	migrations := []string{
		// Version 1: Initial schema
		`
		CREATE TABLE IF NOT EXISTS scans (
			id SERIAL PRIMARY KEY,
			scan_id TEXT UNIQUE NOT NULL,
			target TEXT NOT NULL,
			mode TEXT NOT NULL,
			status TEXT NOT NULL,
			started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP WITH TIME ZONE,
			total_ips INTEGER DEFAULT 0,
			total_services INTEGER DEFAULT 0,
			total_cves INTEGER DEFAULT 0,
			summary JSONB
		);

		CREATE TABLE IF NOT EXISTS services (
			id SERIAL PRIMARY KEY,
			scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT DEFAULT 'tcp',
			service_name TEXT,
			version TEXT,
			banner TEXT,
			source TEXT,
			confidence_score INTEGER,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS cves (
			id SERIAL PRIMARY KEY,
			service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
			cve_id TEXT NOT NULL,
			cvss_score NUMERIC(3,1),
			severity TEXT,
			description TEXT,
			exploit_available BOOLEAN DEFAULT FALSE,
			references TEXT[],
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS threats (
			id SERIAL PRIMARY KEY,
			scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			threat_score INTEGER,
			tags TEXT[],
			provider TEXT,
			details JSONB,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS scores (
			id SERIAL PRIMARY KEY,
			scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			overall_score INTEGER,
			risk_level TEXT,
			details JSONB,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
		CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id);
		CREATE INDEX IF NOT EXISTS idx_services_ip ON services(ip);
		CREATE INDEX IF NOT EXISTS idx_cves_service_id ON cves(service_id);
		CREATE INDEX IF NOT EXISTS idx_threats_scan_id ON threats(scan_id);
		CREATE INDEX IF NOT EXISTS idx_scores_scan_id ON scores(scan_id);
		`,
	}

	// 3. Apply migrations
	for version, sql := range migrations {
		v := version + 1

		var exists bool
		err := db.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM migrations WHERE version = $1)", v).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check migration version %d: %w", v, err)
		}

		if !exists {
			fmt.Printf("[DB] Applying migration version %d...\n", v)

			if err := db.applyMigration(ctx, v, sql); err != nil {
				return err
			}
			fmt.Printf("[DB] Migration version %d applied successfully\n", v)
		}
	}

	return nil
}

// applyMigration applies a single migration in a transaction
func (db *DB) applyMigration(ctx context.Context, version int, sql string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, sql); err != nil {
		return fmt.Errorf("failed to apply migration version %d: %w", version, err)
	}

	if _, err := tx.Exec(ctx, "INSERT INTO migrations (version) VALUES ($1)", version); err != nil {
		return fmt.Errorf("failed to record migration version %d: %w", version, err)
	}

	return tx.Commit(ctx)
}

// SaveScan saves initial scan metadata
func (db *DB) SaveScan(ctx context.Context, scanID, target, mode, status string) error {
	if db == nil {
		return nil
	}

	query := `
		INSERT INTO scans (scan_id, target, mode, status, started_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (scan_id) DO UPDATE SET
			status = EXCLUDED.status,
			started_at = EXCLUDED.started_at
	`

	_, err := db.pool.Exec(ctx, query, scanID, target, mode, status, time.Now())
	return err
}

// UpdateScanStatus updates scan status and final counts
func (db *DB) UpdateScanStatus(ctx context.Context, scanID, status string, totalIPs, totalServices, totalCVEs int) error {
	if db == nil {
		return nil
	}

	query := `
		UPDATE scans 
		SET status = $1, completed_at = $2, total_ips = $3, total_services = $4, total_cves = $5 
		WHERE scan_id = $6
	`
	_, err := db.pool.Exec(ctx, query, status, time.Now(), totalIPs, totalServices, totalCVEs, scanID)
	return err
}

// SaveService saves a discovered service
func (db *DB) SaveService(ctx context.Context, scanID string, ip string, port int, protocol, name, version, banner, source string, confidence int) (int, error) {
	if db == nil {
		return 0, nil
	}

	query := `
		INSERT INTO services (scan_id, ip, port, protocol, service_name, version, banner, source, confidence_score)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`

	var id int
	err := db.pool.QueryRow(ctx, query, scanID, ip, port, protocol, name, version, banner, source, confidence).Scan(&id)
	return id, err
}

// SaveCVE saves a discovered CVE for a service
func (db *DB) SaveCVE(ctx context.Context, serviceID int, cveID string, cvss float64, severity, description string, exploit bool, refs []string) error {
	if db == nil {
		return nil
	}

	query := `
		INSERT INTO cves (service_id, cve_id, cvss_score, severity, description, exploit_available, references)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := db.pool.Exec(ctx, query, serviceID, cveID, cvss, severity, description, exploit, refs)
	return err
}

// SaveThreat saves threat intel data
func (db *DB) SaveThreat(ctx context.Context, scanID string, ip string, score int, tags []string, provider string, details interface{}) error {
	if db == nil {
		return nil
	}

	query := `
		INSERT INTO threats (scan_id, ip, threat_score, tags, provider, details)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := db.pool.Exec(ctx, query, scanID, ip, score, tags, provider, details)
	return err
}

// SaveScore saves scoring details
func (db *DB) SaveScore(ctx context.Context, scanID string, ip string, score int, level string, details interface{}) error {
	if db == nil {
		return nil
	}

	query := `
		INSERT INTO scores (scan_id, ip, overall_score, risk_level, details)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := db.pool.Exec(ctx, query, scanID, ip, score, level, details)
	return err
}

// GetPool returns the underlying connection pool
func (db *DB) GetPool() *pgxpool.Pool {
	if db == nil {
		return nil
	}
	return db.pool
}

// Close closes the database connection pool
func (db *DB) Close() {
	if db != nil && db.pool != nil {
		db.pool.Close()
	}
}

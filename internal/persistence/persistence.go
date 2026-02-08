package persistence

import (
	"database/sql"
	"fmt"
	"redgravity/internal/config"
	"time"

	_ "github.com/lib/pq"
)

// DB represents database connection
type DB struct {
	conn *sql.DB
}

// NewDB creates a new database connection
func NewDB(cfg *config.DatabaseConfig) (*DB, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode,
	)

	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	fmt.Println("[DB] Connected to PostgreSQL")

	db := &DB{conn: conn}
	if err := db.initSchema(); err != nil {
		return nil, err
	}

	return db, nil
}

// initSchema initializes database schema
func (db *DB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id SERIAL PRIMARY KEY,
		scan_id VARCHAR(255) UNIQUE NOT NULL,
		target VARCHAR(255) NOT NULL,
		mode VARCHAR(50) NOT NULL,
		status VARCHAR(50) NOT NULL,
		started_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP,
		total_ips INTEGER,
		total_services INTEGER,
		total_cves INTEGER
	);

	CREATE TABLE IF NOT EXISTS scan_results (
		id SERIAL PRIMARY KEY,
		scan_id VARCHAR(255) REFERENCES scans(scan_id),
		ip VARCHAR(45) NOT NULL,
		port INTEGER NOT NULL,
		service VARCHAR(100),
		version VARCHAR(100),
		cve_id VARCHAR(50),
		cvss_score DECIMAL(3,1),
		severity VARCHAR(20),
		confidence_score INTEGER,
		created_at TIMESTAMP DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
	CREATE INDEX IF NOT EXISTS idx_results_scan_id ON scan_results(scan_id);
	CREATE INDEX IF NOT EXISTS idx_results_ip ON scan_results(ip);
	`

	_, err := db.conn.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	fmt.Println("[DB] Schema initialized")
	return nil
}

// SaveScan saves scan metadata
func (db *DB) SaveScan(scanID, target, mode, status string, totalIPs, totalServices, totalCVEs int) error {
	if db == nil {
		return nil
	}

	query := `
		INSERT INTO scans (scan_id, target, mode, status, started_at, total_ips, total_services, total_cves)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := db.conn.Exec(query, scanID, target, mode, status, time.Now(), totalIPs, totalServices, totalCVEs)
	return err
}

// UpdateScanStatus updates scan status
func (db *DB) UpdateScanStatus(scanID, status string) error {
	if db == nil {
		return nil
	}

	query := `UPDATE scans SET status = $1, completed_at = $2 WHERE scan_id = $3`
	_, err := db.conn.Exec(query, status, time.Now(), scanID)
	return err
}

// Close closes the database connection
func (db *DB) Close() error {
	if db == nil || db.conn == nil {
		return nil
	}
	return db.conn.Close()
}

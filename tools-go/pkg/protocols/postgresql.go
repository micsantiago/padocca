// Package protocols provides PostgreSQL bruteforce implementation
package protocols

import (
	"database/sql"
	"fmt"
	"time"
	
	_ "github.com/lib/pq"
)

// PostgreSQLBruteforcer handles PostgreSQL protocol bruteforce
type PostgreSQLBruteforcer struct {
	host    string
	port    int
	timeout time.Duration
}

// NewPostgreSQLBruteforcer creates a new PostgreSQL bruteforcer
func NewPostgreSQLBruteforcer(host string, port int, timeout time.Duration) *PostgreSQLBruteforcer {
	return &PostgreSQLBruteforcer{
		host:    host,
		port:    port,
		timeout: timeout,
	}
}

// TryAuth attempts PostgreSQL authentication
func (p *PostgreSQLBruteforcer) TryAuth(username, password string) (bool, error) {
	// Build connection string
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=%d",
		username, password, p.host, p.port, int(p.timeout.Seconds()))
	
	// Attempt connection
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()
	
	// Test connection
	err = db.Ping()
	if err != nil {
		return false, nil // Wrong credentials
	}
	
	return true, nil // Success
}

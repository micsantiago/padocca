// Package protocols provides shared protocol implementations for bruteforce attacks
package protocols

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"
	
	_ "github.com/go-sql-driver/mysql"
)

// MySQLBruteforcer handles MySQL protocol bruteforce
type MySQLBruteforcer struct {
	host    string
	port    int
	timeout time.Duration
}

// NewMySQLBruteforcer creates a new MySQL bruteforcer
func NewMySQLBruteforcer(host string, port int, timeout time.Duration) *MySQLBruteforcer {
	return &MySQLBruteforcer{
		host:    host,
		port:    port,
		timeout: timeout,
	}
}

// TryAuth attempts MySQL authentication
func (m *MySQLBruteforcer) TryAuth(username, password string) (bool, error) {
	// Build connection string
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/mysql?timeout=%s",
		username, password, m.host, m.port, m.timeout)
	
	// Attempt connection
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()
	
	// Set connection timeout
	db.SetConnMaxLifetime(m.timeout)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	
	err = db.PingContext(ctx)
	if err != nil {
		// Check if it's authentication error
		// For now, we'll consider any error as failed auth
		// Full implementation would check specific MySQL error codes
		return false, err // Connection error
	}
	
	return true, nil // Success
}

// GetBanner retrieves MySQL server banner
func (m *MySQLBruteforcer) GetBanner() (string, error) {
	conn, err := net.DialTimeout("tcp", 
		fmt.Sprintf("%s:%d", m.host, m.port), m.timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	
	// Read MySQL handshake packet
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(m.timeout))
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}
	
	// Parse version from handshake
	if n > 5 {
		// Skip packet header and protocol version
		versionEnd := 5
		for i := 5; i < n && buffer[i] != 0; i++ {
			versionEnd = i
		}
		if versionEnd > 5 {
			return string(buffer[5:versionEnd]), nil
		}
	}
	
	return "Unknown", nil
}

// CheckVulnerabilities checks for known MySQL vulnerabilities
func (m *MySQLBruteforcer) CheckVulnerabilities() []string {
	vulns := []string{}
	
	// Get banner first
	banner, err := m.GetBanner()
	if err == nil {
		// Check for old versions with known vulnerabilities
		versionChecks := map[string]string{
			"5.0":  "CVE-2012-2122: Authentication bypass",
			"5.1":  "CVE-2012-2122: Authentication bypass",
			"5.5":  "CVE-2016-6662: Remote code execution",
			"5.6":  "CVE-2016-6663: Privilege escalation",
			"5.7.0": "CVE-2016-6664: Root privilege escalation",
		}
		
		for version, vuln := range versionChecks {
			if contains(banner, version) {
				vulns = append(vulns, vuln)
			}
		}
	}
	
	// Check for anonymous access
	if success, _ := m.TryAuth("", ""); success {
		vulns = append(vulns, "Anonymous access enabled")
	}
	
	// Check for default credentials
	defaultCreds := []struct{username, password string}{
		{"root", ""},
		{"root", "root"},
		{"root", "toor"},
		{"admin", "admin"},
		{"mysql", "mysql"},
	}
	
	for _, cred := range defaultCreds {
		if success, _ := m.TryAuth(cred.username, cred.password); success {
			vulns = append(vulns, fmt.Sprintf("Default credentials: %s:%s", 
				cred.username, cred.password))
		}
	}
	
	return vulns
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

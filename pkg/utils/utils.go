package utils

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"
)

// ExpandCIDR expands a CIDR notation into a list of IP addresses
func ExpandCIDR(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var ips []net.IP
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		// Make a copy to avoid reference issues
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}

	return ips, nil
}

// incrementIP increments an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IsPrivateIP checks if an IP is private (RFC1918)
func IsPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBogonIP checks if an IP is in bogon ranges
func IsBogonIP(ip net.IP) bool {
	bogonRanges := []string{
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	for _, cidr := range bogonRanges {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateIP validates if a string is a valid IP address
func ValidateIP(ipStr string) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	return ip, nil
}

// DeduplicateIPs removes duplicate IPs from a slice
func DeduplicateIPs(ips []net.IP) []net.IP {
	seen := make(map[string]bool)
	var result []net.IP

	for _, ip := range ips {
		ipStr := ip.String()
		if !seen[ipStr] {
			seen[ipStr] = true
			result = append(result, ip)
		}
	}
	return result
}

// HTTPClientWithRetry creates an HTTP client with retry logic
type HTTPClientWithRetry struct {
	Client      *http.Client
	MaxRetries  int
	BackoffBase time.Duration
}

// NewHTTPClientWithRetry creates a new HTTP client with retry
func NewHTTPClientWithRetry(maxRetries int, backoff time.Duration) *HTTPClientWithRetry {
	return &HTTPClientWithRetry{
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
		MaxRetries:  maxRetries,
		BackoffBase: backoff,
	}
}

// Do performs an HTTP request with exponential backoff retry
func (c *HTTPClientWithRetry) Do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := 0; i < c.MaxRetries; i++ {
		resp, err = c.Client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		if resp != nil {
			resp.Body.Close()
		}

		// Exponential backoff
		backoff := c.BackoffBase * time.Duration(1<<uint(i))
		time.Sleep(backoff)
	}

	return resp, fmt.Errorf("max retries exceeded: %w", err)
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// RandomString generates a random string of given length
func RandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// RandomInt generates a random integer between min and max
func RandomInt(min, max int) int {
	return rand.Intn(max-min+1) + min
}

// ResolveDNS resolves a domain to IP addresses with context support
func ResolveDNS(domain string) ([]net.IP, error) {
	return ResolveDNSWithContext(context.Background(), domain)
}

// ResolveDNSWithContext resolves a domain to IP addresses with context and timeout
func ResolveDNSWithContext(ctx context.Context, domain string) ([]net.IP, error) {
	// Create resolver with timeout
	resolver := &net.Resolver{
		PreferGo: true,
	}

	// Add timeout to the provided context
	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Use LookupIP with context
	ips, err := resolver.LookupIP(timeoutCtx, "ip", domain)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", domain, err)
	}
	return ips, nil
}

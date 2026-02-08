package stealth

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"redgravity/internal/config"
	"time"
)

// StealthLayer implements stealth techniques
type StealthLayer struct {
	Config     *config.StealthConfig
	userAgents []string
	currentUA  int
}

// NewStealthLayer creates a new stealth layer
func NewStealthLayer(cfg *config.StealthConfig) *StealthLayer {
	return &StealthLayer{
		Config:     cfg,
		userAgents: cfg.UserAgents,
		currentUA:  0,
	}
}

// GetUserAgent returns a rotated user agent
func (sl *StealthLayer) GetUserAgent() string {
	if len(sl.userAgents) == 0 {
		return "Mozilla/5.0 (compatible; RedGravity/1.0)"
	}

	ua := sl.userAgents[sl.currentUA]
	sl.currentUA = (sl.currentUA + 1) % len(sl.userAgents)
	return ua
}

// ApplyRateLimit applies rate limiting with jitter
func (sl *StealthLayer) ApplyRateLimit() {
	if !sl.Config.Enabled {
		return
	}

	baseDelay := time.Duration(sl.Config.RateLimitMs) * time.Millisecond
	jitter := time.Duration(rand.Intn(sl.Config.JitterMs)) * time.Millisecond

	totalDelay := baseDelay + jitter
	time.Sleep(totalDelay)
}

// ConfigureHTTPClient configures an HTTP client with stealth settings
func (sl *StealthLayer) ConfigureHTTPClient(client *http.Client) *http.Client {
	if !sl.Config.Enabled {
		return client
	}

	// Configure transport with stealth settings
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client.Transport = transport
	return client
}

// WrapRequest wraps an HTTP request with stealth settings
func (sl *StealthLayer) WrapRequest(req *http.Request) *http.Request {
	if !sl.Config.Enabled {
		return req
	}

	// Set user agent
	req.Header.Set("User-Agent", sl.GetUserAgent())

	// Set additional headers to look like a real browser
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	return req
}

// GenerateNoiseDNSQueries generates fake DNS queries
func (sl *StealthLayer) GenerateNoiseDNSQueries(ctx context.Context, count int) {
	if !sl.Config.Enabled {
		return
	}

	fmt.Printf("[STEALTH] Generating %d noise DNS queries\n", count)

	commonDomains := []string{
		"google.com", "facebook.com", "youtube.com", "amazon.com",
		"wikipedia.org", "reddit.com", "twitter.com", "instagram.com",
		"linkedin.com", "netflix.com", "microsoft.com", "apple.com",
	}

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		domain := commonDomains[rand.Intn(len(commonDomains))]
		net.LookupIP(domain)

		// Random delay between queries
		time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
	}
}

// ResolveDNSOverHTTPS performs DNS resolution over HTTPS
func (sl *StealthLayer) ResolveDNSOverHTTPS(domain string) ([]net.IP, error) {
	if !sl.Config.UseDoH {
		return net.LookupIP(domain)
	}

	// Use DoH server (Cloudflare 1.1.1.1)
	url := fmt.Sprintf("%s?name=%s&type=A", sl.Config.DoHServer, domain)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-json")
	req = sl.WrapRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		// Fallback to regular DNS
		return net.LookupIP(domain)
	}
	defer resp.Body.Close()

	// Parse DoH response (simplified)
	// In production, properly parse the DNS-over-HTTPS JSON response
	return net.LookupIP(domain)
}

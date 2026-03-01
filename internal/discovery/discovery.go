package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"redgravity/pkg/utils"
	"strings"
	"sync"
	"time"
)

// DiscoveryResult holds discovery output
type DiscoveryResult struct {
	Domains    []string
	Subdomains []string
	Source     string
}

// Discoverer interface for different discovery methods
type Discoverer interface {
	Discover(ctx context.Context, target string) (*DiscoveryResult, error)
}

// DNSDiscoverer performs DNS enumeration
type DNSDiscoverer struct {
	PythonScript string
}

// NewDNSDiscoverer creates a new DNS discoverer
func NewDNSDiscoverer(scriptPath string) *DNSDiscoverer {
	return &DNSDiscoverer{
		PythonScript: scriptPath,
	}
}

// ParallelDNSDiscoverer performs parallel DNS brute-forcing
type ParallelDNSDiscoverer struct {
	Subdomains  []string
	Concurrency int
}

// NewParallelDNSDiscoverer creates a new parallel DNS discoverer
func NewParallelDNSDiscoverer(subdomains []string, concurrency int) *ParallelDNSDiscoverer {
	if concurrency <= 0 {
		concurrency = 20
	}
	return &ParallelDNSDiscoverer{
		Subdomains:  subdomains,
		Concurrency: concurrency,
	}
}

// Discover performs parallel DNS discovery
func (d *ParallelDNSDiscoverer) Discover(ctx context.Context, target string) (*DiscoveryResult, error) {
	fmt.Printf("[DISCOVERY] Running parallel DNS enumeration for: %s (%d workers)\n", target, d.Concurrency)

	subCh := make(chan string, len(d.Subdomains))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var discovered []string

	// Start workers
	for w := 0; w < d.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range subCh {
				select {
				case <-ctx.Done():
					return
				default:
					subdomain := sub + "." + target
					ips, err := utils.ResolveDNSWithContext(ctx, subdomain)
					if err == nil && len(ips) > 0 {
						mu.Lock()
						discovered = append(discovered, subdomain)
						mu.Unlock()
					}
				}
			}
		}()
	}

	// Feed workers
	for _, sub := range d.Subdomains {
		subCh <- sub
	}
	close(subCh)

	// Wait for workers
	wg.Wait()

	fmt.Printf("[DISCOVERY] DNS enumeration found %d subdomains\n", len(discovered))
	return &DiscoveryResult{
		Domains:    discovered,
		Subdomains: discovered,
		Source:     "parallel_dns",
	}, nil
}

// Discover performs DNS discovery
func (d *DNSDiscoverer) Discover(ctx context.Context, target string) (*DiscoveryResult, error) {
	fmt.Printf("[DISCOVERY] Running DNS enumeration for: %s\n", target)

	// Check if Python script exists
	if !utils.FileExists(d.PythonScript) {
		// Fallback to basic DNS resolution
		return d.fallbackDiscovery(target)
	}

	// Run Python script
	result, err := d.runPythonScript(ctx, target)
	if err != nil {
		fmt.Printf("[DISCOVERY] Python script failed, using fallback: %v\n", err)
		return d.fallbackDiscovery(target)
	}

	return result, nil
}

// runPythonScript executes the Python discovery script
func (d *DNSDiscoverer) runPythonScript(ctx context.Context, target string) (*DiscoveryResult, error) {
	cmd := exec.CommandContext(ctx, "python3", d.PythonScript, target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	// Parse output (assuming newline-separated domains)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var domains []string
	for _, line := range lines {
		if line != "" {
			domains = append(domains, strings.TrimSpace(line))
		}
	}

	return &DiscoveryResult{
		Domains:    domains,
		Subdomains: domains,
		Source:     "dns_enumeration",
	}, nil
}

// fallbackDiscovery performs basic DNS resolution as fallback
func (d *DNSDiscoverer) fallbackDiscovery(target string) (*DiscoveryResult, error) {
	fmt.Println("[DISCOVERY] Using fallback DNS resolution")

	// Simple DNS lookup
	ips, err := utils.ResolveDNS(target)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for target: %s", target)
	}

	return &DiscoveryResult{
		Domains:    []string{target},
		Subdomains: []string{target},
		Source:     "basic_dns",
	}, nil
}

// CertificateDiscoverer discovers domains via certificate transparency
type CertificateDiscoverer struct {
	PythonScript string
}

// NewCertificateDiscoverer creates a new certificate discoverer
func NewCertificateDiscoverer(scriptPath string) *CertificateDiscoverer {
	return &CertificateDiscoverer{
		PythonScript: scriptPath,
	}
}

// Discover performs certificate transparency discovery
func (c *CertificateDiscoverer) Discover(ctx context.Context, target string) (*DiscoveryResult, error) {
	fmt.Printf("[DISCOVERY] Searching certificate transparency logs for: %s\n", target)

	if !utils.FileExists(c.PythonScript) {
		fmt.Println("[DISCOVERY] Certificate transparency script not found, skipping")
		return &DiscoveryResult{
			Domains:    []string{},
			Subdomains: []string{},
			Source:     "cert_transparency_skipped",
		}, nil
	}

	cmd := exec.CommandContext(ctx, "python3", c.PythonScript, target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[DISCOVERY] Certificate transparency failed: %v\n", err)
		return &DiscoveryResult{
			Domains:    []string{},
			Subdomains: []string{},
			Source:     "cert_transparency_failed",
		}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var domains []string
	for _, line := range lines {
		if line != "" {
			domains = append(domains, strings.TrimSpace(line))
		}
	}

	return &DiscoveryResult{
		Domains:    domains,
		Subdomains: domains,
		Source:     "cert_transparency_python",
	}, nil
}

// CrtshDiscoverer discovers subdomains via crt.sh API (native Go)
type CrtshDiscoverer struct {
	HTTPClient *utils.HTTPClientWithRetry
}

// NewCrtshDiscoverer creates a new crt.sh discoverer
func NewCrtshDiscoverer() *CrtshDiscoverer {
	return &CrtshDiscoverer{
		HTTPClient: utils.NewHTTPClientWithRetry(3, 1*time.Second),
	}
}

// Discover fetches certificate records from crt.sh
func (c *CrtshDiscoverer) Discover(ctx context.Context, target string) (*DiscoveryResult, error) {
	fmt.Printf("[DISCOVERY] Querying crt.sh for: %s\n", target)

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", target)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status: %d", resp.StatusCode)
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode crt.sh response: %w", err)
	}

	domainMap := make(map[string]bool)
	for _, entry := range entries {
		subs := strings.Split(entry.NameValue, "\n")
		for _, sub := range subs {
			sub = strings.TrimSpace(sub)
			if sub != "" && !strings.Contains(sub, "*") {
				domainMap[sub] = true
			}
		}
	}

	var domains []string
	for domain := range domainMap {
		domains = append(domains, domain)
	}

	fmt.Printf("[DISCOVERY] crt.sh found %d domains\n", len(domains))
	return &DiscoveryResult{
		Domains:    domains,
		Subdomains: domains,
		Source:     "crt.sh",
	}, nil
}

// AggregateDiscovery combines multiple discovery methods
func AggregateDiscovery(ctx context.Context, target string, discoverers []Discoverer) (*DiscoveryResult, error) {
	fmt.Println("[DISCOVERY] Starting multi-source discovery")

	allDomains := make(map[string]bool)
	var sources []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, discoverer := range discoverers {
		wg.Add(1)
		go func(d Discoverer) {
			defer wg.Done()
			result, err := d.Discover(ctx, target)
			if err != nil {
				fmt.Printf("[DISCOVERY] Discoverer failed: %v\n", err)
				return
			}

			mu.Lock()
			defer mu.Unlock()
			sources = append(sources, result.Source)
			for _, domain := range result.Domains {
				allDomains[domain] = true
			}
			for _, subdomain := range result.Subdomains {
				allDomains[subdomain] = true
			}
		}(discoverer)
	}

	wg.Wait()

	// Convert map to slice
	var finalDomains []string
	for domain := range allDomains {
		finalDomains = append(finalDomains, domain)
	}

	fmt.Printf("[DISCOVERY] Found %d unique domains from %d sources\n", len(finalDomains), len(sources))

	return &DiscoveryResult{
		Domains:    finalDomains,
		Subdomains: finalDomains,
		Source:     strings.Join(sources, ","),
	}, nil
}

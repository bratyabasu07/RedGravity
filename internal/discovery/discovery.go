package discovery

import (
	"context"
	"fmt"
	"os/exec"
	"redgravity/pkg/utils"
	"strings"
	"sync"
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
		Source:     "cert_transparency",
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

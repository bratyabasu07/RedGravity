package ip

import (
	"context"
	"fmt"
	"net"
	"redgravity/pkg/utils"
	"sync"
)

// IPNormalizer normalizes and filters IP addresses
type IPNormalizer struct {
	FilterPrivate bool
	FilterBogon   bool
	mutex         sync.Mutex
}

// NewIPNormalizer creates a new IP normalizer
func NewIPNormalizer(filterPrivate, filterBogon bool) *IPNormalizer {
	return &IPNormalizer{
		FilterPrivate: filterPrivate,
		FilterBogon:   filterBogon,
	}
}

// NormalizeResult holds normalization output
type NormalizeResult struct {
	IPs               []net.IP
	FilteredOut       int
	DuplicatesRemoved int
}

// Normalize resolves domains to IPs and applies filters
func (n *IPNormalizer) Normalize(ctx context.Context, domains []string) (*NormalizeResult, error) {
	fmt.Printf("[IP] Normalizing %d domains to IPs\n", len(domains))

	var allIPs []net.IP
	var wg sync.WaitGroup
	ipChan := make(chan []net.IP, len(domains))

	// Resolve domains in parallel
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			ips, err := utils.ResolveDNS(d)
			if err != nil {
				fmt.Printf("[IP] Failed to resolve %s: %v\n", d, err)
				return
			}

			ipChan <- ips
		}(domain)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(ipChan)
	}()

	// Collect IPs
	for ips := range ipChan {
		allIPs = append(allIPs, ips...)
	}

	fmt.Printf("[IP] Resolved to %d IPs (before filtering)\n", len(allIPs))

	// Deduplicate
	deduped := utils.DeduplicateIPs(allIPs)
	duplicatesRemoved := len(allIPs) - len(deduped)

	// Filter
	filtered := n.filterIPs(deduped)
	filteredOut := len(deduped) - len(filtered)

	fmt.Printf("[IP] Removed %d duplicates, filtered out %d IPs\n", duplicatesRemoved, filteredOut)
	fmt.Printf("[IP] Final count: %d clean IPs\n", len(filtered))

	return &NormalizeResult{
		IPs:               filtered,
		FilteredOut:       filteredOut,
		DuplicatesRemoved: duplicatesRemoved,
	}, nil
}

// filterIPs applies filtering rules to IPs
func (n *IPNormalizer) filterIPs(ips []net.IP) []net.IP {
	var result []net.IP

	for _, ip := range ips {
		// Filter private IPs
		if n.FilterPrivate && utils.IsPrivateIP(ip) {
			continue
		}

		// Filter bogon IPs
		if n.FilterBogon && utils.IsBogonIP(ip) {
			continue
		}

		result = append(result, ip)
	}

	return result
}

// ExpandCIDRTargets expands CIDR notation targets to individual IPs
func ExpandCIDRTargets(ctx context.Context, targets []string) ([]net.IP, error) {
	fmt.Printf("[IP] Expanding %d targets (may include CIDRs)\n", len(targets))

	var allIPs []net.IP

	for _, target := range targets {
		// Check if it's a CIDR
		if isCIDR(target) {
			ips, err := utils.ExpandCIDR(target)
			if err != nil {
				fmt.Printf("[IP] Failed to expand CIDR %s: %v\n", target, err)
				continue
			}
			allIPs = append(allIPs, ips...)
		} else {
			// Try parsing as IP
			ip, err := utils.ValidateIP(target)
			if err == nil {
				allIPs = append(allIPs, ip)
			}
		}
	}

	fmt.Printf("[IP] Expanded to %d IPs\n", len(allIPs))
	return allIPs, nil
}

// isCIDR checks if a string is in CIDR notation
func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// IPToString converts net.IP slice to string slice
func IPToString(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

// StringToIP converts string slice to net.IP slice
func StringToIP(ipStrs []string) ([]net.IP, error) {
	var result []net.IP
	for _, ipStr := range ipStrs {
		ip, err := utils.ValidateIP(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid IP %s: %w", ipStr, err)
		}
		result = append(result, ip)
	}
	return result, nil
}

// ParseTargets parses input targets (domains, IPs, CIDRs) and returns net.IP list
func ParseTargets(targets []string) ([]net.IP, error) {
	var allIPs []net.IP

	for _, target := range targets {
		// Try as CIDR first
		if isCIDR(target) {
			ips, err := utils.ExpandCIDR(target)
			if err != nil {
				fmt.Printf("[IP] Failed to expand CIDR %s: %v\n", target, err)
				continue
			}
			allIPs = append(allIPs, ips...)
		} else {
			// Try as direct IP
			ip, err := utils.ValidateIP(target)
			if err == nil {
				allIPs = append(allIPs, ip)
			} else {
				// Try DNS resolution
				ips, err := utils.ResolveDNS(target)
				if err != nil {
					fmt.Printf("[IP] Failed to resolve %s: %v\n", target, err)
					continue
				}
				allIPs = append(allIPs, ips...)
			}
		}
	}

	return allIPs, nil
}

// IsPrivateOrReserved checks if IP is private or reserved
func IsPrivateOrReserved(ip net.IP) bool {
	return utils.IsPrivateIP(ip) || utils.IsBogonIP(ip)
}

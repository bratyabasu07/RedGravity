package noise

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"redgravity/pkg/utils"
	"strings"
	"time"
)

// NoiseFilter filters out noise IPs
type NoiseFilter struct {
	AbuseIPDBKey string
	HTTPClient   *utils.HTTPClientWithRetry
	PythonScript string
}

// NewNoiseFilter creates a new noise filter
func NewNoiseFilter(abuseIPDBKey, pythonScript string) *NoiseFilter {
	return &NoiseFilter{
		AbuseIPDBKey: abuseIPDBKey,
		HTTPClient:   utils.NewHTTPClientWithRetry(3, 1*time.Second),
		PythonScript: pythonScript,
	}
}

// FilterResult holds noise filtering results
type FilterResult struct {
	CleanIPs     []net.IP
	FilteredIPs  []net.IP
	FilterReason map[string]string
}

// Filter applies noise filtering to IPs
func (nf *NoiseFilter) Filter(ctx context.Context, ips []net.IP) (*FilterResult, error) {
	fmt.Printf("[NOISE] Filtering %d IPs\n", len(ips))

	result := &FilterResult{
		CleanIPs:     []net.IP{},
		FilteredIPs:  []net.IP{},
		FilterReason: make(map[string]string),
	}

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		ipStr := ip.String()

		// Check AbuseIPDB
		if nf.AbuseIPDBKey != "" {
			reputation, err := nf.checkAbuseIPDB(ctx, ipStr)
			if err != nil {
				fmt.Printf("[NOISE] AbuseIPDB check failed for %s: %v\n", ipStr, err)
			} else if reputation.Data.AbuseConfidenceScore > 50 {
				fmt.Printf("[NOISE] Filtering %s (AbuseIPDB score: %d)\n", ipStr, reputation.Data.AbuseConfidenceScore)
				result.FilteredIPs = append(result.FilteredIPs, ip)
				result.FilterReason[ipStr] = fmt.Sprintf("AbuseIPDB score: %d", reputation.Data.AbuseConfidenceScore)
				continue
			}
		}

		// Check if it's a CDN/Cloud provider (optional Python script)
		if utils.FileExists(nf.PythonScript) {
			isCDN, err := nf.checkCDNCloud(ctx, ipStr)
			if err != nil {
				fmt.Printf("[NOISE] CDN/Cloud check failed for %s: %v\n", ipStr, err)
			} else if isCDN {
				fmt.Printf("[NOISE] Filtering %s (CDN/Cloud provider)\n", ipStr)
				result.FilteredIPs = append(result.FilteredIPs, ip)
				result.FilterReason[ipStr] = "CDN/Cloud provider"
				continue
			}
		}

		// IP passed all filters
		result.CleanIPs = append(result.CleanIPs, ip)
	}

	fmt.Printf("[NOISE] Filtered out %d IPs, %d clean IPs remaining\n",
		len(result.FilteredIPs), len(result.CleanIPs))

	return result, nil
}

// AbuseIPDBResponse represents AbuseIPDB API response
type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsWhitelisted        bool   `json:"isWhitelisted"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		TotalReports         int    `json:"totalReports"`
		NumDistinctUsers     int    `json:"numDistinctUsers"`
		LastReportedAt       string `json:"lastReportedAt"`
	} `json:"data"`
}

// checkAbuseIPDB queries AbuseIPDB for IP reputation
func (nf *NoiseFilter) checkAbuseIPDB(ctx context.Context, ip string) (*AbuseIPDBResponse, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Key", nf.AbuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := nf.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AbuseIPDB API returned status %d", resp.StatusCode)
	}

	var abuseResp AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&abuseResp); err != nil {
		return nil, err
	}

	return &abuseResp, nil
}

// checkCDNCloud checks if IP belongs to CDN/Cloud provider using Python script
func (nf *NoiseFilter) checkCDNCloud(ctx context.Context, ip string) (bool, error) {
	cmd := exec.CommandContext(ctx, "python3", nf.PythonScript, ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}

	result := strings.TrimSpace(string(output))
	return result == "true" || result == "True" || result == "1", nil
}

// WHOISInfo holds WHOIS information
type WHOISInfo struct {
	IP           string
	Organization string
	Country      string
	ASN          string
}

// GetWHOISInfo retrieves WHOIS information for an IP
func GetWHOISInfo(ctx context.Context, ip string) (*WHOISInfo, error) {
	// Simple whois command execution
	cmd := exec.CommandContext(ctx, "whois", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("whois failed: %w", err)
	}

	info := &WHOISInfo{
		IP: ip,
	}

	// Parse basic information (simplified)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(strings.ToLower(line), "orgname:") ||
			strings.HasPrefix(strings.ToLower(line), "organization:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				info.Organization = strings.TrimSpace(parts[1])
			}
		}

		if strings.HasPrefix(strings.ToLower(line), "country:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				info.Country = strings.TrimSpace(parts[1])
			}
		}

		if strings.HasPrefix(strings.ToLower(line), "originas:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				info.ASN = strings.TrimSpace(parts[1])
			}
		}
	}

	return info, nil
}

package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"redgravity/internal/version"
	"redgravity/pkg/utils"
	"strings"
	"time"
)

// CVEInfo holds CVE information
type CVEInfo struct {
	ID               string
	Description      string
	CVSS             float64
	CVSSVector       string
	Severity         string
	PublishedDate    string
	ModifiedDate     string
	ExploitAvailable bool
	InCISAKEV        bool
	AffectedProducts []string
	References       []string
}

// CVEMatcher matches CVEs to services
type CVEMatcher struct {
	NVDAPIKey     string
	VulnersAPIKey string
	HTTPClient    *utils.HTTPClientWithRetry
}

// NewCVEMatcher creates a new CVE matcher
func NewCVEMatcher(nvdAPIKey string) *CVEMatcher {
	return &CVEMatcher{
		NVDAPIKey:  nvdAPIKey,
		HTTPClient: utils.NewHTTPClientWithRetry(3, 2*time.Second),
	}
}

// NewCVEMatcherWithVulners creates a CVE matcher with Vulners support
func NewCVEMatcherWithVulners(nvdAPIKey, vulnersAPIKey string) *CVEMatcher {
	return &CVEMatcher{
		NVDAPIKey:     nvdAPIKey,
		VulnersAPIKey: vulnersAPIKey,
		HTTPClient:    utils.NewHTTPClientWithRetry(3, 2*time.Second),
	}
}

// CVEMatch holds matched CVE for a service
type CVEMatch struct {
	IP      string
	Port    int
	Service string
	Version string
	CVEs    []CVEInfo
}

// Match finds CVEs for confirmed services
func (cm *CVEMatcher) Match(ctx context.Context, services []version.VersionConfirmation) ([]CVEMatch, error) {
	fmt.Printf("[CVE] Matching CVEs for %d services\n", len(services))

	var matches []CVEMatch

	for _, svc := range services {
		select {
		case <-ctx.Done():
			return matches, ctx.Err()
		default:
		}

		var allCVEs []CVEInfo

		// Try NVD first
		if cm.NVDAPIKey != "" {
			cves, err := cm.searchNVD(ctx, svc.Service, svc.ConfirmedVersion)
			if err != nil {
				fmt.Printf("[CVE] NVD search failed for %s %s: %v\n", svc.Service, svc.ConfirmedVersion, err)
			} else {
				allCVEs = append(allCVEs, cves...)
			}
		}

		// Also try Vulners if available
		if cm.VulnersAPIKey != "" {
			vulnersCVEs, err := cm.searchVulners(ctx, svc.Service, svc.ConfirmedVersion)
			if err != nil {
				fmt.Printf("[CVE] Vulners search failed for %s %s: %v\n", svc.Service, svc.ConfirmedVersion, err)
			} else {
				// Merge with NVD results (avoid duplicates)
				allCVEs = mergeCVEs(allCVEs, vulnersCVEs)
			}
		}

		if len(allCVEs) > 0 {
			matches = append(matches, CVEMatch{
				IP:      svc.IP,
				Port:    svc.Port,
				Service: svc.Service,
				Version: svc.ConfirmedVersion,
				CVEs:    allCVEs,
			})

			fmt.Printf("[CVE] Found %d CVEs for %s:%d (%s %s)\n",
				len(allCVEs), svc.IP, svc.Port, svc.Service, svc.ConfirmedVersion)
		}

		// Rate limiting
		time.Sleep(600 * time.Millisecond)
	}

	fmt.Printf("[CVE] Total CVE matches: %d\n", len(matches))
	return matches, nil
}

// NVDResponse represents NVD API response
type NVDResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSV2 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			Published  string `json:"published"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// searchNVD queries NVD API for CVEs
func (cm *CVEMatcher) searchNVD(ctx context.Context, product, version string) ([]CVEInfo, error) {
	// Skip if product is empty
	if product == "" || strings.TrimSpace(product) == "" {
		return nil, nil
	}

	// Build search query
	keyword := fmt.Sprintf("%s %s", product, version)
	encodedKeyword := url.QueryEscape(keyword)

	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=10", encodedKeyword)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if cm.NVDAPIKey != "" {
		req.Header.Set("apiKey", cm.NVDAPIKey)
	}

	resp, err := cm.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	// Parse CVEs
	var cves []CVEInfo
	for _, vuln := range nvdResp.Vulnerabilities {
		cveInfo := CVEInfo{
			ID:            vuln.CVE.ID,
			PublishedDate: vuln.CVE.Published,
		}

		// Extract description
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cveInfo.Description = desc.Value
				break
			}
		}

		// Extract CVSS score
		if len(vuln.CVE.Metrics.CVSSV31) > 0 {
			cveInfo.CVSS = vuln.CVE.Metrics.CVSSV31[0].CVSSData.BaseScore
			cveInfo.Severity = vuln.CVE.Metrics.CVSSV31[0].CVSSData.BaseSeverity
			cveInfo.CVSSVector = vuln.CVE.Metrics.CVSSV31[0].CVSSData.VectorString
		} else if len(vuln.CVE.Metrics.CVSSV2) > 0 {
			cveInfo.CVSS = vuln.CVE.Metrics.CVSSV2[0].CVSSData.BaseScore
			cveInfo.CVSSVector = vuln.CVE.Metrics.CVSSV2[0].CVSSData.VectorString
			cveInfo.Severity = getCVSSSeverity(cveInfo.CVSS)
		}

		// Extract references
		for _, ref := range vuln.CVE.References {
			cveInfo.References = append(cveInfo.References, ref.URL)
		}

		cves = append(cves, cveInfo)
	}

	return cves, nil
}

// getCVSSSeverity maps CVSS score to severity
func getCVSSSeverity(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	}
	return "LOW"
}

// FilterByCVSS filters CVEs by minimum CVSS score
func FilterByCVSS(matches []CVEMatch, minCVSS float64) []CVEMatch {
	var filtered []CVEMatch

	for _, match := range matches {
		var highCVEs []CVEInfo
		for _, cve := range match.CVEs {
			if cve.CVSS >= minCVSS {
				highCVEs = append(highCVEs, cve)
			}
		}

		if len(highCVEs) > 0 {
			match.CVEs = highCVEs
			filtered = append(filtered, match)
		}
	}

	return filtered
}
// searchVulners queries Vulners API for CVE information
func (cm *CVEMatcher) searchVulners(ctx context.Context, product, version string) ([]CVEInfo, error) {
	// Skip if product is empty
	if product == "" || strings.TrimSpace(product) == "" {
		return nil, nil
	}

	// Build search query
	query := fmt.Sprintf("%s %s", product, version)

	apiURL := "https://vulners.com/api/v3/search/lucene/"

	// Build request body
	requestBody := map[string]interface{}{
		"query":  query,
		"apiKey": cm.VulnersAPIKey,
		"skip":   0,
		"size":   10,
	}

	bodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := cm.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Vulners API returned status %d", resp.StatusCode)
	}

	var vulnersResp struct {
		Result string `json:"result"`
		Data   struct {
			Search []struct {
				ID     string `json:"_id"`
				Source struct {
					CVSSScore   float64 `json:"cvss"`
					Description string  `json:"description"`
					Published   string  `json:"published"`
				} `json:"_source"`
			} `json:"search"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vulnersResp); err != nil {
		return nil, err
	}

	var cves []CVEInfo
	for _, item := range vulnersResp.Data.Search {
		// Only process CVE IDs
		if !strings.HasPrefix(item.ID, "CVE-") {
			continue
		}

		cveInfo := CVEInfo{
			ID:            item.ID,
			Description:   item.Source.Description,
			CVSS:          item.Source.CVSSScore,
			Severity:      getCVSSSeverity(item.Source.CVSSScore),
			PublishedDate: item.Source.Published,
		}

		cves = append(cves, cveInfo)
	}

	return cves, nil
}

// mergeCVEs merges two CVE slices, avoiding duplicates by CVE ID
func mergeCVEs(existing, new []CVEInfo) []CVEInfo {
	// Create map of existing CVE IDs
	seenIDs := make(map[string]bool)
	for _, cve := range existing {
		seenIDs[cve.ID] = true
	}

	// Add new CVEs if not already present
	for _, cve := range new {
		if !seenIDs[cve.ID] {
			existing = append(existing, cve)
			seenIDs[cve.ID] = true
		}
	}

	return existing
}

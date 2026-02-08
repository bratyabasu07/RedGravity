package service

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

// ServiceInfo represents discovered service information
type ServiceInfo struct {
	IP       string
	Port     int
	Service  string
	Version  string
	Banner   string
	Source   string
	Products []string
}

// ServiceDetector interface for different detection methods
type ServiceDetector interface {
	Detect(ctx context.Context, ips []net.IP) ([]ServiceInfo, error)
}

// ShodanDetector uses Shodan API for service detection
type ShodanDetector struct {
	APIKey     string
	HTTPClient *utils.HTTPClientWithRetry
}

// NewShodanDetector creates a new Shodan detector
func NewShodanDetector(apiKey string) *ShodanDetector {
	return &ShodanDetector{
		APIKey:     apiKey,
		HTTPClient: utils.NewHTTPClientWithRetry(3, 1*time.Second),
	}
}

// ShodanResponse represents Shodan API response
type ShodanResponse struct {
	IPStr string `json:"ip_str"`
	Ports []int  `json:"ports"`
	Data  []struct {
		Port      int      `json:"port"`
		Product   string   `json:"product"`
		Version   string   `json:"version"`
		Banner    string   `json:"data"`
		Hostnames []string `json:"hostnames"`
	} `json:"data"`
}

// Detect performs service detection using Shodan
func (sd *ShodanDetector) Detect(ctx context.Context, ips []net.IP) ([]ServiceInfo, error) {
	fmt.Printf("[SERVICE] Detecting services using Shodan for %d IPs\n", len(ips))

	var services []ServiceInfo

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return services, ctx.Err()
		default:
		}

		ipStr := ip.String()
		url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ipStr, sd.APIKey)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			fmt.Printf("[SERVICE] Failed to create request for %s: %v\n", ipStr, err)
			continue
		}

		resp, err := sd.HTTPClient.Do(req)
		if err != nil {
			fmt.Printf("[SERVICE] Shodan API failed for %s: %v\n", ipStr, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("[SERVICE] Shodan returned status %d for %s\n", resp.StatusCode, ipStr)
			continue
		}

		var shodanResp ShodanResponse
		if err := json.NewDecoder(resp.Body).Decode(&shodanResp); err != nil {
			fmt.Printf("[SERVICE] Failed to parse Shodan response for %s: %v\n", ipStr, err)
			continue
		}

		// Parse services
		for _, data := range shodanResp.Data {
			services = append(services, ServiceInfo{
				IP:      ipStr,
				Port:    data.Port,
				Service: data.Product,
				Version: data.Version,
				Banner:  data.Banner,
				Source:  "shodan",
			})
		}

		// Rate limiting
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Printf("[SERVICE] Shodan found %d services\n", len(services))
	return services, nil
}

// CensysDetector uses Censys API for service detection
type CensysDetector struct {
	APIID      string
	APISecret  string
	HTTPClient *utils.HTTPClientWithRetry
}

// NewCensysDetector creates a new Censys detector
func NewCensysDetector(apiID, apiSecret string) *CensysDetector {
	return &CensysDetector{
		APIID:      apiID,
		APISecret:  apiSecret,
		HTTPClient: utils.NewHTTPClientWithRetry(3, 1*time.Second),
	}
}

// CensysResponse represents Censys API response
type CensysResponse struct {
	Result struct {
		Services []struct {
			Port              int    `json:"port"`
			ServiceName       string `json:"service_name"`
			TransportProtocol string `json:"transport_protocol"`
			Software          []struct {
				Product string `json:"product"`
				Version string `json:"version"`
			} `json:"software"`
		} `json:"services"`
	} `json:"result"`
}

// Detect performs service detection using Censys
func (cd *CensysDetector) Detect(ctx context.Context, ips []net.IP) ([]ServiceInfo, error) {
	fmt.Printf("[SERVICE] Detecting services using Censys for %d IPs\n", len(ips))

	var services []ServiceInfo

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return services, ctx.Err()
		default:
		}

		ipStr := ip.String()
		url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ipStr)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			fmt.Printf("[SERVICE] Failed to create request for %s: %v\n", ipStr, err)
			continue
		}

		// Basic auth
		req.SetBasicAuth(cd.APIID, cd.APISecret)

		resp, err := cd.HTTPClient.Do(req)
		if err != nil {
			fmt.Printf("[SERVICE] Censys API failed for %s: %v\n", ipStr, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("[SERVICE] Censys returned status %d for %s\n", resp.StatusCode, ipStr)
			continue
		}

		var censysResp CensysResponse
		if err := json.NewDecoder(resp.Body).Decode(&censysResp); err != nil {
			fmt.Printf("[SERVICE] Failed to parse Censys response for %s: %v\n", ipStr, err)
			continue
		}

		// Parse services
		for _, svc := range censysResp.Result.Services {
			product := ""
			version := ""
			if len(svc.Software) > 0 {
				product = svc.Software[0].Product
				version = svc.Software[0].Version
			}

			services = append(services, ServiceInfo{
				IP:      ipStr,
				Port:    svc.Port,
				Service: product,
				Version: version,
				Banner:  svc.ServiceName,
				Source:  "censys",
			})
		}

		// Rate limiting
		time.Sleep(1 * time.Second)
	}

	fmt.Printf("[SERVICE] Censys found %d services\n", len(services))
	return services, nil
}

// NmapDetector uses nmap for service detection
type NmapDetector struct {
	FastScan bool
}

// NewNmapDetector creates a new nmap detector
func NewNmapDetector(fastScan bool) *NmapDetector {
	return &NmapDetector{
		FastScan: fastScan,
	}
}

// Detect performs service detection using nmap
func (nd *NmapDetector) Detect(ctx context.Context, ips []net.IP) ([]ServiceInfo, error) {
	fmt.Printf("[SERVICE] Detecting services using nmap for %d IPs\n", len(ips))

	var services []ServiceInfo

	// Batch IPs for nmap
	ipStrs := make([]string, len(ips))
	for i, ip := range ips {
		ipStrs[i] = ip.String()
	}

	args := []string{"-sV", "-T4", "--open"}
	if nd.FastScan {
		args = append(args, "-F") // Fast scan, top 100 ports
	}
	args = append(args, ipStrs...)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap execution failed: %w", err)
	}

	// Parse nmap output (simplified)
	services = nd.parseNmapOutput(string(output))

	fmt.Printf("[SERVICE] Nmap found %d services\n", len(services))
	return services, nil
}

// parseNmapOutput parses nmap output
func (nd *NmapDetector) parseNmapOutput(output string) []ServiceInfo {
	var services []ServiceInfo
	lines := strings.Split(output, "\n")

	currentIP := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract IP
		if strings.HasPrefix(line, "Nmap scan report for") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				currentIP = strings.Trim(parts[4], "()")
			}
		}

		// Parse service lines
		if currentIP != "" && strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				portProto := fields[0]
				service := fields[2]
				version := ""
				if len(fields) > 3 {
					version = strings.Join(fields[3:], " ")
				}

				portStr := strings.TrimSuffix(portProto, "/tcp")
				var port int
				fmt.Sscanf(portStr, "%d", &port)

				services = append(services, ServiceInfo{
					IP:      currentIP,
					Port:    port,
					Service: service,
					Version: version,
					Source:  "nmap",
				})
			}
		}
	}

	return services
}

// AggregateDetection combines multiple detection methods
func AggregateDetection(ctx context.Context, ips []net.IP, detectors []ServiceDetector) ([]ServiceInfo, error) {
	fmt.Println("[SERVICE] Running multi-source service detection")

	var allServices []ServiceInfo

	for _, detector := range detectors {
		services, err := detector.Detect(ctx, ips)
		if err != nil {
			fmt.Printf("[SERVICE] Detector failed: %v\n", err)
			continue
		}
		allServices = append(allServices, services...)
	}

	fmt.Printf("[SERVICE] Total services detected: %d\n", len(allServices))
	return allServices, nil
}

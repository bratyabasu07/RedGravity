package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"redgravity/pkg/utils"
	"time"
)

// ThreatInfo holds threat intelligence data
type ThreatInfo struct {
	IP             string
	Classification string // "benign", "unknown", "malicious", "scanner"
	Tags           []string
	LastSeen       string
	Actor          string
	Confidence     int
	Sources        []string
}

// ThreatIntel aggregates threat intelligence from multiple sources
type ThreatIntel struct {
	GreyNoiseAPIKey string
	OTXAPIKey       string
	HTTPClient      *utils.HTTPClientWithRetry
}

// NewThreatIntel creates a new threat intelligence aggregator
func NewThreatIntel(greynoise, otx string) *ThreatIntel {
	return &ThreatIntel{
		GreyNoiseAPIKey: greynoise,
		OTXAPIKey:       otx,
		HTTPClient:      utils.NewHTTPClientWithRetry(3, 1*time.Second),
	}
}

// Enrich enriches IPs with threat intelligence
func (ti *ThreatIntel) Enrich(ctx context.Context, ips []net.IP) (map[string]ThreatInfo, error) {
	fmt.Printf("[THREAT] Enriching %d IPs with threat intelligence\n", len(ips))

	results := make(map[string]ThreatInfo)

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		ipStr := ip.String()
		info := ThreatInfo{
			IP:             ipStr,
			Tags:           []string{},
			Sources:        []string{},
			Classification: "unknown",
		}

		// Check GreyNoise
		if ti.GreyNoiseAPIKey != "" {
			gnInfo, err := ti.checkGreyNoise(ctx, ipStr)
			if err == nil {
				info.Classification = gnInfo.Classification
				info.Tags = append(info.Tags, gnInfo.Tags...)
				info.Sources = append(info.Sources, "greynoise")
			}
		}

		// Check AlienVault OTX
		if ti.OTXAPIKey != "" {
			otxInfo, err := ti.checkOTX(ctx, ipStr)
			if err == nil {
				info.Tags = append(info.Tags, otxInfo.Tags...)
				info.Sources = append(info.Sources, "otx")
			}
		}

		results[ipStr] = info

		// Rate limiting
		time.Sleep(300 * time.Millisecond)
	}

	fmt.Printf("[THREAT] Enriched %d IPs\n", len(results))
	return results, nil
}

// GreyNoiseResponse represents GreyNoise API response
type GreyNoiseResponse struct {
	IP             string   `json:"ip"`
	Classification string   `json:"classification"`
	Seen           bool     `json:"seen"`
	LastSeen       string   `json:"last_seen"`
	Tags           []string `json:"tags"`
	Actor          string   `json:"actor"`
}

// checkGreyNoise queries GreyNoise API
func (ti *ThreatIntel) checkGreyNoise(ctx context.Context, ip string) (*GreyNoiseResponse, error) {
	url := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("key", ti.GreyNoiseAPIKey)

	resp, err := ti.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GreyNoise returned status %d", resp.StatusCode)
	}

	var gnResp GreyNoiseResponse
	if err := json.NewDecoder(resp.Body).Decode(&gnResp); err != nil {
		return nil, err
	}

	return &gnResp, nil
}

// OTXResponse represents AlienVault OTX response
type OTXResponse struct {
	PulseCount int `json:"pulse_count"`
	Pulses     []struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	} `json:"pulses"`
}

// checkOTX queries AlienVault OTX
func (ti *ThreatIntel) checkOTX(ctx context.Context, ip string) (*ThreatInfo, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-OTX-API-KEY", ti.OTXAPIKey)

	resp, err := ti.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTX returned status %d", resp.StatusCode)
	}

	var otxResp OTXResponse
	if err := json.NewDecoder(resp.Body).Decode(&otxResp); err != nil {
		return nil, err
	}

	info := &ThreatInfo{
		IP:   ip,
		Tags: []string{},
	}

	for _, pulse := range otxResp.Pulses {
		info.Tags = append(info.Tags, pulse.Tags...)
	}

	return info, nil
}

// IsHighThreat checks if IP is classified as high threat
func IsHighThreat(info ThreatInfo) bool {
	return info.Classification == "malicious" ||
		contains(info.Tags, "malware") ||
		contains(info.Tags, "botnet") ||
		contains(info.Tags, "exploit")
}

// contains checks if a string slice contains a value
func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

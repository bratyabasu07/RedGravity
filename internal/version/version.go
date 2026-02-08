package version

import (
	"context"
	"fmt"
	"redgravity/internal/service"
	"strings"
)

// VersionConfirmation holds version confirmation result
type VersionConfirmation struct {
	IP               string
	Port             int
	Service          string
	ConfirmedVersion string
	Confidence       int
	Sources          []string
}

// VersionGate filters services based on version confidence
type VersionGate struct {
	MinConfidence int
}

// NewVersionGate creates a new version gate
func NewVersionGate(minConfidence int) *VersionGate {
	return &VersionGate{
		MinConfidence: minConfidence,
	}
}

// Confirm cross-references versions from multiple sources
func (vg *VersionGate) Confirm(ctx context.Context, services []service.ServiceInfo) ([]VersionConfirmation, error) {
	fmt.Printf("[VERSION] Confirming versions for %d services\n", len(services))

	// Group services by IP:Port
	grouped := make(map[string][]service.ServiceInfo)
	for _, svc := range services {
		key := fmt.Sprintf("%s:%d", svc.IP, svc.Port)
		grouped[key] = append(grouped[key], svc)
	}

	var confirmed []VersionConfirmation

	for key, svcGroup := range grouped {
		// Cross-reference versions
		versionMap := make(map[string]int)
		sourceMap := make(map[string][]string)

		for _, svc := range svcGroup {
			if svc.Version != "" {
				normalizedVersion := normalizeVersion(svc.Version)
				versionMap[normalizedVersion]++
				sourceMap[normalizedVersion] = append(sourceMap[normalizedVersion], svc.Source)
			}
		}

		// Find most common version
		var bestVersion string
		var bestCount int
		for version, count := range versionMap {
			if count > bestCount {
				bestVersion = version
				bestCount = count
			}
		}

		if bestVersion != "" {
			// Calculate confidence based on source agreement
			totalSources := len(svcGroup)
			agreementRatio := float64(bestCount) / float64(totalSources)
			confidence := int(agreementRatio * 100)

			if confidence >= vg.MinConfidence {
				confirmed = append(confirmed, VersionConfirmation{
					IP:               svcGroup[0].IP,
					Port:             svcGroup[0].Port,
					Service:          svcGroup[0].Service,
					ConfirmedVersion: bestVersion,
					Confidence:       confidence,
					Sources:          sourceMap[bestVersion],
				})
			} else {
				fmt.Printf("[VERSION] Filtered %s (confidence %d%% < %d%%)\n",
					key, confidence, vg.MinConfidence)
			}
		}
	}

	fmt.Printf("[VERSION] Confirmed %d services with confidence >= %d%%\n",
		len(confirmed), vg.MinConfidence)

	return confirmed, nil
}

// normalizeVersion normalizes version strings for comparison
func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.ToLower(version)

	// Remove common prefixes
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "version ")

	// Extract just the version number (major.minor.patch)
	fields := strings.Fields(version)
	if len(fields) > 0 {
		return fields[0]
	}

	return version
}

// GetHighConfidenceServices returns only high-confidence services
func GetHighConfidenceServices(confirmations []VersionConfirmation, minConfidence int) []VersionConfirmation {
	var result []VersionConfirmation
	for _, conf := range confirmations {
		if conf.Confidence >= minConfidence {
			result = append(result, conf)
		}
	}
	return result
}

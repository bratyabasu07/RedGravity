package scoring

import (
	"fmt"
	"redgravity/internal/cve"
	"redgravity/internal/version"
	"strings"
)

// ScoreWeights holds scoring weight configuration
type ScoreWeights struct {
	SourceDiversity     int
	CVSSScore           int
	ASNReputation       int
	PortAccessibility   int
	ExploitAvailability int
}

// ConfidenceScore holds confidence scoring result
type ConfidenceScore struct {
	IP               string
	Port             int
	Service          string
	Version          string
	TotalScore       int
	Breakdown        map[string]int
	HighestCVSS      float64
	CriticalCVECount int
}

// Scorer calculates confidence scores
type Scorer struct {
	Weights ScoreWeights
}

// NewScorer creates a new scorer
func NewScorer(weights ScoreWeights) *Scorer {
	return &Scorer{
		Weights: weights,
	}
}

// CalculateScores calculates confidence scores for CVE matches
func (s *Scorer) CalculateScores(
	versionConfirmations []version.VersionConfirmation,
	cveMatches []cve.CVEMatch,
) ([]ConfidenceScore, error) {
	fmt.Println("[SCORING] Calculating confidence scores")

	var scores []ConfidenceScore

	// Create lookup map for version confirmations
	versionMap := make(map[string]version.VersionConfirmation)
	for _, vc := range versionConfirmations {
		key := fmt.Sprintf("%s:%d", vc.IP, vc.Port)
		versionMap[key] = vc
	}

	for _, match := range cveMatches {
		key := fmt.Sprintf("%s:%d", match.IP, match.Port)

		score := ConfidenceScore{
			IP:        match.IP,
			Port:      match.Port,
			Service:   match.Service,
			Version:   match.Version,
			Breakdown: make(map[string]int),
		}

		// Source Diversity Score
		if vc, exists := versionMap[key]; exists {
			sourceDiversityScore := s.calculateSourceDiversity(len(vc.Sources))
			score.Breakdown["source_diversity"] = sourceDiversityScore
		}

		// CVSS Score
		cvssScore, highestCVSS, criticalCount := s.calculateCVSSScore(match.CVEs)
		score.Breakdown["cvss"] = cvssScore
		score.HighestCVSS = highestCVSS
		score.CriticalCVECount = criticalCount

		// ASN Reputation (placeholder - would need actual ASN data)
		asnScore := s.calculateASNReputation()
		score.Breakdown["asn_reputation"] = asnScore

		// Port Accessibility (placeholder - assume accessible)
		portScore := s.calculatePortAccessibility(true)
		score.Breakdown["port_accessibility"] = portScore

		// Exploit Availability
		exploitScore := s.calculateExploitAvailability(match.CVEs)
		score.Breakdown["exploit_availability"] = exploitScore

		// Calculate total score
		score.TotalScore = score.Breakdown["source_diversity"] +
			score.Breakdown["cvss"] +
			score.Breakdown["asn_reputation"] +
			score.Breakdown["port_accessibility"] +
			score.Breakdown["exploit_availability"]

		scores = append(scores, score)

		fmt.Printf("[SCORING] %s:%d - Total Score: %d/100\n",
			score.IP, score.Port, score.TotalScore)
	}

	return scores, nil
}

// calculateSourceDiversity calculates score based on number of confirming sources
func (s *Scorer) calculateSourceDiversity(sourceCount int) int {
	// More sources = higher confidence
	maxSources := 5
	if sourceCount >= maxSources {
		return s.Weights.SourceDiversity
	}

	ratio := float64(sourceCount) / float64(maxSources)
	return int(ratio * float64(s.Weights.SourceDiversity))
}

// calculateCVSSScore calculates score based on CVSS scores
func (s *Scorer) calculateCVSSScore(cves []cve.CVEInfo) (int, float64, int) {
	if len(cves) == 0 {
		return 0, 0.0, 0
	}

	var highestCVSS float64
	var criticalCount int

	for _, cveInfo := range cves {
		if cveInfo.CVSS > highestCVSS {
			highestCVSS = cveInfo.CVSS
		}
		if cveInfo.CVSS >= 9.0 {
			criticalCount++
		}
	}

	// Score based on highest CVSS
	cvssRatio := highestCVSS / 10.0
	return int(cvssRatio * float64(s.Weights.CVSSScore)), highestCVSS, criticalCount
}

// calculateASNReputation calculates score based on ASN reputation
func (s *Scorer) calculateASNReputation() int {
	// Placeholder - assume good reputation
	return s.Weights.ASNReputation
}

// calculatePortAccessibility calculates score based on port accessibility
func (s *Scorer) calculatePortAccessibility(accessible bool) int {
	if accessible {
		return s.Weights.PortAccessibility
	}
	return 0
}

// calculateExploitAvailability calculates score based on exploit availability
func (s *Scorer) calculateExploitAvailability(cves []cve.CVEInfo) int {
	for _, cveInfo := range cves {
		if cveInfo.ExploitAvailable {
			return s.Weights.ExploitAvailability
		}
	}

	// Check if any CVE mentions "exploit" in references
	for _, cveInfo := range cves {
		for _, ref := range cveInfo.References {
			if containsExploitKeyword(ref) {
				return int(float64(s.Weights.ExploitAvailability) * 0.7) // 70% confidence
			}
		}
	}

	return 0
}

// containsExploitKeyword checks if a URL contains exploit-related keywords
func containsExploitKeyword(url string) bool {
	keywords := []string{"exploit", "poc", "metasploit", "exploitdb"}
	urlLower := strings.ToLower(url)

	for _, keyword := range keywords {
		if strings.Contains(urlLower, keyword) {
			return true
		}
	}

	return false
}

// FilterByMinScore filters scores by minimum threshold
func FilterByMinScore(scores []ConfidenceScore, minScore int) []ConfidenceScore {
	var filtered []ConfidenceScore
	for _, score := range scores {
		if score.TotalScore >= minScore {
			filtered = append(filtered, score)
		}
	}
	return filtered
}

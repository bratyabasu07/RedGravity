package rules

import (
	"fmt"
	"os"
	"redgravity/internal/cve"
	"redgravity/internal/scoring"

	"gopkg.in/yaml.v3"
)

// Rule represents a custom filtering/selection rule
type Rule struct {
	Name     string      `yaml:"name"`
	Type     string      `yaml:"type"` // "filter" or "exclude"
	Field    string      `yaml:"field"`
	Operator string      `yaml:"operator"` // "==", "!=", ">=", "<=", ">", "<", "in"
	Value    interface{} `yaml:"value"`
	Enabled  bool        `yaml:"enabled"`
}

// RuleSet represents a collection of rules
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// RulesEngine applies custom rules to scan results
type RulesEngine struct {
	Rules    []Rule
	FilePath string
}

// NewRulesEngine creates a new rules engine
func NewRulesEngine(filePath string) (*RulesEngine, error) {
	engine := &RulesEngine{
		FilePath: filePath,
	}

	if err := engine.LoadRules(); err != nil {
		return nil, err
	}

	return engine, nil
}

// LoadRules loads rules from YAML file
func (re *RulesEngine) LoadRules() error {
	data, err := os.ReadFile(re.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %w", err)
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	re.Rules = ruleSet.Rules
	fmt.Printf("[RULES] Loaded %d rules from %s\n", len(re.Rules), re.FilePath)

	return nil
}

// ApplyRules applies all enabled rules to confidence scores
func (re *RulesEngine) ApplyRules(scores []scoring.ConfidenceScore, cveMatches []cve.CVEMatch) ([]scoring.ConfidenceScore, error) {
	fmt.Printf("[RULES] Applying %d rules\n", len(re.Rules))

	filtered := scores
	for _, rule := range re.Rules {
		if !rule.Enabled {
			continue
		}

		filtered = re.applyRule(rule, filtered, cveMatches)
	}

	fmt.Printf("[RULES] %d results after applying rules\n", len(filtered))
	return filtered, nil
}

// applyRule applies a single rule
func (re *RulesEngine) applyRule(rule Rule, scores []scoring.ConfidenceScore, cveMatches []cve.CVEMatch) []scoring.ConfidenceScore {
	var result []scoring.ConfidenceScore

	// Create CVE lookup map
	cveMap := make(map[string]cve.CVEMatch)
	for _, match := range cveMatches {
		key := fmt.Sprintf("%s:%d", match.IP, match.Port)
		cveMap[key] = match
	}

	for _, score := range scores {
		key := fmt.Sprintf("%s:%d", score.IP, score.Port)
		cveMatch, hasCVE := cveMap[key]

		pass := false

		switch rule.Field {
		case "cvss":
			pass = re.evaluateFloatCondition(score.HighestCVSS, rule.Operator, rule.Value)

		case "exploit_available":
			hasExploit := hasExploitAvailable(cveMatch)
			pass = re.evaluateBoolCondition(hasExploit, rule.Operator, rule.Value)

		case "in_cisa_kev":
			inKEV := isInCISAKEV(cveMatch)
			pass = re.evaluateBoolCondition(inKEV, rule.Operator, rule.Value)

		case "asn":
			// Placeholder for ASN filtering
			pass = true

		case "confidence_score":
			pass = re.evaluateIntCondition(score.TotalScore, rule.Operator, rule.Value)

		default:
			pass = true
		}

		// Apply filter/exclude logic
		if rule.Type == "filter" && pass {
			result = append(result, score)
		} else if rule.Type == "exclude" && !pass {
			result = append(result, score)
		} else if rule.Type != "filter" && rule.Type != "exclude" {
			result = append(result, score)
		}
	}

	return result
}

// evaluateFloatCondition evaluates a condition on float values
func (re *RulesEngine) evaluateFloatCondition(value float64, operator string, ruleValue interface{}) bool {
	targetValue, ok := ruleValue.(float64)
	if !ok {
		return false
	}

	switch operator {
	case ">=":
		return value >= targetValue
	case "<=":
		return value <= targetValue
	case ">":
		return value > targetValue
	case "<":
		return value < targetValue
	case "==":
		return value == targetValue
	case "!=":
		return value != targetValue
	default:
		return false
	}
}

// evaluateIntCondition evaluates a condition on int values
func (re *RulesEngine) evaluateIntCondition(value int, operator string, ruleValue interface{}) bool {
	var targetValue int

	switch v := ruleValue.(type) {
	case int:
		targetValue = v
	case float64:
		targetValue = int(v)
	default:
		return false
	}

	switch operator {
	case ">=":
		return value >= targetValue
	case "<=":
		return value <= targetValue
	case ">":
		return value > targetValue
	case "<":
		return value < targetValue
	case "==":
		return value == targetValue
	case "!=":
		return value != targetValue
	default:
		return false
	}
}

// evaluateBoolCondition evaluates a condition on bool values
func (re *RulesEngine) evaluateBoolCondition(value bool, operator string, ruleValue interface{}) bool {
	targetValue, ok := ruleValue.(bool)
	if !ok {
		return false
	}

	if operator == "==" {
		return value == targetValue
	}
	return false
}

// hasExploitAvailable checks if any CVE has an exploit
func hasExploitAvailable(match cve.CVEMatch) bool {
	for _, cveInfo := range match.CVEs {
		if cveInfo.ExploitAvailable {
			return true
		}
	}
	return false
}

// isInCISAKEV checks if any CVE is in CISA KEV
func isInCISAKEV(match cve.CVEMatch) bool {
	for _, cveInfo := range match.CVEs {
		if cveInfo.InCISAKEV {
			return true
		}
	}
	return false
}

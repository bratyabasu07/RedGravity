package config

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	APIKeys   APIKeysConfig   `yaml:"api_keys"`
	Pipeline  PipelineConfig  `yaml:"pipeline"`
	Stealth   StealthConfig   `yaml:"stealth"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Filtering FilteringConfig `yaml:"filtering"`
	Scoring   ScoringConfig   `yaml:"scoring"`
	Output    OutputConfig    `yaml:"output"`
	Database  DatabaseConfig  `yaml:"database"`
	Rules     RulesConfig     `yaml:"rules"`
	ML        MLConfig        `yaml:"ml"`
	API       APIConfig       `yaml:"api"`
	mutex     sync.Mutex
}

// APIKeysConfig holds all API keys
type APIKeysConfig struct {
	Shodan        ShodanConfig    `yaml:"shodan"`
	Censys        CensysConfig    `yaml:"censys"`
	NVD           SimpleAPIConfig `yaml:"nvd"`
	Vulners       SimpleAPIConfig `yaml:"vulners"`
	GreyNoise     SimpleAPIConfig `yaml:"greynoise"`
	AbuseIPDB     SimpleAPIConfig `yaml:"abuseipdb"`
	AlienVaultOTX SimpleAPIConfig `yaml:"alienvault_otx"`
}

// ShodanConfig with key rotation
type ShodanConfig struct {
	Pool         []string `yaml:"pool"`
	CurrentIndex int      `yaml:"current_index"`
}

// CensysConfig holds Censys credentials
type CensysConfig struct {
	APIID     string `yaml:"api_id"`
	APISecret string `yaml:"api_secret"`
}

// SimpleAPIConfig for single API key services
type SimpleAPIConfig struct {
	APIKey string `yaml:"api_key"`
}

// PipelineConfig holds pipeline settings
type PipelineConfig struct {
	TimeoutSeconds          int `yaml:"timeout_seconds"`
	RetryAttempts           int `yaml:"retry_attempts"`
	RetryBackoffMs          int `yaml:"retry_backoff_ms"`
	MaxConcurrentGoroutines int `yaml:"max_concurrent_goroutines"`
}

// StealthConfig holds stealth mode settings
type StealthConfig struct {
	Enabled     bool     `yaml:"enabled"`
	UserAgents  []string `yaml:"user_agents"`
	RateLimitMs int      `yaml:"rate_limit_ms"`
	JitterMs    int      `yaml:"jitter_ms"`
	UseDoH      bool     `yaml:"use_doh"`
	DoHServer   string   `yaml:"doh_server"`
}

// DiscoveryConfig holds discovery settings
type DiscoveryConfig struct {
	DNSEnumeration          bool `yaml:"dns_enumeration"`
	CertificateTransparency bool `yaml:"certificate_transparency"`
	PassiveDNS              bool `yaml:"passive_dns"`
}

// FilteringConfig holds filtering settings
type FilteringConfig struct {
	FilterPrivateIPs     bool `yaml:"filter_private_ips"`
	FilterCDNIPs         bool `yaml:"filter_cdn_ips"`
	FilterCloudProviders bool `yaml:"filter_cloud_providers"`
	ConfidenceThreshold  int  `yaml:"confidence_threshold"`
}

// ScoringConfig holds scoring weights
type ScoringConfig struct {
	SourceDiversity     int `yaml:"source_diversity"`
	CVSSScore           int `yaml:"cvss_score"`
	ASNReputation       int `yaml:"asn_reputation"`
	PortAccessibility   int `yaml:"port_accessibility"`
	ExploitAvailability int `yaml:"exploit_availability"`
}

// OutputConfig holds output settings
type OutputConfig struct {
	DefaultFormat    string   `yaml:"default_format"`
	SupportedFormats []string `yaml:"supported_formats"`
	PrettyPrint      bool     `yaml:"pretty_print"`
}

// DatabaseConfig holds database settings
type DatabaseConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"ssl_mode"`
}

// RulesConfig holds rules engine settings
type RulesConfig struct {
	Path      string `yaml:"path"`
	HotReload bool   `yaml:"hot_reload"`
}

// MLConfig holds machine learning settings
type MLConfig struct {
	Enabled   bool   `yaml:"enabled"`
	ModelPath string `yaml:"model_path"`
}

// APIConfig holds API server settings
type APIConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	AuthRequired bool   `yaml:"auth_required"`
	APIKey       string `yaml:"api_key"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	// Parse YAML
	var config Config
	if err := yaml.Unmarshal([]byte(expanded), &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// GetNextShodanKey returns the next Shodan API key using round-robin
func (c *Config) GetNextShodanKey() string {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if len(c.APIKeys.Shodan.Pool) == 0 {
		return ""
	}

	key := c.APIKeys.Shodan.Pool[c.APIKeys.Shodan.CurrentIndex]
	c.APIKeys.Shodan.CurrentIndex = (c.APIKeys.Shodan.CurrentIndex + 1) % len(c.APIKeys.Shodan.Pool)

	return key
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Check pipeline settings
	if c.Pipeline.TimeoutSeconds <= 0 {
		return fmt.Errorf("pipeline timeout must be positive")
	}
	if c.Pipeline.RetryAttempts < 0 {
		return fmt.Errorf("retry attempts cannot be negative")
	}
	if c.Pipeline.MaxConcurrentGoroutines <= 0 {
		return fmt.Errorf("max concurrent goroutines must be positive")
	}

	// Check scoring weights total to 100
	total := c.Scoring.SourceDiversity +
		c.Scoring.CVSSScore +
		c.Scoring.ASNReputation +
		c.Scoring.PortAccessibility +
		c.Scoring.ExploitAvailability

	if total != 100 {
		return fmt.Errorf("scoring weights must total 100, got %d", total)
	}

	return nil
}

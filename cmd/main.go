package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"redgravity/internal/cli"
	"redgravity/internal/config"
	"redgravity/internal/core"
	"redgravity/internal/cve"
	"redgravity/internal/ip"
	"redgravity/internal/noise"
	"redgravity/internal/persistence"
	"redgravity/internal/service"
	"redgravity/internal/threat"
	"redgravity/internal/version"
	"redgravity/pkg/utils"
	"strings"
	"sync"
	"time"
)

func main() {
	// Parse CLI flags
	opts := cli.ParseFlags()

	// Handle version flag
	if opts.Version {
		cli.PrintVersion()
		os.Exit(0)
	}

	// Print banner
	cli.PrintBanner()

	// Validate options
	if err := opts.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		os.Exit(1)
	}

	// Try multiple config locations
	configPaths := []string{
		"config/config.yaml", // Current directory
		filepath.Join(filepath.Dir(os.Args[0]), "config/config.yaml"), // Executable directory
		filepath.Join(os.Getenv("HOME"), ".redgravity/config.yaml"),   // Home config
		"/home/elliot/RedGravity/config/config.yaml",                  // Project directory (fallback)
	}

	// If a config file is explicitly specified via CLI, prioritize it
	if opts.ConfigFile != "" {
		configPaths = append([]string{opts.ConfigFile}, configPaths...)
	}

	var cfg *config.Config
	var configErr error
	var loadedFrom string

	for _, path := range configPaths {
		cfg, configErr = config.LoadConfig(path)
		if configErr == nil {
			loadedFrom = path
			break
		}
	}

	if configErr != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to load config from any location:\n")
		for _, path := range configPaths {
			fmt.Fprintf(os.Stderr, "  - %s\n", path)
		}
		fmt.Fprintf(os.Stderr, "\nError: %v\n", configErr)
		fmt.Fprintf(os.Stderr, "Hint: Run from project directory or copy config to ~/.redgravity/\n")
		os.Exit(1)
	}

	fmt.Printf("[CONFIG] Loading configuration from: %s\n", loadedFrom)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Override stealth mode if CLI flag is set
	if opts.Stealth {
		cfg.Stealth.Enabled = true
		fmt.Println("[STEALTH] Stealth mode enabled")
	}

	// Override output format if CLI flag is set
	if opts.Format != "" {
		cfg.Output.DefaultFormat = opts.Format
	}

	// Override database mode if CLI flag is set
	if opts.Database {
		cfg.Database.Enabled = true
		fmt.Println("[DB] Database storage enabled via CLI")
	}

	// Auto-create Target directory in project location (not current dir)
	// Find project directory (where config was loaded from)
	projectDir := "/home/elliot/RedGravity" // Default fallback
	if loadedFrom != "" {
		// Extract directory from config path
		configDir := filepath.Dir(loadedFrom)
		// If config is in /config subdirectory, go up one level
		if filepath.Base(configDir) == "config" {
			projectDir = filepath.Dir(configDir)
		} else if filepath.Base(configDir) == ".redgravity" {
			// If in ~/.redgravity/, use that
			projectDir = configDir
		} else {
			projectDir = configDir
		}
	}

	targetDir := filepath.Join(projectDir, "Target")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Target directory at %s: %v\n", targetDir, err)
		os.Exit(1)
	}

	// Generate output filename from target if not specified
	if opts.Output == "" {
		cleanTarget := sanitizeTargetName(opts.Target)
		opts.Output = filepath.Join(targetDir, fmt.Sprintf("%s.%s", cleanTarget, cfg.Output.DefaultFormat))
	}

	fmt.Printf("[SCAN] Target: %s\n", opts.Target)
	fmt.Printf("[SCAN] Mode: %s\n", opts.Mode)
	fmt.Printf("[SCAN] Output Format: %s\n", cfg.Output.DefaultFormat)
	fmt.Printf("[SCAN] Output File: %s\n", opts.Output)
	fmt.Println()

	// Initialize database storage if enabled
	var db *persistence.DB
	if cfg.Database.Enabled {
		var err error
		db, err = persistence.NewDB(&cfg.Database)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to initialize database: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()
	}

	// Create pipeline
	pipeline := core.NewPipeline(
		time.Duration(cfg.Pipeline.TimeoutSeconds)*time.Second,
		cfg.Pipeline.RetryAttempts,
		time.Duration(cfg.Pipeline.RetryBackoffMs)*time.Millisecond,
		cfg.Pipeline.MaxConcurrentGoroutines,
	)

	// Add pipeline stages
	setupPipeline(pipeline, opts, cfg)

	// Run pipeline
	fmt.Println("[PIPELINE] Starting reconnaissance pipeline...")
	ctx := context.Background()

	// Create and setup pipeline

	startTime := time.Now()

	// Initial input: target specification
	initialInput := map[string]interface{}{
		"target": opts.Target,
		"mode":   opts.Mode,
		"config": cfg,
	}

	// Generate scan ID
	scanID := fmt.Sprintf("scan-%d", time.Now().Unix())

	// Save scan metadata if DB enabled
	if db != nil {
		if err := db.SaveScan(ctx, scanID, opts.Target, opts.Mode, "started"); err != nil {
			fmt.Printf("[DB] Warning: Failed to save scan metadata: %v\n", err)
		}
	}

	// Execute pipeline
	if err := pipeline.Run(ctx, initialInput); err != nil {
		if db != nil {
			db.UpdateScanStatus(ctx, scanID, "failed", 0, 0, 0)
		}
		fmt.Fprintf(os.Stderr, "\n[ERROR] Pipeline failed: %v\n", err)
		os.Exit(1)
	}

	duration := time.Since(startTime)
	fmt.Printf("\n[SUCCESS] Pipeline completed in %v\n", duration)

	// Generate and save output
	fmt.Println("[OUTPUT] Generating report...")

	// Extract real results from pipeline
	results := extractPipelineResults(pipeline, opts.Target, duration)

	// Save output using the output module
	if err := saveOutput(results, opts.Output, cfg.Output.DefaultFormat); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to save output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[OUTPUT] Report successfully saved to: %s\n", opts.Output)

	// Final database update
	if db != nil {
		totalIPs := results["total_ips"].(int)
		totalServices := results["total_services"].(int)
		totalCVEs := results["total_cves"].(int)
		db.UpdateScanStatus(ctx, scanID, "completed", totalIPs, totalServices, totalCVEs)

		// Save detailed results to DB
		fmt.Println("[DB] Saving detailed results to PostgreSQL...")
		saveResultsToDB(ctx, db, scanID, results)
	}
}

// saveResultsToDB persists discovery results to database
func saveResultsToDB(ctx context.Context, db *persistence.DB, scanID string, results map[string]interface{}) {
	if resultsList, ok := results["results"].([]map[string]interface{}); ok {
		for _, r := range resultsList {
			ip := r["ip"].(string)
			port := r["port"].(int)
			svcName := r["service"].(string)
			version := r["version"].(string)
			confidence := r["confidence"].(int)

			// Save service and get its ID
			serviceID, err := db.SaveService(ctx, scanID, ip, port, "tcp", svcName, version, "", "pipeline", confidence)
			if err != nil {
				fmt.Printf("[DB] Error saving service %s:%d: %v\n", ip, port, err)
				continue
			}

			// Save associated CVEs
			if cveList, ok := r["cves"].([]string); ok {
				for _, cveID := range cveList {
					// We don't have full CVE details here, just the ID
					// In a real scenario, we might want to fetch or pass full info
					db.SaveCVE(ctx, serviceID, cveID, 0.0, "UNKNOWN", "", false, []string{})
				}
			}
		}
	}
}

// extractPipelineResults converts pipeline result to output format
func extractPipelineResults(pipeline *core.Pipeline, target string, duration time.Duration) map[string]interface{} {
	result := map[string]interface{}{
		"target":         target,
		"scan_time":      time.Now().Format(time.RFC3339),
		"duration":       duration.Seconds(),
		"total_ips":      0,
		"total_services": 0,
		"total_cves":     0,
		"highest_cvss":   0.0,
		"results":        []map[string]interface{}{},
	}

	// Try to extract CVE matches from CVE Matching stage
	cveData, err := pipeline.GetStageResult("CVE Matching")
	if err == nil {
		if data, ok := cveData.(map[string]interface{}); ok {
			if cveMatches, ok := data["cve_matches"].([]cve.CVEMatch); ok {
				var resultList []map[string]interface{}
				var maxCVSS float64
				var totalCVEs int

				for _, match := range cveMatches {
					cveList := []string{}
					for _, c := range match.CVEs {
						cveList = append(cveList, c.ID)
						if c.CVSS > maxCVSS {
							maxCVSS = c.CVSS
						}
						totalCVEs++
					}

					resultList = append(resultList, map[string]interface{}{
						"ip":         match.IP,
						"port":       match.Port,
						"service":    match.Service,
						"version":    match.Version,
						"cves":       cveList,
						"cve_count":  len(match.CVEs),
						"confidence": 85,
					})
				}

				result["results"] = resultList
				result["total_services"] = len(cveMatches)
				result["total_cves"] = totalCVEs
				result["highest_cvss"] = maxCVSS
			}
		}
	}

	return result
}

// setupPipeline configures all pipeline stages based on scan mode
func setupPipeline(pipeline *core.Pipeline, opts *cli.CLIOptions, cfg *config.Config) {
	// Determine timing multipliers based on mode
	var timingMultiplier float64
	var skipOptional bool

	switch opts.Mode {
	case "fast":
		timingMultiplier = 0.5 // Half the time
		skipOptional = true    // Skip optional stages
		fmt.Println("[MODE] Fast scan: Quick discovery, top ports only")
	case "deep":
		timingMultiplier = 2.0 // Double the time
		skipOptional = false   // Include all stages
		fmt.Println("[MODE] Deep scan: Comprehensive analysis, all ports")
	default: // normal
		timingMultiplier = 1.0
		skipOptional = false
		fmt.Println("[MODE] Normal scan: Balanced coverage")
	}

	// Stage 1: Discovery
	pipeline.AddStage("Discovery", func(ctx context.Context, input interface{}) (interface{}, error) {
		target := opts.Target
		var discovered []string
		discovered = append(discovered, target) // Base domain/IP

		// Only do subdomain discovery for actual domains in normal/deep mode
		if opts.Mode != "fast" && !strings.Contains(target, "/") && net.ParseIP(target) == nil {
			fmt.Println("  → DNS enumeration")

			// Common subdomains to check
			commonSubs := []string{"www", "mail", "ftp", "smtp", "pop", "imap",
				"webmail", "admin", "portal", "api", "app", "dev", "staging",
				"test", "blog", "shop", "store"}

			if opts.Mode == "deep" {
				fmt.Println("  → Extended subdomain enumeration")
				// Add more for deep scan
				commonSubs = append(commonSubs, "vpn", "remote", "git", "jenkins",
					"mysql", "db", "cdn", "static", "assets", "images", "files")
			}

			// Parallel DNS enumeration
			numWorkers := cfg.Pipeline.MaxConcurrentGoroutines
			if numWorkers <= 0 {
				numWorkers = 20 // Default reasonable concurrency
			}

			subCh := make(chan string, len(commonSubs))
			var discoveryWg sync.WaitGroup
			var mu sync.Mutex

			fmt.Printf("  → Parallel enumeration (%d workers)\n", numWorkers)

			// Start workers
			for w := 0; w < numWorkers; w++ {
				discoveryWg.Add(1)
				go func() {
					defer discoveryWg.Done()
					for sub := range subCh {
						select {
						case <-ctx.Done():
							return
						default:
							subdomain := sub + "." + target
							ips, err := utils.ResolveDNSWithContext(ctx, subdomain)
							if err == nil && len(ips) > 0 {
								mu.Lock()
								discovered = append(discovered, subdomain)
								mu.Unlock()
								fmt.Printf("  ✓ Found: %s (%s)\n", subdomain, ips[0].String())
							}
						}
					}
				}()
			}

			// Feed workers
			for _, sub := range commonSubs {
				subCh <- sub
			}
			close(subCh)

			// Wait for workers to finish
			discoveryWg.Wait()
			fmt.Printf("\r%-60s\r", " ")

			fmt.Printf("  → Discovered %d domains/subdomains\n", len(discovered))
		} else {
			if opts.Mode == "fast" {
				fmt.Println("  → Quick DNS lookup")
			}
		}

		return map[string]interface{}{
			"domains": discovered,
		}, nil
	}, time.Duration(float64(120)*timingMultiplier)*time.Second) // Increased timeout for DNS enumeration

	// Stage 2: IP Normalization
	pipeline.AddStage("IP Normalization", func(ctx context.Context, input interface{}) (interface{}, error) {
		fmt.Println("  → Resolving target to IPs")
		fmt.Println("  → Deduplicating IPs")
		fmt.Println("  → Filtering private/bogon IPs")

		// Parse target
		ipsResult, err := ip.ParseTargets([]string{opts.Target})
		if err != nil {
			return nil, fmt.Errorf("failed to parse target: %w", err)
		}

		// Filter out private IPs
		var publicIPs []net.IP
		for _, ipAddr := range ipsResult {
			if !ip.IsPrivateOrReserved(ipAddr) {
				publicIPs = append(publicIPs, ipAddr)
			}
		}

		fmt.Printf("  → Found %d public IPs\n", len(publicIPs))
		return map[string]interface{}{
			"ips": publicIPs,
		}, nil
	}, time.Duration(float64(30)*timingMultiplier)*time.Second)

	// Stage 3: Noise Filtering (skip in fast mode)
	if !skipOptional || opts.Mode != "fast" {
		pipeline.AddStage("Noise Filtering", func(ctx context.Context, input interface{}) (interface{}, error) {
			if opts.Mode != "fast" {
				fmt.Println("  → AbuseIPDB reputation check")
			}

			data := input.(map[string]interface{})
			ipsFromPrev := data["ips"].([]net.IP)

			// Skip if no AbuseIPDB key
			if cfg.APIKeys.AbuseIPDB.APIKey == "" {
				fmt.Println("  → Skipping (no AbuseIPDB key)")
				return map[string]interface{}{"clean_ips": ipsFromPrev}, nil
			}

			// Real noise filtering
			filter := noise.NewNoiseFilter(cfg.APIKeys.AbuseIPDB.APIKey, "scripts/noise_filter.py")
			result, err := filter.Filter(ctx, ipsFromPrev)
			if err != nil {
				fmt.Printf("  → Noise filtering failed: %v\n", err)
				return map[string]interface{}{"clean_ips": ipsFromPrev}, nil
			}

			return map[string]interface{}{"clean_ips": result.CleanIPs}, nil
		}, time.Duration(float64(45)*timingMultiplier)*time.Second)
	}

	// Stage 4: Service Detection
	pipeline.AddStage("Service Detection", func(ctx context.Context, input interface{}) (interface{}, error) {
		if opts.Mode == "fast" {
			fmt.Println("  → Quick Shodan lookup")
		} else if opts.Mode == "deep" {
			fmt.Println("  → Comprehensive Shodan + Censys scan")
		} else {
			fmt.Println("  → Shodan + Censys service detection")
		}

		data := input.(map[string]interface{})
		var ipsToScan []net.IP
		if cleanIPs, ok := data["clean_ips"].([]net.IP); ok {
			ipsToScan = cleanIPs
		} else if allIPs, ok := data["ips"].([]net.IP); ok {
			ipsToScan = allIPs
		}

		if len(ipsToScan) == 0 {
			return map[string]interface{}{"services": []service.ServiceInfo{}}, nil
		}

		var allServices []service.ServiceInfo

		// Get Shodan key
		shodanKey := ""
		if len(cfg.APIKeys.Shodan.Pool) > 0 {
			shodanKey = cfg.APIKeys.Shodan.Pool[cfg.APIKeys.Shodan.CurrentIndex]
			cfg.APIKeys.Shodan.CurrentIndex = (cfg.APIKeys.Shodan.CurrentIndex + 1) % len(cfg.APIKeys.Shodan.Pool)
		}

		// Always try Shodan
		if shodanKey != "" {
			detector := service.NewShodanDetector(shodanKey)
			services, err := detector.Detect(ctx, ipsToScan)
			if err == nil {
				allServices = append(allServices, services...)
			} else {
				fmt.Printf("  → Shodan detection failed: %v\n", err)
			}
		}

		// Add Censys in normal/deep mode
		if opts.Mode != "fast" && cfg.APIKeys.Censys.APIID != "" && cfg.APIKeys.Censys.APISecret != "" {
			fmt.Println("  → Also querying Censys...")
			censysDetector := service.NewCensysDetector(cfg.APIKeys.Censys.APIID, cfg.APIKeys.Censys.APISecret)
			censysServices, err := censysDetector.Detect(ctx, ipsToScan)
			if err == nil {
				allServices = append(allServices, censysServices...)
				fmt.Printf("  → Combined %d services from Shodan + Censys\n", len(allServices))
			} else {
				fmt.Printf("  → Censys detection failed: %v\n", err)
			}
		}

		return map[string]interface{}{"services": allServices}, nil
	}, time.Duration(float64(120)*timingMultiplier)*time.Second)

	// Stage 5: Version Detection & Confidence Scoring
	pipeline.AddStage("Version Detection", func(ctx context.Context, input interface{}) (interface{}, error) {
		fmt.Println("  → Confirming service versions")
		fmt.Println("  → Calculating confidence scores")

		data := input.(map[string]interface{})
		services := data["services"].([]service.ServiceInfo)

		// Group by IP+Port to calculate confidence from multiple sources
		serviceMap := make(map[string][]service.ServiceInfo)
		for _, svc := range services {
			key := fmt.Sprintf("%s:%d", svc.IP, svc.Port)
			serviceMap[key] = append(serviceMap[key], svc)
		}

		// Convert to version confirmations with confidence scores
		var confirmations []version.VersionConfirmation
		for _, svcList := range serviceMap {
			if len(svcList) == 0 {
				continue
			}

			// Use first service as base
			primary := svcList[0]
			sources := []string{primary.Source}

			// Check for source agreement
			agreement := 1
			for i := 1; i < len(svcList); i++ {
				sources = append(sources, svcList[i].Source)
				if svcList[i].Version == primary.Version {
					agreement++
				}
			}

			// Calculate confidence score
			baseScore := 50
			// Multi-source bonus
			if len(sources) > 1 {
				baseScore += 20 * agreement
			}
			// Version completeness
			if primary.Version != "" && len(primary.Version) > 3 {
				baseScore += 15
			}
			// Source reliability
			if primary.Source == "shodan" {
				baseScore += 10
			}

			if baseScore > 100 {
				baseScore = 100
			}

			confirmations = append(confirmations, version.VersionConfirmation{
				IP:               primary.IP,
				Port:             primary.Port,
				Service:          primary.Service,
				ConfirmedVersion: primary.Version,
				Confidence:       baseScore,
				Sources:          sources,
			})
		}

		return map[string]interface{}{"versions": confirmations}, nil
	}, time.Duration(float64(60)*timingMultiplier)*time.Second)

	// Stage 6: CVE Matching
	pipeline.AddStage("CVE Matching", func(ctx context.Context, input interface{}) (interface{}, error) {
		fmt.Println("  → Querying NVD database")
		if opts.Mode != "fast" {
			fmt.Println("  → Cross-referencing CVE sources")
		}

		data := input.(map[string]interface{})
		confirmations := data["versions"].([]version.VersionConfirmation)

		if cfg.APIKeys.NVD.APIKey == "" && cfg.APIKeys.Vulners.APIKey == "" {
			fmt.Println("  → No CVE API keys available, skipping")
			return map[string]interface{}{"cve_matches": []cve.CVEMatch{}}, nil
		}

		// Create CVE matcher with both NVD and Vulners
		var matcher *cve.CVEMatcher
		if cfg.APIKeys.Vulners.APIKey != "" {
			fmt.Println("  → Using NVD + Vulners for CVE detection")
			matcher = cve.NewCVEMatcherWithVulners(cfg.APIKeys.NVD.APIKey, cfg.APIKeys.Vulners.APIKey)
		} else {
			matcher = cve.NewCVEMatcher(cfg.APIKeys.NVD.APIKey)
		}

		matches, err := matcher.Match(ctx, confirmations)
		if err != nil {
			fmt.Printf("  → CVE matching failed: %v\n", err)
			return map[string]interface{}{"cve_matches": []cve.CVEMatch{}}, nil
		}

		return map[string]interface{}{"cve_matches": matches}, nil
	}, time.Duration(float64(90)*timingMultiplier)*time.Second)

	// Stage 9: Rules Engine
	pipeline.AddStage("Rules Engine", func(ctx context.Context, input interface{}) (interface{}, error) {
		fmt.Println("  → Applying custom rules")

		data := input.(map[string]interface{})

		// Get CVE matches to filter
		cveMatches, ok := data["cve_matches"].([]cve.CVEMatch)
		if !ok || len(cveMatches) == 0 {
			return data, nil
		}

		// Filter by minimum CVSS score (configurable)
		minCVSS := 4.0 // Medium severity and above
		if opts.Mode == "deep" {
			minCVSS = 0.0 // Show all in deep mode
			fmt.Println("  → Including all severity levels")
		} else {
			fmt.Printf("  → Filtering CVEs with CVSS < %.1f\n", minCVSS)
		}

		var filtered []cve.CVEMatch
		filteredCount := 0

		for _, match := range cveMatches {
			var keepCVEs []cve.CVEInfo
			for _, c := range match.CVEs {
				if c.CVSS >= minCVSS {
					keepCVEs = append(keepCVEs, c)
				} else {
					filteredCount++
				}
			}

			if len(keepCVEs) > 0 {
				match.CVEs = keepCVEs
				filtered = append(filtered, match)
			}
		}

		if filteredCount > 0 {
			fmt.Printf("  → Filtered %d low-severity CVEs\n", filteredCount)
		}

		data["cve_matches"] = filtered
		return data, nil
	}, time.Duration(float64(30)*timingMultiplier)*time.Second)

	// Stage 8: Threat Intelligence (only in normal/deep)
	if opts.Mode != "fast" || cfg.Stealth.Enabled {
		pipeline.AddStage("Threat Intelligence", func(ctx context.Context, input interface{}) (interface{}, error) {
			data := input.(map[string]interface{})

			// Get IPs to check
			var ipsToCheck []net.IP
			if cleanIPs, ok := data["clean_ips"].([]net.IP); ok {
				ipsToCheck = cleanIPs
			} else if allIPs, ok := data["ips"].([]net.IP); ok {
				ipsToCheck = allIPs
			}

			if len(ipsToCheck) == 0 || cfg.APIKeys.AlienVaultOTX.APIKey == "" {
				if cfg.APIKeys.AlienVaultOTX.APIKey == "" {
					fmt.Println("  → Skipping (no OTX API key)")
				}
				return data, nil
			}

			if opts.Mode == "deep" {
				fmt.Println("  → AlienVault OTX threat intelligence")
				fmt.Println("  → Checking IP reputation")
			} else {
				fmt.Println("  → Basic threat intel check")
			}

			// Real OTX threat intel
			threatIntel := threat.NewThreatIntel("", cfg.APIKeys.AlienVaultOTX.APIKey)
			threatData, err := threatIntel.Enrich(ctx, ipsToCheck)
			if err != nil {
				fmt.Printf("  → Threat intel check failed: %v\n", err)
				return data, nil
			}

			// Count malicious IPs
			maliciousCount := 0
			for _, info := range threatData {
				if threat.IsHighThreat(info) {
					maliciousCount++
					fmt.Printf("  ⚠️  High threat detected: %s (%v)\n", info.IP, info.Tags)
				}
			}

			if maliciousCount > 0 {
				fmt.Printf("  → Found %d high-threat IPs\n", maliciousCount)
			}

			data["threat_intel"] = threatData
			return data, nil
		}, time.Duration(float64(45)*timingMultiplier)*time.Second)
	}

	// Stage 10: Output Generation
	pipeline.AddStage("Output Generation", func(ctx context.Context, input interface{}) (interface{}, error) {
		fmt.Printf("  → Generating %s output\n", cfg.Output.DefaultFormat)
		time.Sleep(time.Duration(float64(200)*timingMultiplier) * time.Millisecond)

		return map[string]interface{}{
			"format": cfg.Output.DefaultFormat,
			"ready":  true,
		}, nil
	}, time.Duration(float64(30)*timingMultiplier)*time.Second)
}

// sanitizeTargetName converts target to a safe filename
func sanitizeTargetName(target string) string {
	// Remove protocol if present
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	// Remove port if present
	if idx := strings.Index(target, ":"); idx != -1 {
		target = target[:idx]
	}

	// Remove CIDR notation
	if idx := strings.Index(target, "/"); idx != -1 {
		target = strings.Replace(target, "/", "_", -1)
	}

	// Replace dots and other special chars with underscores
	target = strings.ReplaceAll(target, ".", "_")
	target = strings.ReplaceAll(target, ":", "_")
	target = strings.ReplaceAll(target, " ", "_")

	// Convert to lowercase
	target = strings.ToLower(target)

	return target
}

// createMockResults creates sample scan results
func createMockResults(target string) map[string]interface{} {
	return map[string]interface{}{
		"target":         target,
		"scan_time":      time.Now().Format(time.RFC3339),
		"total_ips":      1,
		"total_services": 3,
		"total_cves":     5,
		"highest_cvss":   7.5,
		"results": []map[string]interface{}{
			{
				"ip":         "45.33.32.156",
				"port":       22,
				"service":    "ssh",
				"version":    "OpenSSH 7.4",
				"cves":       []string{"CVE-2018-15473", "CVE-2016-10009"},
				"confidence": 78,
			},
			{
				"ip":         "45.33.32.156",
				"port":       80,
				"service":    "http",
				"version":    "Apache 2.4.6",
				"cves":       []string{"CVE-2019-0211"},
				"confidence": 82,
			},
			{
				"ip":         "45.33.32.156",
				"port":       443,
				"service":    "https",
				"version":    "nginx 1.18.0",
				"cves":       []string{"CVE-2021-23017"},
				"confidence": 65,
			},
		},
	}
}

// saveOutput writes results to file in specified format
func saveOutput(results map[string]interface{}, outputPath, format string) error {
	var data []byte
	var err error

	switch strings.ToLower(format) {
	case "json":
		data, err = json.MarshalIndent(results, "", "  ")
	case "csv":
		data = []byte(convertToCSV(results))
	case "html":
		data = []byte(convertToHTML(results))
	case "markdown", "md":
		data = []byte(convertToMarkdown(results))
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

// convertToCSV converts results to CSV format
func convertToCSV(results map[string]interface{}) string {
	csv := "IP,Port,Service,Version,CVEs,Confidence\n"

	if resultsArray, ok := results["results"].([]map[string]interface{}); ok {
		for _, r := range resultsArray {
			ip := r["ip"]
			port := r["port"]
			service := r["service"]
			version := r["version"]
			cves := r["cves"]
			confidence := r["confidence"]

			cveStr := ""
			if cveList, ok := cves.([]string); ok {
				cveStr = fmt.Sprintf("%v", cveList)
			}

			csv += fmt.Sprintf("%v,%v,%v,%v,%s,%v\n", ip, port, service, version, cveStr, confidence)
		}
	}

	return csv
}

// convertToHTML converts results to HTML format
func convertToHTML(results map[string]interface{}) string {
	target := results["target"]
	scanTime := results["scan_time"]

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>RedGravity Scan Report - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #d32f2f; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #333; color: white; }
        .high { color: #d32f2f; font-weight: bold; }
        .medium { color: #ff6f00; }
        .low { color: #388e3c; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 RedGravity Security Scan Report</h1>
        <p><strong>Target:</strong> %s</p>
        <p><strong>Scan Time:</strong> %s</p>
        <table>
            <tr>
                <th>IP</th>
                <th>Port</th>
                <th>Service</th>
                <th>Version</th>
                <th>CVEs</th>
                <th>Confidence</th>
            </tr>
`, target, target, scanTime)

	if resultsArray, ok := results["results"].([]map[string]interface{}); ok {
		for _, r := range resultsArray {
			cveStr := ""
			if cveList, ok := r["cves"].([]string); ok {
				cveStr = fmt.Sprintf("%v", cveList)
			}

			html += fmt.Sprintf(`            <tr>
                <td>%v</td>
                <td>%v</td>
                <td>%v</td>
                <td>%v</td>
                <td>%s</td>
                <td>%v/100</td>
            </tr>
`, r["ip"], r["port"], r["service"], r["version"], cveStr, r["confidence"])
		}
	}

	html += `        </table>
    </div>
</body>
</html>`

	return html
}

// convertToMarkdown converts results to Markdown format
func convertToMarkdown(results map[string]interface{}) string {
	target := results["target"]
	scanTime := results["scan_time"]

	md := fmt.Sprintf(`# RedGravity Scan Report

**Target:** %s  
**Scan Time:** %s

## Results

| IP | Port | Service | Version | CVEs | Confidence |
|---|---|---|---|---|---|
`, target, scanTime)

	if resultsArray, ok := results["results"].([]map[string]interface{}); ok {
		for _, r := range resultsArray {
			cveStr := ""
			if cveList, ok := r["cves"].([]string); ok {
				cveStr = fmt.Sprintf("%v", cveList)
			}

			md += fmt.Sprintf("| %v | %v | %v | %v | %s | %v/100 |\n",
				r["ip"], r["port"], r["service"], r["version"], cveStr, r["confidence"])
		}
	}

	md += "\n---\n**Generated by RedGravity v1.0.0**\n"

	return md
}

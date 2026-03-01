package cli

import (
	"flag"
	"fmt"
	"os"
)

// CLIOptions holds command-line options
type CLIOptions struct {
	Target     string
	Mode       string
	Output     string
	Format     string
	Stealth    bool
	ConfigFile string
	Verbose    bool
	Version    bool
	Database   bool
}

// ParseFlags parses command-line flags
func ParseFlags() *CLIOptions {
	opts := &CLIOptions{}

	flag.StringVar(&opts.Target, "target", "", "Target domain, IP, or CIDR (required)")
	flag.StringVar(&opts.Target, "t", "", "Target domain, IP, or CIDR (shorthand)")

	flag.StringVar(&opts.Mode, "mode", "normal", "Scan mode: fast, normal, deep")
	flag.StringVar(&opts.Mode, "m", "normal", "Scan mode (shorthand)")

	flag.StringVar(&opts.Output, "output", "", "Output file path")
	flag.StringVar(&opts.Output, "o", "", "Output file path (shorthand)")

	flag.StringVar(&opts.Format, "format", "json", "Output format: json, csv, html, markdown")
	flag.StringVar(&opts.Format, "f", "json", "Output format (shorthand)")

	flag.BoolVar(&opts.Stealth, "stealth", false, "Enable stealth mode")
	flag.BoolVar(&opts.Stealth, "s", false, "Enable stealth mode (shorthand)")

	flag.StringVar(&opts.ConfigFile, "config", "config/config.yaml", "Path to config file")
	flag.StringVar(&opts.ConfigFile, "c", "config/config.yaml", "Path to config file (shorthand)")

	flag.BoolVar(&opts.Verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&opts.Verbose, "v", false, "Enable verbose output (shorthand)")

	flag.BoolVar(&opts.Version, "version", false, "Print version and exit")
	flag.BoolVar(&opts.Database, "db", false, "Enable database storage")

	flag.Usage = func() {
		PrintBanner()
		fmt.Fprintf(os.Stderr, "\n%s\n\n", "RedGravity - Security Reconnaissance Platform")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -t example.com -m fast -o results.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -t 192.168.1.0/24 -m deep --stealth -f csv\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -t targets.txt -m normal -o report.html -f html\n", os.Args[0])
	}

	flag.Parse()

	return opts
}

// Validate validates the CLI options
func (opts *CLIOptions) Validate() error {
	if opts.Version {
		return nil // Skip validation for version flag
	}

	if opts.Target == "" {
		return fmt.Errorf("target is required (use -t or --target)")
	}

	validModes := map[string]bool{
		"fast":   true,
		"normal": true,
		"deep":   true,
	}
	if !validModes[opts.Mode] {
		return fmt.Errorf("invalid mode: %s (must be fast, normal, or deep)", opts.Mode)
	}

	validFormats := map[string]bool{
		"json":     true,
		"csv":      true,
		"html":     true,
		"markdown": true,
	}
	if !validFormats[opts.Format] {
		return fmt.Errorf("invalid format: %s (must be json, csv, html, or markdown)", opts.Format)
	}

	return nil
}

// PrintBanner prints the RedGravity banner
func PrintBanner() {
	banner := `
██████╗ ███████╗██████╗  ██████╗ ██████╗  █████╗ ██╗   ██╗██╗████████╗██╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝ ██╔══██╗██╔══██╗██║   ██║██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝█████╗  ██║  ██║██║  ███╗██████╔╝███████║██║   ██║██║   ██║    ╚████╔╝ 
██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔══██╗██╔══██║╚██╗ ██╔╝██║   ██║     ╚██╔╝  
██║  ██║███████╗██████╔╝╚██████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║   ██║      ██║   
╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝   ╚═╝      ╚═╝   
                                                                                
         Security Reconnaissance & Vulnerability Intelligence Platform
                     by Elliot Jr (Bratyabasu07) & DefroX556
	`
	fmt.Println(banner)
}

// PrintVersion prints version information
func PrintVersion() {
	fmt.Println("RedGravity v1.1.0")
	fmt.Println("Build: Production")
	fmt.Println("Go version:", "1.24+")
}

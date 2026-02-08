package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"redgravity/internal/cve"
	"redgravity/internal/scoring"
	"strings"
)

// OutputGenerator generates reports in multiple formats
type OutputGenerator struct {
	Format      string
	PrettyPrint bool
}

// NewOutputGenerator creates a new output generator
func NewOutputGenerator(format string, prettyPrint bool) *OutputGenerator {
	return &OutputGenerator{
		Format:      format,
		PrettyPrint: prettyPrint,
	}
}

// ScanResults holds complete scan results
type ScanResults struct {
	Target        string
	ScanTime      string
	TotalIPs      int
	TotalServices int
	TotalCVEs     int
	Scores        []scoring.ConfidenceScore
	CVEMatches    []cve.CVEMatch
	HighestCVSS   float64
	CriticalCount int
}

// Generate generates output in the specified format
func (og *OutputGenerator) Generate(results *ScanResults, outputPath string) error {
	fmt.Printf("[OUTPUT] Generating %s report\n", og.Format)

	var err error
	switch og.Format {
	case "json":
		err = og.generateJSON(results, outputPath)
	case "csv":
		err = og.generateCSV(results, outputPath)
	case "html":
		err = og.generateHTML(results, outputPath)
	case "markdown":
		err = og.generateMarkdown(results, outputPath)
	default:
		return fmt.Errorf("unsupported format: %s", og.Format)
	}

	if err != nil {
		return fmt.Errorf("failed to generate %s: %w", og.Format, err)
	}

	fmt.Printf("[OUTPUT] Report saved to: %s\n", outputPath)
	return nil
}

// generateJSON generates JSON output
func (og *OutputGenerator) generateJSON(results *ScanResults, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if og.PrettyPrint {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(results)
}

// generateCSV generates CSV output
func (og *OutputGenerator) generateCSV(results *ScanResults, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"IP", "Port", "Service", "Version", "CVE ID", "CVSS Score",
		"Severity", "Confidence Score", "Exploit Available",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Create CVE lookup
	cveMap := make(map[string]cve.CVEMatch)
	for _, match := range results.CVEMatches {
		key := fmt.Sprintf("%s:%d", match.IP, match.Port)
		cveMap[key] = match
	}

	// Write data
	for _, score := range results.Scores {
		key := fmt.Sprintf("%s:%d", score.IP, score.Port)
		cveMatch, hasCVE := cveMap[key]

		if hasCVE {
			for _, cveInfo := range cveMatch.CVEs {
				row := []string{
					score.IP,
					fmt.Sprintf("%d", score.Port),
					score.Service,
					score.Version,
					cveInfo.ID,
					fmt.Sprintf("%.1f", cveInfo.CVSS),
					cveInfo.Severity,
					fmt.Sprintf("%d", score.TotalScore),
					fmt.Sprintf("%t", cveInfo.ExploitAvailable),
				}
				if err := writer.Write(row); err != nil {
					return err
				}
			}
		} else {
			row := []string{
				score.IP,
				fmt.Sprintf("%d", score.Port),
				score.Service,
				score.Version,
				"N/A",
				"0.0",
				"N/A",
				fmt.Sprintf("%d", score.TotalScore),
				"false",
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
	}

	return nil
}

// generateHTML generates HTML report
func (og *OutputGenerator) generateHTML(results *ScanResults, path string) error {
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>RedGravity Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #d32f2f; }
        h2 { color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #1976d2; color: white; }
        tr:hover { background: #f5f5f5; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #ff6f00; font-weight: bold; }
        .medium { color: #ffa000; }
        .low { color: #388e3c; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #e3f2fd; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; color: #1976d2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 RedGravity Security Scan Report</h1>
        <p><strong>Target:</strong> {{.Target}}</p>
        <p><strong>Scan Time:</strong> {{.ScanTime}}</p>

        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{.TotalIPs}}</div>
                <div>Total IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.TotalServices}}</div>
                <div>Services Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.TotalCVEs}}</div>
                <div>CVEs Identified</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.CriticalCount}}</div>
                <div>Critical CVEs</div>
            </div>
        </div>

        <h2>Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>CVE</th>
                    <th>CVSS</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {{range .Scores}}
                <tr>
                    <td>{{.IP}}</td>
                    <td>{{.Port}}</td>
                    <td>{{.Service}}</td>
                    <td>{{.Version}}</td>
                    <td>{{.CriticalCVECount}} CVEs</td>
                    <td class="high">{{printf "%.1f" .HighestCVSS}}</td>
                    <td>-</td>
                    <td>{{.TotalScore}}/100</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>
`

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, results)
}

// generateMarkdown generates Markdown report
func (og *OutputGenerator) generateMarkdown(results *ScanResults, path string) error {
	var sb strings.Builder

	sb.WriteString("# RedGravity Security Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", results.Target))
	sb.WriteString(fmt.Sprintf("**Scan Time:** %s\n\n", results.ScanTime))

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- Total IPs: %d\n", results.TotalIPs))
	sb.WriteString(fmt.Sprintf("- Total Services: %d\n", results.TotalServices))
	sb.WriteString(fmt.Sprintf("- Total CVEs: %d\n", results.TotalCVEs))
	sb.WriteString(fmt.Sprintf("- Critical CVEs: %d\n\n", results.CriticalCount))

	sb.WriteString("## Vulnerability Details\n\n")
	sb.WriteString("| IP | Port | Service | Version | CVEs | CVSS | Confidence |\n")
	sb.WriteString("|---|---|---|---|---|---|---|\n")

	for _, score := range results.Scores {
		sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %d | %.1f | %d/100 |\n",
			score.IP, score.Port, score.Service, score.Version,
			score.CriticalCVECount, score.HighestCVSS, score.TotalScore))
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

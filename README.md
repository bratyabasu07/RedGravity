# RedGravity 🚀

> **Production-Grade Security Reconnaissance & Vulnerability Intelligence Platform**

A comprehensive multi-source reconnaissance tool that combines intelligence from Shodan, Censys, NVD, Vulners, AlienVault OTX, and AbuseIPDB to identify vulnerabilities with high confidence scoring.

![Version](https://img.shields.io/badge/version-1.1-blue)
![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-Educational-green)

## ✨ Features

### 🔍 Multi-Source Intelligence
- **Service Detection**: Shodan + Censys integration
- **CVE Matching**: Dual-source (NVD + Vulners API)
- **Threat Intelligence**: AlienVault OTX threat feeds
- **Reputation Filtering**: AbuseIPDB noise reduction
- **DNS Discovery**: Subdomain enumeration (15-28 subdomains)

### 🎯 Core Capabilities
- **3 Scan Modes**: Fast (3-5s) | Normal (20-30s) | Deep (60-90s)
- **Confidence Scoring**: Multi-source agreement algorithm (0-100 score)
- **Rules Engine**: CVSS-based CVE filtering (min threshold 4.0)
- **Stealth Mode**: User-agent rotation, rate limiting, request randomization
- **Real-time Progress**: Live subdomain checking with progress counter

### 📊 Output Formats
- **JSON**: Machine-readable structured data
- **CSV**: Spreadsheet-compatible analysis
- **HTML**: Interactive visual reports
- **Markdown**: Clean formatted reports and documentation

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/bratyabasu07/RedGravity.git
cd RedGravity

# Install dependencies
go mod tidy

# Build binary
go build -o redgravity cmd/main.go

# Install globally (optional)
cp redgravity ~/.local/bin/
```

### Configuration

Create `.env` file with your API keys:

```bash
# Required
SHODAN_API_KEY_1=your_shodan_key_here
NVD_API_KEY=your_nvd_key_here

# Recommended
VULNERS_API_KEY=your_vulners_key_here
OTX_API_KEY=your_otx_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# Optional
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
GREYNOISE_API_KEY=your_greynoise_key
```

### Basic Usage

```bash
# Fast scan
redgravity -t example.com -m fast

# Normal scan with stealth
redgravity -t example.com -m normal --stealth

# Deep scan with CSV output
redgravity -t example.com -m deep -f csv

# Scan CIDR range
redgravity -t 192.168.1.0/24 -m normal
```

## 📖 Command-Line Options

```
-t, --target     Target domain, IP, or CIDR (required)
-m, --mode       Scan mode: fast, normal, deep (default: normal)
-o, --output     Output file path (auto-generated if not specified)
-f, --format     Output format: json, csv, html, markdown (default: json)
-s, --stealth    Enable stealth mode
-c, --config     Custom config file path
-v, --verbose    Enable verbose output
--version        Print version and exit
```

## 🎯 Scan Modes Explained

| Mode | Duration | Subdomains | Features |
|------|----------|------------|----------|
| **Fast** | 3-5s | None | Quick DNS + Shodan only |
| **Normal** | 20-30s | 15 common | Full pipeline, CVSS ≥ 4.0 |
| **Deep** | 60-90s | 28 extended | All CVEs, max timeouts |

## 🔧 Architecture

### Pipeline Stages
```
1. Discovery          → DNS enumeration and subdomain finding
2. IP Normalization   → CIDR expansion, deduplication, filtering
3. Noise Filtering    → AbuseIPDB reputation check
4. Service Detection  → Shodan + Censys multi-source detection
5. Version Detection  → Confidence scoring (source agreement)
6. CVE Matching       → NVD + Vulners dual-source lookup
7. Rules Engine       → CVSS filtering and custom rules
8. Threat Intel       → AlienVault OTX threat correlation
9. Scoring            → Final confidence calculation
10. Output Generation → Multi-format report creation
```

### Intelligence Sources

**Service Detection:**
- Shodan API (primary)
- Censys API (secondary)

**CVE Intelligence:**
- NVD (National Vulnerability Database)
- Vulners API (enhanced coverage)

**Threat Intelligence:**
- AlienVault OTX (threat feeds)
- AbuseIPDB (IP reputation)

## 📊 Output Structure

### JSON Output
```json
{
  "metadata": {
    "tool": "RedGravity",
    "target": "example.com",
    "scan_mode": "normal",
    "timestamp": "2026-02-08T20:00:00Z",
    "scan_duration": "25.4s"
  },
  "services": [...],
  "cves": [...],
  "threats": [...],
  "confidence_scores": [...]
}
```

### Auto-Save Feature
All scan results automatically save to:
```
/path/to/RedGravity/Target/<target_name>.<format>
```

Works from any directory - outputs always save to project's `Target/` folder!

## 🛡️ Rules Engine

Customize filtering in `config/rules.yaml`:

```yaml
rules:
  - name: "High Severity Only"
    type: "filter"
    field: "cvss"
    operator: ">="
    value: 7.0
    enabled: true
    
  - name: "Exclude Low Confidence"
    type: "filter"
    field: "confidence_score"
    operator: ">="
    value: 60
    enabled: true
```

**Default Behavior:**
- Normal/Deep: CVEs with CVSS ≥ 4.0
- Deep mode: All severities (CVSS ≥ 0.0)

## 🎨 Features in Detail

### DNS Subdomain Enumeration
- **Normal Mode**: 15 common subdomains (www, mail, api, admin, etc.)
- **Deep Mode**: 28 extended subdomains (includes vpn, git, mysql, cdn, etc.)
- **2-second timeout** per lookup (fast fail-fast behavior)
- **Real-time progress**: Shows "Checking subdomain X/Y..."

### Confidence Scoring
Multi-factor algorithm considering:
- Source diversity (multiple APIs agree)
- Version completeness (full version vs partial)
- Source reliability (Shodan weighted higher)
- **Maximum score**: 100

### Stealth Mode
When `--stealth` is enabled:
- User-agent rotation from realistic pool
- Random delays with jitter (500-2000ms)
- Rate limiting per API
- DNS over HTTPS (DoH) - Coming Soon

## 🧪 Testing

```bash
# Test fast mode
redgravity -t scanme.nmap.org -m fast

# Test with known vulnerable target
redgravity -t 45.33.32.156 -m normal

# Test deep enumeration
redgravity -t example.com -m deep
```

## 📁 Project Structure

```
RedGravity/
├── cmd/main.go              # Main application entry
├── internal/
│   ├── cli/                 # CLI argument parsing
│   ├── config/              # Configuration management
│   ├── core/                # Pipeline orchestration
│   ├── cve/                 # CVE matching (NVD + Vulners)
│   ├── ip/                  # IP validation and filtering
│   ├── noise/               # AbuseIPDB integration
│   ├── service/             # Shodan + Censys detection
│   ├── threat/              # AlienVault OTX
│   ├── scoring/             # Confidence scoring
│   ├── rules/               # Rules engine
│   └── version/             # Version detection
├── pkg/utils/               # Utility functions
├── config/
│   ├── config.yaml          # Main configuration
│   └── rules.yaml           # Custom rules
├── Target/                  # Scan output directory
└── .env                     # API keys (DO NOT COMMIT!)
```

## 🔒 Security Notes

**⚠️ Important:**
- `.env` file contains sensitive API keys - **keep it secure!**
- `.gitignore` is configured to exclude `.env` and `Target/`
- Only use on authorized targets
- Respect rate limits of APIs

## 🐛 Known Issues

- **Censys API**: May require valid paid account for full access
- **DNS Timeouts**: Network-dependent, 2s timeout per subdomain

## 🚀 Future Enhancements

- [x] PostgreSQL persistence
- [ ] ML-based confidence boosting
- [ ] GreyNoise integration
- [ ] WebUI dashboard
- [ ] REST API mode
- [ ] Parallel DNS lookups
- [ ] Certificate transparency logs

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📜 License

**Educational purposes only.** This tool is for authorized security research and penetration testing. Unauthorized scanning may be illegal in your jurisdiction.

## 👨‍💻 Authors

**Elliot Jr (Bratyabasu07)** & **DefroX556**

Security Reconnaissance & Vulnerability Intelligence Platform

---

## 🙏 Acknowledgments

- **Shodan** - Service detection
- **Censys** - Additional service intelligence
- **NVD** - CVE database
- **Vulners** - Enhanced CVE coverage
- **AlienVault OTX** - Threat intelligence
- **AbuseIPDB** - IP reputation

---

**Made with 🔥 for the security community**

**RedGravity** - Security Reconnaissance Platform

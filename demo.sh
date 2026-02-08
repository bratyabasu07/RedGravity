#!/bin/bash
# RedGravity Demo Script
# This script demonstrates RedGravity's capabilities with various output formats

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           RedGravity - Demo & Testing Script                 ║"
echo "║     Security Reconnaissance & Vulnerability Intelligence     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if binary exists
if [ ! -f "./redgravity" ]; then
    echo -e "${RED}✗ Error: redgravity binary not found!${NC}"
    echo "  Run: go build -o redgravity cmd/main.go"
    exit 1
fi

echo -e "${GREEN}✓ RedGravity binary found${NC}"
echo ""

# Demo 1: Basic JSON Scan
echo -e "${BLUE}═══ Demo 1: Basic JSON Scan ═══${NC}"
echo "Command: ./redgravity -t scanme.nmap.org -m fast -o demo1.json"
echo ""
./redgravity -t scanme.nmap.org -m fast -o demo1.json
echo ""
echo -e "${GREEN}✓ Demo 1 Complete - Check demo1.json${NC}"
echo ""

# Demo 2: HTML Report
echo -e "${BLUE}═══ Demo 2: HTML Visual Report ═══${NC}"
echo "Command: ./redgravity -t example.com -m normal -f html -o demo2.html"
echo ""
./redgravity -t example.com -m normal -f html -o demo2.html
echo ""
echo -e "${GREEN}✓ Demo 2 Complete - Check demo2.html in browser${NC}"
echo ""

# Demo 3: CSV Export
echo -e "${BLUE}═══ Demo 3: CSV Export for Analysis ═══${NC}"
echo "Command: ./redgravity -t 8.8.8.8 -m fast -f csv -o demo3.csv"
echo ""
./redgravity -t 8.8.8.8 -m fast -f csv -o demo3.csv
echo ""
echo -e "${GREEN}✓ Demo 3 Complete - Check demo3.csv${NC}"
echo ""

# Demo 4: Markdown Documentation
echo -e "${BLUE}═══ Demo 4: Markdown Report ═══${NC}"
echo "Command: ./redgravity -t scanme.nmap.org -m fast -f markdown -o demo4.md"
echo ""
./redgravity -t scanme.nmap.org -m fast -f markdown -o demo4.md
echo ""
echo -e "${GREEN}✓ Demo 4 Complete - Check demo4.md${NC}"
echo ""

# Demo 5: Stealth Mode
echo -e "${BLUE}═══ Demo 5: Stealth Mode Scan ═══${NC}"
echo "Command: ./redgravity -t example.com -m fast --stealth -o demo5.json"
echo ""
./redgravity -t example.com -m fast --stealth -o demo5.json
echo ""
echo -e "${GREEN}✓ Demo 5 Complete - Stealth mode engaged!${NC}"
echo ""

# Demo 6: Version Check
echo -e "${BLUE}═══ Demo 6: Version Info ═══${NC}"
./redgravity --version
echo ""

# Demo 7: Help Menu
echo -e "${BLUE}═══ Demo 7: Help Menu ═══${NC}"
./redgravity --help
echo ""

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Demo Summary                               ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║ Generated Files:                                              ║"
echo "║   • demo1.json  - JSON output                                 ║"
echo "║   • demo2.html  - HTML visual report (open in browser)        ║"
echo "║   • demo3.csv   - CSV for spreadsheet analysis                ║"
echo "║   • demo4.md    - Markdown documentation                      ║"
echo "║   • demo5.json  - Stealth mode scan results                   ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║ Key Features Demonstrated:                                    ║"
echo "║   ✓ Multi-format output (JSON/CSV/HTML/Markdown)              ║"
echo "║   ✓ Multiple scan modes (fast/normal/deep)                    ║"
echo "║   ✓ Stealth capabilities                                      ║"
echo "║   ✓ Pipeline orchestration                                    ║"
echo "║   ✓ CVE matching and scoring                                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}All demos completed successfully!${NC}"
echo ""
echo "Next steps:"
echo "  1. View example_output.json for detailed JSON structure"
echo "  2. Open example_output.md for human-readable report"
echo "  3. Check example_output.csv for spreadsheet import"
echo "  4. Configure API keys in config/config.yaml for full features"
echo ""

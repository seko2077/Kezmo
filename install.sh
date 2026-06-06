#!/bin/bash
# ============================================================================
#  KEZMO — Quick Install Script for Kali Linux
#  This installs kezmo as a system-wide command
# ============================================================================

set -e

RED='\033[91m'
GREEN='\033[92m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  ██╗  ██╗███████╗███████╗███╗   ███╗ ██████╗ "
echo "  ██║ ██╔╝██╔════╝╚══███╔╝████╗ ████║██╔═══██╗"
echo "  █████╔╝ █████╗    ███╔╝ ██╔████╔██║██║   ██║"
echo "  ██╔═██╗ ██╔══╝   ███╔╝  ██║╚██╔╝██║██║   ██║"
echo "  ██║  ██╗███████╗███████╗██║ ╚═╝ ██║╚██████╔╝"
echo "  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝ ╚═════╝"
echo -e "${RESET}"
echo -e "${BOLD}  Installing KEZMO...${RESET}\n"

# Step 1: Install system dependencies
echo -e "${CYAN}[1/3]${RESET} Installing system dependencies..."
sudo apt update -qq
sudo apt install -y -qq exiftool binwalk steghide sox foremost john 2>/dev/null
echo -e "${GREEN}  ✔ System dependencies installed${RESET}\n"

# Step 2: Install zsteg (optional, Ruby gem)
echo -e "${CYAN}[2/3]${RESET} Installing zsteg (optional)..."
if command -v gem &>/dev/null; then
    sudo gem install zsteg 2>/dev/null && echo -e "${GREEN}  ✔ zsteg installed${RESET}" || echo -e "  ⚠ zsteg install failed (optional, skipping)"
else
    echo -e "  ⚠ Ruby not found, skipping zsteg (optional)"
fi
echo ""

# Step 3: Install kezmo as a CLI command
echo -e "${CYAN}[3/3]${RESET} Installing kezmo command..."
pip install --break-system-packages . 2>/dev/null || pip install . 2>/dev/null || pip3 install .
echo -e "${GREEN}  ✔ kezmo installed${RESET}\n"

# Verify
if command -v kezmo &>/dev/null; then
    echo -e "${GREEN}${BOLD}  ✔ Installation complete!${RESET}"
    echo -e "  ${BOLD}Usage:${RESET} kezmo <file> [-y] [-no]"
    echo -e "  ${BOLD}Example:${RESET} kezmo challenge.jpg -y\n"
else
    echo -e "${RED}  ✖ Something went wrong. Try: pip install .${RESET}\n"
fi

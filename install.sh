#!/usr/bin/env bash
set -euo pipefail

REPO="SoukoX/SENTINEL"
BIN_NAME="sentinel"
INSTALL_DIR="${HOME}/.local/bin"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}  ┌──────────────────────────────────────────┐${NC}"
echo -e "${CYAN}  │${NC}  SENTINEL — AI Cybersecurity Agent       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}  Installer v1.0                          ${CYAN}│${NC}"
echo -e "${CYAN}  └──────────────────────────────────────────┘${NC}"
echo ""

ARCH="$(uname -m)"
OS="$(uname -s)"

case "${OS}" in
  Linux)  OS="linux"  ;;
  Darwin) OS="macos"  ;;
  *)      echo -e "${RED}✘ Unsupported OS: ${OS}${NC}"; exit 1 ;;
esac

case "${ARCH}" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)      echo -e "${RED}✘ Unsupported arch: ${ARCH}${NC}"; exit 1 ;;
esac

echo -e "  Platform:  ${YELLOW}${OS} ${ARCH}${NC}"

echo -e "  Fetching latest release…"
LATEST="$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('tag_name', ''))
except Exception:
    print('')
")"

if [ -z "${LATEST}" ]; then
  echo -e "${RED}✘ Could not fetch latest release.${NC}"
  exit 1
fi
echo -e "  Release:   ${YELLOW}${LATEST}${NC}"

ASSET="${BIN_NAME}-${OS}-${ARCH}"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"

echo -e "  Downloading ${BIN_NAME}…"
mkdir -p "${INSTALL_DIR}"
echo -e "  ${YELLOW}URL: ${URL}${NC}"
curl -#L "${URL}" -o "${INSTALL_DIR}/${BIN_NAME}" || {
  echo -e "${RED}✘ Download failed.${NC}"
  exit 1
}
chmod +x "${INSTALL_DIR}/${BIN_NAME}"

if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  SHELL_CONFIG="${HOME}/.$(basename "${SHELL}")rc"
  if [ -f "${SHELL_CONFIG}" ]; then
    echo "" >> "${SHELL_CONFIG}"
    echo "# SENTINEL" >> "${SHELL_CONFIG}"
    echo "export PATH=\"\${PATH}:${INSTALL_DIR}\"" >> "${SHELL_CONFIG}"
    echo -e "  ${YELLOW}Added ${INSTALL_DIR} to PATH in ${SHELL_CONFIG}${NC}"
  fi
fi

echo ""
echo -e "${GREEN}  ✅ SENTINEL installed${NC}"
echo ""
echo -e "  ${CYAN}Run:${NC}    ${BIN_NAME}"
echo -e "  ${CYAN}Open:${NC}   http://localhost:8766"
echo ""
echo -e "  ${YELLOW}External tools (nmap, nuclei, etc.) are not bundled.${NC}"
echo -e "  ${YELLOW}Install separately for the full pipeline.${NC}"
echo ""

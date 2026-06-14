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

# ── Detect platform ───────────────────────────────────────────────
ARCH="$(uname -m)"
OS="$(uname -s)"

case "${OS}" in
  Linux)  OS="linux"  ;;
  Darwin) OS="macos"  ;;
  *)
    echo -e "${RED}✘ Unsupported OS: ${OS}${NC}"
    exit 1
    ;;
esac

case "${ARCH}" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)
    echo -e "${RED}✘ Unsupported arch: ${ARCH}${NC}"
    exit 1
    ;;
esac

ASSET="sentinel-${OS}-${ARCH}"
echo -e "  Platform:  ${YELLOW}${OS} ${ARCH}${NC}"

# ── Check if already installed ────────────────────────────────────
CURRENT=""
if command -v "${BIN_NAME}" &>/dev/null; then
  CURRENT="$("${BIN_NAME}" --version 2>/dev/null || true)"
  echo -e "  Installed: ${YELLOW}${CURRENT:-unknown}${NC}"
fi

# ── Fetch latest release ──────────────────────────────────────────
echo -e "  Fetching latest release from ${REPO}…"
LATEST="$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tag_name', ''))
except Exception:
    print('')
" 2>/dev/null || true)"

if [ -z "${LATEST}" ]; then
  echo -e "${RED}✘ Could not fetch latest release. Check your internet or REPO=${REPO}${NC}"
  exit 1
fi

echo -e "  Release:   ${YELLOW}${LATEST}${NC}"

# ── Download binary ───────────────────────────────────────────────
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo -e "  Downloading ${BIN_NAME}…"
curl -sL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${BIN_NAME}" || {
  echo -e "${RED}✘ Download failed. Release may not have this asset.${NC}"
  exit 1
}
chmod +x "${TMP_DIR}/${BIN_NAME}"

# ── Verify ─────────────────────────────────────────────────────────
if ! "${TMP_DIR}/${BIN_NAME}" --help &>/dev/null; then
  echo -e "${RED}✘ Downloaded binary failed to execute.${NC}"
  exit 1
fi

# ── Install ────────────────────────────────────────────────────────
mkdir -p "${INSTALL_DIR}"
cp "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

# Add to PATH if not already
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  SHELL_CONFIG="${HOME}/.$(basename "${SHELL}")rc"
  if [ -f "${SHELL_CONFIG}" ]; then
    echo "" >> "${SHELL_CONFIG}"
    echo "# SENTINEL" >> "${SHELL_CONFIG}"
    echo "export PATH=\"\${PATH}:${INSTALL_DIR}\"" >> "${SHELL_CONFIG}"
    echo -e "  ${YELLOW}Added ${INSTALL_DIR} to PATH in ${SHELL_CONFIG}${NC}"
  fi
fi

# ── Done ───────────────────────────────────────────────────────────
INSTALLED_VER="$("${INSTALL_DIR}/${BIN_NAME}" --version 2>/dev/null || echo "${LATEST}")"
echo ""
echo -e "${GREEN}  ✅ SENTINEL ${INSTALLED_VER} installed${NC}"
echo ""
echo -e "  ${CYAN}Run:${NC}  ${BIN_NAME} example.com"
echo -e "  ${CYAN}Help:${NC} ${BIN_NAME} --help"
echo ""
echo -e "  ${YELLOW}Note: External tools (nmap, nuclei, ffuf, etc.) are not bundled.${NC}"
echo -e "  ${YELLOW}Install them separately for full pipeline:${NC}"
echo -e "  ${CYAN}https://github.com/${REPO}#required-tools${NC}"
echo ""

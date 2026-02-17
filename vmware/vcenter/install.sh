#!/usr/bin/env bash
# ============================================================================
# install.sh — Install the VMware vCenter provider plugin into the
#              AAP Inventory Service.
#
# Run this from the extracted plugin directory (vcenter/).
#
# Environment variables:
#   IS_API_URL      Inventory Service API base URL
#                   (default: http://localhost:8000/api/inventory/v1)
#   IS_USERNAME     API username (default: admin)
#   IS_PASSWORD     API password (default: admin)
#   VENV_PATH       Path to the app's virtualenv (auto-detected if not set)
#   SKIP_SYSTEM     Set to 1 to skip system package installation
#   SKIP_COLLECTIONS  Set to 1 to skip Ansible collection installation
# ============================================================================

set -euo pipefail

# -- Colors ---------------------------------------------------------------
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
NC="\033[0m"

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

# -- Preflight checks -----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/manifest.yml" ]]; then
    fail "manifest.yml not found. Run this script from the plugin directory."
    exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/provider.py" ]]; then
    fail "provider.py not found. Plugin directory appears incomplete."
    exit 1
fi

PLUGIN_NAME=$(python3 -c "
import yaml, sys
with open('${SCRIPT_DIR}/manifest.yml') as f:
    m = yaml.safe_load(f)
print(f\"{m['vendor']}:{m['name']}\")
" 2>/dev/null || echo "vmware:vcenter")

PLUGIN_VERSION=$(python3 -c "
import yaml
with open('${SCRIPT_DIR}/manifest.yml') as f:
    m = yaml.safe_load(f)
print(m.get('version', '0.0.0'))
" 2>/dev/null || echo "0.0.0")

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Inventory Provider Plugin Installer${NC}"
echo -e "${CYAN}  Plugin:  ${PLUGIN_NAME} v${PLUGIN_VERSION}${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# -- Configuration ---------------------------------------------------------
IS_API_URL="${IS_API_URL:-http://localhost:8000/api/inventory/v1}"
IS_USERNAME="${IS_USERNAME:-admin}"
IS_PASSWORD="${IS_PASSWORD:-admin}"
SKIP_SYSTEM="${SKIP_SYSTEM:-0}"
SKIP_COLLECTIONS="${SKIP_COLLECTIONS:-0}"

info "API endpoint: ${IS_API_URL}"
info "Plugin source: ${SCRIPT_DIR}"
echo ""

# -- Step 1: System packages (bindep) ------------------------------------
if [[ "${SKIP_SYSTEM}" != "1" ]] && [[ -f "${SCRIPT_DIR}/bindep.txt" ]]; then
    info "Step 1/5: Checking system dependencies (bindep.txt)"
    if command -v bindep &>/dev/null; then
        MISSING=$(cd "${SCRIPT_DIR}" && bindep -b 2>/dev/null || true)
        if [[ -n "${MISSING}" ]]; then
            warn "Missing system packages: ${MISSING}"
            warn "Install them with your package manager before proceeding."
            warn "  RHEL/Fedora: sudo dnf install ${MISSING}"
            warn "  Ubuntu/Debian: sudo apt-get install ${MISSING}"
        else
            ok "All system dependencies satisfied."
        fi
    else
        warn "bindep not installed — skipping system dependency check."
        warn "  Install with: pip install bindep"
    fi
else
    info "Step 1/5: System dependencies — skipped."
fi
echo ""

# -- Step 2: Python dependencies (requirements.txt) ----------------------
info "Step 2/5: Installing Python dependencies (requirements.txt)"
if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
    pip install -r "${SCRIPT_DIR}/requirements.txt" 2>&1 | while read -r line; do
        echo "         ${line}"
    done
    ok "Python dependencies installed."
else
    warn "No requirements.txt found — skipping."
fi
echo ""

# -- Step 3: Ansible collections (requirements.yml) ----------------------
if [[ "${SKIP_COLLECTIONS}" != "1" ]]; then
    info "Step 3/5: Installing Ansible collections (requirements.yml)"
    if [[ -f "${SCRIPT_DIR}/requirements.yml" ]]; then
        if command -v ansible-galaxy &>/dev/null; then
            ansible-galaxy collection install -r "${SCRIPT_DIR}/requirements.yml" 2>&1 | while read -r line; do
                echo "         ${line}"
            done
            ok "Ansible collections installed."
        else
            warn "ansible-galaxy not available — skipping collection install."
        fi
    else
        warn "No requirements.yml found — skipping."
    fi
else
    info "Step 3/5: Ansible collections — skipped."
fi
echo ""

# -- Step 4: Install the plugin package ----------------------------------
info "Step 4/5: Installing plugin package (pip install)"
pip install "${SCRIPT_DIR}" 2>&1 | while read -r line; do
    echo "         ${line}"
done

# Verify the entry point is registered
EP_CHECK=$(python3 -c "
from importlib.metadata import entry_points
eps = entry_points(group='inventory_providers')
found = [ep for ep in eps if 'vmware' in ep.name]
for ep in found:
    print(f'  {ep.name} -> {ep.value}')
if not found:
    print('  (none)')
" 2>/dev/null || echo "  (check failed)")

ok "Plugin package installed. Entry points:"
echo "${EP_CHECK}"
echo ""

# -- Step 5: Refresh registry and verify via API -------------------------
info "Step 5/5: Verifying plugin via Inventory Service API"

# Check API is reachable
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${IS_USERNAME}:${IS_PASSWORD}" \
    "${IS_API_URL}/provider-plugins/" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "000" ]]; then
    warn "Cannot reach API at ${IS_API_URL}"
    warn "The plugin is installed but could not verify via API."
    warn "Start the service and run:"
    warn "  curl -u ${IS_USERNAME}:${IS_PASSWORD} ${IS_API_URL}/provider-plugins/${PLUGIN_NAME}/"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  Installation complete (API verification skipped)${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    exit 0
fi

if [[ "${HTTP_CODE}" == "401" ]] || [[ "${HTTP_CODE}" == "403" ]]; then
    warn "API returned ${HTTP_CODE} — authentication failed."
    warn "Check IS_USERNAME and IS_PASSWORD environment variables."
    warn "The plugin is installed but could not verify via API."
    echo ""
    exit 1
fi

# Trigger registry refresh
info "Refreshing plugin registry..."
REFRESH_RESPONSE=$(curl -s -X POST \
    -u "${IS_USERNAME}:${IS_PASSWORD}" \
    -H "Content-Type: application/json" \
    "${IS_API_URL}/provider-plugins/refresh/" 2>/dev/null)

REFRESH_COUNT=$(echo "${REFRESH_RESPONSE}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('detail', 'unknown'))
except:
    print('Could not parse response')
" 2>/dev/null)
ok "${REFRESH_COUNT}"

# Verify the specific plugin
info "Querying plugin: ${PLUGIN_NAME}"
PLUGIN_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -u "${IS_USERNAME}:${IS_PASSWORD}" \
    "${IS_API_URL}/provider-plugins/${PLUGIN_NAME}/" 2>/dev/null)

PLUGIN_BODY=$(echo "${PLUGIN_RESPONSE}" | head -n -1)
PLUGIN_HTTP=$(echo "${PLUGIN_RESPONSE}" | tail -1)

if [[ "${PLUGIN_HTTP}" == "200" ]]; then
    echo "${PLUGIN_BODY}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"  Key:            {data.get('key', 'N/A')}\")
print(f\"  Display name:   {data.get('display_name', 'N/A')}\")
print(f\"  Vendor:         {data.get('vendor', 'N/A')}\")
print(f\"  Provider type:  {data.get('provider_type', 'N/A')}\")
print(f\"  Class:          {data.get('class_path', 'N/A')}\")
types = ', '.join(data.get('supported_resource_types', []))
print(f\"  Resource types: {types}\")
instances = data.get('configured_instances', 0)
print(f\"  Configured:     {instances} instance(s)\")
" 2>/dev/null
    echo ""
    ok "Plugin ${PLUGIN_NAME} is registered and available!"
else
    fail "Plugin not found (HTTP ${PLUGIN_HTTP})."
    fail "Response: ${PLUGIN_BODY}"
    echo ""
    fail "The package was installed but the registry did not pick it up."
    fail "Check that the entry point group is 'inventory_providers'."
    exit 1
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation successful!${NC}"
echo -e "${GREEN}${NC}"
echo -e "${GREEN}  Next steps:${NC}"
echo -e "${GREEN}    1. Create a Provider instance via the API:${NC}"
echo -e "${GREEN}       POST ${IS_API_URL}/providers/${NC}"
echo -e "${GREEN}       {"name": "My vCenter", "vendor": "vmware",${NC}"
echo -e "${GREEN}        "provider_type": "vcenter", ...}${NC}"
echo -e "${GREEN}${NC}"
echo -e "${GREEN}    2. Test connectivity:${NC}"
echo -e "${GREEN}       POST ${IS_API_URL}/provider-plugins/${PLUGIN_NAME}/test/${NC}"
echo -e "${GREEN}${NC}"
echo -e "${GREEN}    3. Trigger a collection:${NC}"
echo -e "${GREEN}       POST ${IS_API_URL}/providers/{id}/collect/${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

#!/usr/bin/env bash
# install.sh - Upload provider plugin to running inventory-service in aap-dev
# Usage: ./install.sh [--force]
set -euo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[0;36m"; BOLD="\033[1m"; NC="\033[0m"
info()  { echo -e "${CYAN}i${NC}  $*"; }
ok()    { echo -e "${GREEN}+${NC}  $*"; }
warn()  { echo -e "${YELLOW}!${NC}  $*"; }
fail()  { echo -e "${RED}x${NC}  $*"; }
die()   { fail "$*"; exit 1; }

FORCE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force|-f) FORCE="?force=true" ;;
        --help|-h)  echo "Usage: $0 [--force]"; exit 0 ;;
        *)          die "Unknown option: $1" ;;
    esac; shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "${SCRIPT_DIR}/manifest.yml" ]] || die "manifest.yml not found"
[[ -f "${SCRIPT_DIR}/provider.py" ]]  || die "provider.py not found"

PLUGIN_NAME=$(python3 -c "import yaml; m=yaml.safe_load(open('${SCRIPT_DIR}/manifest.yml')); print(f\"{m.get('vendor','?')}:{m.get('provider_type',m.get('name','?'))}\")" 2>/dev/null || echo "unknown")
PLUGIN_VERSION=$(python3 -c "import yaml; m=yaml.safe_load(open('${SCRIPT_DIR}/manifest.yml')); print(m.get('version','0.0.0'))" 2>/dev/null || echo "0.0.0")

echo ""
echo -e "${BOLD}${CYAN}  Provider Plugin Installer - ${PLUGIN_NAME} v${PLUGIN_VERSION}${NC}"
echo ""

AAP_NAMESPACE="${AAP_NAMESPACE:-aap26}"
IS_USERNAME="${IS_USERNAME:-admin}"

if [[ -z "${IS_API_URL:-}" ]]; then
    if [[ -n "${AAP_DEV_ROOT:-}" ]]; then
        :
    elif [[ -d "${SCRIPT_DIR}/../../../aap-dev" ]]; then
        AAP_DEV_ROOT="$(cd "${SCRIPT_DIR}/../../../aap-dev" && pwd)"
    elif [[ -d "${HOME}/upstream/aap-dev" ]]; then
        AAP_DEV_ROOT="${HOME}/upstream/aap-dev"
    else
        die "Cannot find aap-dev. Set AAP_DEV_ROOT or IS_API_URL."
    fi

    KUBECONFIG_PATH="${AAP_DEV_ROOT}/.tmp/26.kubeconfig"
    [[ -f "${KUBECONFIG_PATH}" ]] || die "Kubeconfig not found: ${KUBECONFIG_PATH}"
    export KUBECONFIG="${KUBECONFIG_PATH}"
    info "aap-dev:     ${AAP_DEV_ROOT}"
    info "kubeconfig:  ${KUBECONFIG_PATH}"
    info "namespace:   ${AAP_NAMESPACE}"

    GATEWAY_PORT=$(kubectl get service myaap -n "${AAP_NAMESPACE}" \
        -o jsonpath='{.spec.ports[?(@.name=="gateway-api")].nodePort}' 2>/dev/null || echo "")
    if [[ -z "${GATEWAY_PORT}" ]]; then
        GATEWAY_PORT=$(docker port 26-control-plane 44926 2>/dev/null | head -1 | cut -d: -f2 || echo "44926")
    fi
    IS_API_URL="http://localhost:${GATEWAY_PORT}/api/inventory/v1"

    if [[ -z "${IS_PASSWORD:-}" ]]; then
        IS_PASSWORD=$(kubectl get secret myaap-admin-password -n "${AAP_NAMESPACE}" \
            -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null || echo "")
        [[ -n "${IS_PASSWORD}" ]] || die "Cannot read admin password. Set IS_PASSWORD."
        ok "Admin password auto-detected"
    fi
fi

IS_PASSWORD="${IS_PASSWORD:?Set IS_PASSWORD or ensure cluster is running}"
info "API target:  ${IS_API_URL}"
echo ""

# Connectivity check
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${IS_USERNAME}:${IS_PASSWORD}" \
    "${IS_API_URL}/provider-plugins/" 2>/dev/null || echo "000")
[[ "${HTTP_CODE}" != "000" ]] || die "Cannot reach ${IS_API_URL}"
[[ "${HTTP_CODE}" != "401" && "${HTTP_CODE}" != "403" ]] || die "Auth failed (HTTP ${HTTP_CODE})"
[[ "${HTTP_CODE}" != "503" ]] || die "Service unavailable (503)"
ok "API reachable (HTTP ${HTTP_CODE})"
echo ""

# Package
info "Packaging plugin..."
TMPFILE=$(mktemp /tmp/plugin-upload-XXXXXX.tar.gz)
trap "rm -f '${TMPFILE}'" EXIT
tar czf "${TMPFILE}" -C "${SCRIPT_DIR}" \
    --exclude='*.egg-info' --exclude='build' --exclude='dist' \
    --exclude='__pycache__' --exclude='.git' --exclude='*.pyc' \
    --exclude='install.sh' .
FILESIZE=$(wc -c < "${TMPFILE}" | tr -d ' ')
ok "Tarball: ${FILESIZE} bytes"
echo ""

# Upload
info "Uploading to ${IS_API_URL}/provider-plugins/upload/"
RESPONSE_FILE=$(mktemp /tmp/plugin-response-XXXXXX.json)
HTTP_CODE=$(curl -s -o "${RESPONSE_FILE}" -w "%{http_code}" \
    -X POST \
    -u "${IS_USERNAME}:${IS_PASSWORD}" \
    -F "plugin=@${TMPFILE};type=application/gzip" \
    "${IS_API_URL}/provider-plugins/upload/${FORCE}" 2>/dev/null)
BODY=$(cat "${RESPONSE_FILE}")
rm -f "${RESPONSE_FILE}"

case "${HTTP_CODE}" in
    201)
        python3 -c "
import json, sys
try:
    data = json.loads(sys.argv[1])
    p = data.get('plugin', {})
    if p:
        print(f'  Key:            {p.get(\"key\", \"N/A\")}')
        print(f'  Display name:   {p.get(\"display_name\", \"N/A\")}')
        print(f'  Class:          {p.get(\"class_path\", \"N/A\")}')
        t = ', '.join(p.get('supported_resource_types', []))
        print(f'  Resource types: {t}')
except: pass
" "${BODY}" 2>/dev/null
        echo ""
        echo -e "${GREEN}${BOLD}  Plugin installed - no restart needed${NC}"
        echo -e "  ${CYAN}Next: POST ${IS_API_URL}/providers/ to create a provider${NC}"
        echo ""
        ;;
    409)
        warn "Plugin already installed. Use --force to overwrite."
        python3 -c "import json,sys; print('  '+json.loads(sys.argv[1]).get('detail',''))" "${BODY}" 2>/dev/null
        exit 1
        ;;
    000)
        die "Connection lost during upload."
        ;;
    *)
        fail "Upload failed (HTTP ${HTTP_CODE})"
        echo "  ${BODY}"
        exit 1
        ;;
esac

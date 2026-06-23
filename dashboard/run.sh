#!/bin/bash
set -e

cd "$(dirname "$0")"
PROJECT_ROOT="$(cd .. && pwd)"
TOOLBOX_IMAGE="k8s-escape-toolbox"
TOOLBOX_CONTAINER="k8s-escape-toolbox"

# ─── Detect environment ─────────────────────────────────────────────────────
detect_env() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    DOCKER_AVAILABLE=false
    DOCKER_SOCK=""

    case "$OS" in
        Darwin)
            PLATFORM="macos"
            # Docker Desktop socket locations on macOS
            if [ -S "/var/run/docker.sock" ]; then
                DOCKER_SOCK="/var/run/docker.sock"
            elif [ -S "$HOME/.docker/run/docker.sock" ]; then
                DOCKER_SOCK="$HOME/.docker/run/docker.sock"
            elif [ -S "$HOME/.colima/default/docker.sock" ]; then
                DOCKER_SOCK="$HOME/.colima/default/docker.sock"
            fi
            ;;
        Linux)
            PLATFORM="linux"
            if [ -S "/var/run/docker.sock" ]; then
                DOCKER_SOCK="/var/run/docker.sock"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            PLATFORM="windows"
            # Docker Desktop on Windows (WSL2 or named pipe)
            if [ -S "/var/run/docker.sock" ]; then
                DOCKER_SOCK="/var/run/docker.sock"
            fi
            ;;
        *)
            PLATFORM="unknown"
            ;;
    esac

    # Check if docker CLI is available
    if command -v docker &> /dev/null && [ -n "$DOCKER_SOCK" ]; then
        if docker info &> /dev/null; then
            DOCKER_AVAILABLE=true
        fi
    fi

    echo "==> Environment detected:"
    echo "    OS:       $OS ($PLATFORM)"
    echo "    Arch:     $ARCH"
    echo "    Docker:   $DOCKER_AVAILABLE"
    [ -n "$DOCKER_SOCK" ] && echo "    Socket:   $DOCKER_SOCK"
    echo ""
}

detect_env

# ─── Python venv ─────────────────────────────────────────────────────────────
if [ ! -d ".venv" ]; then
    echo "==> Creating Python virtual environment..."
    python3 -m venv .venv
fi

# Activate venv
source .venv/bin/activate

echo "==> Installing dependencies..."
pip install -q -r requirements.txt

# ─── Toolbox container (background) ─────────────────────────────────────────
if [ "$DOCKER_AVAILABLE" = true ]; then
    echo "==> Building toolbox container (background)..."
    (
        cd "$PROJECT_ROOT"

        # Determine platform for docker build
        case "$ARCH" in
            x86_64|amd64)   BUILD_PLATFORM="linux/amd64" ;;
            arm64|aarch64)  BUILD_PLATFORM="linux/arm64" ;;
            *)              BUILD_PLATFORM="linux/amd64" ;;
        esac

        echo "  [toolbox] Building for $BUILD_PLATFORM..."

        # Rebuild when the image is missing OR Dockerfile.toolbox changed.
        # We stamp the image with a SHA-256 of Dockerfile.toolbox (as a label)
        # and compare it on each start. Content-based on purpose: git clone/pull
        # does not preserve file mtimes, so a date comparison would be unreliable.
        DF_HASH=$(shasum -a 256 Dockerfile.toolbox 2>/dev/null | awk '{print $1}')
        [ -z "$DF_HASH" ] && DF_HASH=$(sha256sum Dockerfile.toolbox 2>/dev/null | awk '{print $1}')

        NEED_BUILD=true
        if docker image inspect "$TOOLBOX_IMAGE" > /dev/null 2>&1; then
            IMG_HASH=$(docker image inspect "$TOOLBOX_IMAGE" \
                --format '{{ index .Config.Labels "toolbox_dockerfile_sha" }}' 2>/dev/null)
            if [ -n "$DF_HASH" ] && [ "$IMG_HASH" = "$DF_HASH" ]; then
                NEED_BUILD=false
                echo "  [toolbox] Image up to date (Dockerfile.toolbox unchanged), skipping build"
            else
                echo "  [toolbox] Dockerfile.toolbox changed since last build — rebuilding..."
            fi
        fi

        if [ "$NEED_BUILD" = true ]; then
            # Build with retry (Docker Hub can be temporarily unavailable)
            BUILD_OK=false
            for attempt in 1 2 3; do
                echo "  [toolbox] Build attempt $attempt/3..."
                if docker build \
                    --platform "$BUILD_PLATFORM" \
                    -f Dockerfile.toolbox \
                    --label "toolbox_dockerfile_sha=$DF_HASH" \
                    -t "$TOOLBOX_IMAGE" . 2>&1 | while read line; do
                    echo "  [toolbox] $line"
                done; then
                    BUILD_OK=true
                    break
                else
                    echo "  [toolbox] Build failed (attempt $attempt/3)"
                    if [ $attempt -lt 3 ]; then
                        echo "  [toolbox] Retrying in 10s... (Docker Hub may be temporarily unavailable)"
                        sleep 10
                    fi
                fi
            done

            if [ "$BUILD_OK" = false ]; then
                echo "  [toolbox] ERROR: Failed to build toolbox after 3 attempts"
                echo "  [toolbox] Possible causes:"
                echo "  [toolbox]   - Docker Hub temporarily unavailable (503)"
                echo "  [toolbox]   - Network/proxy/firewall blocking Docker Hub"
                echo "  [toolbox]   - VPN (GlobalProtect) inspection blocking downloads"
                echo "  [toolbox] The dashboard will run without the toolbox (tools must be installed locally)"
                exit 0
            fi
        fi

        # Stop existing container if running
        docker rm -f "$TOOLBOX_CONTAINER" 2>/dev/null || true

        # Build volume mounts
        VOLUMES="-v $PROJECT_ROOT:/project"
        [ -n "$DOCKER_SOCK" ] && VOLUMES="$VOLUMES -v $DOCKER_SOCK:/var/run/docker.sock"
        [ -d "$HOME/.aws" ] && VOLUMES="$VOLUMES -v $HOME/.aws:/root/.aws:ro"
        [ -d "$HOME/.kube" ] && VOLUMES="$VOLUMES -v $HOME/.kube:/root/.kube:ro"

        # Start the toolbox container
        docker run -d \
            --name "$TOOLBOX_CONTAINER" \
            --platform "$BUILD_PLATFORM" \
            --restart unless-stopped \
            $VOLUMES \
            "$TOOLBOX_IMAGE" \
            sleep infinity

        echo "  [toolbox] Container started: $TOOLBOX_CONTAINER"

        # ── Transparent CA trust (VPN / corporate SSL inspection) ────────────
        # Some networks (GlobalProtect, Zscaler, corporate proxies) intercept
        # TLS and present certificates signed by an internal CA. The host OS
        # already trusts that CA (browsers work), so we export the host's
        # trusted roots and add them to the toolbox trust store. This makes
        # downloads that do strict TLS verification (e.g. terraform fetching
        # providers from github.com) work behind inspection — on any laptop,
        # on or off VPN. With no extra CA present it is a harmless no-op.
        HOST_CA="$(mktemp 2>/dev/null || echo /tmp/host-ca.pem)"
        : > "$HOST_CA"
        case "$(uname -s)" in
            Darwin)
                # macOS — System keychain holds MDM/corporate-pushed CAs
                security find-certificate -a -p /Library/Keychains/System.keychain >> "$HOST_CA" 2>/dev/null
                security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain >> "$HOST_CA" 2>/dev/null
                ;;
            Linux)
                # Linux host / VM trust store (Debian/Ubuntu, then RHEL/Fedora)
                [ -f /etc/ssl/certs/ca-certificates.crt ] && cat /etc/ssl/certs/ca-certificates.crt >> "$HOST_CA" 2>/dev/null
                [ -f /etc/pki/tls/certs/ca-bundle.crt ]   && cat /etc/pki/tls/certs/ca-bundle.crt   >> "$HOST_CA" 2>/dev/null
                # WSL2 (Docker Desktop on Windows): the corporate/VPN CA usually
                # lives in the Windows store, not the WSL distro — import it too.
                if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null && command -v powershell.exe >/dev/null 2>&1; then
                    powershell.exe -NoProfile -Command \
                        "Get-ChildItem Cert:\LocalMachine\Root,Cert:\LocalMachine\CA | ForEach-Object { '-----BEGIN CERTIFICATE-----'; [Convert]::ToBase64String(\$_.RawData,'InsertLineBreaks'); '-----END CERTIFICATE-----' }" \
                        2>/dev/null | tr -d '\r' >> "$HOST_CA"
                fi
                ;;
        esac
        if [ -s "$HOST_CA" ]; then
            if docker cp "$HOST_CA" "$TOOLBOX_CONTAINER:/usr/local/share/ca-certificates/host-trusted.crt" >/dev/null 2>&1 \
               && docker exec "$TOOLBOX_CONTAINER" update-ca-certificates >/dev/null 2>&1; then
                echo "  [toolbox] Host CA trust synced (VPN / proxy friendly)"
            fi
        fi
        rm -f "$HOST_CA"

        # Verify tools
        echo "  [toolbox] Versions:"
        docker exec "$TOOLBOX_CONTAINER" bash -c '
            echo "    platform: $(uname -m)"
            echo "    terraform: $(terraform --version 2>/dev/null | head -1)"
            echo "    kubectl: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"
            echo "    aws: $(aws --version 2>/dev/null)"
            echo "    helm: $(helm version --short 2>/dev/null)"
            echo "    node: $(node --version 2>/dev/null)"
            echo "    docker: $(docker --version 2>/dev/null)"
            echo "    cortexcli: $(cortexcli --version 2>/dev/null || echo "downloaded at runtime from Cortex tenant")"
        ' 2>/dev/null || echo "  [toolbox] Warning: could not verify tools"

        echo "  [toolbox] Ready!"
    ) &
    TOOLBOX_PID=$!
    echo "    (toolbox building in background — PID $TOOLBOX_PID)"
else
    echo "==> Docker not available — running without toolbox container"
    echo "    Tools must be installed locally (terraform, kubectl, aws, cortexcli)"
fi

# ─── Start the dashboard ────────────────────────────────────────────────────
echo ""
echo "==> Starting dashboard on http://localhost:5555"
echo ""

python app.py

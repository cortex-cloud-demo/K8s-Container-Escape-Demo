import json
import os
import subprocess
import tempfile
import threading
import time
import uuid

import io
import ssl
import yaml
import zipfile
import urllib.request
import urllib.error
import urllib.parse

from flask import Flask, jsonify, render_template, request, send_file

app = Flask(__name__)

# Project root (parent of dashboard/)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TERRAFORM_DIR = os.path.join(PROJECT_ROOT, "terraform-infra")
TERRAFORM_LAMBDA_DIR = os.path.join(PROJECT_ROOT, "terraform-lambda")
TERRAFORM_GCP_DIR = os.path.join(PROJECT_ROOT, "terraform-gcp-infra")
TERRAFORM_RKE2_DIR = os.path.join(PROJECT_ROOT, "terraform-rke2")
K8S_DIR = os.path.join(PROJECT_ROOT, "k8s")
ATTACK_DIR = os.path.join(PROJECT_ROOT, "attack")
PLAYBOOK_DIR = os.path.join(PROJECT_ROOT, "playbook")
KUBECONFIG_PATH = os.path.join(PROJECT_ROOT, "dashboard", ".kubeconfig")
KUBECONFIG_BYOC_PATH = os.path.join(PROJECT_ROOT, "dashboard", ".kubeconfig-byoc")

# RKE2 mode defaults — must match terraform-rke2/variables.tf
RKE2_PROJECT_NAME = "k8s-escape-demo-rke2"
RKE2_DEFAULT_IMAGE = "chrisley75/k8s-escape-demo-vuln-app:1.0.0"
RKE2_INGRESS_PORT = 30080

# Toolbox container name
TOOLBOX_CONTAINER = "k8s-escape-toolbox"


def active_kubeconfig_path():
    """Return the kubeconfig path to use based on current mode (BYOC vs EKS)."""
    if external_cluster.get("enabled") and external_cluster.get("kubeconfig"):
        return KUBECONFIG_BYOC_PATH
    return KUBECONFIG_PATH


def active_kubeconfig_container_path():
    """Same as active_kubeconfig_path() but mapped to the toolbox container path."""
    if external_cluster.get("enabled") and external_cluster.get("kubeconfig"):
        return "/project/dashboard/.kubeconfig-byoc"
    return "/project/dashboard/.kubeconfig"


def is_toolbox_running():
    """Check if the toolbox container is running."""
    try:
        result = subprocess.run(
            f"docker inspect -f '{{{{.State.Running}}}}' {TOOLBOX_CONTAINER}",
            shell=True, capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip().strip("'") == "true"
    except Exception:
        return False


def toolbox_cmd(command, cwd=None):
    """Wrap a command to run inside the toolbox container.
    If the toolbox is running, the command is executed via docker exec.
    The project is mounted at /project in the container.
    """
    if is_toolbox_running():
        # Replace local project paths with container paths
        cmd = command.replace(PROJECT_ROOT, "/project")
        # Determine working directory inside container
        if cwd:
            container_cwd = cwd.replace(PROJECT_ROOT, "/project")
            cmd = f"cd {container_cwd} && {cmd}"
        # Pass AWS env vars into the container
        env_flags = ""
        for var in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION", "AWS_REGION"]:
            env_flags += f' -e {var}="${{{var}}}"'
        # Map KUBECONFIG path to container path (BYOC-aware)
        env_flags += f' -e KUBECONFIG={active_kubeconfig_container_path()}'
        # Write Cortex credentials to a file in the container via docker cp
        # (avoids shell escaping issues with special chars in API keys)
        if cortex_settings.get("base_url"):
            import tempfile
            env_content = (
                f'export CORTEX_API_URL="{cortex_settings["base_url"]}"\n'
                f'export CORTEX_API_KEY="{cortex_settings.get("api_key", "")}"\n'
                f'export CORTEX_API_KEY_ID="{cortex_settings.get("api_key_id", "")}"\n'
            )
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False)
            tmp.write(env_content)
            tmp.close()
            subprocess.run(
                f"docker cp {tmp.name} {TOOLBOX_CONTAINER}:/tmp/.cortex_env",
                shell=True, capture_output=True, timeout=5,
            )
            os.unlink(tmp.name)
            cmd = f"source /tmp/.cortex_env 2>/dev/null; {cmd}"
        # Inject GCP SA credentials into container
        if gcp_credentials.get("service_account_json"):
            gcp_tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            gcp_tmp.write(gcp_credentials["service_account_json"])
            gcp_tmp.close()
            subprocess.run(
                f"docker cp {gcp_tmp.name} {TOOLBOX_CONTAINER}:/tmp/.gcp_sa.json",
                shell=True, capture_output=True, timeout=5,
            )
            os.unlink(gcp_tmp.name)
            env_flags += ' -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/.gcp_sa.json'
        if gcp_credentials.get("project_id"):
            proj = gcp_credentials["project_id"].replace('"', '').replace("'", '')
            env_flags += f' -e GOOGLE_CLOUD_PROJECT="{proj}"'
            env_flags += f' -e GCLOUD_PROJECT="{proj}"'
        if gcp_credentials.get("region"):
            reg = gcp_credentials["region"].replace('"', '').replace("'", '')
            env_flags += f' -e CLOUDSDK_COMPUTE_REGION="{reg}"'
        # Escape single quotes in the command for bash -c '...'
        cmd_escaped = cmd.replace("'", "'\\''")
        return f"docker exec{env_flags} {TOOLBOX_CONTAINER} bash -c '{cmd_escaped}'"
    return command

# In-memory store for task outputs
tasks = {}

# Credentials file path (persisted locally, excluded from git)
CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), ".credentials.json")

# In-memory store for AWS credentials
aws_credentials = {
    "aws_access_key_id": "",
    "aws_secret_access_key": "",
    "aws_session_token": "",
    "aws_region": "eu-west-3",
}

# In-memory store for Cortex credentials
cortex_settings = {
    "base_url": "",
    "api_key_id": "",
    "api_key": "",
}

# In-memory store for external cluster (BYOC mode)
external_cluster = {
    "enabled": False,
    "kubeconfig": "",       # raw kubeconfig content or path
    "app_host": "",         # LoadBalancer hostname of the vuln-app
    "image_url": "",        # Container image URL (e.g. public ECR or Docker Hub)
}

# In-memory store for GCP credentials
gcp_credentials = {
    "project_id": "",
    "region": "europe-west1",
    "service_account_json": "",
}

# In-memory store for general app settings (persisted in .credentials.json)
app_settings = {
    "infra_mode": "eks",    # "eks" | "rke2" | "gcp" | "byoc"
}


def save_credentials():
    """Persist credentials to local file (excluded from git)."""
    data = {
        "aws": aws_credentials,
        "cortex": cortex_settings,
        "external_cluster": external_cluster,
        "gcp": gcp_credentials,
        "app_settings": app_settings,
    }
    try:
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Warning: cannot save credentials: {e}")


def load_credentials():
    """Load persisted credentials from local file."""
    if not os.path.isfile(CREDENTIALS_FILE):
        return
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            data = json.load(f)
        if "aws" in data:
            aws_credentials.update(data["aws"])
        if "cortex" in data:
            cortex_settings.update(data["cortex"])
        if "external_cluster" in data:
            external_cluster.update(data["external_cluster"])
        if "gcp" in data:
            gcp_credentials.update(data["gcp"])
        if "app_settings" in data:
            app_settings.update(data["app_settings"])
        print(f"Credentials loaded from {CREDENTIALS_FILE}")
    except Exception as e:
        print(f"Warning: cannot load credentials: {e}")


# Load on startup
load_credentials()


def get_aws_env():
    """Build AWS credential environment variables.

    Explicitly sets all AWS env vars to prevent fallback to ~/.aws/credentials
    or ~/.aws/config which can cause credential mixing between accounts.
    """
    env = {
        "KUBECONFIG": active_kubeconfig_path(),
        # Prevent AWS SDK from reading ~/.aws/credentials and ~/.aws/config
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
        "AWS_CONFIG_FILE": "/dev/null",
    }
    if aws_credentials["aws_access_key_id"]:
        env["AWS_ACCESS_KEY_ID"] = aws_credentials["aws_access_key_id"]
    if aws_credentials["aws_secret_access_key"]:
        env["AWS_SECRET_ACCESS_KEY"] = aws_credentials["aws_secret_access_key"]
    # Always set session token (empty string clears any inherited value)
    env["AWS_SESSION_TOKEN"] = aws_credentials.get("aws_session_token", "")
    if aws_credentials["aws_region"]:
        env["AWS_DEFAULT_REGION"] = aws_credentials["aws_region"]
        env["AWS_REGION"] = aws_credentials["aws_region"]
    return env


def get_gcp_env():
    """Build GCP credential environment variables from the stored service account JSON."""
    env = {}
    if gcp_credentials.get("service_account_json"):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tmp.write(gcp_credentials["service_account_json"])
        tmp.close()
        env["GOOGLE_APPLICATION_CREDENTIALS"] = tmp.name
    if gcp_credentials.get("project_id"):
        env["GOOGLE_CLOUD_PROJECT"] = gcp_credentials["project_id"]
        env["GCLOUD_PROJECT"] = gcp_credentials["project_id"]
    if gcp_credentials.get("region"):
        env["CLOUDSDK_COMPUTE_REGION"] = gcp_credentials["region"]
    return env


def tf_var_region():
    """Return -var='region=...' flag using the configured AWS region."""
    region = aws_credentials.get("aws_region") or "eu-west-3"
    return f'-var="region={region}"'


def tf_var_gcp():
    """Return terraform -var flags for GCP project_id and region."""
    parts = []
    if gcp_credentials.get("project_id"):
        parts.append(f'-var="project_id={gcp_credentials["project_id"]}"')
    region = gcp_credentials.get("region") or "europe-west1"
    parts.append(f'-var="region={region}"')
    return " ".join(parts)


def patch_kubeconfig_skip_tls(content):
    """Rewrite a kubeconfig so each cluster uses insecure-skip-tls-verify.

    Removes certificate-authority-data and sets insecure-skip-tls-verify: true.
    This avoids TLS validation failures when a TLS-intercepting VPN
    (GlobalProtect with `decrypt-untrust`) sits between the client and the
    RKE2 API server. The cluster control plane is exposed publicly for the
    demo and authenticated via client cert / bearer token in the same file,
    so skipping CA verification is acceptable here.
    """
    try:
        kc = yaml.safe_load(content)
    except Exception:
        return content
    if not isinstance(kc, dict) or not kc.get("clusters"):
        return content
    for entry in kc["clusters"]:
        cluster = entry.get("cluster") or {}
        cluster.pop("certificate-authority-data", None)
        cluster.pop("certificate-authority", None)
        cluster["insecure-skip-tls-verify"] = True
        entry["cluster"] = cluster
    return yaml.safe_dump(kc, default_flow_style=False)


def ensure_rke2_kubeconfig(force_refresh=False):
    """Ensure the RKE2 BYOC kubeconfig file exists, fetching from SSM if needed.

    Returns (ok, message, info) where info is {'cluster': ..., 'region': ...,
    'endpoint': ...} on success.
    """
    region = aws_credentials.get("aws_region") or "eu-west-3"
    info = {"cluster": "rke2-escape-demo", "region": region, "endpoint": ""}

    if (not force_refresh
            and os.path.isfile(KUBECONFIG_BYOC_PATH)
            and os.path.getsize(KUBECONFIG_BYOC_PATH) > 0):
        return True, "kubeconfig already present", info

    env = os.environ.copy()
    env.update(get_aws_env())
    param_name = f"/{RKE2_PROJECT_NAME}/kubeconfig"
    r = subprocess.run(
        toolbox_cmd(
            f"aws ssm get-parameter --region {region} --name {param_name} "
            f"--with-decryption --query Parameter.Value --output text"
        ),
        shell=True, capture_output=True, text=True, env=env, timeout=30,
    )
    if r.returncode != 0:
        msg = r.stderr.strip() or "unknown error"
        return False, (
            f"Failed to fetch RKE2 kubeconfig from SSM ({param_name}): {msg}. "
            f"Check that the RKE2 apply has finished and cloud-init pushed the "
            f"kubeconfig (~3-5 min after apply)."
        ), info
    kc = r.stdout.strip()
    if not kc or kc.startswith("file://"):
        return False, (
            "SSM returned empty kubeconfig. Wait for cloud-init to finish "
            "(~3-5 min after RKE2 apply) and try again."
        ), info

    kc = patch_kubeconfig_skip_tls(kc)
    with open(KUBECONFIG_BYOC_PATH, "w") as f:
        f.write(kc)
    os.chmod(KUBECONFIG_BYOC_PATH, 0o600)

    external_cluster["enabled"] = True
    external_cluster["kubeconfig"] = kc
    if not external_cluster.get("app_host"):
        public_ip = tf_output(TERRAFORM_RKE2_DIR, "public_ip", env)
        if public_ip:
            external_cluster["app_host"] = f"{public_ip}:{RKE2_INGRESS_PORT}"
    if not external_cluster.get("image_url"):
        external_cluster["image_url"] = RKE2_DEFAULT_IMAGE
    save_credentials()
    return True, "kubeconfig fetched from SSM", info


def generate_kubeconfig(cluster_name, region):
    """Generate a kubeconfig with AWS credentials embedded in the exec env section."""
    env = os.environ.copy()
    env.update(get_aws_env())

    # Get cluster details
    result = subprocess.run(
        toolbox_cmd(f"aws eks describe-cluster --name {cluster_name} --region {region} --output json"),
        shell=True,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to describe cluster: {result.stderr}")

    cluster_info = json.loads(result.stdout)["cluster"]
    endpoint = cluster_info["endpoint"]
    ca_data = cluster_info["certificateAuthority"]["data"]

    # Build exec env entries with current AWS credentials
    exec_env = []
    if aws_credentials["aws_access_key_id"]:
        exec_env.append({"name": "AWS_ACCESS_KEY_ID", "value": aws_credentials["aws_access_key_id"]})
    if aws_credentials["aws_secret_access_key"]:
        exec_env.append({"name": "AWS_SECRET_ACCESS_KEY", "value": aws_credentials["aws_secret_access_key"]})
    if aws_credentials["aws_session_token"]:
        exec_env.append({"name": "AWS_SESSION_TOKEN", "value": aws_credentials["aws_session_token"]})

    import yaml
    kubeconfig = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "name": cluster_name,
            "cluster": {
                "server": endpoint,
                "certificate-authority-data": ca_data,
            },
        }],
        "contexts": [{
            "name": cluster_name,
            "context": {
                "cluster": cluster_name,
                "user": cluster_name,
            },
        }],
        "current-context": cluster_name,
        "users": [{
            "name": cluster_name,
            "user": {
                "exec": {
                    "apiVersion": "client.authentication.k8s.io/v1beta1",
                    "command": "aws",
                    "args": [
                        "eks", "get-token",
                        "--cluster-name", cluster_name,
                        "--region", region,
                    ],
                    "env": exec_env if exec_env else None,
                    "interactiveMode": "Never",
                },
            },
        }],
    }

    with open(KUBECONFIG_PATH, "w") as f:
        yaml.dump(kubeconfig, f, default_flow_style=False)

    return KUBECONFIG_PATH


def run_command(task_id, command, cwd=None, env_extra=None, use_toolbox=False):
    """Run a shell command asynchronously and store streaming output.
    If use_toolbox=True and the toolbox container is running, the command
    is executed inside the container via docker exec.
    """
    tasks[task_id]["status"] = "running"
    tasks[task_id]["start_time"] = time.time()

    env = os.environ.copy()
    # Inject AWS credentials
    env.update(get_aws_env())
    if env_extra:
        env.update(env_extra)

    # Wrap with toolbox if requested and available
    actual_command = command
    if use_toolbox and is_toolbox_running():
        actual_command = toolbox_cmd(command, cwd=cwd)
        tasks[task_id]["output"] += "[toolbox] Running inside container\n"

    try:
        proc = subprocess.Popen(
            actual_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd or PROJECT_ROOT,
            env=env,
            text=True,
        )
        tasks[task_id]["pid"] = proc.pid

        for line in proc.stdout:
            tasks[task_id]["output"] += line

        proc.wait()
        tasks[task_id]["exit_code"] = proc.returncode
        tasks[task_id]["status"] = "success" if proc.returncode == 0 else "error"
    except Exception as e:
        tasks[task_id]["output"] += f"\nERROR: {e}\n"
        tasks[task_id]["status"] = "error"
        tasks[task_id]["exit_code"] = -1

    tasks[task_id]["end_time"] = time.time()


def create_task(name, command, cwd=None, env_extra=None, use_toolbox=False):
    """Create and start a background task."""
    task_id = str(uuid.uuid4())[:8]
    tasks[task_id] = {
        "id": task_id,
        "name": name,
        "command": command,
        "status": "starting",
        "output": "",
        "exit_code": None,
        "start_time": None,
        "end_time": None,
        "pid": None,
    }
    t = threading.Thread(
        target=run_command, args=(task_id, command, cwd, env_extra, use_toolbox), daemon=True
    )
    t.start()
    return task_id


# ─── Routes ───────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/toolbox/status", methods=["GET"])
def toolbox_status():
    """Check if the toolbox container is running and return tool versions."""
    running = is_toolbox_running()
    if not running:
        return jsonify({"status": "stopped", "running": False})

    try:
        result = subprocess.run(
            f"docker exec {TOOLBOX_CONTAINER} bash -c '"
            "echo terraform=$(terraform --version 2>/dev/null | head -1); "
            "echo kubectl=$(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1); "
            "echo aws=$(aws --version 2>/dev/null); "
            "echo helm=$(helm version --short 2>/dev/null); "
            "echo node=$(node --version 2>/dev/null); "
            "echo docker=$(docker --version 2>/dev/null); "
            "echo cortexcli=$(cortexcli --version 2>/dev/null || echo not installed); "
            "echo platform=$(uname -m); "
            "echo os=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d \\\")'",
            shell=True, capture_output=True, text=True, timeout=10,
        )
        versions = {}
        for line in result.stdout.strip().split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                versions[k.strip()] = v.strip()
        return jsonify({"status": "running", "running": True, "versions": versions})
    except Exception as e:
        return jsonify({"status": "error", "running": running, "message": str(e)})


# ─── AWS Credentials ────────────────────────────────────────────────────────


@app.route("/api/credentials", methods=["GET"])
def get_credentials():
    """Return current AWS credentials (masked secret key)."""
    masked = dict(aws_credentials)
    if masked["aws_secret_access_key"]:
        masked["aws_secret_access_key"] = "****" + masked["aws_secret_access_key"][-4:]
    if masked["aws_session_token"]:
        masked["aws_session_token"] = "****" + masked["aws_session_token"][-4:]
    return jsonify(masked)


@app.route("/api/credentials", methods=["POST"])
def set_credentials():
    """Set AWS credentials."""
    data = request.json
    if "aws_access_key_id" in data:
        aws_credentials["aws_access_key_id"] = data["aws_access_key_id"].strip()
    if "aws_secret_access_key" in data:
        aws_credentials["aws_secret_access_key"] = data["aws_secret_access_key"].strip()
    if "aws_session_token" in data:
        aws_credentials["aws_session_token"] = data["aws_session_token"].strip()
    if "aws_region" in data:
        aws_credentials["aws_region"] = data["aws_region"].strip()
    save_credentials()
    return jsonify({"status": "ok"})


@app.route("/api/credentials/test", methods=["POST"])
def test_credentials():
    """Test AWS credentials by calling sts get-caller-identity."""
    env = os.environ.copy()
    env.update(get_aws_env())
    try:
        result = subprocess.run(
            toolbox_cmd("aws sts get-caller-identity --output json"),
            shell=True,
            capture_output=True,
            text=True,
            env=env,
        )
        if result.returncode == 0:
            return jsonify({"status": "ok", "identity": json.loads(result.stdout)})
        return jsonify({"status": "error", "message": result.stderr.strip()}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─── GCP Credentials ────────────────────────────────────────────────────────


@app.route("/api/credentials/gcp", methods=["GET"])
def get_gcp_credentials():
    """Return current GCP credentials (masked service account JSON)."""
    masked = dict(gcp_credentials)
    if masked["service_account_json"]:
        masked["service_account_json"] = "****configured****"
    return jsonify(masked)


@app.route("/api/credentials/gcp", methods=["POST"])
def set_gcp_credentials():
    """Set GCP credentials from service account JSON."""
    data = request.json
    if "project_id" in data:
        gcp_credentials["project_id"] = data["project_id"].strip()
    if "region" in data:
        gcp_credentials["region"] = data["region"].strip()
    if "service_account_json" in data:
        gcp_credentials["service_account_json"] = data["service_account_json"].strip()
    save_credentials()
    return jsonify({"status": "ok"})


@app.route("/api/credentials/gcp/test", methods=["POST"])
def test_gcp_credentials():
    """Test GCP credentials by calling the Resource Manager API."""
    if not gcp_credentials.get("service_account_json"):
        return jsonify({"status": "error", "message": "No GCP service account JSON configured"}), 400

    try:
        sa_data = json.loads(gcp_credentials["service_account_json"])
    except json.JSONDecodeError:
        return jsonify({"status": "error", "message": "Invalid JSON — cannot parse service account file"}), 400

    required_fields = ["type", "project_id", "private_key", "client_email"]
    missing = [f for f in required_fields if f not in sa_data]
    if missing:
        return jsonify({"status": "error", "message": f"Invalid service account JSON — missing: {missing}"}), 400

    project_id = gcp_credentials.get("project_id") or sa_data.get("project_id", "")
    client_email = sa_data.get("client_email", "")

    try:
        from google.oauth2 import service_account
        import google.auth.transport.requests as ga_requests

        creds = service_account.Credentials.from_service_account_info(
            sa_data, scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        creds.refresh(ga_requests.Request())

        url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {creds.token}"})
        ssl_ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as resp:
            project_data = json.loads(resp.read().decode())

        return jsonify({
            "status": "ok",
            "project_id": project_data.get("projectId"),
            "project_name": project_data.get("name"),
            "project_number": project_data.get("projectNumber"),
            "client_email": client_email,
        })

    except ImportError:
        return jsonify({
            "status": "ok",
            "message": "Service account JSON is valid. Install google-auth for full API connectivity test.",
            "project_id": project_id,
            "client_email": client_email,
        })
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        return jsonify({"status": "error", "message": f"GCP API error {e.code}: {body}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─── External Cluster (BYOC) ───────────────────────────────────────────────


@app.route("/api/external-cluster", methods=["GET"])
def get_external_cluster():
    """Return current external cluster config."""
    return jsonify(external_cluster)


@app.route("/api/external-cluster", methods=["POST"])
def set_external_cluster():
    """Configure an external cluster (BYOC mode)."""
    data = request.json
    external_cluster["enabled"] = data.get("enabled", False)
    external_cluster["app_host"] = data.get("app_host", "").strip()
    external_cluster["image_url"] = data.get("image_url", "").strip()

    kubeconfig_content = data.get("kubeconfig", "").strip()
    if kubeconfig_content:
        external_cluster["kubeconfig"] = kubeconfig_content
        # Write kubeconfig to file
        byoc_kubeconfig = os.path.join(PROJECT_ROOT, "dashboard", ".kubeconfig-byoc")
        with open(byoc_kubeconfig, "w") as f:
            f.write(kubeconfig_content)
        os.environ["KUBECONFIG"] = byoc_kubeconfig

    save_credentials()
    return jsonify({"status": "ok", "external_cluster": external_cluster})


@app.route("/api/external-cluster/test", methods=["POST"])
def test_external_cluster():
    """Test connectivity to the external cluster."""
    if not external_cluster.get("enabled"):
        return jsonify({"status": "error", "message": "External cluster not configured"}), 400

    try:
        env = os.environ.copy()
        if external_cluster.get("kubeconfig"):
            byoc_kubeconfig = os.path.join(PROJECT_ROOT, "dashboard", ".kubeconfig-byoc")
            env["KUBECONFIG"] = byoc_kubeconfig

        result = subprocess.run(
            toolbox_cmd("kubectl cluster-info 2>&1 && echo '---' && kubectl get nodes -o wide 2>&1"),
            shell=True, capture_output=True, text=True, env=env, timeout=15,
        )
        return jsonify({"status": "ok", "output": result.stdout + result.stderr})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─── App Settings (infra mode) ──────────────────────────────────────────────


VALID_INFRA_MODES = {"eks", "rke2", "gcp", "byoc"}


@app.route("/api/app-settings", methods=["GET"])
def get_app_settings():
    return jsonify(app_settings)


@app.route("/api/app-settings", methods=["POST"])
def set_app_settings():
    data = request.json or {}
    mode = (data.get("infra_mode") or "").strip().lower()
    if mode and mode not in VALID_INFRA_MODES:
        return jsonify({"status": "error", "message": f"infra_mode must be one of {sorted(VALID_INFRA_MODES)}"}), 400
    if mode:
        app_settings["infra_mode"] = mode
        # Switching to a cloud mode (EKS/GCP) disables any active BYOC mapping so
        # kubeconfig resolution goes back to the cloud kubeconfig. RKE2 mode keeps
        # BYOC enabled because the cluster is provisioned by Terraform and auto-wired.
        if mode in ("eks", "gcp"):
            external_cluster["enabled"] = False
    save_credentials()
    return jsonify({"status": "ok", "app_settings": app_settings})


# ─── Kubeconfig ─────────────────────────────────────────────────────────────


@app.route("/api/kubeconfig/generate", methods=["POST"])
def api_generate_kubeconfig():
    """Connect to the cluster. EKS: generate kubeconfig with embedded AWS creds.
    RKE2/BYOC: ensure the BYOC kubeconfig file is present (fetch from SSM for RKE2)."""
    try:
        mode = (app_settings.get("infra_mode") or "eks").lower()

        if mode == "rke2":
            # Always re-fetch from SSM so we pick up the latest server IP after
            # an EC2 re-deploy. Cheap (one AWS call) and avoids the "stale
            # kubeconfig with old IP" trap.
            ok, msg, info = ensure_rke2_kubeconfig(force_refresh=True)
            if not ok:
                return jsonify({"status": "error", "message": msg}), 500
            return jsonify({
                "status": "ok",
                "path": KUBECONFIG_BYOC_PATH,
                "cluster": info.get("cluster") or "rke2-escape-demo",
                "region": info.get("region") or aws_credentials.get("aws_region") or "eu-west-3",
                "mode": "rke2",
            })

        if mode == "byoc":
            if not external_cluster.get("enabled") or not os.path.isfile(KUBECONFIG_BYOC_PATH):
                return jsonify({
                    "status": "error",
                    "message": "BYOC kubeconfig not configured. Use the BYOC settings card to upload one.",
                }), 400
            return jsonify({
                "status": "ok",
                "path": KUBECONFIG_BYOC_PATH,
                "cluster": "byoc-cluster",
                "region": aws_credentials.get("aws_region") or "",
                "mode": "byoc",
            })

        # EKS (default)
        env = os.environ.copy()
        env.update(get_aws_env())
        region = tf_output(TERRAFORM_DIR, "region", env) or aws_credentials["aws_region"] or "eu-west-3"
        cluster = tf_output(TERRAFORM_DIR, "cluster_name", env) or "eks-escape-demo"
        path = generate_kubeconfig(cluster, region)
        return jsonify({
            "status": "ok", "path": path, "cluster": cluster,
            "region": region, "mode": "eks",
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/kubeconfig/status", methods=["GET"])
def api_kubeconfig_status():
    """Check kubeconfig existence and test cluster connectivity.

    Mode-aware: in EKS mode we read .kubeconfig and run `aws eks get-token`;
    in RKE2/BYOC mode we read .kubeconfig-byoc and skip the AWS auth step.
    """
    debug_log = []
    mode = (app_settings.get("infra_mode") or "eks").lower()
    is_external = mode in ("rke2", "byoc")
    kubeconfig_file = KUBECONFIG_BYOC_PATH if is_external else KUBECONFIG_PATH

    result = {
        "kubeconfig_exists": os.path.exists(kubeconfig_file),
        "cluster_name": None,
        "region": None,
        "endpoint": None,
        "connected": False,
        "server_version": None,
        "nodes": None,
        "error": None,
        "mode": mode,
        "debug": debug_log,
    }

    debug_log.append(f"Infra mode: {mode}")
    debug_log.append(f"KUBECONFIG path: {kubeconfig_file}")
    debug_log.append(f"KUBECONFIG exists: {result['kubeconfig_exists']}")

    if not result["kubeconfig_exists"]:
        if is_external:
            debug_log.append(
                "No BYOC kubeconfig found. For RKE2: click 'Connect' to fetch it "
                "from SSM (requires cloud-init to be done, ~3-5 min after apply)."
            )
        else:
            debug_log.append("No kubeconfig file found. Click 'Connect' to generate one.")
        return jsonify(result)

    # Read cluster name from kubeconfig
    try:
        with open(kubeconfig_file) as f:
            kc = yaml.safe_load(f)
        if kc and kc.get("clusters"):
            result["cluster_name"] = kc["clusters"][0]["name"]
            result["endpoint"] = kc["clusters"][0]["cluster"].get("server", "")
            debug_log.append(f"Cluster: {result['cluster_name']}")
            debug_log.append(f"Endpoint: {result['endpoint']}")
        if kc and kc.get("users") and not is_external:
            user_exec = kc["users"][0].get("user", {}).get("exec", {})
            args = user_exec.get("args", [])
            for i, a in enumerate(args):
                if a == "--region" and i + 1 < len(args):
                    result["region"] = args[i + 1]
            exec_env = user_exec.get("env") or []
            has_key = any(e.get("name") == "AWS_ACCESS_KEY_ID" for e in exec_env)
            has_token = any(e.get("name") == "AWS_SESSION_TOKEN" for e in exec_env)
            debug_log.append(f"Exec command: {user_exec.get('command')}")
            debug_log.append(f"Exec args: {' '.join(args)}")
            debug_log.append(f"AWS_ACCESS_KEY_ID in exec env: {has_key}")
            debug_log.append(f"AWS_SESSION_TOKEN in exec env: {has_token}")
    except Exception as e:
        debug_log.append(f"Error reading kubeconfig: {e}")

    # Build env: for EKS we need AWS creds for the exec plugin; for BYOC/RKE2
    # we only need KUBECONFIG to point at the right file.
    env = os.environ.copy()
    if is_external:
        env["KUBECONFIG"] = kubeconfig_file
    else:
        env.update(get_aws_env())
        debug_log.append(f"AWS_ACCESS_KEY_ID set in env: {bool(env.get('AWS_ACCESS_KEY_ID'))}")
        debug_log.append(f"AWS_SESSION_TOKEN set in env: {bool(env.get('AWS_SESSION_TOKEN'))}")
        debug_log.append(f"AWS_REGION: {env.get('AWS_REGION', 'not set')}")

    # Step 1 (EKS only): test aws eks get-token
    if not is_external:
        try:
            cluster_name = result["cluster_name"] or "eks-escape-demo"
            region = result["region"] or env.get("AWS_REGION", "eu-west-3")
            token_r = subprocess.run(
                toolbox_cmd(f"aws eks get-token --cluster-name {cluster_name} --region {region} --output json"),
                shell=True, capture_output=True, text=True, env=env, timeout=15,
            )
            if token_r.returncode == 0:
                debug_log.append("aws eks get-token: OK")
            else:
                debug_log.append(f"aws eks get-token: FAILED (exit {token_r.returncode})")
                debug_log.append(f"stderr: {token_r.stderr.strip()}")
                result["error"] = f"aws eks get-token failed: {token_r.stderr.strip()}"
                return jsonify(result)
        except subprocess.TimeoutExpired:
            debug_log.append("aws eks get-token: TIMEOUT (15s)")
            result["error"] = "aws eks get-token timed out"
            return jsonify(result)
        except Exception as e:
            debug_log.append(f"aws eks get-token: EXCEPTION {e}")

    # Step 2: kubectl version
    try:
        debug_log.append("Running: kubectl version --output=json")
        version_r = subprocess.run(
            toolbox_cmd("kubectl version --output=json"),
            shell=True, capture_output=True, text=True, env=env, timeout=15,
        )
        debug_log.append(f"kubectl version exit code: {version_r.returncode}")
        if version_r.returncode == 0:
            result["connected"] = True
            vinfo = json.loads(version_r.stdout)
            sv = vinfo.get("serverVersion", {})
            result["server_version"] = f"{sv.get('major', '?')}.{sv.get('minor', '?')}"
            debug_log.append(f"Server version: {result['server_version']}")
        else:
            stderr = version_r.stderr.strip()
            # kubectl version may return exit 1 but still have serverVersion in output
            try:
                vinfo = json.loads(version_r.stdout)
                sv = vinfo.get("serverVersion")
                if sv:
                    result["connected"] = True
                    result["server_version"] = f"{sv.get('major', '?')}.{sv.get('minor', '?')}"
                    debug_log.append(f"Server version (from partial output): {result['server_version']}")
            except Exception:
                pass
            if not result["connected"]:
                result["error"] = stderr or "kubectl version failed"
                debug_log.append(f"kubectl version stderr: {stderr}")
                debug_log.append(f"kubectl version stdout: {version_r.stdout.strip()[:500]}")
    except subprocess.TimeoutExpired:
        result["error"] = "kubectl version timed out (15s)"
        debug_log.append("kubectl version: TIMEOUT")
    except Exception as e:
        result["error"] = str(e)
        debug_log.append(f"kubectl version exception: {e}")

    # Step 3: get nodes (only if connected)
    if result["connected"]:
        try:
            nodes_r = subprocess.run(
                toolbox_cmd("kubectl get nodes --no-headers -o custom-columns='NAME:.metadata.name,STATUS:.status.conditions[-1].type,VERSION:.status.nodeInfo.kubeletVersion'"),
                shell=True, capture_output=True, text=True, env=env, timeout=10,
            )
            if nodes_r.returncode == 0:
                result["nodes"] = nodes_r.stdout.strip()
                debug_log.append(f"Nodes: {result['nodes']}")
            else:
                debug_log.append(f"kubectl get nodes failed: {nodes_r.stderr.strip()}")
        except Exception as e:
            debug_log.append(f"kubectl get nodes exception: {e}")

    return jsonify(result)


@app.route("/api/kubeconfig/download", methods=["GET"])
def api_kubeconfig_download():
    """Download the active kubeconfig file (EKS .kubeconfig or BYOC/RKE2 .kubeconfig-byoc)."""
    mode = (app_settings.get("infra_mode") or "eks").lower()
    is_external = mode in ("rke2", "byoc")
    path = KUBECONFIG_BYOC_PATH if is_external else KUBECONFIG_PATH
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return jsonify({
            "status": "error",
            "message": f"No kubeconfig available for mode '{mode}'. Click Connect first.",
        }), 404
    download_name = f"kubeconfig-{mode}.yaml"
    return send_file(
        path,
        mimetype="application/yaml",
        as_attachment=True,
        download_name=download_name,
    )


# ─── Terraform Helpers ───────────────────────────────────────────────────────


def tf_init_cmd():
    """Simple terraform init command (local backend)."""
    return "terraform init -input=false"


def tf_output(tf_dir, output_name, env=None):
    """Run terraform output for a given module.

    Runs inside the toolbox container if available, so the providers cache
    in `.terraform/providers/` (Linux binaries) matches the runtime arch.
    Falls back to local execution otherwise.

    Returns the output value as string, or empty string on failure.
    """
    if env is None:
        env = os.environ.copy()
        env.update(get_aws_env())
    raw_cmd = f'terraform output -raw {output_name}'
    if is_toolbox_running():
        wrapped = toolbox_cmd(raw_cmd, cwd=tf_dir)
        result = subprocess.run(
            wrapped, shell=True, capture_output=True, text=True, env=env, timeout=30,
        )
    else:
        result = subprocess.run(
            raw_cmd, shell=True, capture_output=True, text=True, cwd=tf_dir, env=env, timeout=30,
        )
    return result.stdout.strip() if result.returncode == 0 else ""


# ─── Infrastructure ──────────────────────────────────────────────────────────


@app.route("/api/infra/plan", methods=["POST"])
def infra_plan():
    lambda_dir = TERRAFORM_LAMBDA_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    infra_dir = TERRAFORM_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    cmd = f"""set -e
echo "=================================================="
echo "  PHASE 1: Infrastructure Plan"
echo "=================================================="
cd {infra_dir}
{tf_init_cmd()}
terraform plan -no-color {tf_var_region()}

echo ""
echo "=================================================="
echo "  PHASE 2: Lambda Plan"
echo "=================================================="
cd ../{lambda_dir}
{tf_init_cmd()}
terraform plan -no-color {tf_var_region()}
"""
    task_id = create_task(
        "Terraform Plan",
        cmd,
        use_toolbox=True,
    )
    return jsonify({"task_id": task_id})


@app.route("/api/infra/apply", methods=["POST"])
def infra_apply():
    # Deploy infra + lambda in one shot
    lambda_dir = TERRAFORM_LAMBDA_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    infra_dir = TERRAFORM_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    cmd = f"""set -e
echo "=================================================="
echo "  PHASE 1: Infrastructure (EKS + VPC + IAM)"
echo "=================================================="
cd {infra_dir}
{tf_init_cmd()}
terraform apply -auto-approve -no-color {tf_var_region()}

echo ""
echo "=================================================="
echo "  PHASE 1b: Upload sensitive data to S3 bucket"
echo "=================================================="
BUCKET=$(terraform output -raw vuln_data_bucket_name 2>/dev/null || echo '')
if [ -n "$BUCKET" ]; then
  echo "Uploading to s3://$BUCKET"
  cd {PROJECT_ROOT}
  aws s3 cp s3-data/credentials.txt     "s3://$BUCKET/credentials.txt"
  aws s3 cp s3-data/customers.csv       "s3://$BUCKET/customers.csv"
  aws s3 cp s3-data/internal-report.pdf "s3://$BUCKET/internal-report.pdf"
  echo "Files uploaded. Public URL: https://$BUCKET.s3.amazonaws.com"
  cd {infra_dir}
else
  echo "WARNING: Could not determine bucket name, skipping file upload"
fi

echo ""
echo "=================================================="
echo "  PHASE 2: Lambda Containment"
echo "=================================================="
cd ../{lambda_dir}
{tf_init_cmd()}
terraform apply -auto-approve -no-color {tf_var_region()}

echo ""
echo "=================================================="
echo "  [OK] Infrastructure + Lambda deployed successfully"
echo "=================================================="
"""
    task_id = create_task(
        "Terraform Apply",
        cmd,
        use_toolbox=True,
    )
    return jsonify({"task_id": task_id})


@app.route("/api/infra/destroy", methods=["POST"])
def infra_destroy():
    region = aws_credentials.get("aws_region") or "eu-west-3"
    cmd = f"""set -e

echo '=================================================='
echo '  CLEANUP K8S RESOURCES'
echo '=================================================='
kubectl delete svc vuln-app-service -n vuln-app --ignore-not-found=true 2>/dev/null || true
kubectl delete namespace vuln-app --ignore-not-found=true --wait=false 2>/dev/null || true
kubectl delete clusterrolebinding vuln-app-cluster-admin --ignore-not-found=true 2>/dev/null || true

VPC_ID=$(terraform output -raw vpc_id 2>/dev/null || echo '')
if [ -n "$VPC_ID" ]; then
  echo ''
  echo '=================================================='
  echo "  CLEANUP AWS RESOURCES IN VPC $VPC_ID"
  echo '=================================================='

  # Delete Classic ELBs in the VPC
  echo '==> Checking Classic Load Balancers...'
  ELBS=$(aws elb describe-load-balancers --region {region} \
    --query "LoadBalancerDescriptions[?VPCId==\\`$VPC_ID\\`].LoadBalancerName" --output text 2>/dev/null || echo '')
  for ELB in $ELBS; do
    echo "    Deleting Classic ELB: $ELB"
    aws elb delete-load-balancer --load-balancer-name "$ELB" --region {region} 2>/dev/null || true
  done

  # Delete ALB/NLBs in the VPC
  echo '==> Checking ALB/NLB Load Balancers...'
  LB_ARNS=$(aws elbv2 describe-load-balancers --region {region} \
    --query "LoadBalancers[?VpcId==\\`$VPC_ID\\`].LoadBalancerArn" --output text 2>/dev/null || echo '')
  for LB_ARN in $LB_ARNS; do
    echo "    Deleting ALB/NLB: $LB_ARN"
    aws elbv2 delete-load-balancer --load-balancer-arn "$LB_ARN" --region {region} 2>/dev/null || true
  done

  # Release Elastic IPs associated with the VPC
  echo '==> Checking Elastic IPs...'
  EIPS=$(aws ec2 describe-addresses --region {region} \
    --filters Name=domain,Values=vpc \
    --query "Addresses[?NetworkInterfaceId!=null].AllocationId" --output text 2>/dev/null || echo '')
  for EIP in $EIPS; do
    echo "    Releasing EIP: $EIP"
    aws ec2 release-address --allocation-id "$EIP" --region {region} 2>/dev/null || true
  done

  # Detach and delete orphaned ENIs (non-primary, non-Lambda)
  echo '==> Checking orphaned ENIs...'
  ENI_IDS=$(aws ec2 describe-network-interfaces --region {region} \
    --filters Name=vpc-id,Values=$VPC_ID \
    --query "NetworkInterfaces[?Attachment.DeviceIndex!=\\`0\\` || Attachment.InstanceId==null].NetworkInterfaceId" \
    --output text 2>/dev/null || echo '')
  for ENI in $ENI_IDS; do
    ATTACH_ID=$(aws ec2 describe-network-interfaces --region {region} \
      --network-interface-ids "$ENI" \
      --query 'NetworkInterfaces[0].Attachment.AttachmentId' --output text 2>/dev/null || echo 'None')
    if [ "$ATTACH_ID" != "None" ] && [ -n "$ATTACH_ID" ]; then
      echo "    Detaching ENI: $ENI (attachment: $ATTACH_ID)"
      aws ec2 detach-network-interface --attachment-id "$ATTACH_ID" --force --region {region} 2>/dev/null || true
      sleep 5
    fi
    echo "    Deleting ENI: $ENI"
    aws ec2 delete-network-interface --network-interface-id "$ENI" --region {region} 2>/dev/null || true
  done

  # Wait for all ENIs to clear
  echo '==> Waiting for ENI cleanup...'
  for i in $(seq 1 30); do
    ENI_COUNT=$(aws ec2 describe-network-interfaces --region {region} \
      --filters Name=vpc-id,Values=$VPC_ID Name=status,Values=in-use \
      --query 'length(NetworkInterfaces)' --output text 2>/dev/null || echo '0')
    if [ "$ENI_COUNT" = "0" ] || [ "$ENI_COUNT" = "None" ]; then
      echo '==> VPC clean, no active ENIs remaining.'
      break
    fi
    echo "    Waiting... $ENI_COUNT ENI(s) still in use (attempt $i/30)"
    sleep 10
  done
fi

echo ''
echo '=================================================='
echo '  PHASE 1: DESTROY LAMBDA'
echo '=================================================='
cd {TERRAFORM_LAMBDA_DIR}
{tf_init_cmd()} && terraform destroy -auto-approve -no-color {tf_var_region()} || echo 'Lambda destroy skipped (not deployed?)'

echo ''
echo '=================================================='
echo '  PHASE 2: DESTROY INFRASTRUCTURE'
echo '=================================================='
cd {TERRAFORM_DIR}
{tf_init_cmd()} && terraform destroy -auto-approve -no-color {tf_var_region()}

echo ''
echo '=================================================='
echo '  [OK] All infrastructure destroyed'
echo '=================================================='
"""
    task_id = create_task("Terraform Destroy", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


# ─── GCP Infrastructure ───────────────────────────────────────────────────────


@app.route("/api/gcp-infra/plan", methods=["POST"])
def gcp_infra_plan():
    gcp_dir = TERRAFORM_GCP_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    cmd = f"""set -e
echo "=================================================="
echo "  GCP Infrastructure Plan"
echo "=================================================="
cd {gcp_dir}
{tf_init_cmd()}
terraform plan -no-color {tf_var_gcp()}
"""
    task_id = create_task("GCP Terraform Plan", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/gcp-infra/apply", methods=["POST"])
def gcp_infra_apply():
    gcp_dir = TERRAFORM_GCP_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    cmd = f"""set -e
echo "=================================================="
echo "  GCP Infrastructure Apply (GKE + Artifact Registry + GCS + VPC)"
echo "=================================================="
cd {gcp_dir}
{tf_init_cmd()}
terraform apply -auto-approve -no-color {tf_var_gcp()}

echo ""
echo "=================================================="
echo "  Upload sensitive data to GCS bucket"
echo "=================================================="
BUCKET=$(terraform output -raw vuln_data_bucket_name 2>/dev/null || echo '')
if [ -n "$BUCKET" ]; then
  echo "Bucket: gs://$BUCKET"
  if command -v gsutil &>/dev/null; then
    gsutil cp /project/s3-data/credentials.txt     "gs://$BUCKET/credentials.txt"
    gsutil cp /project/s3-data/customers.csv       "gs://$BUCKET/customers.csv"
    gsutil cp /project/s3-data/internal-report.pdf "gs://$BUCKET/internal-report.pdf"
    echo "Files uploaded. Public URL: https://storage.googleapis.com/$BUCKET"
  else
    echo "Note: gsutil not available in toolbox — bucket created but data upload skipped"
    echo "Public bucket URL: https://storage.googleapis.com/$BUCKET"
  fi
else
  echo "WARNING: Could not determine bucket name, skipping file upload"
fi

echo ""
echo "=================================================="
echo "  [OK] GCP Infrastructure deployed successfully"
echo "=================================================="
"""
    task_id = create_task("GCP Terraform Apply", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/gcp-infra/destroy", methods=["POST"])
def gcp_infra_destroy():
    gcp_dir = TERRAFORM_GCP_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    cmd = f"""set -e
echo '=================================================='
echo '  DESTROY GCP Infrastructure'
echo '=================================================='
cd {gcp_dir}
{tf_init_cmd()} && terraform destroy -auto-approve -no-color {tf_var_gcp()}

echo ''
echo '=================================================='
echo '  [OK] GCP infrastructure destroyed'
echo '=================================================='
"""
    task_id = create_task("GCP Terraform Destroy", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/infra/outputs", methods=["GET"])
def infra_outputs():
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        result = subprocess.run(
            toolbox_cmd("terraform output -json", cwd=TERRAFORM_DIR),
            shell=True,
            capture_output=True,
            text=True,
            cwd=TERRAFORM_DIR,
            env=env,
        )
        if result.returncode == 0:
            return jsonify(json.loads(result.stdout))
        return jsonify({"error": result.stderr}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Infrastructure (RKE2) ──────────────────────────────────────────────────


@app.route("/api/infra-rke2/plan", methods=["POST"])
def infra_rke2_plan():
    """Show terraform plan for the RKE2 stack only (no EKS infra)."""
    rke2_dir = TERRAFORM_RKE2_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    region = aws_credentials.get("aws_region") or "eu-west-3"
    cmd = f"""set -e
echo "=================================================="
echo "  Terraform Plan (RKE2 single-node on EC2)"
echo "=================================================="
cd {rke2_dir}
{tf_init_cmd()}
terraform plan -no-color -var="aws_region={region}"
"""
    task_id = create_task("Terraform Plan (RKE2)", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/infra-rke2/apply", methods=["POST"])
def infra_rke2_apply():
    """Apply the RKE2 Terraform stack, then auto-configure BYOC from SSM."""
    rke2_dir = TERRAFORM_RKE2_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    region = aws_credentials.get("aws_region") or "eu-west-3"
    cmd = f"""set -e
echo "=================================================="
echo "  RKE2: VPC + EC2 Ubuntu 22.04 + RKE2 bootstrap"
echo "=================================================="
cd {rke2_dir}
{tf_init_cmd()}
terraform apply -auto-approve -no-color -var="aws_region={region}"

echo ""
echo "=================================================="
echo "  RKE2 apply complete"
echo "=================================================="
echo "  Public IP : $(terraform output -raw public_ip 2>/dev/null)"
echo "  Ingress   : $(terraform output -raw ingress_http_url 2>/dev/null)"
echo ""
echo "  Note: RKE2 bootstrap (cloud-init) takes ~3-5 min after"
echo "  the EC2 is ready. The dashboard will poll SSM Parameter"
echo "  Store and auto-configure BYOC once the kubeconfig is up."
"""
    task_id = create_task("Terraform Apply (RKE2)", cmd, use_toolbox=True)

    # Schedule the BYOC finalization in a background thread
    def _watch_then_finalize():
        # Wait for terraform task to finish
        deadline = time.time() + 30 * 60
        while time.time() < deadline:
            status = tasks.get(task_id, {}).get("status")
            if status in ("success", "error"):
                break
            time.sleep(5)
        if tasks.get(task_id, {}).get("status") != "success":
            return
        # Read public_ip from terraform output
        env = os.environ.copy()
        env.update(get_aws_env())
        public_ip = tf_output(TERRAFORM_RKE2_DIR, "public_ip", env)
        if not public_ip:
            tasks[task_id]["output"] += "\n[finalize] Could not read public_ip terraform output\n"
            return
        # Wait for SSM kubeconfig parameter to appear (cloud-init pushes it at the end)
        tasks[task_id]["output"] += "\n[finalize] Waiting for cloud-init to push kubeconfig to SSM (~3-5 min)...\n"
        param_name = f"/{RKE2_PROJECT_NAME}/kubeconfig"
        deadline = time.time() + 10 * 60
        while time.time() < deadline:
            r = subprocess.run(
                toolbox_cmd(
                    f"aws ssm get-parameter --region {aws_credentials.get('aws_region') or 'eu-west-3'} "
                    f"--name {param_name} --query Parameter.Name --output text"
                ),
                shell=True, capture_output=True, text=True, env=env, timeout=10,
            )
            if r.returncode == 0 and param_name in r.stdout:
                break
            time.sleep(15)
        # Fetch the actual kubeconfig content (decrypted)
        r2 = subprocess.run(
            toolbox_cmd(
                f"aws ssm get-parameter --region {aws_credentials.get('aws_region') or 'eu-west-3'} "
                f"--name {param_name} --with-decryption --query Parameter.Value --output text"
            ),
            shell=True, capture_output=True, text=True, env=env, timeout=60,
        )
        kc = r2.stdout.strip()
        if r2.returncode != 0 or not kc or kc.startswith("file://"):
            tasks[task_id]["output"] += f"\n[finalize] kubeconfig fetch failed: {r2.stderr or 'empty'}\n"
            return
        kc = patch_kubeconfig_skip_tls(kc)
        with open(KUBECONFIG_BYOC_PATH, "w") as f:
            f.write(kc)
        os.chmod(KUBECONFIG_BYOC_PATH, 0o600)
        external_cluster["enabled"] = True
        external_cluster["kubeconfig"] = kc
        external_cluster["app_host"] = f"{public_ip}:{RKE2_INGRESS_PORT}"
        external_cluster["image_url"] = RKE2_DEFAULT_IMAGE
        save_credentials()
        tasks[task_id]["output"] += (
            f"\n[finalize] BYOC auto-configured:\n"
            f"  kubeconfig : {KUBECONFIG_BYOC_PATH}\n"
            f"  app_host   : {external_cluster['app_host']}\n"
            f"  image_url  : {external_cluster['image_url']}\n"
        )

    threading.Thread(target=_watch_then_finalize, daemon=True).start()
    return jsonify({"task_id": task_id})


@app.route("/api/infra-rke2/destroy", methods=["POST"])
def infra_rke2_destroy():
    rke2_dir = TERRAFORM_RKE2_DIR.replace(PROJECT_ROOT, "").lstrip("/")
    region = aws_credentials.get("aws_region") or "eu-west-3"
    cmd = f"""set -e
echo "=================================================="
echo "  RKE2: Terraform Destroy"
echo "=================================================="
cd {rke2_dir}
{tf_init_cmd()}
terraform destroy -auto-approve -no-color -var="aws_region={region}"
echo ""
echo "  RKE2 infrastructure destroyed"
"""
    task_id = create_task("Terraform Destroy (RKE2)", cmd, use_toolbox=True)

    # On success, disable BYOC mapping to keep the dashboard state coherent
    def _reset_byoc_after_destroy():
        deadline = time.time() + 15 * 60
        while time.time() < deadline:
            status = tasks.get(task_id, {}).get("status")
            if status in ("success", "error"):
                break
            time.sleep(5)
        if tasks.get(task_id, {}).get("status") == "success":
            external_cluster["enabled"] = False
            external_cluster["kubeconfig"] = ""
            external_cluster["app_host"] = ""
            external_cluster["image_url"] = ""
            try:
                if os.path.isfile(KUBECONFIG_BYOC_PATH):
                    os.unlink(KUBECONFIG_BYOC_PATH)
            except Exception:
                pass
            save_credentials()
            tasks[task_id]["output"] += "\n[reset] BYOC mapping cleared\n"

    threading.Thread(target=_reset_byoc_after_destroy, daemon=True).start()
    return jsonify({"task_id": task_id})


@app.route("/api/infra-rke2/outputs", methods=["GET"])
def infra_rke2_outputs():
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        result = subprocess.run(
            toolbox_cmd("terraform output -json", cwd=TERRAFORM_RKE2_DIR),
            shell=True, capture_output=True, text=True,
            cwd=TERRAFORM_RKE2_DIR, env=env, timeout=30,
        )
        if result.returncode == 0:
            return jsonify(json.loads(result.stdout))
        return jsonify({"error": result.stderr}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Cortex CLI Image Scan ──────────────────────────────────────────────────


@app.route("/api/cortex/image-scan", methods=["POST"])
def cortex_image_scan():
    """Scan a Docker image with cortexcli (CWP) before push."""
    if not cortex_settings.get("api_key"):
        return jsonify({"error": "Cortex API not configured — open Settings > Cortex > Configure."}), 400

    # Derive the cortexcli API base URL from the Cortex API URL
    api_base_url = cortex_settings["base_url"].rstrip("/")
    api_key = cortex_settings["api_key"]
    api_key_id = cortex_settings["api_key_id"]

    # Get the image name to scan
    image_name = request.json.get("image", "")
    if not image_name:
        # Try to get from terraform output (ECR URL)
        env = os.environ.copy()
        env.update(get_aws_env())
        ecr_url = tf_output(TERRAFORM_DIR, "ecr_repository_url", env)
        if ecr_url:
            image_name = f"{ecr_url}:latest"
        else:
            return jsonify({"error": "No image specified and ECR URL not found — run Terraform Apply first or pass an image via Custom."}), 400

    # Extract region from image name for ECR login
    region = aws_credentials.get("aws_region") or "eu-west-3"

    cmd = f"""
echo "=================================================="
echo "  CORTEX CLI - Container Image Scan (CWP)"
echo "=================================================="
echo ""
echo "  Image: {image_name}"
echo "  API:   {api_base_url}"
echo ""

# Check if cortexcli is installed — download from tenant if needed
if ! command -v cortexcli &> /dev/null; then
    echo "[*] cortexcli not found. Downloading from Cortex tenant..."
    if command -v cortexcli-install &> /dev/null; then
        export CORTEX_API_URL="{api_base_url}"
        export CORTEX_API_KEY="{api_key}"
        export CORTEX_API_KEY_ID="{api_key_id}"
        cortexcli-install
    else
        ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
        echo "[*] Getting signed download URL..."
        SIGNED_URL=$(curl -sk \\
            "{api_base_url}/public_api/v1/unified-cli/releases/download-link?os=linux&architecture=${{ARCH}}" \\
            -H "x-xdr-auth-id: {api_key_id}" \\
            -H "Authorization: {api_key}" | jq -r ".signed_url" 2>/dev/null)
        if [ -n "$SIGNED_URL" ] && [ "$SIGNED_URL" != "null" ]; then
            echo "[*] Downloading cortexcli for linux-${{ARCH}}..."
            curl -sk -o /usr/local/bin/cortexcli "$SIGNED_URL" && chmod +x /usr/local/bin/cortexcli
        else
            echo "[!] Failed to get download link. Install cortexcli manually."
            echo "    brew tap paloaltonetworks/cortexcli && brew install cortexcli"
        fi
    fi
fi

echo "==> cortexcli version: $(cortexcli --version 2>/dev/null || echo 'unknown')"
echo ""

# Check if image exists locally
echo "==> Checking if image exists locally..."
if docker image inspect "{image_name}" > /dev/null 2>&1; then
    echo "  [OK] Image found locally"
else
    echo "  [!] Image not found locally. Pulling from registry..."
    # Login to ECR if image is from ECR
    if echo "{image_name}" | grep -q "dkr.ecr"; then
        ACCOUNT_ID=$(echo "{image_name}" | cut -d. -f1)
        ECR_REGION=$(echo "{image_name}" | grep -oP 'ecr\\.\\K[^.]+')
        echo "  [*] Logging in to ECR (account: $ACCOUNT_ID, region: ${{ECR_REGION:-{region}}})..."
        aws ecr get-login-password --region ${{ECR_REGION:-{region}}} | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.${{ECR_REGION:-{region}}}.amazonaws.com 2>&1
    fi
    echo "  [*] Pulling image: {image_name}..."
    docker pull "{image_name}" 2>&1
    if [ $? -ne 0 ]; then
        echo "  [FAIL] Cannot pull image. Make sure you have access to the registry."
        exit 1
    fi
    echo "  [OK] Image pulled successfully"
fi
echo ""

echo "==> Scanning image: {image_name}"
echo "    (this may take 2-5 minutes — cortexcli is analyzing layers...)"
echo ""

# Progress indicator in background (prints dots while scan runs)
(
    while true; do
        sleep 5
        printf "." >&2
    done
) &
PROGRESS_PID=$!
trap "kill $PROGRESS_PID 2>/dev/null" EXIT
echo "==> Command:"
echo "    cortexcli --api-base-url {api_base_url} --api-key ****{api_key[-4:]} --api-key-id {api_key_id} image scan {image_name} --timeout 300"
echo ""

# Run the CWP image scan (timeout 5 min)
cortexcli \\
    --api-base-url "{api_base_url}" \\
    --api-key "{api_key}" \\
    --api-key-id "{api_key_id}" \\
    image scan "{image_name}" \\
    --timeout 300 2>&1

SCAN_EXIT=$?

# Stop progress indicator
kill $PROGRESS_PID 2>/dev/null
echo ""

echo ""
echo "=================================================="
if [ $SCAN_EXIT -eq 0 ]; then
    echo "  [OK] Image scan completed - no policy violations"
elif [ $SCAN_EXIT -eq 1 ]; then
    echo "  [!] Image scan completed - POLICY VIOLATIONS FOUND"
    echo "      Vulnerabilities or compliance issues detected."
else
    echo "  [!] Image scan failed (exit code $SCAN_EXIT)"
    echo "      Check the output above for details."
fi
echo "=================================================="
"""
    task_id = create_task("Cortex CLI: Image Scan", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/cortex/iac-scan", methods=["POST"])
def cortex_iac_scan():
    """Scan IaC (Terraform + K8s manifests) with cortexcli code scan."""
    if not cortex_settings.get("api_key"):
        return jsonify({"error": "Cortex API not configured — open Settings > Cortex > Configure."}), 400

    # Scan directories
    scan_target = request.json.get("target", "all")  # all, terraform, k8s

    # Use env vars $CORTEX_API_URL, $CORTEX_API_KEY, $CORTEX_API_KEY_ID
    # These are passed to the toolbox container by toolbox_cmd()
    cmd = """
echo "=================================================="
echo "  CORTEX CLI - IaC Security Scan (Code Security)"
echo "=================================================="
echo ""
echo "  API:   $CORTEX_API_URL"
echo "  Target: """ + scan_target + """
"
echo ""

# Check if cortexcli is installed — download from tenant if needed
if ! command -v cortexcli > /dev/null 2>&1; then
    echo "[*] cortexcli not found. Downloading from Cortex tenant..."
    if command -v cortexcli-install > /dev/null 2>&1; then
        cortexcli-install
    else
        ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
        echo "[*] Getting signed download URL..."
        SIGNED_URL=$(curl -sk \\
            "$CORTEX_API_URL/public_api/v1/unified-cli/releases/download-link?os=linux&architecture=${ARCH}" \\
            -H "x-xdr-auth-id: $CORTEX_API_KEY_ID" \\
            -H "Authorization: $CORTEX_API_KEY" | jq -r ".signed_url" 2>/dev/null)
        if [ -n "$SIGNED_URL" ] && [ "$SIGNED_URL" != "null" ]; then
            echo "[*] Downloading cortexcli for linux-${ARCH}..."
            curl -sk -o /usr/local/bin/cortexcli "$SIGNED_URL" && chmod +x /usr/local/bin/cortexcli
            echo "[OK] cortexcli installed: $(cortexcli --version 2>/dev/null)"
        else
            echo "[!] Failed to get download link."
            exit 1
        fi
    fi
fi

echo "==> cortexcli version: $(cortexcli --version 2>/dev/null || echo unknown)"
echo "==> node version: $(node --version 2>/dev/null || echo not found)"
echo ""

"""

    if scan_target == "all":
        cmd += """
echo "=================================================="
echo "  Full Project Scan (k8s-container-escape-demo/)"
echo "=================================================="
echo ""
echo "==> Command: cortexcli code scan --directory . --repo-id cortex-cloud-demo/K8s-Container-Escape-Demo"
echo ""
cortexcli \\
    --api-base-url "$CORTEX_API_URL" \\
    --api-key "$CORTEX_API_KEY" \\
    --api-key-id "$CORTEX_API_KEY_ID" \\
    code scan \\
    --directory . \\
    --repo-id cortex-cloud-demo/K8s-Container-Escape-Demo 2>&1 || true
echo ""
"""

    if scan_target == "terraform":
        cmd += """
echo "=================================================="
echo "  Terraform Infrastructure (terraform-infra/)"
echo "=================================================="
echo ""
echo "==> Command: cortexcli code scan --directory terraform-infra --repo-id cortex-cloud-demo/K8s-Container-Escape-Demo-terraform"
echo ""
cortexcli \\
    --api-base-url "$CORTEX_API_URL" \\
    --api-key "$CORTEX_API_KEY" \\
    --api-key-id "$CORTEX_API_KEY_ID" \\
    code scan \\
    --directory terraform-infra \\
    --repo-id cortex-cloud-demo/K8s-Container-Escape-Demo-terraform 2>&1 || true
echo ""
"""

    if scan_target == "k8s":
        cmd += """
echo "=================================================="
echo "  Kubernetes Manifests (k8s/)"
echo "=================================================="
echo ""
echo "==> Command: cortexcli code scan --directory k8s --repo-id cortex-cloud-demo/K8s-Container-Escape-Demo-k8s-manifest"
echo ""
cortexcli \\
    --api-base-url "$CORTEX_API_URL" \\
    --api-key "$CORTEX_API_KEY" \\
    --api-key-id "$CORTEX_API_KEY_ID" \\
    code scan \\
    --directory k8s \\
    --repo-id cortex-cloud-demo/K8s-Container-Escape-Demo-k8s-manifest 2>&1 || true
echo ""
"""

    if scan_target == "sca":
        cmd += """
echo "=================================================="
echo "  WebApp SCA (app/)"
echo "=================================================="
echo ""
echo "==> Command: cortexcli code scan --directory app --repo-id cortex-cloud-demo/K8s-Container-Escape-Demo-webapp"
echo ""
cortexcli \\
    --api-base-url "$CORTEX_API_URL" \\
    --api-key "$CORTEX_API_KEY" \\
    --api-key-id "$CORTEX_API_KEY_ID" \\
    code scan \\
    --directory app \\
    --repo-id cortex-cloud-demo/K8s-Container-Escape-Demo-webapp 2>&1 || true
echo ""
"""

    cmd += """
echo "=================================================="
echo "  [OK] AppSec scan complete"
echo "=================================================="
"""

    task_id = create_task("Cortex CLI: AppSec Scan", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


# ─── Docker Build & Push ────────────────────────────────────────────────────


@app.route("/api/image/build-push", methods=["POST"])
def image_build_push():
    cmd = """
set -uo pipefail

echo "==> Resolving configuration..."

REGION="${AWS_REGION:-}"
if [ -z "$REGION" ]; then
  REGION=$(cd terraform-infra 2>/dev/null && terraform output -raw region 2>/dev/null || true)
fi
REGION="${REGION:-eu-west-3}"
echo "    REGION=$REGION"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>&1)
RC=$?
if [ $RC -ne 0 ] || [ -z "$ACCOUNT_ID" ]; then
  echo ""
  echo "✗ FAILED: AWS credentials are invalid or expired."
  echo "  aws sts returned: $ACCOUNT_ID"
  echo "  Fix: open Settings > AWS > Configure and paste fresh credentials."
  exit 1
fi
echo "    ACCOUNT_ID=$ACCOUNT_ID"

ECR_URL=$(cd terraform-infra 2>/dev/null && terraform output -raw ecr_repository_url 2>/dev/null || true)
if [ -z "$ECR_URL" ]; then
  echo "    (no usable terraform state on host, querying ECR API...)"
  ECR_URL=$(aws ecr describe-repositories \\
    --region "$REGION" \\
    --repository-names k8s-escape-demo/vuln-app \\
    --query 'repositories[0].repositoryUri' --output text 2>&1)
  RC=$?
  if [ $RC -ne 0 ] || [ -z "$ECR_URL" ] || [ "$ECR_URL" = "None" ]; then
    echo ""
    echo "✗ FAILED: cannot resolve ECR repository URL."
    echo "  aws ecr returned: $ECR_URL"
    echo "  Fix: run INFRA > Apply first (creates the ECR repo)."
    exit 1
  fi
fi
echo "    ECR_URL=$ECR_URL"

if ! docker info >/dev/null 2>&1; then
  echo ""
  echo "✗ FAILED: Docker daemon is not running."
  echo "  Fix: start Docker Desktop and retry."
  exit 1
fi

echo "==> Logging in to ECR..."
LOGIN_OUT=$(aws ecr get-login-password --region "$REGION" 2>&1 \\
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com" 2>&1)
RC=$?
echo "$LOGIN_OUT"
if [ $RC -ne 0 ]; then
  echo ""
  echo "✗ FAILED: ECR login failed."
  echo "  Fix: check the AWS user has ecr:GetAuthorizationToken permission."
  exit 1
fi

echo "==> Building image (linux/amd64)..."
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_REPO_URL=$(git config --get remote.origin.url 2>/dev/null | sed -E 's#git@github.com:#https://github.com/#; s#\\.git$##' || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "    GIT_COMMIT=$GIT_COMMIT"
echo "    GIT_REPO_URL=$GIT_REPO_URL"
echo "    BUILD_DATE=$BUILD_DATE"
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 \\
  --build-arg GIT_COMMIT="$GIT_COMMIT" \\
  --build-arg GIT_REPO_URL="$GIT_REPO_URL" \\
  --build-arg BUILD_DATE="$BUILD_DATE" \\
  -t "${ECR_URL}:latest" .
RC=$?
if [ $RC -ne 0 ]; then
  echo ""
  echo "✗ FAILED: docker build returned $RC."
  echo "  Common causes: no QEMU for cross-arch on Apple Silicon,"
  echo "  or Dockerfile error. Check the build output above."
  exit 1
fi

echo "==> Pushing to ECR..."
docker push "${ECR_URL}:latest"
RC=$?
if [ $RC -ne 0 ]; then
  echo ""
  echo "✗ FAILED: docker push returned $RC."
  echo "  Common causes: ECR login expired (retry), or network issue."
  exit 1
fi

echo ""
echo "==> Done! Image pushed to ${ECR_URL}:latest"
"""
    task_id = create_task("Build & Push Image", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


# ─── K8s Deploy ──────────────────────────────────────────────────────────────


@app.route("/api/k8s/deploy", methods=["POST"])
def k8s_deploy():
    # BYOC mode: skip EKS kubeconfig generation, use the user-provided one
    if external_cluster.get("enabled") and external_cluster.get("kubeconfig"):
        if not os.path.isfile(KUBECONFIG_BYOC_PATH):
            return jsonify({"error": "BYOC kubeconfig not found on disk — re-save it in Settings"}), 400
    else:
        # EKS mode: regenerate kubeconfig with embedded AWS credentials
        try:
            env = os.environ.copy()
            env.update(get_aws_env())
            region = tf_output(TERRAFORM_DIR, "region", env) or aws_credentials["aws_region"] or "eu-west-3"
            cluster = tf_output(TERRAFORM_DIR, "cluster_name", env) or "eks-escape-demo"
            generate_kubeconfig(cluster, region)
        except Exception as e:
            return jsonify({"error": f"Failed to generate kubeconfig: {e}"}), 500

    # Determine image URL
    if external_cluster.get("enabled") and external_cluster.get("image_url"):
        image_url = external_cluster["image_url"]
    else:
        image_url = None  # Will be resolved from terraform output

    if image_url:
        # BYOC mode: use provided image URL.
        # 1. Patch Service from LoadBalancer to NodePort (no cloud LB controller on RKE2/vanilla).
        # 2. Try to create an Ingress on the existing ingress-nginx controller (the
        #    common pattern: NodePort 30080 is open in the SG and reaches the controller).
        cmd = f"""
set -e
echo "==> BYOC Mode: Deploying to external cluster"
echo "==> Testing cluster access..."
kubectl cluster-info

echo "==> Applying manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/service-account.yaml

echo "==> Setting image: {image_url} (and patching Service to NodePort)"
sed -e "s|ECR_IMAGE_PLACEHOLDER|{image_url}|g" \\
    -e "s|type: LoadBalancer|type: NodePort|" k8s/deployment.yaml | kubectl apply -f -

echo "==> Waiting for deployment rollout..."
kubectl rollout status deployment/vuln-app -n vuln-app --timeout=300s

# ── Try to create an Ingress on ingress-nginx if available ──
INGRESS_SVC_JSON=$(kubectl get svc -A -l app.kubernetes.io/name=ingress-nginx -o json 2>/dev/null)
INGRESS_NS=$(echo "$INGRESS_SVC_JSON" | grep -m1 '"namespace"' | cut -d'"' -f4)
if [ -n "$INGRESS_NS" ]; then
    echo "==> Detected ingress-nginx in namespace '$INGRESS_NS' — creating Ingress"
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vuln-app-ingress
  namespace: vuln-app
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
spec:
  ingressClassName: nginx
  rules:
  - http:
      paths:
      - path: /app
        pathType: Prefix
        backend:
          service:
            name: vuln-app-service
            port:
              number: 80
EOF
fi

# ── Resolve HOST: prefer ingress-nginx (NodePort + EIP), fallback to vuln-app NodePort ──
echo "==> Resolving HOST..."
NODE_IP=$(kubectl get nodes -o jsonpath='{{.items[0].status.addresses[?(@.type=="ExternalIP")].address}}' 2>/dev/null)
# RKE2/k3s without cloud-provider plugin: ExternalIP is empty, fall back to the
# API server host from the kubeconfig (this is usually the EIP / publicly reachable IP).
if [ -z "$NODE_IP" ]; then
    NODE_IP=$(kubectl config view --minify -o jsonpath='{{.clusters[0].cluster.server}}' 2>/dev/null \\
        | sed -E 's|^https?://||' | cut -d: -f1)
fi
# Last resort: InternalIP (only useful if you're on the same private network)
[ -z "$NODE_IP" ] && NODE_IP=$(kubectl get nodes -o jsonpath='{{.items[0].status.addresses[?(@.type=="InternalIP")].address}}' 2>/dev/null)

INGRESS_PORT=""
if [ -n "$INGRESS_NS" ]; then
    INGRESS_PORT=$(kubectl get svc -n "$INGRESS_NS" -l app.kubernetes.io/name=ingress-nginx \\
        -o jsonpath='{{.items[?(@.spec.type=="NodePort")].spec.ports[?(@.port==80)].nodePort}}' 2>/dev/null | awk '{{print $1}}')
fi

if [ -n "$INGRESS_PORT" ]; then
    HOST="${{NODE_IP}}:${{INGRESS_PORT}}"
    ROUTE="ingress-nginx"
else
    HOST="${{NODE_IP}}:$(kubectl get svc vuln-app-service -n vuln-app -o jsonpath='{{.spec.ports[0].nodePort}}' 2>/dev/null)"
    ROUTE="vuln-app NodePort (direct)"
fi

echo ""
echo "=================================================="
echo "  Application deployed (BYOC)"
echo "=================================================="
echo "  Route    : ${{ROUTE}}"
echo "  Node IP  : ${{NODE_IP}}"
echo "  HOST     : ${{HOST}}"
echo "  URL      : http://${{HOST}}/app"
echo ""
echo "  >>> The dashboard auto-resolves this HOST"
echo "      (or paste it in Settings > BYOC if you prefer)"
echo "=================================================="
"""
    else:
        cmd = f"""
set -e
REGION=$(cd terraform-infra && terraform output -raw region 2>/dev/null || echo "$AWS_REGION")
ECR_URL=$(cd terraform-infra && terraform output -raw ecr_repository_url 2>/dev/null)

echo "==> Kubeconfig generated with embedded AWS credentials"
echo "==> Testing cluster access..."
kubectl cluster-info

echo "==> Applying manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/service-account.yaml

echo "==> Setting ECR image in deployment..."
sed "s|ECR_IMAGE_PLACEHOLDER|${{ECR_URL}}:latest|g" k8s/deployment.yaml | kubectl apply -f -

echo "==> Waiting for deployment rollout..."
kubectl rollout status deployment/vuln-app -n vuln-app --timeout=300s

echo "==> Waiting for LoadBalancer..."
sleep 15
HOST=$(kubectl get svc vuln-app-service -n vuln-app -o jsonpath='{{.status.loadBalancer.ingress[0].hostname}}' 2>/dev/null || echo "pending")
echo ""
echo "==> Application deployed!"
echo "==> HOST=${{HOST}}"
echo "==> URL: http://${{HOST}}/app"
"""
    task_id = create_task("Deploy to EKS", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/k8s/undeploy", methods=["POST"])
def k8s_undeploy():
    cmd = """set -e
echo "==> Deleting vuln-app resources..."
kubectl delete -f k8s/deployment.yaml --ignore-not-found=true 2>/dev/null || true
kubectl delete -f k8s/service-account.yaml --ignore-not-found=true 2>/dev/null || true
kubectl delete -f k8s/namespace.yaml --ignore-not-found=true --wait=false 2>/dev/null || true
echo "==> Waiting for namespace deletion..."
kubectl wait --for=delete namespace/vuln-app --timeout=60s 2>/dev/null || true
echo "==> Undeploy complete"
"""
    task_id = create_task("Undeploy from EKS", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/k8s/status", methods=["GET"])
def k8s_status():
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        result = subprocess.run(
            toolbox_cmd("kubectl get pods,svc -n vuln-app -o wide 2>/dev/null"),
            shell=True,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env=env,
        )
        return jsonify({"output": result.stdout or result.stderr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/k8s/host", methods=["GET"])
def k8s_host():
    try:
        host = get_host()
        return jsonify({"host": host if host else None})
    except Exception:
        return jsonify({"host": None})


# ─── kubectl ────────────────────────────────────────────────────────────────


@app.route("/api/kubectl", methods=["POST"])
def kubectl_exec():
    """Execute a kubectl command."""
    args = request.json.get("command", "").strip()
    if not args:
        return jsonify({"error": "No command provided"}), 400

    # Prevent command injection: only allow kubectl arguments
    if any(c in args for c in [";", "&", "|", "`", "$", "(", ")", "\n"]):
        return jsonify({"error": "Invalid characters in command"}), 400

    task_id = create_task(
        f"kubectl {args[:40]}",
        f"kubectl {args}",
        use_toolbox=True,
    )
    return jsonify({"task_id": task_id})


# ─── Attack Steps ────────────────────────────────────────────────────────────


def _kubectl_jsonpath(jsonpath, extra=""):
    env = os.environ.copy()
    env.update(get_aws_env())
    r = subprocess.run(
        toolbox_cmd(f"kubectl {extra} -o jsonpath='{jsonpath}' 2>/dev/null"),
        shell=True, capture_output=True, text=True, env=env,
    )
    return r.stdout.strip().strip("'")


def get_host():
    """Get the LoadBalancer hostname (or external cluster host if BYOC).

    BYOC resolution order:
      1. user-provided app_host
      2. ingress-nginx NodePort + Node IP (preferred — well-known port, usually open in SG)
      3. vuln-app Service NodePort + Node IP (fallback)
    """
    if external_cluster.get("enabled"):
        if external_cluster.get("app_host"):
            return external_cluster["app_host"]

        # 1. Try node ExternalIP (works on EKS/GKE/AKS with cloud-provider plugin)
        node_ip = _kubectl_jsonpath(
            '{.items[0].status.addresses[?(@.type=="ExternalIP")].address}',
            "get nodes",
        )
        # 2. RKE2/k3s/vanilla without cloud-provider: extract API server host from kubeconfig
        if not node_ip:
            env = os.environ.copy()
            env.update(get_aws_env())
            r = subprocess.run(
                toolbox_cmd("kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null"),
                shell=True, capture_output=True, text=True, env=env,
            )
            server = r.stdout.strip().strip("'")
            if server:
                import re
                m = re.match(r'^https?://([^:/]+)', server)
                if m:
                    node_ip = m.group(1)
        # 3. Last resort: InternalIP (only reachable on the same private network)
        if not node_ip:
            node_ip = _kubectl_jsonpath(
                '{.items[0].status.addresses[?(@.type=="InternalIP")].address}',
                "get nodes",
            )
        if not node_ip:
            return ""

        # Prefer ingress-nginx NodePort
        ingress_np = _kubectl_jsonpath(
            '{.items[?(@.spec.type=="NodePort")].spec.ports[?(@.port==80)].nodePort}',
            "get svc -A -l app.kubernetes.io/name=ingress-nginx",
        ).split()
        if ingress_np:
            return f"{node_ip}:{ingress_np[0]}"

        # Fallback: vuln-app Service NodePort
        app_np = _kubectl_jsonpath(
            '{.spec.ports[0].nodePort}',
            "get svc vuln-app-service -n vuln-app",
        )
        return f"{node_ip}:{app_np}" if app_np else ""

    # EKS mode: read the LoadBalancer hostname from the service
    return _kubectl_jsonpath(
        '{.status.loadBalancer.ingress[0].hostname}',
        "get svc vuln-app-service -n vuln-app",
    )


@app.route("/api/attack/step1", methods=["POST"])
def attack_step1():
    host = get_host()
    if not host:
        return jsonify({"error": "No HOST found. Deploy the app first."}), 400
    task_id = create_task(
        "Step 1: Spring4Shell RCE",
        f"bash {ATTACK_DIR}/01-exploit-rce.sh",
        env_extra={"HOST": host},
    )
    return jsonify({"task_id": task_id})


@app.route("/api/attack/step2", methods=["POST"])
def attack_step2():
    host = get_host()
    if not host:
        return jsonify({"error": "No HOST found. Deploy the app first."}), 400
    task_id = create_task(
        "Step 2: Container Escape",
        f"bash {ATTACK_DIR}/02-container-escape.sh",
        env_extra={"HOST": host},
    )
    return jsonify({"task_id": task_id})


@app.route("/api/attack/step3", methods=["POST"])
def attack_step3():
    host = get_host()
    if not host:
        return jsonify({"error": "No HOST found. Deploy the app first."}), 400
    task_id = create_task(
        "Step 3: Cluster Takeover",
        f"bash {ATTACK_DIR}/03-cluster-takeover.sh",
        env_extra={"HOST": host},
    )
    return jsonify({"task_id": task_id})


@app.route("/api/attack/step4", methods=["POST"])
def attack_step4():
    host = get_host()
    if not host:
        return jsonify({"error": "No HOST found. Deploy the app first."}), 400
    task_id = create_task(
        "Step 4: K8s Vulnerability Scanning",
        f"bash {ATTACK_DIR}/04-k8s-scanning.sh",
        env_extra={"HOST": host},
    )
    return jsonify({"task_id": task_id})


@app.route("/api/attack/step5", methods=["POST"])
def attack_step5():
    host = get_host()
    if not host:
        return jsonify({"error": "No HOST found. Deploy the app first."}), 400
    task_id = create_task(
        "Step 5: Deploy Malware",
        f"bash {ATTACK_DIR}/05-deploy-malware.sh",
        env_extra={"HOST": host},
    )
    return jsonify({"task_id": task_id})


@app.route("/api/attack/step6", methods=["POST"])
def attack_step6():
    host = get_host()
    if not host:
        return jsonify({"error": "No HOST found. Deploy the app first."}), 400
    task_id = create_task(
        "Step 6: Lateral Movement",
        f"bash {ATTACK_DIR}/06-lateral-movement.sh",
        env_extra={"HOST": host},
    )
    return jsonify({"task_id": task_id})


@app.route("/api/attack/shell", methods=["POST"])
def attack_shell():
    """Execute a custom command on the compromised pod via webshell."""
    host = get_host()
    if not host:
        return jsonify({"error": "No HOST found."}), 400

    cmd = request.json.get("command", "id")
    task_id = create_task(
        f"Shell: {cmd[:40]}",
        f"bash {ATTACK_DIR}/remote_shell.sh \"$SHELL_CMD\"",
        env_extra={"HOST": host, "SHELL_CMD": cmd},
    )
    return jsonify({"task_id": task_id})


# ─── Lambda Management ──────────────────────────────────────────────────────


@app.route("/api/lambda/apply", methods=["POST"])
def lambda_apply():
    """Deploy the containment Lambda via Terraform (separate state)."""
    if not os.path.isdir(TERRAFORM_LAMBDA_DIR):
        return jsonify({"error": f"Terraform Lambda directory not found: {TERRAFORM_LAMBDA_DIR}"}), 400
    task_id = create_task(
        "Deploy Lambda",
        f"echo '>>> Terraform Lambda Deploy starting...' && {tf_init_cmd()} 2>&1 && terraform apply -auto-approve -no-color {tf_var_region()} 2>&1",
        cwd=TERRAFORM_LAMBDA_DIR,
        use_toolbox=True,
    )
    return jsonify({"task_id": task_id})


@app.route("/api/lambda/destroy", methods=["POST"])
def lambda_destroy():
    """Destroy the containment Lambda via Terraform."""
    task_id = create_task(
        "Destroy Lambda",
        f"{tf_init_cmd()} && terraform destroy -auto-approve -no-color {tf_var_region()}",
        cwd=TERRAFORM_LAMBDA_DIR,
        use_toolbox=True,
    )
    return jsonify({"task_id": task_id})


@app.route("/api/lambda/status", methods=["GET"])
def lambda_status():
    """Get Lambda function status from terraform-lambda outputs."""
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        name = tf_output(TERRAFORM_LAMBDA_DIR, "containment_lambda_name", env)
        arn = tf_output(TERRAFORM_LAMBDA_DIR, "containment_lambda_arn", env)
        if name:
            return jsonify({"status": "deployed", "name": name, "arn": arn})
        return jsonify({"status": "not_deployed", "name": None, "arn": None})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/lambda/test", methods=["POST"])
def test_lambda():
    """Test the Lambda function by invoking collect_evidence."""
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        lambda_name = tf_output(TERRAFORM_LAMBDA_DIR, "containment_lambda_name", env)
        if not lambda_name:
            return jsonify({"error": "Lambda not deployed. Deploy it first."}), 400

        payload = json.dumps({
            "action": "collect_evidence",
            "cluster_name": "eks-escape-demo",
            "namespace": "vuln-app",
        })

        cmd = (
            f"echo 'Invoking Lambda: {lambda_name}...' && "
            f"aws lambda invoke --function-name {lambda_name} "
            f"--payload '{payload}' --cli-binary-format raw-in-base64-out "
            f"--region {aws_credentials.get('aws_region') or 'eu-west-3'} "
            f"/tmp/lambda_response.json 2>&1 && "
            f"echo '' && echo '--- Lambda Response ---' && "
            f"python3 -m json.tool /tmp/lambda_response.json"
        )
        task_id = create_task("Test Lambda: collect_evidence", cmd, use_toolbox=True)
        return jsonify({"task_id": task_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Cortex Playbook / Containment ──────────────────────────────────────────

CONTAINMENT_STEPS = [
    {
        "id": "collect_evidence",
        "name": "Collect Evidence",
        "desc": "Pod forensics, logs, RBAC, events",
        "kubectl": (
            'echo "==> Collecting pod details..."\n'
            'kubectl get pods -n vuln-app -o wide\n'
            'echo ""\n'
            'echo "==> Pod security context..."\n'
            'kubectl get pods -n vuln-app -o jsonpath=\'{range .items[*]}{"Pod: "}{.metadata.name}{"\\n  privileged: "}{.spec.containers[0].securityContext.privileged}{"\\n  hostPID: "}{.spec.hostPID}{"\\n  hostNetwork: "}{.spec.hostNetwork}{"\\n  SA: "}{.spec.serviceAccountName}{"\\n\\n"}{end}\'\n'
            'echo ""\n'
            'echo "==> ClusterRoleBindings (cluster-admin)..."\n'
            'kubectl get clusterrolebindings -o wide | grep -E "NAME|cluster-admin"\n'
            'echo ""\n'
            'echo "==> Recent events..."\n'
            'kubectl get events -n vuln-app --sort-by=.lastTimestamp --no-headers | tail -15\n'
            'echo ""\n'
            'echo "==> Pod logs (last 30 lines)..."\n'
            'kubectl logs -n vuln-app -l app=vuln-app --tail=30 2>/dev/null || echo "No logs available"\n'
            'echo ""\necho "==> Evidence collection complete."'
        ),
    },
    {
        "id": "network_isolate",
        "name": "Network Isolation",
        "desc": "Deny-all NetworkPolicy on namespace",
        "kubectl": (
            'echo "==> Applying deny-all NetworkPolicy on vuln-app namespace..."\n'
            "cat <<'NETPOL' | kubectl apply -f -\n"
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: containment-deny-all\n"
            "  namespace: vuln-app\n"
            "  labels:\n"
            "    cortex-xsoar: containment\n"
            "spec:\n"
            "  podSelector: {}\n"
            "  policyTypes:\n"
            "    - Ingress\n"
            "    - Egress\n"
            "  ingress: []\n"
            "  egress: []\n"
            "NETPOL\n"
            'echo "==> NetworkPolicy applied. All traffic blocked."\n'
            'kubectl get networkpolicy -n vuln-app'
        ),
    },
    {
        "id": "revoke_rbac",
        "name": "Revoke RBAC",
        "desc": "Remove cluster-admin ClusterRoleBinding",
        "kubectl": (
            'echo "==> Current ClusterRoleBinding..."\n'
            'kubectl get clusterrolebinding vuln-app-cluster-admin -o wide 2>/dev/null || echo "Not found"\n'
            'echo ""\n'
            'echo "==> Deleting cluster-admin ClusterRoleBinding..."\n'
            'kubectl delete clusterrolebinding vuln-app-cluster-admin --ignore-not-found=true\n'
            'echo "==> RBAC privileges revoked."'
        ),
    },
    {
        "id": "scale_down",
        "name": "Scale Down",
        "desc": "Scale deployment to 0 replicas",
        "kubectl": (
            'echo "==> Current deployment status..."\n'
            'kubectl get deployment vuln-app -n vuln-app -o wide 2>/dev/null\n'
            'echo ""\n'
            'echo "==> Scaling deployment to 0 replicas..."\n'
            'kubectl scale deployment vuln-app -n vuln-app --replicas=0\n'
            'echo "==> Waiting for pods to terminate..."\n'
            'kubectl wait --for=delete pod -l app=vuln-app -n vuln-app --timeout=60s 2>/dev/null || true\n'
            'echo "==> Deployment scaled down."\n'
            'kubectl get pods -n vuln-app 2>/dev/null || echo "No pods running."'
        ),
    },
    {
        "id": "cordon_node",
        "name": "Cordon Node",
        "desc": "Mark compromised node as unschedulable",
        "kubectl": (
            'echo "==> Finding node running vuln-app pods..."\n'
            'NODE=$(kubectl get pods -n vuln-app -o jsonpath=\'{.items[0].spec.nodeName}\' 2>/dev/null)\n'
            'if [ -z "$NODE" ]; then\n'
            '  echo "No running pods found, checking all nodes..."\n'
            '  kubectl get nodes -o wide\n'
            'else\n'
            '  echo "==> Cordoning node: $NODE"\n'
            '  kubectl cordon "$NODE"\n'
            '  echo "==> Node $NODE cordoned."\n'
            '  kubectl get nodes -o wide\n'
            'fi'
        ),
    },
    {
        "id": "delete_pod",
        "name": "Kill Pods",
        "desc": "Force delete compromised pods",
        "kubectl": (
            'echo "==> Force deleting all pods in vuln-app namespace..."\n'
            'kubectl delete pods --all -n vuln-app --force --grace-period=0 2>/dev/null || echo "No pods to delete"\n'
            'echo "==> Verifying..."\n'
            'kubectl get pods -n vuln-app 2>/dev/null || echo "Namespace clean."\n'
            'echo "==> Pods terminated."'
        ),
    },
]


@app.route("/api/playbook/steps", methods=["GET"])
def playbook_steps():
    """Return the list of containment steps."""
    return jsonify([{"id": s["id"], "name": s["name"], "desc": s["desc"]} for s in CONTAINMENT_STEPS])


@app.route("/api/playbook/run/<step_id>", methods=["POST"])
def playbook_run_step(step_id):
    """Run a single containment step via kubectl."""
    step = next((s for s in CONTAINMENT_STEPS if s["id"] == step_id), None)
    if not step:
        return jsonify({"error": f"Unknown step: {step_id}"}), 400

    task_id = create_task(
        f"Cortex: {step['name']}",
        f"set -e\n{step['kubectl']}",
        use_toolbox=True,
    )
    return jsonify({"task_id": task_id})


@app.route("/api/playbook/run-all", methods=["POST"])
def playbook_run_all():
    """Run the full containment playbook (all steps sequentially)."""
    all_cmds = []
    for step in CONTAINMENT_STEPS:
        all_cmds.append(f'echo ""\necho "{"=" * 50}"\necho "  CORTEX PLAYBOOK - {step["name"].upper()}"')
        all_cmds.append(f'echo "{"=" * 50}"\necho ""\n{step["kubectl"]}')

    full_script = "\n".join(all_cmds)
    task_id = create_task("Cortex: Full Containment Playbook", f"set -e\n{full_script}", use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/playbook/lambda/<step_id>", methods=["POST"])
def playbook_lambda_step(step_id):
    """Run a containment step via AWS Lambda invocation."""
    try:
        env = os.environ.copy()
        env.update(get_aws_env())

        # Get Lambda function name from terraform-lambda outputs
        lambda_name = tf_output(TERRAFORM_LAMBDA_DIR, "containment_lambda_name", env)
        if not lambda_name:
            return jsonify({"error": "Lambda not deployed. Deploy it first."}), 400

        payload = json.dumps({
            "action": step_id,
            "cluster_name": "eks-escape-demo",
            "namespace": "vuln-app",
        })

        cmd = f'aws lambda invoke --function-name {lambda_name} --payload \'{payload}\' --cli-binary-format raw-in-base64-out /dev/stdout 2>/dev/null'
        task_id = create_task(f"Lambda: {step_id}", cmd, use_toolbox=True)
        return jsonify({"task_id": task_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Cortex API ──────────────────────────────────────────────────────────────


@app.route("/api/cortex/credentials", methods=["GET"])
def get_cortex_credentials():
    """Return current Cortex settings (masked API key)."""
    masked = dict(cortex_settings)
    if masked["api_key"]:
        masked["api_key"] = "****" + masked["api_key"][-4:]
    return jsonify(masked)


@app.route("/api/cortex/credentials", methods=["POST"])
def set_cortex_credentials():
    """Set Cortex API credentials."""
    data = request.json
    if "base_url" in data:
        # Normalize: strip trailing slashes
        cortex_settings["base_url"] = data["base_url"].strip().rstrip("/")
    if "api_key_id" in data:
        cortex_settings["api_key_id"] = data["api_key_id"].strip()
    if "api_key" in data:
        # Strip non-ASCII chars that may come from copy/paste
        cortex_settings["api_key"] = data["api_key"].encode("ascii", errors="ignore").decode("ascii").strip()
    save_credentials()
    return jsonify({"status": "ok"})


@app.route("/api/cortex/test", methods=["POST"])
def test_cortex_connection():
    """Test Cortex API connection."""
    base_url = cortex_settings["base_url"]
    api_key = cortex_settings["api_key"]
    api_key_id = cortex_settings["api_key_id"]

    if not base_url or not api_key or not api_key_id:
        return jsonify({"status": "error", "message": "Missing Cortex credentials (Base URL, API Key ID, API Key)"}), 400

    url = f"{base_url}/xsoar/public/v1/settings/integration/search"
    headers = {
        "Authorization": api_key,
        "x-xdr-auth-id": api_key_id,
        "Content-Type": "application/json",
    }

    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=b'{"size": 1}', headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as resp:
            return jsonify({"status": "ok", "message": f"Connected to Cortex ({base_url})", "http_status": resp.status})
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        return jsonify({"status": "error", "message": f"HTTP {e.code}: {body}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


def cortex_upload_file(api_path, file_path, file_field="file"):
    """Upload a file to Cortex API via multipart/form-data."""
    base_url = cortex_settings["base_url"]
    api_key = cortex_settings["api_key"]
    api_key_id = cortex_settings["api_key_id"]

    if not base_url or not api_key or not api_key_id:
        return {"status": "error", "message": "Missing Cortex credentials. Configure them first."}, 400

    if not os.path.exists(file_path):
        return {"status": "error", "message": f"File not found: {file_path}"}, 400

    with open(file_path, "rb") as f:
        file_content = f.read()

    filename = os.path.basename(file_path)
    boundary = uuid.uuid4().hex

    body = b""
    body += f"--{boundary}\r\n".encode()
    body += f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode()
    body += b"Content-Type: application/octet-stream\r\n"
    body += b"\r\n"
    body += file_content
    body += f"\r\n--{boundary}--\r\n".encode()

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    url = f"{base_url}{api_path}"
    headers = {
        "Authorization": api_key,
        "x-xdr-auth-id": api_key_id,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }

    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": "ok",
                "message": f"Uploaded {filename} to Cortex",
                "http_status": resp.status,
                "response": resp_body[:1000],
            }, 200
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:500]
        return {"status": "error", "message": f"HTTP {e.code}: {err_body}"}, e.code
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500


def cortex_upload_playbook_zip(api_path, yaml_path):
    """Upload a playbook YAML as a ZIP file to Cortex API (required format).
    Dynamically injects current AWS credentials into playbook inputs."""
    base_url = cortex_settings["base_url"]
    api_key = cortex_settings["api_key"]
    api_key_id = cortex_settings["api_key_id"]

    if not base_url or not api_key or not api_key_id:
        return {"status": "error", "message": "Missing Cortex credentials."}, 400

    if not os.path.exists(yaml_path):
        return {"status": "error", "message": f"File not found: {yaml_path}"}, 400

    # Read and parse YAML to inject AWS credentials dynamically
    with open(yaml_path, "r") as f:
        playbook_data = yaml.safe_load(f)

    # Map AWS settings to playbook input keys
    aws_input_map = {
        "AWSAccessKeyID": aws_credentials.get("aws_access_key_id", ""),
        "AWSSecretAccessKey": aws_credentials.get("aws_secret_access_key", ""),
        "AWSSessionToken": aws_credentials.get("aws_session_token", ""),
        "Region": aws_credentials.get("aws_region", "eu-west-3"),
    }

    # Update playbook inputs with current AWS credentials
    if "inputs" in playbook_data:
        for inp in playbook_data["inputs"]:
            if inp.get("key") in aws_input_map and aws_input_map[inp["key"]]:
                inp["value"] = {"simple": aws_input_map[inp["key"]]}

    yaml_content = yaml.dump(playbook_data, default_flow_style=False, allow_unicode=True, sort_keys=False).encode("utf-8")

    zip_buffer = io.BytesIO()
    yaml_filename = os.path.basename(yaml_path)
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(yaml_filename, yaml_content)
    zip_data = zip_buffer.getvalue()

    zip_filename = yaml_filename.replace(".yml", ".zip").replace(".yaml", ".zip")

    boundary = uuid.uuid4().hex
    body = b""
    body += f"--{boundary}\r\n".encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{zip_filename}"\r\n'.encode()
    body += b"Content-Type: application/zip\r\n"
    body += b"\r\n"
    body += zip_data
    body += f"\r\n--{boundary}--\r\n".encode()

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    url = f"{base_url}{api_path}"
    headers = {
        "Authorization": api_key,
        "x-xdr-auth-id": api_key_id,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
        "Accept": "application/json",
    }

    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": "ok",
                "message": f"Playbook uploaded as ZIP to Cortex",
                "http_status": resp.status,
                "response": resp_body[:1000],
            }, 200
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:500]
        return {"status": "error", "message": f"HTTP {e.code}: {err_body}"}, e.code
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500


def cortex_json_request(api_path, json_data, method="POST"):
    """Send a JSON request to Cortex API."""
    base_url = cortex_settings["base_url"]
    api_key = cortex_settings["api_key"]
    api_key_id = cortex_settings["api_key_id"]

    if not base_url or not api_key or not api_key_id:
        return {"status": "error", "message": "Missing Cortex credentials."}, 400

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    url = f"{base_url}{api_path}"
    body = json.dumps(json_data).encode("utf-8")
    # Ensure API key is ASCII-safe (strip any non-ASCII chars from copy/paste)
    safe_api_key = api_key.encode("ascii", errors="ignore").decode("ascii").strip()
    safe_api_key_id = api_key_id.encode("ascii", errors="ignore").decode("ascii").strip()
    headers = {
        "Authorization": safe_api_key,
        "x-xdr-auth-id": safe_api_key_id,
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }

    try:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": "ok",
                "message": f"{method} {api_path} succeeded",
                "http_status": resp.status,
                "response": resp_body,
            }, 200
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:500]
        return {"status": "error", "message": f"HTTP {e.code} on {method} {api_path}: {err_body}"}, e.code
    except Exception as e:
        return {"status": "error", "message": f"{method} {api_path}: {e}"}, 500


def load_automation_as_json(yaml_path):
    """Load a Cortex automation YAML and convert to JSON for API upload."""
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
    return data


def build_cortex_script_payload(script_name, yaml_path):
    """Build the Cortex API payload for script upload using the official API format.

    API spec: POST /xsoar/public/v1/automation
    Body: {"script": {"name": ..., "type": "python", "subtype": "python3", ...}}
    """
    automation_data = load_automation_as_json(yaml_path)

    # Read the raw Python code from the .py file
    py_path = os.path.join(PROJECT_ROOT, "cortex-scripts", f"{script_name}.py")
    if os.path.exists(py_path):
        with open(py_path, "r") as f:
            script_content = f.read()
    else:
        script_content = automation_data.get("script", "")

    # Convert YAML 'args' to API 'arguments' format
    yaml_args = automation_data.get("args", [])
    arguments = []
    for arg in yaml_args:
        arguments.append({
            "name": arg.get("name", ""),
            "description": arg.get("description", ""),
            "required": arg.get("required", False),
            "isArray": arg.get("isArray", False),
        })

    # Build the payload with the {"script": {...}} envelope per Cortex API spec
    payload = {
        "script": {
            "name": automation_data.get("name", script_name),
            "comment": automation_data.get("comment", ""),
            "type": "python",
            "subtype": "python3",
            "tags": automation_data.get("tags", []),
            "enabled": automation_data.get("enabled", True),
            "script": script_content,
            "dockerImage": automation_data.get("dockerimage", "demisto/python3:3.10.14.100715"),
            "arguments": arguments,
            "outputs": automation_data.get("outputs", []),
            "version": -1,
        }
    }
    return payload


@app.route("/api/cortex/deploy-script", methods=["POST"])
def deploy_script_to_cortex():
    """Upload an automation script to Cortex via the official API."""
    script_name = request.json.get("script_name", "ExtractK8sContainerEscapeIOCs")

    scripts_map = {
        "ExtractK8sContainerEscapeIOCs": os.path.join(
            PROJECT_ROOT, "cortex-scripts", "automation-ExtractK8sContainerEscapeIOCs.yml"
        ),
        "InvokeK8sContainmentLambda": os.path.join(
            PROJECT_ROOT, "cortex-scripts", "automation-InvokeK8sContainmentLambda.yml"
        ),
        "K8sForensicAnalysis": os.path.join(
            PROJECT_ROOT, "cortex-scripts", "automation-K8sForensicAnalysis.yml"
        ),
        "K8sSearchSimilarEvents": os.path.join(
            PROJECT_ROOT, "cortex-scripts", "automation-K8sSearchSimilarEvents.yml"
        ),
        "CodeToCloudPivot": os.path.join(
            PROJECT_ROOT, "cortex-scripts", "automation-CodeToCloudPivot.yml"
        ),
        "EnrichCloudAssetYorTags": os.path.join(
            PROJECT_ROOT, "cortex-scripts", "automation-EnrichCloudAssetYorTags.yml"
        ),
        "AwsAddInternetExposedTagToS3Bucket": os.path.join(
            PROJECT_ROOT, "cortex-scripts", "aws-add-internet-exposed-tag-to-s3-bucket.yml"
        ),
        "AwsRemoveS3PublicAccess": os.path.join(
            PROJECT_ROOT, "cortex-scripts", "aws-remove-s3-public-access.yml"
        ),
    }

    if script_name not in scripts_map:
        return jsonify({"status": "error", "message": f"Unknown script: {script_name}"}), 400

    yaml_path = scripts_map[script_name]
    errors = []

    try:
        payload = build_cortex_script_payload(script_name, yaml_path)
        api_path = "/xsoar/public/v1/automation"
        result, status_code = cortex_json_request(api_path, payload)
        if result["status"] == "ok":
            result["script_name"] = script_name
            result["api_path"] = api_path
            result["method"] = "json-create"
            return jsonify(result)

        # Handle 409 Conflict: script already exists, retry as update with existing ID
        if status_code == 409:
            import re
            err_msg = result.get("message", "") + " " + result.get("response", "")
            id_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', err_msg)
            if id_match:
                existing_id = id_match.group(1)
                payload["script"]["id"] = existing_id
                # Try POST with ID (update mode)
                result2, status_code2 = cortex_json_request(api_path, payload, method="POST")
                if result2["status"] == "ok":
                    result2["script_name"] = script_name
                    result2["api_path"] = api_path
                    result2["method"] = "json-update-post"
                    return jsonify(result2)
                errors.append(f"JSON POST update (id={existing_id}): HTTP {status_code2} {result2.get('message', 'unknown')}")
                # Try PUT with ID
                result3, status_code3 = cortex_json_request(api_path, payload, method="PUT")
                if result3["status"] == "ok":
                    result3["script_name"] = script_name
                    result3["api_path"] = api_path
                    result3["method"] = "json-update-put"
                    return jsonify(result3)
                errors.append(f"JSON PUT update (id={existing_id}): HTTP {status_code3} {result3.get('message', 'unknown')}")
            else:
                errors.append(f"JSON {api_path}: 409 conflict but could not extract existing ID from: {err_msg[:200]}")
        else:
            errors.append(f"JSON {api_path}: {result.get('message', 'unknown')}")
    except Exception as e:
        errors.append(f"JSON error: {e}")

    # Fallback: Multipart file upload (YAML)
    upload_api_paths = [
        "/xsoar/public/v1/automations/import",
        "/xsoar/public/v1/automation/upload",
    ]
    for api_path in upload_api_paths:
        result, status_code = cortex_upload_file(api_path, yaml_path)
        if result["status"] == "ok":
            result["script_name"] = script_name
            result["api_path"] = api_path
            result["method"] = "multipart"
            return jsonify(result)
        errors.append(f"Multipart {api_path}: {result.get('message', 'unknown')}")

    error_detail = "\n".join(errors)
    return jsonify({"status": "error", "message": f"Script upload failed. Tried {len(errors)} methods:\n{error_detail}"}), 400


@app.route("/api/cortex/publish-playbook", methods=["POST"])
def publish_playbook_to_cortex():
    """Publish YAML playbook(s) to Cortex via API (ZIP format required).
    Accepts optional playbook_name parameter to deploy a specific playbook."""
    playbook_name = request.json.get("playbook_name", "containment") if request.is_json else "containment"

    playbooks_map = {
        "containment": os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_Spring4Shell_Containment.yml"),
        "forensic": os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_Forensic_Analysis.yml"),
        "search": os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_Search_Similar_Events.yml"),
        "pivot": os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_CodeToCloud_Pivot.yml"),
        "s3-remediation": os.path.join(PLAYBOOK_DIR, "Public_S3_Bucket_Auto_Remediation.yml"),
    }

    playbook_path = playbooks_map.get(playbook_name)
    if not playbook_path:
        return jsonify({"status": "error", "message": f"Unknown playbook: {playbook_name}"}), 400

    # Cortex Cloud API: POST /public_api/v1/playbooks/insert with YAML in ZIP
    api_paths = [
        "/public_api/v1/playbooks/insert",
        "/xsoar/public/v1/playbooks/import",
    ]

    errors = []
    for api_path in api_paths:
        result, status_code = cortex_upload_playbook_zip(api_path, playbook_path)
        if result["status"] == "ok":
            result["api_path"] = api_path
            result["playbook_name"] = playbook_name
            return jsonify(result)
        errors.append(f"{api_path}: HTTP {status_code} - {result.get('message', 'Unknown')[:200]}")

    error_detail = "\n".join(errors)
    return jsonify({"status": "error", "message": f"Playbook publish failed. Tried {len(errors)} methods:\n{error_detail}"}), 400


@app.route("/api/cortex/deploy-all", methods=["POST"])
def deploy_all_to_cortex():
    """Deploy all Cortex objects: scripts + playbook."""
    results = []

    # 1. Deploy scripts
    scripts = [
        ("ExtractK8sContainerEscapeIOCs",
         os.path.join(PROJECT_ROOT, "cortex-scripts", "automation-ExtractK8sContainerEscapeIOCs.yml")),
        ("InvokeK8sContainmentLambda",
         os.path.join(PROJECT_ROOT, "cortex-scripts", "automation-InvokeK8sContainmentLambda.yml")),
        ("K8sForensicAnalysis",
         os.path.join(PROJECT_ROOT, "cortex-scripts", "automation-K8sForensicAnalysis.yml")),
        ("K8sSearchSimilarEvents",
         os.path.join(PROJECT_ROOT, "cortex-scripts", "automation-K8sSearchSimilarEvents.yml")),
        ("CodeToCloudPivot",
         os.path.join(PROJECT_ROOT, "cortex-scripts", "automation-CodeToCloudPivot.yml")),
        ("EnrichCloudAssetYorTags",
         os.path.join(PROJECT_ROOT, "cortex-scripts", "automation-EnrichCloudAssetYorTags.yml")),
        ("AwsAddInternetExposedTagToS3Bucket",
         os.path.join(PROJECT_ROOT, "cortex-scripts", "aws-add-internet-exposed-tag-to-s3-bucket.yml")),
        ("AwsRemoveS3PublicAccess",
         os.path.join(PROJECT_ROOT, "cortex-scripts", "aws-remove-s3-public-access.yml")),
    ]

    for script_name, yaml_path in scripts:
        deployed = False
        script_errors = []

        # Try JSON API with correct {"script": {...}} envelope
        try:
            payload = build_cortex_script_payload(script_name, yaml_path)
            api_path = "/xsoar/public/v1/automation"
            result, status_code = cortex_json_request(api_path, payload)
            if result["status"] == "ok":
                results.append({"type": "script", "name": script_name, "status": "ok", "api_path": api_path, "method": "json-create"})
                deployed = True
            elif status_code == 409:
                # Script already exists — retry as update with existing ID
                import re
                err_msg = result.get("message", "") + " " + result.get("response", "")
                id_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', err_msg)
                if id_match:
                    existing_id = id_match.group(1)
                    payload["script"]["id"] = existing_id
                    # Try POST with ID
                    result2, status_code2 = cortex_json_request(api_path, payload, method="POST")
                    if result2["status"] == "ok":
                        results.append({"type": "script", "name": script_name, "status": "ok", "api_path": api_path, "method": "json-update-post"})
                        deployed = True
                    else:
                        script_errors.append(f"JSON POST update (id={existing_id}): HTTP {status_code2}")
                        # Try PUT with ID
                        result3, status_code3 = cortex_json_request(api_path, payload, method="PUT")
                        if result3["status"] == "ok":
                            results.append({"type": "script", "name": script_name, "status": "ok", "api_path": api_path, "method": "json-update-put"})
                            deployed = True
                        else:
                            script_errors.append(f"JSON PUT update (id={existing_id}): HTTP {status_code3}")
                else:
                    script_errors.append(f"JSON {api_path}: 409 conflict, could not extract ID")
            else:
                script_errors.append(f"JSON {api_path}: HTTP {status_code}")
        except Exception as e:
            script_errors.append(f"JSON error: {e}")

        # Fallback: multipart upload
        if not deployed:
            for api_path in ["/xsoar/public/v1/automations/import", "/xsoar/public/v1/automation/upload"]:
                result, status_code = cortex_upload_file(api_path, yaml_path)
                if result["status"] == "ok":
                    results.append({"type": "script", "name": script_name, "status": "ok", "api_path": api_path, "method": "multipart"})
                    deployed = True
                    break
                script_errors.append(f"Multipart {api_path}: HTTP {status_code}")

        if not deployed:
            results.append({"type": "script", "name": script_name, "status": "error",
                           "message": " | ".join(script_errors)})

    # 2. Deploy playbooks (ZIP format required by Cortex Cloud API)
    playbooks = [
        ("K8s Container Escape Containment",
         os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_Spring4Shell_Containment.yml")),
        ("K8s Container Escape Forensic Analysis",
         os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_Forensic_Analysis.yml")),
        ("K8s Container Escape Search Similar Events",
         os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_Search_Similar_Events.yml")),
        ("K8s Container Escape Code-to-Cloud Pivot",
         os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_CodeToCloud_Pivot.yml")),
        ("Public S3 Bucket Auto Remediation",
         os.path.join(PLAYBOOK_DIR, "Public_S3_Bucket_Auto_Remediation.yml")),
    ]

    playbook_api_paths = [
        "/public_api/v1/playbooks/insert",
        "/xsoar/public/v1/playbooks/import",
    ]

    for pb_name, playbook_path in playbooks:
        deployed = False
        playbook_errors = []
        for api_path in playbook_api_paths:
            result, status_code = cortex_upload_playbook_zip(api_path, playbook_path)
            if result["status"] == "ok":
                results.append({"type": "playbook", "name": pb_name, "status": "ok", "api_path": api_path})
                deployed = True
                break
            playbook_errors.append(f"{api_path}: HTTP {status_code}")

        if not deployed:
            results.append({"type": "playbook", "name": pb_name, "status": "error",
                            "message": " | ".join(playbook_errors)})

    all_ok = all(r["status"] == "ok" for r in results)
    return jsonify({
        "status": "ok" if all_ok else "partial",
        "message": f"{'All' if all_ok else 'Some'} objects deployed to Cortex",
        "results": results,
    })


# ─── Cortex Policy Import ────────────────────────────────────────────────────

CORTEX_POLICY_DIR = os.path.join(PROJECT_ROOT, "cortex-policy")

CORTEX_POLICY_GROUP = "eks-k8s-container-escape-demo"
CORTEX_POLICY_NAME = "k8s_cortex-cloud-demo"

# Prevention profiles to create via API
# All modules set to "report" for the demo (detect but don't block)
CORTEX_PREVENTION_PROFILES = [
    {
        "name": "k8s-demo-malware",
        "profile_type": "Malware",
        "platform": "Linux",
        "description": "K8s Container Escape Demo - Malware profile (Report mode). Detects webshells, container escapes, credential theft without blocking the attack chain.",
        "modules": {},
    },
    {
        "name": "k8s-demo-exploit",
        "profile_type": "Exploit",
        "platform": "Linux",
        "description": "K8s Container Escape Demo - Exploit profile (Report mode). Detects exploitation techniques without blocking.",
        "modules": {},
    },
    {
        "name": "k8s-demo-agent-settings",
        "profile_type": "Agent Settings",
        "platform": "Linux",
        "description": "K8s Container Escape Demo - Agent settings for K8s nodes.",
        "modules": {},
    },
]


# ─── Code-to-Cloud Pivot ────────────────────────────────────────────────────

@app.route("/api/code-to-cloud-pivot", methods=["GET"])
def code_to_cloud_pivot():
    """
    Build a Code-to-Cloud pivot for an image digest. Returns 6 deep links
    (image registry, CWP findings, repo, commit, Dockerfile, Code Security)
    using the OCI labels we baked into the image at build time.
    Reads git HEAD locally to fill in commit_sha + repo_url defaults.
    """
    import re
    import subprocess

    raw_digest = (request.args.get("image_digest") or "").strip()
    raw_image_name = (request.args.get("image_name") or "").strip()

    # Normalize digest to bare 64-char hex
    s = raw_digest
    if "@sha256:" in s:
        s = s.split("@sha256:")[-1]
    elif s.startswith("sha256:"):
        s = s[len("sha256:"):]
    m = re.search(r"[a-fA-F0-9]{64}", s)
    digest_hex = m.group(0).lower() if m else ""

    # Defaults from local git
    try:
        commit_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True
        ).strip()
    except Exception:
        commit_sha = "main"
    try:
        raw_remote = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"], cwd=PROJECT_ROOT, text=True
        ).strip()
        if raw_remote.startswith("git@github.com:"):
            raw_remote = "https://github.com/" + raw_remote[len("git@github.com:"):]
        if raw_remote.endswith(".git"):
            raw_remote = raw_remote[:-4]
        repo_url = raw_remote
    except Exception:
        repo_url = "https://github.com/cortex-cloud-demo/K8s-Container-Escape-Demo"

    dockerfile_path = "Dockerfile"

    # Cortex console base
    tenant_url = (cortex_settings.get("base_url") or "").strip()
    console_base = ""
    if tenant_url:
        u = tenant_url.replace("https://", "").replace("http://", "").rstrip("/")
        if u.startswith("api-"):
            u = u[len("api-"):]
        console_base = "https://" + u

    # Build URLs (same logic as CodeToCloudPivot.py)
    if console_base and digest_hex:
        registry_url = console_base + "/assets/inventory?name=sha256:" + digest_hex
        cwp_url = (console_base + "/cloud-security/findings"
                   "?filter=asset_category:Container%20Image"
                   "&filter=asset_name:sha256:" + digest_hex +
                   "&filter=is_active:true")
    elif console_base:
        registry_url = console_base + "/assets/inventory"
        cwp_url = console_base + "/cloud-security/findings?filter=asset_category:Container%20Image"
    else:
        registry_url = ""
        cwp_url = ""

    if console_base and repo_url:
        safe_url = repo_url.replace(":", "%3A").replace("/", "%2F")
        codesec_url = console_base + "/cloud-security/code-security/repositories?filter=url:" + safe_url
    elif console_base:
        codesec_url = console_base + "/cloud-security/code-security"
    else:
        codesec_url = ""

    commit_url = (repo_url + "/commit/" + commit_sha) if commit_sha != "main" else (repo_url + "/commits/main")
    dockerfile_url = repo_url + "/blob/" + commit_sha + "/" + dockerfile_path.lstrip("/")

    return jsonify({
        "status": "ok",
        "image_digest": digest_hex,
        "image_name": raw_image_name,
        "repo_url": repo_url,
        "commit_sha": commit_sha,
        "dockerfile_path": dockerfile_path,
        "console_base": console_base,
        "pivots": {
            "registry":      {"label": "Image in Registry",         "url": registry_url},
            "cwp_findings":  {"label": "Active CVEs (CWP findings)", "url": cwp_url},
            "code_security": {"label": "Repo Code Security findings","url": codesec_url},
            "repo":          {"label": "Source repository",          "url": repo_url},
            "commit":        {"label": "Build commit",               "url": commit_url},
            "dockerfile":    {"label": "Dockerfile @ commit",        "url": dockerfile_url},
        },
    })


@app.route("/api/cortex/playbook-runs", methods=["GET"])
def cortex_playbook_runs():
    """Fetch recent playbook run statuses from Cortex."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex API not configured"}), 400

    api_path = "/public_api/v1/inv_playbook/get_playbook_runs"
    import time as _time
    now_ms = int(_time.time() * 1000)
    day_ago_ms = now_ms - (24 * 60 * 60 * 1000)

    payload = {
        "request_data": {
            "search_from": 0,
            "search_to": 10,
            "sort": {"field": "start_time", "keyword": "desc"},
            "filters": [
                {"field": "start_time", "operator": "gte", "value": day_ago_ms}
            ],
        }
    }

    result, status_code = cortex_json_request(api_path, payload)
    if result.get("status") != "ok":
        return jsonify(result), status_code

    try:
        data = json.loads(result.get("response", "{}"))
        runs = data.get("reply", {}).get("playbook_runs", [])
        return jsonify({"status": "ok", "runs": runs, "total": len(runs)})
    except Exception as e:
        return jsonify({"status": "ok", "runs": [], "raw": result.get("response", "")[:500]})


@app.route("/api/cortex/soc-alerts", methods=["GET"])
def cortex_soc_alerts():
    """Fetch recent XDR incidents/alerts for the SOC Live dashboard."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex API not configured"}), 400

    # Get incidents from last 24 hours
    api_path = "/public_api/v1/incidents/get_incidents"
    import time as _time
    now_ms = int(_time.time() * 1000)
    day_ago_ms = now_ms - (24 * 60 * 60 * 1000)

    payload = {
        "request_data": {
            "search_from": 0,
            "search_to": 50,
            "sort": {"field": "creation_time", "keyword": "desc"},
            "filters": [
                {"field": "creation_time", "operator": "gte", "value": day_ago_ms}
            ],
        }
    }

    result, status_code = cortex_json_request(api_path, payload)
    if result.get("status") != "ok":
        return jsonify(result), status_code

    try:
        data = json.loads(result.get("response", "{}"))
        incidents = data.get("reply", {}).get("incidents", [])
        alerts = []
        for inc in incidents:
            alerts.append({
                "id": inc.get("incident_id"),
                "name": inc.get("description", inc.get("incident_name", "Unknown")),
                "severity": inc.get("severity", "unknown"),
                "status": inc.get("status", ""),
                "created": inc.get("creation_time"),
                "host": inc.get("hosts", [""])[0] if inc.get("hosts") else "",
                "mitre": inc.get("mitre_techniques_ids_and_names", []),
                "alert_count": inc.get("alert_count", 0),
                "category": inc.get("alert_categories", []),
            })
        return jsonify({"status": "ok", "alerts": alerts, "total": len(alerts)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/cortex/policy-check", methods=["GET"])
def cortex_policy_check():
    """Check if Cortex policy objects exist on the configured tenant."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex API not configured"}), 400

    results = []

    # 1. Check prevention profiles to create
    for profile in CORTEX_PREVENTION_PROFILES:
        results.append({
            "type": f"Profile: {profile['profile_type']}",
            "name": profile["name"],
            "exists": None,
            "detail": f"{profile['platform']} - will be created on import",
        })

    return jsonify({"status": "ok", "results": results})


@app.route("/api/cortex/policy-check-legacy", methods=["GET"])
def cortex_policy_check_legacy():
    """Legacy: Check endpoint group and policy assignment."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex API not configured"}), 400

    results = []

    try:
        resp, code = cortex_json_request(
            "/public_api/v1/endpoints/get_endpoint",
            {"request_data": {"search_from": 0, "search_to": 100}},
        )
        if resp.get("status") == "ok":
            data = json.loads(resp.get("response", "{}"))
            reply = data.get("reply", {})
            endpoints = reply.get("endpoints", []) if isinstance(reply, dict) else []
            matched = [e for e in endpoints if CORTEX_POLICY_NAME in str(e.get("policy_name", ""))]
            results.append({
                "type": "Prevention Policy",
                "name": CORTEX_POLICY_NAME,
                "exists": len(matched) > 0,
                "detail": f"assigned to {len(matched)}/{len(endpoints)} endpoint(s)",
            })
        else:
            results.append({"type": "Prevention Policy", "name": CORTEX_POLICY_NAME, "exists": None, "detail": resp.get("message", "")})
    except Exception as e:
        results.append({"type": "Prevention Policy", "name": CORTEX_POLICY_NAME, "exists": None, "detail": str(e)})

    # 3. Check prevention profiles to create
    for profile in CORTEX_PREVENTION_PROFILES:
        results.append({
            "type": f"Profile: {profile['profile_type']}",
            "name": profile["name"],
            "exists": None,
            "detail": f"{profile['platform']} - will be created on import",
        })

    return jsonify({"status": "ok", "results": results})


@app.route("/api/cortex/policy-list-profiles", methods=["GET"])
def cortex_policy_list_profiles():
    """List existing prevention profiles to discover valid module names."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex API not configured"}), 400
    api_path = "/public_api/v1/profiles/prevention/list"
    result, status_code = cortex_json_request(api_path, {"request_data": {}})
    return jsonify(result), status_code


@app.route("/api/cortex/policy-import", methods=["POST"])
def cortex_policy_import():
    """Create Cortex prevention profiles via API."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex API not configured"}), 400

    results = []
    api_path = "/public_api/v1/profiles/prevention/add"

    for profile in CORTEX_PREVENTION_PROFILES:
        profile_data = {
            "name": profile["name"],
            "profile_type": profile["profile_type"],
            "platform": profile["platform"],
            "description": profile["description"],
        }
        if profile.get("modules"):
            profile_data["modules"] = profile["modules"]
        payload = {"request_data": profile_data}

        try:
            result, status_code = cortex_json_request(api_path, payload)
            if result.get("status") == "ok":
                results.append({
                    "type": f"Profile: {profile['profile_type']}",
                    "name": profile["name"],
                    "status": "ok",
                    "message": "Created successfully",
                })
            else:
                msg = result.get("message", "") + " " + result.get("response", "")
                # Check if profile already exists
                if status_code == 409 or "already exists" in msg.lower() or "duplicate" in msg.lower():
                    results.append({
                        "type": f"Profile: {profile['profile_type']}",
                        "name": profile["name"],
                        "status": "exists",
                        "message": "Profile already exists",
                    })
                else:
                    results.append({
                        "type": f"Profile: {profile['profile_type']}",
                        "name": profile["name"],
                        "status": "error",
                        "message": f"HTTP {status_code}: {msg[:300]}",
                    })
        except Exception as e:
            results.append({
                "type": f"Profile: {profile['profile_type']}",
                "name": profile["name"],
                "status": "error",
                "message": str(e),
            })

    overall = "ok" if all(r.get("status") in ("ok", "exists") for r in results) else "partial" if any(r.get("status") in ("ok", "exists") for r in results) else "error"
    return jsonify({"status": overall, "results": results})


# ─── XDR Agent for Kubernetes ────────────────────────────────────────────────

# In-memory store for XDR distribution
xdr_distribution = {
    "distribution_id": "",
    "status": "",
}


@app.route("/api/cortex/xdr-k8s-versions", methods=["GET"])
def xdr_k8s_versions():
    """Get available agent versions from Cortex API."""
    api_path = "/public_api/v1/distributions/get_versions"
    result, status_code = cortex_json_request(api_path, {})
    if result.get("status") == "ok":
        try:
            resp = json.loads(result.get("response", "{}"))
            linux_versions = resp.get("reply", {}).get("linux", [])
            return jsonify({"status": "ok", "versions": linux_versions})
        except Exception:
            return jsonify({"status": "ok", "versions": [], "raw": result.get("response", "")[:500]})
    return jsonify(result), status_code


@app.route("/api/cortex/xdr-k8s-deploy", methods=["POST"])
def xdr_k8s_deploy():
    """Create or reuse a Cortex XDR Kubernetes distribution (agent installer).

    Flow:
    1. Check if a K8s distribution already exists via get_distributions
    2. If exists with latest agent version, reuse it
    3. Otherwise, get latest agent version and create a new distribution
    """
    # Get cluster name from terraform outputs
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        cluster_name = tf_output(TERRAFORM_DIR, "cluster_name", env) or "eks-escape-demo"
    except Exception:
        cluster_name = "eks-escape-demo"

    dist_name = request.json.get("name", f"K8s-Container-Escape-Demo-{cluster_name}")
    agent_version = request.json.get("agent_version", "")
    tags = ["K8s-Container-Escape-Demo", cluster_name]

    # Step 1: Get latest agent version
    latest_version = ""
    ver_result, ver_status = cortex_json_request("/public_api/v1/distributions/get_versions", {})
    if ver_result.get("status") == "ok":
        try:
            resp = json.loads(ver_result.get("response", "{}"))
            linux_versions = resp.get("reply", {}).get("linux", [])
            if linux_versions:
                latest_version = linux_versions[-1]
        except Exception:
            pass

    if not agent_version:
        agent_version = latest_version

    # Step 2: Check for existing K8s distributions
    search_payload = {
        "request_data": {
            "search_from": 0,
            "search_to": 100,
            "sort": {"field": "name", "keyword": "asc"},
            "filters": [
                {"field": "package_type", "operator": "eq", "value": "kubernetes"},
                {"field": "name", "operator": "contains", "value": "K8s-Container-Escape-Demo"},
            ],
        }
    }

    existing_dist = None
    list_result, list_status = cortex_json_request(
        "/public_api/v1/distributions/get_distributions", search_payload
    )
    if list_result.get("status") == "ok":
        try:
            resp = json.loads(list_result.get("response", "{}"))
            distributions = resp.get("reply", {}).get("data", [])
            for dist in distributions:
                dist_status = dist.get("status", "")
                dist_ver = dist.get("agent_version", "")
                # Reuse if completed and matches latest version
                if dist_status == "completed" and dist_ver == agent_version:
                    existing_dist = dist
                    break
                # Also reuse if still in progress
                if dist_status == "in_progress":
                    existing_dist = dist
                    break
        except Exception:
            pass

    if existing_dist:
        dist_id = existing_dist["distribution_id"]
        xdr_distribution["distribution_id"] = dist_id
        xdr_distribution["status"] = existing_dist.get("status", "")
        return jsonify({
            "status": "exists",
            "message": f"Reusing existing distribution: {existing_dist.get('name', dist_id)}",
            "distribution_id": dist_id,
            "agent_version": existing_dist.get("agent_version", ""),
            "cluster_name": cluster_name,
            "distribution_status": existing_dist.get("status", ""),
            "tags": existing_dist.get("tags", []),
        })

    # Step 3: Create a new distribution
    create_payload = {
        "request_data": {
            "name": dist_name,
            "package_type": "kubernetes",
            "agent_version": agent_version,
            "deployment_platform": "standard",
            "default_namespace": "cortex-xdr",
            "cluster_name": cluster_name,
            "run_on_master_node": True,
            "run_on_all_nodes": True,
            "description": f"XDR agent for K8s Container Escape Demo - cluster {cluster_name}",
            "endpoint_tags": tags,
        }
    }

    result, status_code = cortex_json_request(
        "/public_api/v1/distributions/create", create_payload
    )

    if result.get("status") == "ok":
        try:
            resp = json.loads(result.get("response", "{}"))
            dist_id = resp.get("reply", {}).get("distribution_id", "")
            xdr_distribution["distribution_id"] = dist_id
            xdr_distribution["status"] = "pending"
            return jsonify({
                "status": "ok",
                "message": f"Distribution created: {dist_name}",
                "distribution_id": dist_id,
                "agent_version": agent_version,
                "cluster_name": cluster_name,
                "tags": tags,
            })
        except Exception:
            return jsonify({
                "status": "ok",
                "message": "Distribution created (could not parse response)",
                "raw": result.get("response", "")[:500],
            })

    return jsonify(result), status_code


@app.route("/api/cortex/xdr-k8s-status", methods=["GET"])
def xdr_k8s_status():
    """Check the status of the XDR K8s distribution."""
    dist_id = request.args.get("distribution_id", "") or xdr_distribution.get("distribution_id", "")
    if not dist_id:
        return jsonify({"status": "error", "message": "No distribution ID. Create one first."}), 400

    payload = {"request_data": {"distribution_id": dist_id}}
    result, status_code = cortex_json_request(
        "/public_api/v1/distributions/get_status", payload
    )

    if result.get("status") == "ok":
        try:
            resp = json.loads(result.get("response", "{}"))
            dist_status = resp.get("reply", {}).get("status", "unknown")
            xdr_distribution["status"] = dist_status
            return jsonify({
                "status": "ok",
                "distribution_id": dist_id,
                "distribution_status": dist_status,
            })
        except Exception:
            return jsonify({"status": "ok", "raw": result.get("response", "")[:500]})

    return jsonify(result), status_code


@app.route("/api/cortex/xdr-k8s-agent-status", methods=["GET"])
def xdr_k8s_agent_status():
    """Check the XDR agent installation status on the K8s cluster via kubectl."""
    env = os.environ.copy()
    env.update(get_aws_env())

    try:
        # Check for Cortex agent pods in cortex-xdr namespace
        result = subprocess.run(
            toolbox_cmd(
                "kubectl get pods -n cortex-xdr -o "
                "\"jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name} {.status.phase}{'\\n'}{end}\""
            ),
            shell=True, capture_output=True, text=True, env=env, timeout=15
        )
        pods_output = result.stdout.strip()

        if not pods_output:
            # Try broader search with label
            result2 = subprocess.run(
                toolbox_cmd(
                    "kubectl get pods -A -l app.kubernetes.io/name=cortex-agent -o "
                    "\"jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name} {.status.phase}{'\\n'}{end}\""
                ),
                shell=True, capture_output=True, text=True, env=env, timeout=15
            )
            pods_output = result2.stdout.strip()

        if not pods_output:
            # Last resort: search for any cortex/xdr pod
            result3 = subprocess.run(
                toolbox_cmd("kubectl get pods -A --no-headers"),
                shell=True, capture_output=True, text=True, env=env, timeout=15
            )
            xdr_lines = [l for l in result3.stdout.strip().split("\n") if l and ("cortex" in l.lower() or "xdr" in l.lower())]
            pods_output = "\n".join(xdr_lines) if xdr_lines else ""

        if not pods_output:
            return jsonify({"status": "ok", "installed": False, "message": "No XDR agent pods found", "pods": []})

        pods = []
        for line in pods_output.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                pods.append({"name": parts[0], "phase": parts[1]})
            elif parts:
                pods.append({"name": parts[0], "phase": "unknown"})

        all_running = all(p["phase"] == "Running" for p in pods)
        return jsonify({
            "status": "ok",
            "installed": True,
            "agent_status": "Running" if all_running else "Pending",
            "pods_total": len(pods),
            "pods_running": sum(1 for p in pods if p["phase"] == "Running"),
            "pods": pods,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "kubectl timed out"}), 504
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/cortex/xdr-k8s-agent-pods", methods=["POST"])
def xdr_k8s_agent_pods():
    """Show detailed agent status on the cluster."""
    cmd = """set -e
echo "=================================================="
echo "  Cortex Cloud Security Agent - Cluster Status"
echo "=================================================="
echo ""

echo "==> Agent DaemonSet:"
kubectl get daemonset -A -l app=cortex-xdr -o wide 2>/dev/null || \
kubectl get daemonset -n cortex-xdr -o wide 2>/dev/null || \
echo "  No DaemonSet found"
echo ""

echo "==> Agent Pods:"
kubectl get pods -A -l app=cortex-xdr -o wide 2>/dev/null || \
kubectl get pods -n cortex-xdr -o wide 2>/dev/null || \
echo "  No agent pods found"
echo ""

echo "==> All DaemonSets:"
kubectl get daemonset -A -o wide 2>/dev/null
echo ""

echo "==> Namespace cortex-xdr:"
kubectl get all -n cortex-xdr 2>/dev/null || echo "  Namespace not found"
echo ""
echo "=================================================="
"""
    task_id = create_task("XDR Agent: Status Check", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


@app.route("/api/cortex/xdr-k8s-install", methods=["POST"])
def xdr_k8s_install():
    """Download the distribution YAML from Cortex and apply to the EKS cluster.
    Uses the same payload as the Cortex console download:
    POST /public_api/v1/distributions/get_dist_url with
    {"distribution_id": "...", "package_type": "yaml", "cpu_type": null}
    """
    dist_id = request.json.get("distribution_id", "") or xdr_distribution.get("distribution_id", "")
    if not dist_id:
        return jsonify({"status": "error", "message": "No distribution ID. Create one first."}), 400

    base_url = cortex_settings.get("base_url", "")
    api_key = cortex_settings.get("api_key", "")
    api_key_id = cortex_settings.get("api_key_id", "")

    if not base_url or not api_key or not api_key_id:
        return jsonify({"status": "error", "message": "Missing Cortex credentials. Configure them in Settings."}), 400

    # Everything in a single shell task for full visibility
    cmd = f"""set -e
echo "=================================================="
echo "  XDR Agent for Kubernetes - Install"
echo "=================================================="
echo ""

DIST_ID="{dist_id}"
XDR_URL="{base_url}"
AUTH_ID="{api_key_id}"
AUTH_TOKEN="{api_key}"

# Step 1: Get distribution download URL
echo "==> [1/3] Getting distribution download URL..."
echo "    Distribution ID: $DIST_ID"

RESPONSE=$(curl --silent --location "$XDR_URL/public_api/v1/distributions/get_dist_url" \
  --header "Accept: application/json" \
  --header "x-xdr-auth-id: $AUTH_ID" \
  --header "Authorization: $AUTH_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{{"request_data": {{"distribution_id": "'$DIST_ID'", "package_type": "yaml"}}}}')

echo "    API Response: $RESPONSE"

# Extract distribution_url
DIST_URL=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('reply',{{}}).get('distribution_url',''))" 2>/dev/null || echo "")

if [ -z "$DIST_URL" ] || [ "$DIST_URL" = "None" ]; then
    echo "[FAIL] Could not extract distribution_url from response."
    echo "    Full response: $RESPONSE"
    exit 1
fi

echo "    Download URL: $DIST_URL"
echo ""

# Step 2: Download the YAML from the distribution URL
echo "==> [2/3] Downloading K8s YAML..."
HTTP_CODE=$(curl --silent --location --output /tmp/xdr-agent-k8s.yaml --write-out "%{{http_code}}" \
  --header "x-xdr-auth-id: $AUTH_ID" \
  --header "Authorization: $AUTH_TOKEN" \
  "$DIST_URL")

FILE_SIZE=$(wc -c < /tmp/xdr-agent-k8s.yaml | tr -d ' ')
echo "    HTTP Status: $HTTP_CODE"
echo "    Downloaded: /tmp/xdr-agent-k8s.yaml ($FILE_SIZE bytes)"

if [ "$HTTP_CODE" != "200" ]; then
    echo "[FAIL] Download failed (HTTP $HTTP_CODE):"
    cat /tmp/xdr-agent-k8s.yaml
    exit 1
fi

# Check if the response is an error (JSON instead of YAML)
if head -1 /tmp/xdr-agent-k8s.yaml | grep -q "err_code"; then
    echo "[FAIL] Cortex returned an error instead of YAML:"
    cat /tmp/xdr-agent-k8s.yaml
    exit 1
fi

echo ""
echo "    YAML preview:"
echo "    ---"
head -30 /tmp/xdr-agent-k8s.yaml | sed 's/^/    /'
echo ""
echo "    ... (truncated)"
echo ""

# Step 3: Apply to cluster
echo "==> [3/3] Applying XDR agent to EKS cluster..."
kubectl apply -f /tmp/xdr-agent-k8s.yaml
echo ""

echo "==> Waiting for XDR agent pods to start (15s)..."
sleep 15

echo ""
echo "==> XDR agent pods status:"
kubectl get pods -A -l app=cortex-xdr -o wide 2>/dev/null || kubectl get pods -A | grep -i xdr || echo "(no XDR pods found yet)"
echo ""
kubectl get daemonset -A 2>/dev/null | head -5 || true
echo ""

echo "=================================================="
echo "  XDR Agent deployment complete!"
echo "=================================================="
"""

    task_id = create_task("XDR Agent: Install on K8s", cmd, use_toolbox=True)
    return jsonify({
        "status": "ok",
        "task_id": task_id,
        "distribution_id": dist_id,
    })


# ─── Reset Containment (Cleanup for Demo Replay) ─────────────────────────────


@app.route("/api/containment/reset", methods=["POST"])
def reset_containment():
    """Undo all containment actions so the demo can be replayed."""
    cmd = r"""
set -e
echo "=================================================="
echo "  RESET CONTAINMENT - Preparing for demo replay"
echo "=================================================="
echo ""

echo "==> [1/5] Removing NetworkPolicy containment-deny-all..."
kubectl delete networkpolicy containment-deny-all -n vuln-app --ignore-not-found=true
echo "    Done."
echo ""

echo "==> [2/5] Recreating ClusterRoleBinding vuln-app-cluster-admin..."
cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vuln-app-cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: vuln-app-sa
    namespace: vuln-app
EOF
echo "    Done."
echo ""

echo "==> [3/5] Uncordoning all nodes..."
for NODE in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
  kubectl uncordon "$NODE" 2>/dev/null || true
done
echo "    Done."
echo ""

echo "==> [4/5] Scaling deployment vuln-app back to 1 replica..."
kubectl scale deployment vuln-app -n vuln-app --replicas=1 2>/dev/null || echo "    Deployment not found, skipping."
echo "    Done."
echo ""

echo "==> [5/5] Waiting for pod to be ready..."
kubectl rollout status deployment/vuln-app -n vuln-app --timeout=120s 2>/dev/null || echo "    Timeout or deployment not found."
echo ""

echo "==> Verifying state..."
echo ""
echo "--- Pods ---"
kubectl get pods -n vuln-app -o wide 2>/dev/null || echo "No pods"
echo ""
echo "--- NetworkPolicies ---"
kubectl get networkpolicy -n vuln-app 2>/dev/null || echo "None"
echo ""
echo "--- ClusterRoleBinding ---"
kubectl get clusterrolebinding vuln-app-cluster-admin -o wide 2>/dev/null || echo "Not found"
echo ""
echo "--- Nodes ---"
kubectl get nodes -o wide 2>/dev/null
echo ""
echo "=================================================="
echo "  RESET COMPLETE - Demo ready to replay"
echo "=================================================="
"""
    task_id = create_task("Reset Containment", cmd, use_toolbox=True)
    return jsonify({"task_id": task_id})


# ─── Task Status ─────────────────────────────────────────────────────────────


# ─── Security Posture (Radar) ──────────────────────────────────────────────


@app.route("/api/security/posture", methods=["GET"])
def security_posture():
    """Query K8s cluster and return security posture scores for the radar chart."""
    env = os.environ.copy()
    env.update(get_aws_env())
    timeout = 10

    posture = {
        "network_isolation": 0,
        "rbac_security": 0,
        "pod_security": 0,
        "node_security": 0,
        "deployment_control": 0,
        "evidence": 0,
        "objects": {},
    }

    # 1. NetworkPolicy: deny-all exists?
    r = subprocess.run(
        toolbox_cmd("kubectl get networkpolicy containment-deny-all -n vuln-app -o jsonpath='{.metadata.name}' 2>/dev/null"),
        shell=True, capture_output=True, text=True, env=env, timeout=timeout,
    )
    has_netpol = r.returncode == 0 and "containment-deny-all" in r.stdout
    posture["network_isolation"] = 95 if has_netpol else 10
    posture["objects"]["networkpolicy"] = {
        "name": "containment-deny-all",
        "exists": has_netpol,
        "status": "deny-all applied" if has_netpol else "no policy (open)",
        "secure": has_netpol,
    }

    # 2. ClusterRoleBinding: cluster-admin for vuln-app SA?
    r = subprocess.run(
        toolbox_cmd("kubectl get clusterrolebinding vuln-app-cluster-admin -o jsonpath='{.metadata.name}' 2>/dev/null"),
        shell=True, capture_output=True, text=True, env=env, timeout=timeout,
    )
    has_crb = r.returncode == 0 and "vuln-app-cluster-admin" in r.stdout
    posture["rbac_security"] = 10 if has_crb else 95
    posture["objects"]["clusterrolebinding"] = {
        "name": "vuln-app-cluster-admin",
        "exists": has_crb,
        "status": "cluster-admin BOUND" if has_crb else "revoked",
        "secure": not has_crb,
    }

    # 3. Pods: running in vuln-app?
    r = subprocess.run(
        toolbox_cmd("kubectl get pods -n vuln-app -o json 2>/dev/null"),
        shell=True, capture_output=True, text=True, env=env, timeout=timeout,
    )
    pods = []
    pod_count = 0
    any_privileged = False
    if r.returncode == 0:
        try:
            items = json.loads(r.stdout).get("items", [])
            pod_count = len(items)
            for p in items:
                name = p["metadata"]["name"]
                phase = p.get("status", {}).get("phase", "Unknown")
                priv = False
                for c in p.get("spec", {}).get("containers", []):
                    if c.get("securityContext", {}).get("privileged"):
                        priv = True
                        any_privileged = True
                host_pid = p.get("spec", {}).get("hostPID", False)
                pods.append({"name": name, "phase": phase, "privileged": priv, "hostPID": host_pid})
        except Exception:
            pass

    posture["pod_security"] = 95 if pod_count == 0 else (5 if any_privileged else 40)
    posture["objects"]["pods"] = {
        "count": pod_count,
        "items": pods[:5],
        "privileged": any_privileged,
        "status": "no pods running" if pod_count == 0 else f"{pod_count} pod(s) running" + (" [PRIVILEGED]" if any_privileged else ""),
        "secure": pod_count == 0,
    }

    # 4. Deployment: replicas?
    r = subprocess.run(
        toolbox_cmd("kubectl get deployment vuln-app -n vuln-app -o json 2>/dev/null"),
        shell=True, capture_output=True, text=True, env=env, timeout=timeout,
    )
    replicas = -1
    ready_replicas = 0
    if r.returncode == 0:
        try:
            dep = json.loads(r.stdout)
            replicas = dep.get("spec", {}).get("replicas", 0)
            ready_replicas = dep.get("status", {}).get("readyReplicas", 0) or 0
        except Exception:
            pass

    posture["deployment_control"] = 95 if replicas == 0 else (10 if replicas > 0 else 50)
    posture["objects"]["deployment"] = {
        "name": "vuln-app",
        "replicas": replicas,
        "ready": ready_replicas,
        "status": f"{replicas} replica(s) ({ready_replicas} ready)" if replicas >= 0 else "not found",
        "secure": replicas == 0,
    }

    # 5. Nodes: cordoned?
    r = subprocess.run(
        toolbox_cmd("kubectl get nodes -o json 2>/dev/null"),
        shell=True, capture_output=True, text=True, env=env, timeout=timeout,
    )
    nodes = []
    any_cordoned = False
    if r.returncode == 0:
        try:
            for n in json.loads(r.stdout).get("items", []):
                name = n["metadata"]["name"]
                unschedulable = n.get("spec", {}).get("unschedulable", False)
                if unschedulable:
                    any_cordoned = True
                nodes.append({"name": name, "cordoned": bool(unschedulable)})
        except Exception:
            pass

    posture["node_security"] = 90 if any_cordoned else 25
    posture["objects"]["nodes"] = {
        "items": nodes[:5],
        "any_cordoned": any_cordoned,
        "status": "node(s) cordoned" if any_cordoned else "all nodes schedulable",
        "secure": any_cordoned,
    }

    # 6. Evidence: check if events exist
    r = subprocess.run(
        toolbox_cmd("kubectl get events -n vuln-app --no-headers 2>/dev/null | wc -l"),
        shell=True, capture_output=True, text=True, env=env, timeout=timeout,
    )
    event_count = 0
    try:
        event_count = int(r.stdout.strip())
    except Exception:
        pass
    posture["evidence"] = min(90, event_count * 10) if event_count > 0 else 5
    posture["objects"]["events"] = {
        "count": event_count,
        "status": f"{event_count} events captured" if event_count > 0 else "no events",
        "secure": event_count > 0,
    }

    # Overall score
    scores = [
        posture["network_isolation"],
        posture["rbac_security"],
        posture["pod_security"],
        posture["node_security"],
        posture["deployment_control"],
        posture["evidence"],
    ]
    posture["overall_score"] = int(sum(scores) / len(scores))

    return jsonify(posture)


@app.route("/api/onboarding/aws/status", methods=["GET"])
def onboarding_aws_status():
    """Check if the current AWS account is already onboarded in Cortex Cloud."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex credentials not configured."}), 400

    # Get current AWS account ID
    env = os.environ.copy()
    env.update(get_aws_env())
    try:
        sts = subprocess.run(
            toolbox_cmd("aws sts get-caller-identity --output json"),
            shell=True, capture_output=True, text=True, env=env,
        )
        if sts.returncode != 0:
            return jsonify({"status": "error", "message": f"AWS STS failed: {sts.stderr.strip()}"}), 400
        account_id = json.loads(sts.stdout).get("Account", "")
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    # Step 1: get all non-pending AWS instances
    list_payload = {
        "request_data": {
            "filter_data": {
                "sort": [{"FIELD": "STATUS", "ORDER": "DESC"}],
                "paging": {"from": 0, "to": 50},
                "filter": {
                    "AND": [
                        {"SEARCH_FIELD": "CLOUD_PROVIDER", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "AWS"}
                    ]
                },
            }
        }
    }
    list_result, list_code = cortex_json_request("/public_api/v1/cloud_onboarding/get_instances", list_payload)
    if list_code != 200:
        return jsonify(list_result), list_code

    try:
        instances = json.loads(list_result.get("response", "{}")).get("reply", {}).get("DATA", [])
    except Exception:
        return jsonify({"status": "error", "message": "Failed to parse get_instances response."}), 500

    # Step 2: for each instance call get_accounts filtered by the current AWS account ID
    matched_instance = None
    matched_account = None

    for inst in instances:
        inst_id = inst.get("instance_id", "")
        if not inst_id:
            continue

        accounts_payload = {
            "request_data": {
                "instance_id": inst_id,
                "filter_data": {
                    "sort": [{"FIELD": "STATUS", "ORDER": "DESC"}],
                    "paging": {"from": 0, "to": 50},
                    "filter": {
                        "AND": [
                            {"SEARCH_FIELD": "CLOUD_ACCOUNT_ID", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": account_id}
                        ]
                    },
                },
            }
        }
        acc_result, acc_code = cortex_json_request("/public_api/v1/cloud_onboarding/get_accounts", accounts_payload)
        if acc_code != 200:
            continue
        try:
            accounts_data = json.loads(acc_result.get("response", "{}")).get("reply", {}).get("DATA", [])
        except Exception:
            continue

        if accounts_data:
            matched_instance = inst
            matched_account = accounts_data[0]
            break

    return jsonify({
        "status": "ok",
        "account_id": account_id,
        "onboarded": matched_instance is not None,
        "instance": matched_instance,
        "account": matched_account,
        "total_aws_instances": len(instances),
    })


@app.route("/api/onboarding/aws", methods=["POST"])
def onboarding_aws():
    """Onboard AWS to Cortex Cloud Security via CloudFormation deployed with the AWS CLI."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex credentials not configured."}), 400

    # Resolve AWS account ID and region
    env = os.environ.copy()
    env.update(get_aws_env())
    region = aws_credentials.get("aws_region") or "eu-west-3"

    try:
        sts = subprocess.run(
            toolbox_cmd("aws sts get-caller-identity --output json"),
            shell=True, capture_output=True, text=True, env=env,
        )
        if sts.returncode != 0:
            return jsonify({"status": "error", "message": f"AWS STS failed: {sts.stderr.strip()}"}), 400
        identity = json.loads(sts.stdout)
        account_id = identity.get("Account", "unknown")
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to get AWS identity: {e}"}), 500

    instance_name = f"AWS-{account_id}"

    payload = {
        "request_data": {
            "scope": "ACCOUNT",
            "scan_mode": "MANAGED",
            "instance_name": instance_name,
            "cloud_provider": "AWS",
            "cloud_partition": "COMMERCIAL",
            "custom_resources_tags": [],
            "collection_configuration": {
                "audit_logs": {
                    "enabled": True,
                    "collection_method": "AUTOMATED",
                    "data_events": True,
                }
            },
            "scope_modifications": {
                "regions": {"enabled": False},
            },
            "additional_capabilities": {
                "xsiam_analytics": True,
                "data_security_posture_management": True,
                "registry_scanning": True,
                "registry_scanning_options": {"type": "ECR"},
                "serverless_scanning": True,
                "agentless_disk_scanning": True,
                "kubernetes_security": True,
            },
        }
    }

    result, status_code = cortex_json_request(
        "/public_api/v1/cloud_onboarding/create_instance_template", payload
    )

    if status_code != 200:
        return jsonify(result), status_code

    # Parse CloudFormation parameters from the console link fragment
    # Link format: https://console.aws.amazon.com/cloudformation/home?region=X#/stacks/create/review?templateURL=...&stackName=...&param_Foo=Bar
    try:
        resp_data = json.loads(result.get("response", "{}"))
        cf_link = resp_data.get("reply", {}).get("automated", {}).get("link", "")
        tracking_guid = resp_data.get("reply", {}).get("automated", {}).get("tracking_guid", "")
    except Exception:
        return jsonify({"status": "error", "message": "Failed to parse Cortex API response."}), 500

    if not cf_link:
        return jsonify({"status": "error", "message": "Cortex API returned no CloudFormation link."}), 500

    parsed = urllib.parse.urlparse(cf_link)
    fragment = parsed.fragment  # e.g. /stacks/create/review?templateURL=...&stackName=...
    qs = fragment.split("?", 1)[1] if "?" in fragment else ""
    params = urllib.parse.parse_qs(qs, keep_blank_values=True)

    template_url = params.get("templateURL", [""])[0]
    stack_name = params.get("stackName", [f"CortexCloud-{account_id}"])[0]

    # Collect param_* entries as CloudFormation --parameters
    cf_params = []
    for key, values in params.items():
        if key.startswith("param_"):
            cf_params.append(f"ParameterKey={key[6:]},ParameterValue={values[0]}")

    params_arg = ""
    if cf_params:
        params_arg = "--parameters " + " ".join(f'"{p}"' for p in cf_params)

    script = f"""
set -e
echo "=== Cortex Cloud Onboarding ==="
echo "Account   : {account_id}"
echo "Region    : {region}"
echo "Stack     : {stack_name}"
echo "Tracking  : {tracking_guid}"
echo ""

echo "Creating CloudFormation stack..."
aws cloudformation create-stack \\
  --stack-name "{stack_name}" \\
  --template-url "{template_url}" \\
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \\
  {params_arg} \\
  --region "{region}" \\
  --output json

echo ""
echo "Waiting for stack to complete (this may take a few minutes)..."
aws cloudformation wait stack-create-complete \\
  --stack-name "{stack_name}" \\
  --region "{region}"

echo ""
echo "Stack creation complete."
aws cloudformation describe-stacks \\
  --stack-name "{stack_name}" \\
  --region "{region}" \\
  --query "Stacks[0].StackStatus" \\
  --output text
"""

    task_id = create_task(
        name="AWS Onboarding — Cortex Cloud Security",
        command=script,
        env_extra=get_aws_env(),
        use_toolbox=True,
    )
    return jsonify({"status": "ok", "task_id": task_id})


# ─── GCP Onboarding ───────────────────────────────────────────────────────────


@app.route("/api/onboarding/gcp/status", methods=["GET"])
def onboarding_gcp_status():
    """Check if the current GCP project is already onboarded in Cortex Cloud."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex credentials not configured."}), 400

    project_id = gcp_credentials.get("project_id", "")
    if not project_id:
        return jsonify({"status": "error", "message": "GCP project_id not configured. Add GCP credentials first."}), 400

    list_payload = {
        "request_data": {
            "filter_data": {
                "sort": [{"FIELD": "STATUS", "ORDER": "DESC"}],
                "paging": {"from": 0, "to": 50},
                "filter": {
                    "AND": [
                        {"SEARCH_FIELD": "CLOUD_PROVIDER", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "GCP"}
                    ]
                },
            }
        }
    }
    list_result, list_code = cortex_json_request("/public_api/v1/cloud_onboarding/get_instances", list_payload)
    if list_code != 200:
        return jsonify(list_result), list_code

    try:
        instances = json.loads(list_result.get("response", "{}")).get("reply", {}).get("DATA", [])
    except Exception:
        return jsonify({"status": "error", "message": "Failed to parse get_instances response."}), 500

    matched_instance = None
    matched_account = None

    for inst in instances:
        inst_id = inst.get("instance_id", "")
        if not inst_id:
            continue

        accounts_payload = {
            "request_data": {
                "instance_id": inst_id,
                "filter_data": {
                    "sort": [{"FIELD": "STATUS", "ORDER": "DESC"}],
                    "paging": {"from": 0, "to": 50},
                    "filter": {
                        "AND": [
                            {"SEARCH_FIELD": "CLOUD_ACCOUNT_ID", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": project_id}
                        ]
                    },
                },
            }
        }
        acc_result, acc_code = cortex_json_request("/public_api/v1/cloud_onboarding/get_accounts", accounts_payload)
        if acc_code != 200:
            continue
        try:
            accounts_data = json.loads(acc_result.get("response", "{}")).get("reply", {}).get("DATA", [])
        except Exception:
            continue

        if accounts_data:
            matched_instance = inst
            matched_account = accounts_data[0]
            break

    return jsonify({
        "status": "ok",
        "project_id": project_id,
        "onboarded": matched_instance is not None,
        "instance": matched_instance,
        "account": matched_account,
        "total_gcp_instances": len(instances),
    })


@app.route("/api/onboarding/gcp", methods=["POST"])
def onboarding_gcp():
    """Onboard GCP project to Cortex Cloud Security.

    Calls create_instance_template, downloads the Terraform template, and
    applies it inside the toolbox container (which already has GCP credentials).
    """
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex credentials not configured."}), 400

    project_id = gcp_credentials.get("project_id", "")
    region = gcp_credentials.get("region") or "europe-west1"

    if not project_id:
        return jsonify({"status": "error", "message": "GCP project_id not configured. Add GCP credentials first."}), 400

    instance_name = f"GCP-{project_id}"

    payload = {
        "request_data": {
            "scope": "ACCOUNT",
            "scan_mode": "MANAGED",
            "instance_name": instance_name,
            "cloud_provider": "GCP",
            "cloud_partition": "COMMERCIAL",
            "custom_resources_tags": [],
            "collection_configuration": {
                "audit_logs": {
                    "enabled": True,
                    "collection_method": "AUTOMATED",
                }
            },
            "scope_modifications": {
                "regions": {"enabled": False},
            },
            "additional_capabilities": {
                "xsiam_analytics": True,
                "data_security_posture_management": True,
                "registry_scanning": True,
                "registry_scanning_options": {"type": "GCR"},
                "serverless_scanning": True,
                "agentless_disk_scanning": True,
            },
        }
    }

    result, status_code = cortex_json_request(
        "/public_api/v1/cloud_onboarding/create_instance_template", payload
    )

    if status_code != 200:
        return jsonify(result), status_code

    raw_response = result.get("response", "{}")
    try:
        resp_data = json.loads(raw_response)
        reply = resp_data.get("reply", {})
        automated = reply.get("automated", {})
        manual = reply.get("manual", {})
        template_url = (
            automated.get("link") or
            manual.get("TF") or
            manual.get("link") or
            reply.get("link") or ""
        )
        tracking_guid = (
            automated.get("tracking_guid") or
            manual.get("tracking_guid") or
            reply.get("tracking_guid") or ""
        )
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to parse Cortex API response: {e}", "raw": raw_response[:2000]}), 500

    if not template_url:
        return jsonify({
            "status": "error",
            "message": "Cortex API returned no template link.",
            "raw": raw_response[:2000],
        }), 500

    work_dir = "/tmp/cortex-gcp-onboarding"
    apis_dir = "/tmp/cortex-gcp-enable-apis"

    script = f"""set -e
echo "=========================================================="
echo "  Cortex Cloud Onboarding — GCP"
echo "=========================================================="
echo "Project  : {project_id}"
echo "Region   : {region}"
echo "Tracking : {tracking_guid}"
echo ""

echo "=========================================================="
echo "  STEP 0: Enable required GCP APIs"
echo "=========================================================="
rm -rf {apis_dir}
mkdir -p {apis_dir}
cat > {apis_dir}/main.tf << 'TFEOF'
terraform {{
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = "~> 6.0"
    }}
  }}
}}
variable "project_id" {{ type = string }}
resource "google_project_service" "apis" {{
  for_each = toset([
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "cloudfunctions.googleapis.com",
    "artifactregistry.googleapis.com",
    "container.googleapis.com",
    "cloudkms.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}}
TFEOF
cd {apis_dir}
terraform init -input=false -no-color
terraform apply -var="project_id={project_id}" -auto-approve -no-color
echo "  APIs enabled. Waiting 15s for propagation..."
sleep 15
echo ""

echo "==> Downloading Cortex GCP onboarding template..."
mkdir -p {work_dir}
cd {work_dir}

curl -sfL -o template.tar.gz "{template_url}"
echo "  Download complete."
echo ""

echo "==> Extracting template (tar.gz)..."
tar -xzvf template.tar.gz
rm template.tar.gz
echo "  (Existing terraform state preserved if present)"
echo ""

echo "==> Template contents:"
ls -la
echo ""

echo "=========================================================="
echo "  Running: terraform init"
echo "=========================================================="
terraform init -input=false

echo ""
echo "=========================================================="
echo "  Running: terraform apply --var-file=template_params.tfvars"
echo "=========================================================="
if [ -f template_params.tfvars ]; then
  terraform apply --var-file=template_params.tfvars -var="project_id={project_id}" -auto-approve -no-color
else
  echo "  Warning: template_params.tfvars not found — applying without var file"
  terraform apply -var="project_id={project_id}" -auto-approve -no-color
fi

echo ""
echo "=========================================================="
echo "  [OK] GCP Onboarding complete"
echo "=========================================================="
echo "Project {project_id} is now connected to Cortex Cloud."
echo "Initial discovery scan has started — assets visible in Cortex shortly."
echo "Click 'Test' to verify the connection."
"""

    task_id = create_task(
        name="GCP Onboarding — Cortex Cloud Security",
        command=script,
        use_toolbox=True,
    )
    return jsonify({"status": "ok", "task_id": task_id, "template_url": template_url})


@app.route("/api/tasks/<task_id>", methods=["GET"])
def get_task(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)


@app.route("/api/tasks", methods=["GET"])
def list_tasks():
    return jsonify(list(tasks.values()))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)

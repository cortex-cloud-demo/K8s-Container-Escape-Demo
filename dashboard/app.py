import json
import os
import subprocess
import threading
import time
import uuid

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Project root (parent of dashboard/)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TERRAFORM_DIR = os.path.join(PROJECT_ROOT, "terraform")
K8S_DIR = os.path.join(PROJECT_ROOT, "k8s")
ATTACK_DIR = os.path.join(PROJECT_ROOT, "attack")
KUBECONFIG_PATH = os.path.join(PROJECT_ROOT, "dashboard", ".kubeconfig")

# In-memory store for task outputs
tasks = {}

# In-memory store for AWS credentials
aws_credentials = {
    "aws_access_key_id": "",
    "aws_secret_access_key": "",
    "aws_session_token": "",
    "aws_region": "eu-west-3",
}


def get_aws_env():
    """Build AWS credential environment variables."""
    env = {"KUBECONFIG": KUBECONFIG_PATH}
    if aws_credentials["aws_access_key_id"]:
        env["AWS_ACCESS_KEY_ID"] = aws_credentials["aws_access_key_id"]
    if aws_credentials["aws_secret_access_key"]:
        env["AWS_SECRET_ACCESS_KEY"] = aws_credentials["aws_secret_access_key"]
    if aws_credentials["aws_session_token"]:
        env["AWS_SESSION_TOKEN"] = aws_credentials["aws_session_token"]
    if aws_credentials["aws_region"]:
        env["AWS_DEFAULT_REGION"] = aws_credentials["aws_region"]
        env["AWS_REGION"] = aws_credentials["aws_region"]
    return env


def generate_kubeconfig(cluster_name, region):
    """Generate a kubeconfig with AWS credentials embedded in the exec env section."""
    env = os.environ.copy()
    env.update(get_aws_env())

    # Get cluster details
    result = subprocess.run(
        f"aws eks describe-cluster --name {cluster_name} --region {region} --output json",
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


def run_command(task_id, command, cwd=None, env_extra=None):
    """Run a shell command asynchronously and store streaming output."""
    tasks[task_id]["status"] = "running"
    tasks[task_id]["start_time"] = time.time()

    env = os.environ.copy()
    # Inject AWS credentials
    env.update(get_aws_env())
    if env_extra:
        env.update(env_extra)

    try:
        proc = subprocess.Popen(
            command,
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


def create_task(name, command, cwd=None, env_extra=None):
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
        target=run_command, args=(task_id, command, cwd, env_extra), daemon=True
    )
    t.start()
    return task_id


# ─── Routes ───────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html")


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
    return jsonify({"status": "ok"})


@app.route("/api/credentials/test", methods=["POST"])
def test_credentials():
    """Test AWS credentials by calling sts get-caller-identity."""
    env = os.environ.copy()
    env.update(get_aws_env())
    try:
        result = subprocess.run(
            "aws sts get-caller-identity --output json",
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


# ─── Kubeconfig ─────────────────────────────────────────────────────────────


@app.route("/api/kubeconfig/generate", methods=["POST"])
def api_generate_kubeconfig():
    """Generate kubeconfig with embedded AWS credentials."""
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        region_r = subprocess.run(
            "terraform output -raw region",
            shell=True, capture_output=True, text=True, cwd=TERRAFORM_DIR, env=env,
        )
        cluster_r = subprocess.run(
            "terraform output -raw cluster_name",
            shell=True, capture_output=True, text=True, cwd=TERRAFORM_DIR, env=env,
        )
        region = region_r.stdout.strip() or aws_credentials["aws_region"] or "eu-west-3"
        cluster = cluster_r.stdout.strip() or "eks-escape-demo"
        path = generate_kubeconfig(cluster, region)
        return jsonify({"status": "ok", "path": path, "cluster": cluster, "region": region})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/kubeconfig/status", methods=["GET"])
def api_kubeconfig_status():
    """Check kubeconfig existence and test cluster connectivity."""
    debug_log = []
    result = {
        "kubeconfig_exists": os.path.exists(KUBECONFIG_PATH),
        "cluster_name": None,
        "region": None,
        "endpoint": None,
        "connected": False,
        "server_version": None,
        "nodes": None,
        "error": None,
        "debug": debug_log,
    }

    debug_log.append(f"KUBECONFIG path: {KUBECONFIG_PATH}")
    debug_log.append(f"KUBECONFIG exists: {result['kubeconfig_exists']}")

    if not result["kubeconfig_exists"]:
        debug_log.append("No kubeconfig file found. Click 'Connect' to generate one.")
        return jsonify(result)

    # Read cluster name from kubeconfig
    try:
        import yaml
        with open(KUBECONFIG_PATH) as f:
            kc = yaml.safe_load(f)
        if kc and kc.get("clusters"):
            result["cluster_name"] = kc["clusters"][0]["name"]
            result["endpoint"] = kc["clusters"][0]["cluster"].get("server", "")
            debug_log.append(f"Cluster: {result['cluster_name']}")
            debug_log.append(f"Endpoint: {result['endpoint']}")
        if kc and kc.get("users"):
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

    # Test connectivity
    env = os.environ.copy()
    env.update(get_aws_env())
    debug_log.append(f"AWS_ACCESS_KEY_ID set in env: {bool(env.get('AWS_ACCESS_KEY_ID'))}")
    debug_log.append(f"AWS_SESSION_TOKEN set in env: {bool(env.get('AWS_SESSION_TOKEN'))}")
    debug_log.append(f"AWS_REGION: {env.get('AWS_REGION', 'not set')}")

    # Step 1: test aws eks get-token
    try:
        cluster_name = result["cluster_name"] or "eks-escape-demo"
        region = result["region"] or env.get("AWS_REGION", "eu-west-3")
        token_r = subprocess.run(
            f"aws eks get-token --cluster-name {cluster_name} --region {region} --output json",
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
            "kubectl version --output=json",
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
                "kubectl get nodes --no-headers -o custom-columns='NAME:.metadata.name,STATUS:.status.conditions[-1].type,VERSION:.status.nodeInfo.kubeletVersion'",
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


# ─── Infrastructure ──────────────────────────────────────────────────────────


@app.route("/api/infra/plan", methods=["POST"])
def infra_plan():
    task_id = create_task(
        "Terraform Plan",
        "terraform init -input=false && terraform plan -no-color",
        cwd=TERRAFORM_DIR,
    )
    return jsonify({"task_id": task_id})


@app.route("/api/infra/apply", methods=["POST"])
def infra_apply():
    task_id = create_task(
        "Terraform Apply",
        "terraform init -input=false && terraform apply -auto-approve -no-color",
        cwd=TERRAFORM_DIR,
    )
    return jsonify({"task_id": task_id})


@app.route("/api/infra/destroy", methods=["POST"])
def infra_destroy():
    cmd = (
        "kubectl delete namespace vuln-app --ignore-not-found=true 2>/dev/null; "
        "kubectl delete clusterrolebinding vuln-app-cluster-admin --ignore-not-found=true 2>/dev/null; "
        "terraform init -input=false && terraform destroy -auto-approve -no-color"
    )
    task_id = create_task("Terraform Destroy", cmd, cwd=TERRAFORM_DIR)
    return jsonify({"task_id": task_id})


@app.route("/api/infra/outputs", methods=["GET"])
def infra_outputs():
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        result = subprocess.run(
            "terraform output -json",
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


# ─── Docker Build & Push ────────────────────────────────────────────────────


@app.route("/api/image/build-push", methods=["POST"])
def image_build_push():
    cmd = """
set -e
REGION=$(cd terraform && terraform output -raw region 2>/dev/null || echo "eu-west-3")
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_URL=$(cd terraform && terraform output -raw ecr_repository_url 2>/dev/null)

echo "==> Logging in to ECR..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

echo "==> Building image (linux/amd64)..."
docker buildx build --platform linux/amd64 -t ${ECR_URL}:latest --load .

echo "==> Pushing to ECR..."
docker push ${ECR_URL}:latest

echo "==> Done! Image pushed to ${ECR_URL}:latest"
"""
    task_id = create_task("Build & Push Image", cmd)
    return jsonify({"task_id": task_id})


# ─── K8s Deploy ──────────────────────────────────────────────────────────────


@app.route("/api/k8s/deploy", methods=["POST"])
def k8s_deploy():
    # Generate kubeconfig with embedded AWS credentials before deploying
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        region_r = subprocess.run(
            "terraform output -raw region",
            shell=True, capture_output=True, text=True, cwd=TERRAFORM_DIR, env=env,
        )
        cluster_r = subprocess.run(
            "terraform output -raw cluster_name",
            shell=True, capture_output=True, text=True, cwd=TERRAFORM_DIR, env=env,
        )
        region = region_r.stdout.strip() or aws_credentials["aws_region"] or "eu-west-3"
        cluster = cluster_r.stdout.strip() or "eks-escape-demo"
        generate_kubeconfig(cluster, region)
    except Exception as e:
        return jsonify({"error": f"Failed to generate kubeconfig: {e}"}), 500

    cmd = """
set -e
REGION=$(cd terraform && terraform output -raw region 2>/dev/null || echo "eu-west-3")
ECR_URL=$(cd terraform && terraform output -raw ecr_repository_url 2>/dev/null)

echo "==> Kubeconfig generated with embedded AWS credentials"
echo "==> Testing cluster access..."
kubectl cluster-info

echo "==> Applying manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/service-account.yaml

echo "==> Setting ECR image in deployment..."
sed "s|ECR_IMAGE_PLACEHOLDER|${ECR_URL}:latest|g" k8s/deployment.yaml | kubectl apply -f -

echo "==> Waiting for deployment rollout..."
kubectl rollout status deployment/vuln-app -n vuln-app --timeout=300s

echo "==> Waiting for LoadBalancer..."
sleep 15
HOST=$(kubectl get svc vuln-app-service -n vuln-app -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "pending")
echo ""
echo "==> Application deployed!"
echo "==> HOST=${HOST}"
echo "==> URL: http://${HOST}/app"
"""
    task_id = create_task("Deploy to EKS", cmd)
    return jsonify({"task_id": task_id})


@app.route("/api/k8s/status", methods=["GET"])
def k8s_status():
    try:
        env = os.environ.copy()
        env.update(get_aws_env())
        result = subprocess.run(
            "kubectl get pods,svc -n vuln-app -o wide 2>/dev/null",
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
        env = os.environ.copy()
        env.update(get_aws_env())
        result = subprocess.run(
            "kubectl get svc vuln-app-service -n vuln-app -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null",
            shell=True,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env=env,
        )
        host = result.stdout.strip().strip("'")
        return jsonify({"host": host if host else None})
    except Exception as e:
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
    )
    return jsonify({"task_id": task_id})


# ─── Attack Steps ────────────────────────────────────────────────────────────


def get_host():
    """Get the LoadBalancer hostname."""
    env = os.environ.copy()
    env.update(get_aws_env())
    result = subprocess.run(
        "kubectl get svc vuln-app-service -n vuln-app -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null",
        shell=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return result.stdout.strip().strip("'")


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


@app.route("/api/attack/shell", methods=["POST"])
def attack_shell():
    """Execute a custom command on the compromised pod via webshell."""
    host = get_host()
    if not host:
        return jsonify({"error": "No HOST found."}), 400

    cmd = request.json.get("command", "id")
    task_id = create_task(
        f"Shell: {cmd[:40]}",
        f"bash {ATTACK_DIR}/remote_shell.sh {cmd}",
        env_extra={"HOST": host},
    )
    return jsonify({"task_id": task_id})


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
    task_id = create_task("Cortex: Full Containment Playbook", f"set -e\n{full_script}")
    return jsonify({"task_id": task_id})


@app.route("/api/playbook/lambda/<step_id>", methods=["POST"])
def playbook_lambda_step(step_id):
    """Run a containment step via AWS Lambda invocation."""
    try:
        env = os.environ.copy()
        env.update(get_aws_env())

        # Get Lambda function name from Terraform outputs
        lambda_r = subprocess.run(
            "terraform output -raw containment_lambda_name",
            shell=True, capture_output=True, text=True, cwd=TERRAFORM_DIR, env=env,
        )
        lambda_name = lambda_r.stdout.strip()
        if not lambda_name:
            return jsonify({"error": "Lambda not deployed. Run Terraform Apply first."}), 400

        payload = json.dumps({
            "action": step_id,
            "cluster_name": "eks-escape-demo",
            "namespace": "vuln-app",
        })

        cmd = f'aws lambda invoke --function-name {lambda_name} --payload \'{payload}\' --cli-binary-format raw-in-base64-out /dev/stdout 2>/dev/null'
        task_id = create_task(f"Lambda: {step_id}", cmd)
        return jsonify({"task_id": task_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Task Status ─────────────────────────────────────────────────────────────


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
    app.run(host="0.0.0.0", port=5000, debug=True)

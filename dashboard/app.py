import json
import os
import subprocess
import threading
import time
import uuid

import io
import ssl
import yaml
import zipfile
import urllib.request
import urllib.error

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Project root (parent of dashboard/)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TERRAFORM_DIR = os.path.join(PROJECT_ROOT, "terraform")
TERRAFORM_LAMBDA_DIR = os.path.join(PROJECT_ROOT, "terraform-lambda")
K8S_DIR = os.path.join(PROJECT_ROOT, "k8s")
ATTACK_DIR = os.path.join(PROJECT_ROOT, "attack")
PLAYBOOK_DIR = os.path.join(PROJECT_ROOT, "playbook")
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

# In-memory store for Cortex credentials
cortex_settings = {
    "base_url": "",
    "api_key_id": "",
    "api_key": "",
}


def get_aws_env():
    """Build AWS credential environment variables.

    Explicitly sets all AWS env vars to prevent fallback to ~/.aws/credentials
    or ~/.aws/config which can cause credential mixing between accounts.
    """
    env = {
        "KUBECONFIG": KUBECONFIG_PATH,
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


def tf_var_region():
    """Return -var='region=...' flag using the configured AWS region."""
    region = aws_credentials.get("aws_region") or "eu-west-3"
    return f'-var="region={region}"'


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
        region = tf_output(TERRAFORM_DIR, "region", env) or aws_credentials["aws_region"] or "eu-west-3"
        cluster = tf_output(TERRAFORM_DIR, "cluster_name", env) or "eks-escape-demo"
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


# ─── Terraform Helpers ───────────────────────────────────────────────────────


def tf_init_cmd():
    """Simple terraform init command (local backend)."""
    return "terraform init -input=false"


def tf_output(tf_dir, output_name, env=None):
    """Run terraform output for a given module.

    Returns the output value as string, or empty string on failure.
    """
    if env is None:
        env = os.environ.copy()
        env.update(get_aws_env())
    result = subprocess.run(
        f'terraform output -raw {output_name}',
        shell=True, capture_output=True, text=True, cwd=tf_dir, env=env, timeout=30,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


# ─── Infrastructure ──────────────────────────────────────────────────────────


@app.route("/api/infra/plan", methods=["POST"])
def infra_plan():
    task_id = create_task(
        "Terraform Plan",
        f"{tf_init_cmd()} && terraform plan -no-color {tf_var_region()}",
        cwd=TERRAFORM_DIR,
    )
    return jsonify({"task_id": task_id})


@app.route("/api/infra/apply", methods=["POST"])
def infra_apply():
    task_id = create_task(
        "Terraform Apply",
        f"{tf_init_cmd()} && terraform apply -auto-approve -no-color {tf_var_region()}",
        cwd=TERRAFORM_DIR,
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
    --query "LoadBalancerDescriptions[?VPCId==\`$VPC_ID\`].LoadBalancerName" --output text 2>/dev/null || echo '')
  for ELB in $ELBS; do
    echo "    Deleting Classic ELB: $ELB"
    aws elb delete-load-balancer --load-balancer-name "$ELB" --region {region} 2>/dev/null || true
  done

  # Delete ALB/NLBs in the VPC
  echo '==> Checking ALB/NLB Load Balancers...'
  LB_ARNS=$(aws elbv2 describe-load-balancers --region {region} \
    --query "LoadBalancers[?VpcId==\`$VPC_ID\`].LoadBalancerArn" --output text 2>/dev/null || echo '')
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
    --query "NetworkInterfaces[?Attachment.DeviceIndex!=\`0\` || Attachment.InstanceId==null].NetworkInterfaceId" \
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
echo '  TERRAFORM DESTROY'
echo '=================================================='
{tf_init_cmd()} && terraform destroy -auto-approve -no-color {tf_var_region()}
"""
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
    cmd = f"""
set -e
REGION=$(cd terraform && terraform output -raw region 2>/dev/null || echo "$AWS_REGION")
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_URL=$(cd terraform && terraform output -raw ecr_repository_url 2>/dev/null)

echo "==> Logging in to ECR..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ${{ACCOUNT_ID}}.dkr.ecr.${{REGION}}.amazonaws.com

echo "==> Building image (linux/amd64)..."
docker buildx build --platform linux/amd64 -t ${{ECR_URL}}:latest --load .

echo "==> Pushing to ECR..."
docker push ${{ECR_URL}}:latest

echo "==> Done! Image pushed to ${{ECR_URL}}:latest"
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
        region = tf_output(TERRAFORM_DIR, "region", env) or aws_credentials["aws_region"] or "eu-west-3"
        cluster = tf_output(TERRAFORM_DIR, "cluster_name", env) or "eks-escape-demo"
        generate_kubeconfig(cluster, region)
    except Exception as e:
        return jsonify({"error": f"Failed to generate kubeconfig: {e}"}), 500

    cmd = f"""
set -e
REGION=$(cd terraform && terraform output -raw region 2>/dev/null || echo "$AWS_REGION")
ECR_URL=$(cd terraform && terraform output -raw ecr_repository_url 2>/dev/null)

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
    )
    return jsonify({"task_id": task_id})


@app.route("/api/lambda/destroy", methods=["POST"])
def lambda_destroy():
    """Destroy the containment Lambda via Terraform."""
    task_id = create_task(
        "Destroy Lambda",
        f"{tf_init_cmd()} && terraform destroy -auto-approve -no-color {tf_var_region()}",
        cwd=TERRAFORM_LAMBDA_DIR,
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
        task_id = create_task("Test Lambda: collect_evidence", cmd)
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
        task_id = create_task(f"Lambda: {step_id}", cmd)
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
        cortex_settings["api_key"] = data["api_key"].strip()
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


def cortex_json_request(api_path, json_data):
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
    headers = {
        "Authorization": api_key,
        "x-xdr-auth-id": api_key_id,
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }

    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": "ok",
                "message": f"Request to {api_path} succeeded",
                "http_status": resp.status,
                "response": resp_body,
            }, 200
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:500]
        return {"status": "error", "message": f"HTTP {e.code} on {api_path}: {err_body}"}, e.code
    except Exception as e:
        return {"status": "error", "message": f"{api_path}: {e}"}, 500


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
            err_msg = result.get("message", "")
            id_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', err_msg)
            if id_match:
                existing_id = id_match.group(1)
                payload["script"]["id"] = existing_id
                result2, status_code2 = cortex_json_request(api_path, payload)
                if result2["status"] == "ok":
                    result2["script_name"] = script_name
                    result2["api_path"] = api_path
                    result2["method"] = "json-update"
                    return jsonify(result2)
                errors.append(f"JSON update (id={existing_id}): {result2.get('message', 'unknown')}")
            else:
                errors.append(f"JSON {api_path}: 409 conflict but could not extract existing ID")
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
    """Publish the YAML playbook to Cortex via API (ZIP format required)."""
    playbook_path = os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_Spring4Shell_Containment.yml")

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
                err_msg = result.get("message", "")
                id_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', err_msg)
                if id_match:
                    payload["script"]["id"] = id_match.group(1)
                    result2, status_code2 = cortex_json_request(api_path, payload)
                    if result2["status"] == "ok":
                        results.append({"type": "script", "name": script_name, "status": "ok", "api_path": api_path, "method": "json-update"})
                        deployed = True
                    else:
                        script_errors.append(f"JSON update (id={id_match.group(1)}): HTTP {status_code2}")
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

    # 2. Deploy playbook (ZIP format required by Cortex Cloud API)
    playbook_path = os.path.join(PLAYBOOK_DIR, "K8s_Container_Escape_Spring4Shell_Containment.yml")
    playbook_api_paths = [
        "/public_api/v1/playbooks/insert",
        "/xsoar/public/v1/playbooks/import",
    ]

    deployed = False
    playbook_errors = []
    for api_path in playbook_api_paths:
        result, status_code = cortex_upload_playbook_zip(api_path, playbook_path)
        if result["status"] == "ok":
            results.append({"type": "playbook", "name": "K8s Container Escape Containment", "status": "ok", "api_path": api_path})
            deployed = True
            break
        playbook_errors.append(f"{api_path}: HTTP {status_code}")

    if not deployed:
        results.append({"type": "playbook", "name": "K8s Container Escape Containment", "status": "error",
                        "message": " | ".join(playbook_errors)})

    all_ok = all(r["status"] == "ok" for r in results)
    return jsonify({
        "status": "ok" if all_ok else "partial",
        "message": f"{'All' if all_ok else 'Some'} objects deployed to Cortex",
        "results": results,
    })


# ─── Cortex Policy Import ────────────────────────────────────────────────────

CORTEX_POLICY_DIR = os.path.join(PROJECT_ROOT, "cortex-policy")

CORTEX_POLICY_OBJECTS = [
    {
        "key": "policy_rules",
        "file": "policy_rules_k8s_cortex-cloud-demo.export",
        "name": "k8s_cortex-cloud-demo",
        "label": "Policy Rules",
    },
    {
        "key": "profiles",
        "file": "profiles_k8s_cortex-cloud-demo.export",
        "name": "k8s_cortex-cloud-demo",
        "label": "Profiles",
    },
]

CORTEX_POLICY_GROUP = "eks-k8s-container-escape-demo"
CORTEX_POLICY_NAME = "k8s_cortex-cloud-demo"


@app.route("/api/cortex/policy-check", methods=["GET"])
def cortex_policy_check():
    """Check if Cortex policy objects exist on the configured tenant."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex API not configured"}), 400

    results = []

    # 1. Check endpoint group via endpoints API
    try:
        resp, code = cortex_json_request(
            "/public_api/v1/endpoints/get_endpoint",
            {"request_data": {
                "search_from": 0, "search_to": 5,
                "filters": [{"field": "group_name", "operator": "in", "value": [CORTEX_POLICY_GROUP]}],
            }},
        )
        if resp.get("status") == "ok":
            data = json.loads(resp.get("response", "{}"))
            reply = data.get("reply", {})
            count = reply.get("result_count", 0) if isinstance(reply, dict) else 0
            endpoints = reply.get("endpoints", []) if isinstance(reply, dict) else []
            results.append({
                "type": "Endpoint Group",
                "name": CORTEX_POLICY_GROUP,
                "exists": count > 0,
                "detail": f"{count} endpoint(s)",
            })
        else:
            results.append({"type": "Endpoint Group", "name": CORTEX_POLICY_GROUP, "exists": None, "detail": resp.get("message", "")})
    except Exception as e:
        results.append({"type": "Endpoint Group", "name": CORTEX_POLICY_GROUP, "exists": None, "detail": str(e)})

    # 2. Check prevention policy assignment on endpoints
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

    # 3. Check local export files
    for obj in CORTEX_POLICY_OBJECTS:
        fpath = os.path.join(CORTEX_POLICY_DIR, obj["file"])
        exists = os.path.isfile(fpath)
        size = os.path.getsize(fpath) if exists else 0
        results.append({
            "type": f"Local: {obj['label']}",
            "name": obj["file"],
            "exists": exists,
            "detail": f"{size} bytes" if exists else "file not found",
        })

    # Check group TSV
    group_files = [f for f in os.listdir(CORTEX_POLICY_DIR) if f.endswith(".tsv")] if os.path.isdir(CORTEX_POLICY_DIR) else []
    if group_files:
        fpath = os.path.join(CORTEX_POLICY_DIR, group_files[0])
        results.append({
            "type": "Local: Endpoint Group",
            "name": group_files[0],
            "exists": True,
            "detail": f"{os.path.getsize(fpath)} bytes",
        })

    return jsonify({"status": "ok", "results": results})


@app.route("/api/cortex/policy-import", methods=["POST"])
def cortex_policy_import():
    """Import Cortex policy objects from local export files."""
    if not cortex_settings.get("api_key"):
        return jsonify({"status": "error", "message": "Cortex API not configured"}), 400

    base_url = cortex_settings["base_url"].rstrip("/")
    api_key = cortex_settings["api_key"]
    api_key_id = cortex_settings["api_key_id"]

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    results = []

    # Import policy rules and profiles via multipart upload
    import_endpoints = {
        "policy_rules": "/public_api/v1/policy/import_policy_rules",
        "profiles": "/public_api/v1/policy/import_profiles",
    }

    for obj in CORTEX_POLICY_OBJECTS:
        fpath = os.path.join(CORTEX_POLICY_DIR, obj["file"])
        if not os.path.isfile(fpath):
            results.append({"type": obj["label"], "status": "error", "message": f"File not found: {obj['file']}"})
            continue

        with open(fpath, "rb") as f:
            file_data = f.read()

        api_path = import_endpoints.get(obj["key"], "")
        url = f"{base_url}{api_path}"

        # Build multipart body manually (no requests library)
        boundary = f"----CortexImport{uuid.uuid4().hex[:12]}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{obj["file"]}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + file_data + f"\r\n--{boundary}--\r\n".encode("utf-8")

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
                results.append({
                    "type": obj["label"],
                    "status": "ok",
                    "http_code": resp.status,
                    "message": f"Imported successfully",
                    "response": resp_body[:500],
                })
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:500]
            results.append({
                "type": obj["label"],
                "status": "error",
                "http_code": e.code,
                "message": f"HTTP {e.code}: {err_body}",
            })
        except Exception as e:
            results.append({
                "type": obj["label"],
                "status": "error",
                "message": str(e),
            })

    overall = "ok" if all(r.get("status") == "ok" for r in results) else "partial" if any(r.get("status") == "ok" for r in results) else "error"
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
        # Check for XDR daemonset/pods across all namespaces
        result = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-l", "app=cortex-xdr",
             "-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name} {.status.phase}{'\\n'}{end}"],
            capture_output=True, text=True, env=env, timeout=15
        )
        pods_output = result.stdout.strip()

        if not pods_output:
            # Try broader search
            result2 = subprocess.run(
                ["kubectl", "get", "pods", "-A", "--no-headers"],
                capture_output=True, text=True, env=env, timeout=15
            )
            xdr_lines = [l for l in result2.stdout.strip().split("\n") if l and "xdr" in l.lower()]
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

    task_id = create_task("XDR Agent: Install on K8s", cmd)
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
    task_id = create_task("Reset Containment", cmd)
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
        "kubectl get networkpolicy containment-deny-all -n vuln-app -o jsonpath='{.metadata.name}' 2>/dev/null",
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
        "kubectl get clusterrolebinding vuln-app-cluster-admin -o jsonpath='{.metadata.name}' 2>/dev/null",
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
        "kubectl get pods -n vuln-app -o json 2>/dev/null",
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
        "kubectl get deployment vuln-app -n vuln-app -o json 2>/dev/null",
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
        "kubectl get nodes -o json 2>/dev/null",
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
        "kubectl get events -n vuln-app --no-headers 2>/dev/null | wc -l",
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

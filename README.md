# Kubernetes Container Escape Demo

Security demonstration: exploitation of a vulnerable containerized application leading to container escape and full cluster takeover on AWS EKS, with automated incident response via Cortex XSOAR playbook.

## Attack & Response Chain

```
ATTACK                                          RESPONSE (Cortex XSOAR)
──────                                          ────────────────────────
Spring4Shell RCE (CVE-2022-22965)               1. Collect Evidence
  |-> Webshell on the pod                          |-> Pod forensics, logs, RBAC audit
      |-> Container Escape                      2. Network Isolation
          |-> Node access (nsenter)                |-> Deny-all NetworkPolicy
          |-> Host filesystem r/w               3. Revoke RBAC
          |-> AWS IMDS credential theft            |-> Delete cluster-admin binding
      |-> Cluster Takeover                      4. Scale Down
          |-> Full K8s API access                  |-> Deployment replicas -> 0
          |-> Secrets exfiltration              5. Cordon Node
          |-> Lateral movement to AWS              |-> Mark node unschedulable
                                                6. Kill Pods
                                                   |-> Force delete all pods
```

## Architecture

| Component | Description |
|-----------|-------------|
| **EKS Cluster** | AWS managed Kubernetes (v1.35) on AL2023 with GP3 volumes |
| **ECR** | Container registry for the vulnerable image |
| **Vulnerable App** | Spring Boot app with CVE-2022-22965 (Spring4Shell) |
| **Pod Misconfigs** | `privileged: true`, `hostPID`, `hostNetwork`, `hostPath: /`, SA `cluster-admin` |
| **Lambda** | Containment function invoked by Cortex XSOAR to isolate the cluster |
| **Cortex Playbook** | XSOAR playbook orchestrating automated incident response |

## Prerequisites

- AWS account with admin access
- AWS CLI v2 installed
- `kubectl`, `terraform` (>= 1.5) installed
- Docker with buildx support (for cross-compilation ARM -> AMD64)
- Python 3.9+ with pip

## Web Dashboard

The project includes a full web-based demo interface to orchestrate the attack and response from a browser.

### Quick Start

```bash
cd dashboard
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000**

### Dashboard Workflow

The dashboard guides you through the full demo in order:

#### 1. Configure AWS Credentials

Click **Configure** in the AWS Settings card. Enter:
- **AWS Region** (default: `eu-west-3`)
- **AWS Access Key ID**
- **AWS Secret Access Key**
- **AWS Session Token** (if using STS temporary credentials)

Click **Test** to validate with `aws sts get-caller-identity`.

> Credentials are stored in-memory only and never persisted to disk.

#### 2. Deploy Infrastructure

Click **Apply** in the EKS + ECR + VPC card. Terraform provisions:
- VPC + 2 public subnets + IGW
- EKS cluster (v1.35) + node group (2x t3.medium, AL2023, GP3)
- ECR repository
- Lambda containment function + IAM role + EKS access entry

> ~15 minutes for EKS cluster creation.

#### 3. Connect to Cluster

Click **Connect** in the Cluster Connection card. This generates a dedicated kubeconfig (`dashboard/.kubeconfig`) with AWS credentials embedded in the exec section, so kubectl works seamlessly.

The card shows:
- Cluster name, region, K8s version
- Node list with status
- Debug log (expandable) for troubleshooting

#### 4. Build & Push Image

Click **Build & Push**. This:
- Logs in to ECR
- Builds the vulnerable Spring4Shell app (`linux/amd64` for EKS nodes)
- Pushes to ECR

#### 5. Deploy Vulnerable App

Click **Deploy**. This applies K8s manifests:
- Namespace `vuln-app`
- ServiceAccount with `cluster-admin` ClusterRoleBinding
- Privileged Deployment (hostPID, hostNetwork, hostPath: /)
- LoadBalancer Service

#### 6. Run the Attack (Attack Chain section)

Three steps, each with a dedicated button:

| Step | Button | Action |
|------|--------|--------|
| **Step 1** | Exploit | Spring4Shell RCE - deploys webshell (`shell.jsp`) |
| **Step 2** | Escape | Container escape - nsenter, host fs, IMDS |
| **Step 3** | Takeover | Cluster takeover - SA token, secrets, AWS creds |

The **Terminal** tab shows live output. Use the command bar at the bottom to execute commands on the compromised pod (e.g. `id`, `cat /etc/passwd`, `ls /host`).

#### 7. Connect Cortex XSOAR

Click **Configure** in the Cortex XSOAR card. Enter:
- **FQDN** (e.g. `myinstance.xdr.us.paloaltonetworks.com`)
- **API Key ID** (numeric ID)
- **API Key** (Standard or Advanced)

Click **Test** to validate the connection.

> API format: `https://api-{fqdn}/xsoar/public/v1/` with `Authorization: {api_key}` + `x-xdr-auth-id: {key_id}` headers.

#### 8. Publish Playbook to Cortex

Click **Publish to Cortex** to push the containment playbook (`K8s_Container_Escape_Spring4Shell_Containment.yml`) to your Cortex XSOAR instance via the `POST /playbook/save/yaml` API endpoint.

Once published, the playbook runs **from Cortex XSOAR** (not the dashboard). The dashboard is the attack platform; Cortex handles the response.

#### Local Containment (fallback)

The **Local Containment** section allows running containment steps directly via kubectl without Cortex:

| Step | Action | Effect |
|------|--------|--------|
| **Collect Evidence** | Pod forensics | Captures pod config, security context, logs, events, RBAC |
| **Network Isolation** | Deny-all NetworkPolicy | Blocks all ingress/egress on `vuln-app` namespace |
| **Revoke RBAC** | Delete ClusterRoleBinding | Removes `cluster-admin` access from the SA |
| **Scale Down** | Replicas -> 0 | Terminates pods while preserving deployment for forensics |
| **Cordon Node** | Mark unschedulable | Prevents new workloads on the compromised node |
| **Kill Pods** | Force delete pods | Ensures no compromised containers remain running |

### Dashboard Tabs

| Tab | Purpose |
|-----|---------|
| **Terminal** | Main output for infrastructure, build, deploy, and attack operations |
| **kubectl** | Interactive kubectl with shortcut buttons (nodes, pods, services, secrets, events, RBAC, logs...) |
| **Playbook** | Cortex XSOAR playbook flow visualization + containment output |

### Cleanup

Click **Destroy All** in the Cleanup section. Confirms with a modal, then:
1. Deletes K8s namespace and ClusterRoleBinding
2. Runs `terraform destroy` to remove all AWS resources

## Cortex XSOAR Integration

### Playbook

The file `playbook/K8s_Container_Escape_Spring4Shell_Containment.yml` is a ready-to-import XSOAR playbook (YAML format). You can import it via the dashboard's **Publish to Cortex** button or manually:

```
Start -> Triage -> Collect Evidence -> Severity Check
                                          |
                   Critical ──────────────┤
                                          |
                   Manual Approval <──── Low
                          |
          Network Isolate -> Revoke RBAC -> Scale Down
              -> Cordon Node -> Kill Pods -> Verify -> Done
```

Import into XSOAR: **Settings > Playbooks > Import** and select the YAML file, or use the dashboard's **Publish to Cortex** button to push it via API.

### Lambda Function

The Lambda (`lambda/containment/handler.py`) is the execution engine called by the playbook. It authenticates to EKS via STS and makes direct K8s API calls.

Supported actions (passed in `event.action`):
- `collect_evidence` - Pod details, logs, events, RBAC audit
- `network_isolate` - Apply deny-all NetworkPolicy
- `revoke_rbac` - Delete cluster-admin ClusterRoleBinding
- `scale_down` - Scale deployment to 0
- `cordon_node` - Cordon the affected node
- `delete_pod` - Force delete all pods
- `full_containment` - Run all steps in sequence

Example invocation:
```json
{
  "action": "full_containment",
  "cluster_name": "eks-escape-demo",
  "namespace": "vuln-app",
  "region": "eu-west-3"
}
```

## CLI Deployment (alternative)

### Via GitHub Actions

1. **Deploy Infrastructure** - Run workflow "01 - Deploy Infrastructure (EKS + ECR)" with action `apply`
2. **Build & Push Image** - Run workflow "02 - Build & Push Vulnerable Image to ECR"
3. **Deploy App** - Run workflow "03 - Deploy Vulnerable App to EKS"
4. **Get URL**:
   ```bash
   aws eks update-kubeconfig --name eks-escape-demo --region eu-west-3
   export HOST=$(kubectl get svc vuln-app-service -n vuln-app -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
   echo "App URL: http://${HOST}/app"
   ```

### Attack Scripts

```bash
./attack/01-exploit-rce.sh       # Spring4Shell webshell
./attack/02-container-escape.sh  # Node escape via nsenter
./attack/03-cluster-takeover.sh  # Cluster-admin exploitation
```

### Manual Cleanup

```bash
kubectl delete namespace vuln-app
kubectl delete clusterrolebinding vuln-app-cluster-admin
cd terraform && terraform destroy -auto-approve
```

## Misconfigurations Exploited

| Misconfiguration | Impact | Remediation |
|---|---|---|
| `privileged: true` | Full host kernel access | `allowPrivilegeEscalation: false` |
| `hostPID: true` | Host process visibility, `nsenter` escape | Disable hostPID |
| `hostNetwork: true` | Node network access, IMDS | Disable hostNetwork, IMDSv2 hop limit=1 |
| `hostPath: /` | Read/write entire host filesystem | PVCs, restrict via PSA |
| SA `cluster-admin` | Full K8s API control | Least privilege RBAC |
| EC2FullAccess on nodes | Lateral movement to AWS | Minimal IAM, IRSA |
| No Pod Security Standards | All misconfigs allowed | Enforce `restricted` PSA |
| No Network Policies | Unrestricted pod communication | Implement NetworkPolicies |

## Project Structure

```
.
├── .github/workflows/
│   ├── 01-deploy-infra.yml              # Terraform EKS + ECR
│   ├── 02-build-push-image.yml          # Build & push to ECR
│   ├── 03-deploy-app.yml                # Deploy vuln app to EKS
│   └── 99-destroy-infra.yml             # Cleanup
├── dashboard/
│   ├── app.py                           # Flask web dashboard (backend)
│   ├── requirements.txt                 # flask, pyyaml
│   ├── templates/
│   │   └── index.html                   # Dashboard UI
│   └── static/
│       ├── css/style.css                # Dark theme, playbook flow
│       └── js/app.js                    # Tabs, polling, playbook logic
├── terraform/
│   ├── main.tf                          # EKS + ECR + VPC + IAM
│   ├── lambda.tf                        # Containment Lambda + IAM + EKS access
│   ├── variables.tf
│   ├── outputs.tf
│   └── backend.tf
├── lambda/
│   └── containment/
│       ├── handler.py                   # Lambda containment handler
│       └── requirements.txt
├── playbook/
│   └── K8s_Container_Escape_Spring4Shell_Containment.yml  # Cortex XSOAR playbook (YAML)
├── app/                                 # Spring4Shell vulnerable app (Java)
├── k8s/
│   ├── namespace.yaml
│   ├── service-account.yaml             # cluster-admin binding
│   └── deployment.yaml                  # Privileged pod
├── attack/
│   ├── 01-exploit-rce.sh                # Spring4Shell webshell
│   ├── 02-container-escape.sh           # Node escape
│   ├── 03-cluster-takeover.sh           # Cluster-admin exploitation
│   └── remote_shell.sh                  # Helper script
├── Dockerfile
└── README.md
```

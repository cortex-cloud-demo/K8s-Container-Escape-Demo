# Kubernetes Container Escape Demo

Full attack chain demo on AWS EKS — from Spring4Shell RCE to container escape to cluster takeover — with automated detection by Cortex XDR and incident response via Cortex playbook + AWS Lambda containment.

Everything is orchestrated from a **web dashboard**: infrastructure provisioning, attack execution, and automated remediation.

## Architecture Diagram

![Architecture Diagram](docs/architecture.png)

## Attack & Response Chain

![Attack & Response Chain](docs/attack-response-chain.png)

## Quick Start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **AWS CLI** | v2+ | AWS API access |
| **Terraform** | >= 1.5 | Infrastructure provisioning |
| **kubectl** | latest | Kubernetes management |
| **Docker** | with buildx | Image build (cross-compilation ARM → AMD64) |
| **Python** | 3.9+ | Dashboard application |
| **AWS Account** | admin access | Initial bootstrap (one-time) |
| **Cortex Instance** | XSIAM/XSOAR | Playbook deployment (optional) |

### 1. Clone & Launch Dashboard

```bash
git clone https://github.com/cleypanw/K8s-Container-Escape-Demo.git
cd K8s-Container-Escape-Demo/dashboard
./run.sh
```

This creates a Python virtual environment, installs dependencies, and starts the dashboard.

Open **http://localhost:5000**

### 2. Configure AWS Credentials

In the dashboard, click **AWS > Configure** and enter your admin credentials:
- **Access Key ID**
- **Secret Access Key**
- **Session Token** (if using SSO/temporary credentials)
- **Region** (e.g. `eu-west-2`)

Click **Test** to verify connectivity.

> Credentials are stored in-memory only and never persisted to disk.

### 3. Deploy Infrastructure (~15 min)

Click **INFRA > Apply** — Terraform provisions:
- VPC (2 public subnets, Internet Gateway, route tables)
- EKS cluster (v1.35, AL2023 nodes, GP3 volumes)
- ECR repository
- Dashboard IAM User + Operator Role
- EKS access entries

### 4. Switch to Dashboard User (permanent credentials)

After infra is deployed, retrieve the dedicated dashboard user credentials:

```bash
cd terraform
terraform output dashboard_user_access_key_id
terraform output -raw dashboard_user_secret_access_key
```

Paste these in **AWS > Configure** (Access Key + Secret Key, no Session Token needed). These credentials never expire.

### 5. Build, Deploy & Attack

| Step | Card/Button | Action |
|------|-------------|--------|
| Connect | **Connect** | Generates kubeconfig |
| Build | **Build Image** | Docker build (linux/amd64) + push to ECR |
| Deploy | **Deploy** | K8s manifests: namespace, SA, privileged deployment, LB |
| RCE | **Step 1: Exploit** | Spring4Shell webshell |
| Escape | **Step 2: Escape** | Container escape via nsenter, host fs, IMDS |
| Takeover | **Step 3: Takeover** | cluster-admin SA token, secrets, AWS creds |

### 6. Deploy Cortex Response

| Step | Card | Action |
|------|------|--------|
| Lambda | **LAMBDA > Apply** | Terraform: Lambda function, IAM, EKS access entry, Cortex IAM user |
| Scripts | **CORTEX > Scripts Only** | Push automation scripts to Cortex |
| Playbook | **CORTEX > Playbook Only** | Push playbook to Cortex |
| Policy | **POLICY > Import** | Import prevention policy rules + profiles (BETA) |

### 7. Cleanup

Click **Destroy Lambda** then **Destroy All** in the Cleanup section. The dashboard automatically cleans up K8s resources (LoadBalancer, ENIs, EIPs) before running `terraform destroy`.

## Components

| Component | Description |
|-----------|-------------|
| **Dashboard** | Web UI to orchestrate the full demo (infra, attack, response, security radar) |
| **EKS Cluster** | AWS managed Kubernetes (v1.35) on AL2023 with GP3 volumes |
| **ECR** | Container registry for the vulnerable image |
| **Vulnerable App** | Spring Boot app with CVE-2022-22965 (Spring4Shell) on Tomcat 9 |
| **Pod Misconfigs** | `privileged`, `hostPID`, `hostNetwork`, `hostPath: /`, SA `cluster-admin` |
| **Lambda** | Containment function authenticating to EKS via STS (x-k8s-aws-id) |
| **Cortex Scripts** | `ExtractK8sContainerEscapeIOCs` (triage) + `InvokeK8sContainmentLambda` (containment) |
| **Cortex Playbook** | Automated incident response orchestration |
| **Prevention Policy** | Prevention rules, profiles & endpoint group for K8s nodes (BETA) |

## IAM Architecture

The project uses **dedicated IAM Users with permanent Access Keys** and **scoped IAM Roles** (least-privilege). No admin credentials are needed after the initial bootstrap.

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  BOOTSTRAP (one-time, admin credentials)                            │
│                                                                     │
│  Admin credentials ──► terraform apply (terraform/ + terraform-lambda/)
│                          ├── VPC, EKS, ECR, Lambda                  │
│                          ├── Dashboard IAM User + Operator Role     │
│                          └── Cortex IAM User + Lambda Invoker Role  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  DASHBOARD (permanent credentials, no expiration)                   │
│                                                                     │
│  dashboard-user (Access Key) ──► AssumeRole ──► dashboard-operator  │
│                                                   ├── EKS, ECR      │
│                                                   ├── Lambda, IAM   │
│                                                   └── VPC, Logs     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  CORTEX PLAYBOOK (permanent credentials, no expiration)             │
│                                                                     │
│  cortex-playbook-user (Access Key) ──► AssumeRole ──► lambda-invoker│
│                                                        └── lambda:  │
│                                                         InvokeFunction│
└─────────────────────────────────────────────────────────────────────┘
```

### IAM Users & Roles

| Resource | Module | Purpose |
|----------|--------|---------|
| `k8s-escape-demo-dashboard-user` | `terraform/` | Permanent Access Key → AssumeRole on operator role |
| `k8s-escape-demo-dashboard-operator` | `terraform/` | Scoped permissions (EKS, ECR, Lambda, IAM, VPC, Logs, ELB) |
| `k8s-escape-demo-cortex-playbook-user` | `terraform-lambda/` | Permanent Access Key → AssumeRole on invoker role |
| `k8s-escape-demo-lambda-invoker` | `terraform-lambda/` | `lambda:InvokeFunction` on containment Lambda only |

### Getting Credentials

```bash
# Dashboard user
cd terraform
terraform output dashboard_user_access_key_id
terraform output -raw dashboard_user_secret_access_key

# Cortex playbook user
cd terraform-lambda
terraform output cortex_user_access_key_id
terraform output -raw cortex_user_secret_access_key
terraform output lambda_invoker_role_arn
```

## Dashboard Tabs

| Tab | Purpose |
|-----|---------|
| **Overview** | Architecture overview, attack chain, MITRE techniques, auth flow |
| **Terminal** | Main output for all operations + webshell command execution |
| **kubectl** | Interactive kubectl with shortcut buttons |
| **Cortex** | Cortex playbook flow visualization + containment output |
| **Security Radar** | Before/after security posture comparison |

### Security Radar

Visual security posture assessment — 6 axes scored 0-100:

| Axis | Vulnerable (10) | Secure (95) |
|------|-----------------|-------------|
| Network Isolation | No NetworkPolicy | deny-all applied |
| RBAC Security | cluster-admin bound | ClusterRoleBinding deleted |
| Pod Security | Privileged pods | No pods running |
| Node Security | Nodes schedulable | Node(s) cordoned |
| Deployment Control | Replicas > 0 | Scaled to 0 |
| Evidence | No forensic data | Events + logs collected |

**Usage:** Snapshot Before (red) → Run containment → Scan Current (green overlay)

## Cortex Integration

### Playbook Authentication Flow

Cortex XSIAM runs on GCP — no AWS SDK available. The script uses **pure SigV4 signing** (`hmac`/`hashlib`):

```
cortex-playbook-user (permanent Access Key)
    │
    ├── 1. STS AssumeRole (SigV4-signed POST)
    │      → sts.<region>.amazonaws.com
    │      → Returns temporary credentials
    │
    ├── 2. Lambda Invoke (SigV4-signed POST)
    │      → lambda.<region>.amazonaws.com
    │      → Containment action payload
    │
    └── 3. Lambda → EKS API
           → STS presigned URL (x-k8s-aws-id)
           → K8s API calls (NetworkPolicy, RBAC, scale, cordon...)
```

**Dual-mode:** if `assume_role_arn` is omitted, STS AssumeRole is skipped and Lambda is invoked directly.

### Playbook Flow

```
Start → #1 Triage (ExtractK8sContainerEscapeIOCs)
      → #2 Collect Evidence (Lambda)
      → #3 Severity Check (Critical + SpringShell?)
      → #31 Operator Approval
      → #4 Network Isolation
      → #5 Revoke RBAC
      → #6 Scale Down
      → #7 Cordon Node
      → #8 Kill Pods
      → #9 Verify Containment
      → #10 Complete
```

### Lambda Actions

| Action | Effect |
|--------|--------|
| `collect_evidence` | Pod details, logs, events, RBAC audit, node status |
| `network_isolate` | Apply deny-all NetworkPolicy |
| `revoke_rbac` | Delete cluster-admin ClusterRoleBinding |
| `scale_down` | Scale deployment to 0 replicas |
| `cordon_node` | Mark node as unschedulable |
| `delete_pod` | Force delete all pods |
| `full_containment` | Run all steps in sequence |

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

## Terraform State

Local state in each module directory (excluded from git):

| Module | Resources |
|--------|-----------|
| `terraform/` | VPC, EKS, ECR, IAM, Dashboard user + operator role |
| `terraform-lambda/` | Lambda, IAM, EKS access entry, Cortex user + lambda invoker role |

## Project Structure

```
.
├── dashboard/
│   ├── app.py                    # Dashboard backend (Flask API)
│   ├── run.sh                    # Launch script (venv + install + run)
│   ├── requirements.txt          # flask, pyyaml
│   ├── templates/index.html      # Dashboard UI
│   └── static/
│       ├── css/style.css
│       └── js/app.js
├── terraform/
│   ├── main.tf                   # VPC, EKS, ECR, IAM, node group
│   ├── iam-dashboard.tf          # Dashboard IAM User + Operator Role
│   ├── backend.tf                # Provider config
│   ├── outputs.tf                # Cluster, ECR, dashboard credentials
│   └── variables.tf
├── terraform-lambda/
│   ├── main.tf                   # Lambda, IAM, EKS access, Cortex user + invoker role
│   ├── backend.tf                # Provider config
│   ├── outputs.tf                # Lambda, Cortex credentials
│   └── variables.tf
├── lambda/containment/
│   ├── handler.py                # Lambda: EKS auth + K8s API containment
│   └── requirements.txt
├── cortex-scripts/
│   ├── ExtractK8sContainerEscapeIOCs.py
│   ├── automation-ExtractK8sContainerEscapeIOCs.yml
│   ├── InvokeK8sContainmentLambda.py
│   └── automation-InvokeK8sContainmentLambda.yml
├── cortex-policy/
│   ├── policy_rules_*.export     # Prevention policy rules
│   ├── profiles_*.export         # Prevention profiles
│   └── XDR_Group_*.tsv           # Endpoint group definition
├── playbook/
│   └── K8s_Container_Escape_Spring4Shell_Containment.yml
├── app/                          # Spring4Shell vulnerable app (Java/Maven)
├── k8s/
│   ├── namespace.yaml
│   ├── service-account.yaml
│   └── deployment.yaml           # Privileged pod + LoadBalancer
├── attack/
│   ├── 01-exploit-rce.sh         # Spring4Shell RCE
│   ├── 02-container-escape.sh    # nsenter, host fs, IMDS
│   ├── 03-cluster-takeover.sh    # SA token, secrets, AWS creds
│   └── remote_shell.sh
├── Dockerfile                    # Multi-stage: Maven build + Tomcat 9
├── .gitignore
└── README.md
```

## CLI Alternative

```bash
# Attack scripts (without dashboard)
./attack/01-exploit-rce.sh
./attack/02-container-escape.sh
./attack/03-cluster-takeover.sh

# Manual cleanup
kubectl delete namespace vuln-app
kubectl delete clusterrolebinding vuln-app-cluster-admin
cd terraform-lambda && terraform destroy -auto-approve
cd terraform && terraform destroy -auto-approve
```

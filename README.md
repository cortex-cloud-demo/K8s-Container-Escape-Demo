# Kubernetes Container Escape Demo

Security demonstration: exploitation of a vulnerable containerized application leading to container escape and full cluster takeover on AWS EKS, with automated incident response via Cortex XSIAM/XSOAR playbook and AWS Lambda containment.

## Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                              OPERATOR WORKSTATION                                  |
|                                                                                    |
|   +---------------------------+         +-----------------------------------+      |
|   |    Flask Dashboard :5000  |         |       Cortex XSIAM / XSOAR       |      |
|   |  +---------------------+ |         |  +-----------------------------+  |      |
|   |  | Settings            | |         |  | ExtractK8sContainerEscape   |  |      |
|   |  |  - AWS Credentials  | |  deploy |  |   IOCs (automation script)  |  |      |
|   |  |  - Cortex API Keys  | | ------> |  +-----------------------------+  |      |
|   |  +---------------------+ |  scripts|  | InvokeK8sContainmentLambda  |  |      |
|   |  | Infrastructure      | |    +    |  |   (automation script)       |  |      |
|   |  |  - S3 Backend       | | playbook|  +-----------------------------+  |      |
|   |  |  - EKS/ECR/VPC      | |         |  | Playbook: K8s Container     |  |      |
|   |  |  - Lambda Deploy    | |         |  |   Escape Containment        |  |      |
|   |  +---------------------+ |         |  +-------------+---------------+  |      |
|   |  | Attack Chain        | |         |                |                  |      |
|   |  |  1. Spring4Shell RCE| |         |    XDR Issue   | Playbook         |      |
|   |  |  2. Container Escape| |         |    triggers    | invokes          |      |
|   |  |  3. Cluster Takeover| |         |    playbook    | Lambda           |      |
|   |  +---------------------+ |         +----------------|-----------------+      |
|   +---------------------------+                          |                         |
+----------------------------------------------------------|-------------------------+
                                                           |
                              +----------------------------v----------------------------+
                              |                      AWS CLOUD                          |
                              |                                                         |
                              |   +--------------------------------------------------+  |
                              |   |              AWS Lambda Function                  |  |
                              |   |         k8s-escape-demo-containment               |  |
                              |   |                                                   |  |
                              |   |  Actions:                                         |  |
                              |   |   - collect_evidence  (pod forensics, logs, RBAC) |  |
                              |   |   - network_isolate   (deny-all NetworkPolicy)    |  |
                              |   |   - revoke_rbac       (delete ClusterRoleBinding) |  |
                              |   |   - scale_down        (replicas -> 0)             |  |
                              |   |   - cordon_node       (mark unschedulable)        |  |
                              |   |   - delete_pod        (force delete pods)         |  |
                              |   |   - full_containment  (all steps in sequence)     |  |
                              |   +------------------+-------------------------------+  |
                              |                      | STS Token                        |
                              |                      | (x-k8s-aws-id)                   |
                              |                      v                                  |
                              |   +--------------------------------------------------+  |
                              |   |                 Amazon EKS                        |  |
                              |   |            eks-escape-demo (v1.35)                |  |
                              |   |                                                   |  |
                              |   |   +------- Namespace: vuln-app ----------------+  |  |
                              |   |   |                                            |  |  |
                              |   |   |  +------------------+   +--------------+   |  |  |
                              |   |   |  | Deployment       |   | ServiceAcct  |   |  |  |
                              |   |   |  | vuln-app         |   | vuln-app-sa  |   |  |  |
                              |   |   |  |  privileged:true  |   |  cluster-    |   |  |  |
                              |   |   |  |  hostPID:true     |   |  admin       |   |  |  |
                              |   |   |  |  hostNetwork:true |   +--------------+   |  |  |
                              |   |   |  |  hostPath: /      |                      |  |  |
                              |   |   |  +------------------+   +--------------+   |  |  |
                              |   |   |                         | LoadBalancer  |   |  |  |
                              |   |   |  Spring4Shell App       | :80 -> :8080  |   |  |  |
                              |   |   |  (CVE-2022-22965)       +--------------+   |  |  |
                              |   |   +--------------------------------------------+  |  |
                              |   |                                                   |  |
                              |   |   +-- Node Group (2x t3.medium, AL2023) -------+  |  |
                              |   |   |   EC2 instances with GP3 EBS volumes       |  |  |
                              |   |   |   IMDS accessible (credential theft)       |  |  |
                              |   |   +--------------------------------------------+  |  |
                              |   +--------------------------------------------------+  |
                              |                                                         |
                              |   +------------------+  +----------------------------+  |
                              |   |   Amazon ECR      |  |  S3 Terraform State       |  |
                              |   |   vuln-app:latest |  |  k8s-escape-demo-tfstate- |  |
                              |   +------------------+  |    <account-id>            |  |
                              |                         |  Keys: eks/ , lambda/      |  |
                              |   +------------------+  +----------------------------+  |
                              |   |   VPC 10.0.0.0/16|                                  |
                              |   |   2 public subnets|                                 |
                              |   |   IGW + routes    |                                 |
                              |   +------------------+                                  |
                              +---------------------------------------------------------+
```

## Attack & Response Chain

```
ATTACK                                          RESPONSE (Cortex XSIAM + Lambda)
------                                          --------------------------------
Spring4Shell RCE (CVE-2022-22965)               1. XDR Issue -> Playbook triggered
  |-> Webshell on the pod                       2. Triage - Extract IOCs from issue fields
      |-> Container Escape                      3. Operator enters AWS credentials
          |-> Node access (nsenter)             4. Collect Evidence (Lambda -> EKS API)
          |-> Host filesystem r/w                  |-> Pod forensics, logs, RBAC audit
          |-> AWS IMDS credential theft         5. Severity Check + Operator Approval
      |-> Cluster Takeover                      6. Network Isolation (deny-all NetworkPolicy)
          |-> Full K8s API access               7. Revoke RBAC (delete cluster-admin)
          |-> Secrets exfiltration              8. Scale Down (replicas -> 0)
          |-> Lateral movement to AWS           9. Cordon Node (mark unschedulable)
                                               10. Kill Pods (force delete)
                                               11. Verify Containment (re-collect evidence)
```

## Components

| Component | Description |
|-----------|-------------|
| **Flask Dashboard** | Web UI to orchestrate the full demo (infra, attack, response, Cortex deploy) |
| **Terraform Backend** | S3 bucket for remote state storage (shared across environments) |
| **EKS Cluster** | AWS managed Kubernetes (v1.35) on AL2023 with GP3 volumes |
| **ECR** | Container registry for the vulnerable image |
| **Vulnerable App** | Spring Boot app with CVE-2022-22965 (Spring4Shell) on Tomcat 9 |
| **Pod Misconfigs** | `privileged`, `hostPID`, `hostNetwork`, `hostPath: /`, SA `cluster-admin` |
| **Lambda** | Containment function authenticating to EKS via STS (x-k8s-aws-id) |
| **Cortex Scripts** | `ExtractK8sContainerEscapeIOCs` (triage) + `InvokeK8sContainmentLambda` (containment) |
| **Cortex Playbook** | XSIAM/XSOAR playbook orchestrating the full incident response |

## Prerequisites

- AWS account with admin access
- AWS CLI v2 installed
- `kubectl`, `terraform` (>= 1.5) installed
- Docker with buildx support (for cross-compilation ARM -> AMD64)
- Python 3.9+ with pip
- Cortex XSIAM/XSOAR instance (for playbook deployment)

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

#### 1. Configure Credentials

- **AWS Settings** - Access Key, Secret Key, Session Token, Region
- **Cortex API** - Base URL, API Key ID, API Key

> Credentials are stored in-memory only and never persisted to disk.

#### 2. Deploy Infrastructure

| Step | Card | Action |
|------|------|--------|
| **S3 Backend** | Terraform State Backend | Creates S3 bucket + versioning + encryption for remote TF state |
| **EKS + ECR + VPC** | Infrastructure | Terraform: VPC, EKS v1.35, ECR, IAM (~15 min) |
| **Cluster Connection** | Connect | Generates kubeconfig with embedded AWS credentials |
| **Build & Push** | Build Image | Docker build (linux/amd64) + push to ECR |
| **Deploy App** | Deploy | K8s manifests: namespace, SA, privileged deployment, LB |

#### 3. Run the Attack

| Step | Button | Action |
|------|--------|--------|
| **Step 1** | Exploit | Spring4Shell RCE - deploys webshell (`shell.jsp`) |
| **Step 2** | Escape | Container escape - nsenter, host fs, IMDS |
| **Step 3** | Takeover | Cluster takeover - SA token, secrets, AWS creds |

The **Terminal** tab shows live output. Use the command bar to execute commands on the compromised pod.

#### 4. Cortex Response

| Step | Card | Action |
|------|------|--------|
| **Deploy Lambda** | Lambda | Terraform: IAM role, EKS access entry, Lambda function |
| **Deploy Cortex Objects** | Cortex | Push 2 automation scripts + playbook to Cortex XSIAM |

#### 5. Cleanup

Destroy Lambda, EKS infrastructure, and S3 backend (in that order).

### Dashboard Tabs

| Tab | Purpose |
|-----|---------|
| **Terminal** | Main output for all operations + webshell command execution |
| **kubectl** | Interactive kubectl with shortcut buttons (nodes, pods, services, secrets, events, RBAC, logs) |
| **Playbook** | Cortex playbook flow visualization + containment output |

## Cortex XSIAM Integration

### Automation Scripts

| Script | Purpose |
|--------|---------|
| `ExtractK8sContainerEscapeIOCs` | Analyzes XDR issue fields (details, container_id, namespace, host FQDN, process info) to extract IOCs, determine severity, and identify containment targets |
| `InvokeK8sContainmentLambda` | Invokes the AWS Lambda via SigV4-signed HTTP (no AWS integration dependency). Takes AWS credentials as input, returns evidence/results, writes to issue field |

### Playbook Flow

```
Start -> #1 Triage (ExtractK8sContainerEscapeIOCs)
      -> #11 Enter AWS Credentials (operator form)
      -> #2 Collect Evidence (InvokeK8sContainmentLambda)
      -> #3 Severity Check (Critical + SpringShell?)
      -> #31 Operator Approval (Approve / Reject)
      -> #4 Network Isolation
      -> #5 Revoke RBAC
      -> #6 Scale Down
      -> #7 Cordon Node
      -> #8 Kill Pods
      -> #9 Verify Containment
      -> #10 Complete
```

### XDR Issue Fields Used

| Field | Usage |
|-------|-------|
| `details` | "Dropped webshell using the SpringShell exploit" |
| `container_id` | Compromised container ID |
| `namespace` | K8s namespace (vuln-app) |
| `cluster_name` | EKS cluster name |
| `xdm.source.host.fqdn` | EKS node FQDN (for targeted cordon) |
| `xdm.source.host.ipv4_addresses` | Node IPs |
| `xdm.source.user.username` | root (privilege escalation indicator) |
| `causality_actor_process_command_line` | runc / nsenter (container escape indicator) |
| `image_id` | Container image SHA256 |

### Lambda Function

The Lambda (`lambda/containment/handler.py`) authenticates to EKS via STS presigned URL with the `x-k8s-aws-id` header and makes direct K8s API calls.

Supported actions:

| Action | Effect |
|--------|--------|
| `collect_evidence` | Pod details, logs, events, RBAC audit, node status |
| `network_isolate` | Apply deny-all NetworkPolicy |
| `revoke_rbac` | Delete cluster-admin ClusterRoleBinding |
| `scale_down` | Scale deployment to 0 replicas |
| `cordon_node` | Mark node as unschedulable |
| `delete_pod` | Force delete all pods |
| `full_containment` | Run all steps in sequence |

## Terraform State Management

The project uses 3 separate Terraform configurations with S3 remote state:

| Module | State Key | Resources |
|--------|-----------|-----------|
| `terraform-backend/` | Local only | S3 bucket (bootstraps remote state) |
| `terraform/` | `eks/terraform.tfstate` | VPC, EKS, ECR, IAM |
| `terraform-lambda/` | `lambda/terraform.tfstate` | Lambda, IAM role, EKS access entry |

The S3 bucket is created via `terraform-backend/` (local state) and used as remote backend by the other modules. State locking uses S3 native lock files (`use_lockfile = true`).

## CLI Deployment (alternative)

### Via GitHub Actions

1. **Deploy Infrastructure** - Run workflow "01 - Deploy Infrastructure (EKS + ECR)"
2. **Build & Push Image** - Run workflow "02 - Build & Push Vulnerable Image to ECR"
3. **Deploy App** - Run workflow "03 - Deploy Vulnerable App to EKS"

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
cd terraform-lambda && terraform destroy -auto-approve
cd terraform && terraform destroy -auto-approve
cd terraform-backend && terraform destroy -auto-approve
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
├── dashboard/
│   ├── app.py                           # Flask web dashboard (backend API)
│   ├── requirements.txt                 # flask, pyyaml
│   ├── templates/index.html             # Dashboard UI (dark theme)
│   └── static/
│       ├── css/style.css                # Styles, playbook flow, kill chain
│       └── js/app.js                    # Tabs, polling, API calls, state
├── terraform-backend/
│   ├── main.tf                          # S3 bucket for remote TF state
│   ├── outputs.tf                       # bucket_name, region
│   └── variables.tf                     # region, project_name
├── terraform/
│   ├── main.tf                          # VPC, EKS, ECR, IAM, node group
│   ├── backend.tf                       # S3 backend (dynamic config)
│   ├── outputs.tf                       # cluster_name, ecr_url, region
│   └── variables.tf
├── terraform-lambda/
│   ├── main.tf                          # Lambda function, IAM, EKS access
│   ├── backend.tf                       # S3 backend (dynamic config)
│   ├── outputs.tf                       # lambda_name, lambda_arn
│   └── variables.tf
├── lambda/containment/
│   ├── handler.py                       # Lambda: EKS auth + K8s API containment
│   └── requirements.txt
├── cortex-scripts/
│   ├── ExtractK8sContainerEscapeIOCs.py           # IOC extraction script
│   ├── automation-ExtractK8sContainerEscapeIOCs.yml # YAML automation wrapper
│   ├── InvokeK8sContainmentLambda.py              # Lambda invocation script (SigV4)
│   └── automation-InvokeK8sContainmentLambda.yml   # YAML automation wrapper
├── playbook/
│   └── K8s_Container_Escape_Spring4Shell_Containment.yml  # Cortex playbook
├── app/                                 # Spring4Shell vulnerable app (Java/Maven)
│   ├── pom.xml
│   └── src/main/java/...               # Spring Boot controllers
├── k8s/
│   ├── namespace.yaml                   # vuln-app namespace
│   ├── service-account.yaml             # SA + cluster-admin ClusterRoleBinding
│   └── deployment.yaml                  # Privileged pod + LoadBalancer
├── attack/
│   ├── 01-exploit-rce.sh               # Spring4Shell webshell deployment
│   ├── 02-container-escape.sh          # nsenter, host fs, IMDS
│   ├── 03-cluster-takeover.sh          # SA token, secrets, AWS creds
│   └── remote_shell.sh                 # Helper script
├── .github/workflows/                   # CI/CD alternative (GitHub Actions)
├── Dockerfile                           # Multi-stage: Maven build + Tomcat 9
├── .gitignore                           # Excludes tfstate, .terraform, credentials
└── README.md
```

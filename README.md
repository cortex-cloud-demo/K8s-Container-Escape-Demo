# Code-to-Cloud-to-SOC — K8s Container Escape Demo

Full attack chain demo on AWS EKS — from Spring4Shell RCE to container escape to cluster takeover — with automated detection by Cortex XDR and incident response via Cortex playbooks + AWS Lambda containment.

6 attack steps, 14+ Cortex XDR issues generated, automated containment via playbooks. Shift-left scanning with CortexCLI (CWP + IaC/SCA).

Everything is orchestrated from a **web dashboard** with a **Docker toolbox container** for portability (no local tool install required).

## Demo Video

https://github.com/user-attachments/assets/be352d10-b865-4da2-a20d-8689d79344bd

## Architecture

```
┌─────────────────────────── LOCAL MACHINE ──────────────────────────┐
│                                                                     │
│  Flask Dashboard (app.py)  <── run.sh ──>  Browser :5555            │
│       │                                                             │
│       │ docker exec                                                 │
│       v                                                             │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Runner Toolbox Container (Ubuntu 24.04)                       │ │
│  │  Terraform │ kubectl │ AWS CLI │ Helm │ Docker │ CortexCLI │ Node.js │ │
│  │  /project mounted │ Docker socket │ tfstate local              │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                      │
         v                    v                      v
   ┌── AWS Cloud ──┐   ┌── Cortex Cloud ──┐   ┌── Attack ──┐
   │ EKS + Lambda  │   │ XSIAM + Agent    │   │ Steps 1-6  │
   │ ECR + IAM     │   │ Playbooks + XQL  │   │ via webshell│
   └───────────────┘   └──────────────────┘   └────────────┘
```

## Quick Start

### Prerequisites

| Tool | Purpose |
|------|---------|
| **Docker Desktop** | Toolbox container + image build (only requirement) |
| **Python 3.9+** | Dashboard application |
| **AWS Account** | Infrastructure provisioning (admin for bootstrap) |
| **Cortex XSIAM** | Detection, playbooks, CWP/IaC scanning (optional) |

> All CLI tools (terraform, kubectl, aws, helm, cortexcli, node.js) run inside the toolbox container — no local installation needed.

### 1. Clone & Launch

```bash
git clone https://github.com/cortex-cloud-demo/K8s-Container-Escape-Demo.git
cd K8s-Container-Escape-Demo/dashboard
./run.sh
```

This will:
1. Create a Python virtual environment and install dependencies
2. Detect your OS/arch (macOS arm64/Intel, Linux, Windows WSL2)
3. Build the **Runner Toolbox** Docker container (background)
4. Start the dashboard on **http://localhost:5555**

### 2. Configure Credentials

**AWS** — Click **AWS > Configure** and enter credentials (or paste `export AWS_*` commands):
- Access Key ID, Secret Access Key, Session Token (optional), Region

**Cortex** — Click **CORTEX > Configure**:
- API Base URL, API Key ID, API Key

### 3. Deploy Infrastructure

Click **INFRA > Apply** — deploys in 2 phases via the Runner Toolbox:
1. **Infrastructure**: VPC, EKS cluster (AL2023), ECR, IAM users/roles
2. **Lambda**: Containment function, IAM invoker role, EKS access entry

### 4. Build & Deploy

| Step | Button | Action |
|------|--------|--------|
| Connect | **Connect** | Generate kubeconfig for EKS |
| Build | **Build & Push** | Docker build (linux/amd64) + push to ECR |
| Deploy | **Deploy** | K8s manifests: privileged pod + LoadBalancer |

### 5. AppSec — Shift-Left Scanning

| Scan | Button | Target | What it detects |
|------|--------|--------|-----------------|
| **CWP Image** | Scan Image | Container image | Vulnerabilities, malware, secrets, SBOM |
| **IaC** | Terraform | terraform-infra/ | Terraform misconfigurations |
| **K8s** | K8s | k8s/ | K8s manifest security issues |
| **SCA** | SCA | app/ | Vulnerable dependencies (Spring4Shell) |
| **Full** | Scan All | Entire repo | All of the above + secrets detection |

All scans run via **CortexCLI** inside the Runner Toolbox container (downloaded dynamically from Cortex tenant).

### 6. Run Attack Chain

| Step | Button | MITRE | What it does |
|------|--------|-------|-------------|
| Step 1 | **Exploit** | T1190, T1505 | Spring4Shell RCE — deploy JSP webshell |
| Step 2 | **Escape** | T1611, T1552 | Container escape — nsenter, mount, chroot, IMDS |
| Step 3 | **Takeover** | T1078, T1552 | Cluster takeover — SA token, all secrets/pods/nodes |
| Step 4 | **Scan** | T1610, T1613 | K8s scanning — deepce, kube-hunter, RBAC enum |
| Step 5 | **Deploy** | T1105, T1059 | Malware — WildFire ELF, reverse shell, cryptominer |
| Step 6 | **Move** | T1021, T1550 | Lateral movement — SSH, rogue pod, IMDS theft |

Or use **Run Full Demo** (or click **Run Attack** in the diagram) to execute all 6 steps automatically. The Overview diagram animates in real-time — red flows show the attack path, green flows show Cortex detection and response.

After completion, click **"Analyze / Forensic and take action in Cortex XSIAM"** to open the Cortex console directly on the Cases page.

### 7. Deploy Cortex Response

| Step | Button | Action |
|------|--------|--------|
| Lambda | **Deploy** | Redeploy containment Lambda (if needed) |
| Scripts | **Deploy All** | Push 4 automation scripts to Cortex |
| Playbooks | **Deploy All** | Push 3 playbooks to Cortex |
| Policy | **Import** | Create prevention profiles via API |

### 8. Cleanup

Click **Destroy All** — automatically cleans up K8s resources (LB, ENIs, EIPs), destroys Lambda, then destroys infrastructure.

## Dashboard Tabs

| Tab | Color | Purpose |
|-----|-------|---------|
| **Code to Cloud to SOC** | Green | Unified diagram showing the 3 phases (Code → Cloud → SOC) with narrative and feedback loop |
| **Cloud / Runtime Security** | Purple | Interactive architecture diagram with live attack/detection/response animations. Default view during attacks |
| **AppSec** | Cyan | Interactive diagram for CWP image scanning and IaC/SCA code scanning with clickable scan targets |
| **Terminal** | — | Command output for all operations + remote webshell |
| **kubectl** | — | Interactive kubectl with shortcuts (nodes, pods, secrets, kill pods) |
| **Cortex** | — | Playbook flow visualization + script/playbook deployment |
| **SOC Live** | Red | Real-time Cortex XDR alerts, MITRE ATT&CK heatmap, detection timer |
| **Code** | Cyan | Shift-left: CVE details, K8s misconfigurations, IaC findings with fixes |
| **Security Radar** | Cyan | Before/after security posture comparison (6-axis spider chart) |
| **Architecture** | Cyan | Platform architecture diagram (dashboard, toolbox, AWS, Cortex) |

## Cortex XDR Issues Generated

The 6 attack steps generate **14+ issues** in Cortex XDR:

| Issue | Severity | MITRE | Triggered by |
|-------|----------|-------|-------------|
| Local Threat Detected (x3) | HIGH | — | Webshell JSP creation |
| Evasion Technique | HIGH | T1059.004 | Base64 script decode + exec |
| Local Analysis Malware | HIGH | — | Malicious file detected |
| Container Image immutability (x2) | MEDIUM | T1118 | curl/kubectl installed (drift) |
| Kubernetes nsenter escape | LOW | T1611 | nsenter container escape |
| Possible data obfuscation (x3) | LOW | T1140 | Base64 usage in pod |
| kubectl execution in pod | LOW | T1134 | kubectl with SA token |
| UNIX LOLBIN rare host | LOW | T1071 | curl to dl.k8s.io |
| Uncommon service started | LOW | T1543 | Service via nsenter |

## Runner Toolbox

The toolbox is a Docker container (Ubuntu 24.04) with all CLI tools, **auto-built at startup**:

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform | 1.9.8 | Infrastructure provisioning (EKS, VPC, Lambda) |
| kubectl | 1.29 | Kubernetes management |
| AWS CLI | v2 | AWS API operations (ECR, STS, EKS) |
| Helm | 3.17 | Chart deployments (XDR agent) |
| Node.js | 22 | Required by CortexCLI for code scanning |
| Docker CLI | latest | Build, push, image scan (via mounted socket) |
| CortexCLI | latest | CWP image scan + IaC/SCA code scanning (downloaded from tenant) |

**CortexCLI** is downloaded dynamically from your Cortex tenant at runtime — no manual install needed.

**Portability:**
- macOS Apple Silicon (arm64) + Intel (amd64)
- Linux (amd64/arm64)
- Windows (WSL2)
- Fallback: runs without Docker (tools must be installed locally)

**Volumes mounted:**
- `/project` — source code + terraform state (local)
- `/var/run/docker.sock` — Docker engine access
- `~/.aws` — AWS credentials (read-only)

## IaC Tagging (Yor)

All Terraform resources are tagged with [Yor](https://github.com/bridgecrewio/yor) for traceability:

| Tag | Description |
|-----|-------------|
| `yor_trace` | Unique resource trace ID |
| `yor_name` | Resource name |
| `git_repo` | Repository name |
| `git_org` | GitHub organization |
| `git_file` | Source file path |
| `git_commit` | Last commit hash |
| `git_last_modified_at` | Last modification date |
| `git_last_modified_by` | Last author |

Run `yor tag -d .` to update tags after changes.

## BYOC Mode (Bring Your Own Cluster)

Use an existing Kubernetes cluster instead of deploying one:

1. **Settings > BYOC > Configure**
2. Paste kubeconfig content
3. Set the LoadBalancer hostname
4. Optionally provide a container image URL

Skip the infrastructure steps and go straight to Deploy + Attack.

## Components

| Component | Description |
|-----------|-------------|
| **Dashboard** | Flask web UI — orchestrates infra, attack, response, security radar |
| **Runner Toolbox** | Docker container with terraform, kubectl, aws, helm, cortexcli, node.js |
| **EKS Cluster** | AWS managed K8s on AL2023 with GP3 volumes |
| **Vulnerable App** | Spring Boot with CVE-2022-22965 on Tomcat 9 |
| **Lambda** | Containment function — STS auth to EKS API |
| **Cortex Scripts** | 4 automation scripts (triage, containment, forensic, threat hunt) |
| **Cortex Playbooks** | 3 playbooks (containment, forensic analysis, search similar events) |
| **CortexCLI CWP** | Container image scanning (vulnerabilities, malware, secrets) |
| **CortexCLI Code Security** | IaC + SCA + secrets scanning for Terraform, K8s manifests, and app code |

## Project Structure

```
.
├── dashboard/
│   ├── app.py                    # Flask API + task manager + toolbox routing
│   ├── run.sh                    # Launch script (venv + toolbox build + flask)
│   ├── requirements.txt
│   ├── templates/index.html      # Dashboard UI (SVG diagrams, 10 tabs)
│   └── static/
│       ├── css/style.css         # Dark/light theme
│       └── js/app.js             # Kill chain, SOC live, architecture, AppSec
├── Dockerfile                    # Vulnerable app (Maven + Tomcat 9)
├── Dockerfile.toolbox            # Runner toolbox (Ubuntu 24.04, all CLI tools)
├── terraform-infra/              # VPC, EKS, ECR, IAM (local tfstate, Yor tags)
├── terraform-lambda/             # Lambda, IAM invoker, EKS access (local tfstate, Yor tags)
├── lambda/containment/           # Lambda handler (STS + K8s API)
├── cortex-scripts/               # 4 automation scripts (.py + .yml)
├── cortex-policy/                # Prevention profiles exports
├── playbook/                     # 3 playbook YAMLs
├── app/                          # Spring4Shell vulnerable app (Java/Maven)
├── k8s/                          # K8s manifests (namespace, SA, deployment)
├── attack/                       # 6 attack scripts + remote shell
│   ├── 01-exploit-rce.sh         # Spring4Shell RCE (/bin/sh -c webshell)
│   ├── 02-container-escape.sh    # nsenter, mount, chroot, IMDS
│   ├── 03-cluster-takeover.sh    # SA token, kubectl via upload
│   ├── 04-k8s-scanning.sh       # deepce, kube-hunter, peirates sim
│   ├── 05-deploy-malware.sh     # WildFire ELF, reverse shell, cryptominer
│   ├── 06-lateral-movement.sh   # SSH, rogue pod, IMDS, cross-namespace
│   └── remote_shell.sh
└── docs/                         # Architecture diagrams, pitch, PowerPoint
```

## Demo Features

| Feature | Description |
|---------|-------------|
| **Code to Cloud to SOC Tab** | Unified 3-phase diagram: Code (shift-left) → Cloud (attack) → SOC (response) with feedback loop |
| **Run Full Demo / Run Attack** | One-click: execute all 6 attack steps with live diagram animation |
| **Live Architecture Diagram** | Interactive SVG — animated attack flows (red), detection (green), particles traveling along paths |
| **AppSec Tab** | Interactive diagram for CWP image scan + IaC/SCA code scan with clickable targets and dynamic results |
| **SOC Live** | Real-time Cortex XDR alert feed + MITRE ATT&CK heatmap |
| **Code (Shift-Left)** | CVE + K8s misconfigurations with severity and fixes |
| **Security Radar** | Before/after spider chart (6 security axes) |
| **CortexCLI CWP** | Container image scanning with results link to Cortex Cloud inventory |
| **CortexCLI IaC/SCA** | Terraform + K8s + app code scanning with results link to Cortex Cloud AppSec |
| **Cortex Console Links** | Click on diagram elements to open Cortex console (Dashboard, Cases, AppSec, Container Images) |
| **Architecture Tab** | Platform architecture (dashboard, toolbox, AWS, Cortex) |
| **Yor IaC Tags** | Terraform resources tagged with git traceability (yor_trace, git_repo, git_commit) |
| **Theme Toggle** | Dark / Light / Auto mode (persisted) |
| **AWS Paste Import** | Paste `export AWS_*` commands to auto-fill credentials |
| **BYOC Mode** | Bring Your Own Cluster — skip infra, use existing K8s |
| **Runner Status** | Live toolbox container status indicator in header |
| **Credential Persistence** | Credentials saved locally and auto-loaded on restart |

## CLI Alternative

```bash
export HOST=<LB_HOSTNAME>
./attack/01-exploit-rce.sh
./attack/02-container-escape.sh
./attack/03-cluster-takeover.sh
./attack/04-k8s-scanning.sh
./attack/05-deploy-malware.sh
./attack/06-lateral-movement.sh

# Cleanup
kubectl delete namespace vuln-app
kubectl delete clusterrolebinding vuln-app-cluster-admin
cd terraform-lambda && terraform destroy -auto-approve
cd terraform-infra && terraform destroy -auto-approve
```

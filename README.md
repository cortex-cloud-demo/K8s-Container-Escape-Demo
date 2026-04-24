# Kubernetes Container Escape Demo

**Code to Cloud to SOC** — Full attack chain demo on AWS EKS with automated detection by Cortex XDR and incident response via Cortex playbooks + AWS Lambda containment.

From Spring4Shell RCE to container escape to cluster takeover — 6 attack steps, 14+ Cortex XDR issues generated, automated containment via playbooks.

Everything is orchestrated from a **web dashboard** with a **Docker toolbox container** for portability (no local tool install required).

## Demo Video

https://github.com/user-attachments/assets/be352d10-b865-4da2-a20d-8689d79344bd

## Architecture

```
┌─────────────────────────── LOCAL MACHINE ──────────────────────────┐
│                                                                     │
│  Flask Dashboard (app.py)  ◄── run.sh ──►  Browser :5555           │
│       │                                                             │
│       │ docker exec                                                 │
│       ▼                                                             │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Runner Toolbox Container (k8s-escape-toolbox)                 │ │
│  │  Terraform │ kubectl │ AWS CLI │ Helm │ Docker CLI │ CortexCLI │ │
│  │  /project mounted │ Docker socket │ tfstate local              │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                      │
         ▼                    ▼                      ▼
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
| **Cortex XSIAM** | Detection, playbooks, CWP scanning (optional) |

> All CLI tools (terraform, kubectl, aws, helm, cortexcli) run inside the toolbox container — no local installation needed.

### 1. Clone & Launch

```bash
git clone https://github.com/cortex-cloud-demo/K8s-Container-Escape-Demo.git
cd K8s-Container-Escape-Demo/dashboard
./run.sh
```

This will:
1. Create a Python virtual environment and install dependencies
2. Build the **Runner Toolbox** Docker container (background)
3. Start the dashboard on **http://localhost:5555**

The toolbox container auto-detects your OS/arch (macOS arm64/Intel, Linux, Windows WSL2).

### 2. Configure Credentials

**AWS** — Click **AWS > Configure** and enter credentials (or paste `export AWS_*` commands):
- Access Key ID, Secret Access Key, Session Token (optional), Region

**Cortex** — Click **CORTEX > Configure**:
- API Base URL, API Key ID, API Key

### 3. Deploy Infrastructure

Click **INFRA > Apply** — deploys in 2 phases:
1. **Infrastructure**: VPC, EKS cluster (AL2023), ECR, IAM users/roles
2. **Lambda**: Containment function, IAM invoker role, EKS access entry

### 4. Build & Deploy

| Step | Button | Action |
|------|--------|--------|
| Connect | **Connect** | Generate kubeconfig for EKS |
| Build | **Build & Push** | Docker build (linux/amd64) + push to ECR |
| Scan | **Scan Image** | CortexCLI CWP scan (vulnerabilities + malware) |
| Deploy | **Deploy** | K8s manifests: privileged pod + LoadBalancer |

### 5. Run Attack Chain

| Step | Button | MITRE | What it does |
|------|--------|-------|-------------|
| Step 1 | **Exploit** | T1190, T1505 | Spring4Shell RCE — deploy JSP webshell |
| Step 2 | **Escape** | T1611, T1552 | Container escape — nsenter, mount, chroot, IMDS |
| Step 3 | **Takeover** | T1078, T1552 | Cluster takeover — SA token, all secrets/pods/nodes |
| Step 4 | **Scan** | T1610, T1613 | K8s scanning — deepce, kube-hunter, RBAC enum |
| Step 5 | **Deploy** | T1105, T1059 | Malware — WildFire ELF, reverse shell, cryptominer |
| Step 6 | **Move** | T1021, T1550 | Lateral movement — SSH, rogue pod, IMDS theft |

Or use **Run Full Demo** to execute all 6 steps automatically. The Overview diagram animates in real-time — red flows show the attack path, green flows show Cortex detection and response. After completion, click **"Analyze / Forensic and take action in Cortex XSIAM"** to open the Cortex console directly on the Cases page.

### 6. Deploy Cortex Response

| Step | Button | Action |
|------|--------|--------|
| Scan Image | **Scan Image** | CortexCLI container image scan (CWP) |
| Lambda | **Deploy** | Redeploy containment Lambda (if needed) |
| Scripts | **Deploy All** | Push 4 automation scripts to Cortex |
| Playbooks | **Deploy All** | Push 3 playbooks to Cortex |
| Policy | **Import** | Create prevention profiles via API |

### 7. Cleanup

Click **Destroy All** — automatically cleans up K8s resources (LB, ENIs, EIPs), destroys Lambda, then destroys infrastructure.

## Dashboard Tabs

| Tab | Purpose |
|-----|---------|
| **Overview** | Interactive architecture diagram with live attack/detection/response animations. Default view during attacks — all steps open here to watch the diagram animate in real-time |
| **Terminal** | Command output for all operations + remote webshell. Runs in background during attacks |
| **kubectl** | Interactive kubectl with shortcuts (nodes, pods, secrets, kill pods) |
| **Cortex** | Playbook flow visualization + script/playbook deployment |
| **SOC Live** | Real-time Cortex XDR alerts, MITRE ATT&CK heatmap, detection timer |
| **Code** | Shift-left: CVE details, K8s misconfigurations, IaC findings with fixes |
| **Security Radar** | Before/after security posture comparison (6-axis spider chart) |
| **Architecture** | Platform architecture diagram (dashboard, toolbox, AWS, Cortex) |

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

The toolbox is a Docker container with all CLI tools, **auto-built at startup**:

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform | 1.9.8 | Infrastructure provisioning |
| kubectl | 1.29 | Kubernetes management |
| AWS CLI | v2 | AWS API operations |
| Helm | latest | Chart deployments |
| Docker CLI | latest | Build, push, scan (via socket) |
| CortexCLI | latest | Container image scanning (CWP) |

**Portability:**
- macOS Apple Silicon (arm64) + Intel (amd64)
- Linux (amd64/arm64)
- Windows (WSL2)
- Fallback: runs without Docker (tools must be installed locally)

**Volumes mounted:**
- `/project` — source code + terraform state (local)
- `/var/run/docker.sock` — Docker engine access
- `~/.aws` — AWS credentials (read-only)

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
| **Runner Toolbox** | Docker container with terraform, kubectl, aws, helm, cortexcli |
| **EKS Cluster** | AWS managed K8s on AL2023 with GP3 volumes |
| **Vulnerable App** | Spring Boot with CVE-2022-22965 on Tomcat 9 |
| **Lambda** | Containment function — STS auth to EKS API |
| **Cortex Scripts** | 4 automation scripts (triage, containment, forensic, threat hunt) |
| **Cortex Playbooks** | 3 playbooks (containment, forensic analysis, search similar events) |
| **CortexCLI** | Container image scanning (CWP) before push |

## Project Structure

```
.
├── dashboard/
│   ├── app.py                    # Flask API + task manager
│   ├── run.sh                    # Launch script (venv + toolbox + flask)
│   ├── requirements.txt
│   ├── templates/index.html      # Dashboard UI (SVG diagrams, tabs)
│   └── static/
│       ├── css/style.css         # Dark/light theme
│       └── js/app.js             # Kill chain, SOC live, architecture
├── Dockerfile                    # Vulnerable app (Maven + Tomcat 9)
├── Dockerfile.toolbox            # Runner toolbox (terraform, kubectl, aws, cortexcli)
├── terraform-infra/              # VPC, EKS, ECR, IAM (local tfstate)
├── terraform-lambda/             # Lambda, IAM invoker, EKS access (local tfstate)
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
└── docs/                         # Architecture diagrams, PowerPoint
```

## Demo Features

| Feature | Description |
|---------|-------------|
| **Run Full Demo** | One-click: execute all 6 attack steps automatically with live diagram |
| **Live Architecture Diagram** | Interactive SVG — animated attack flows (red), detection (green), response (green) with particles traveling along paths. All steps open the Overview to watch the diagram live |
| **Kill Chain Progress** | Header bar: 9 stages with animated dots tracking attack progression |
| **SOC Live** | Real-time Cortex XDR alert feed + MITRE ATT&CK heatmap |
| **Code (Shift-Left)** | CVE details + K8s misconfigurations with severity and fixes |
| **Security Radar** | Before/after spider chart (6 security axes) |
| **CortexCLI Scan** | Pre-push container image scanning (CWP) via Runner Toolbox |
| **Cortex Console Link** | Click on Cortex XSIAM in diagram → opens console. Post-attack CTA → opens `/cases` |
| **Architecture Tab** | Platform architecture diagram (dashboard, toolbox, AWS, Cortex) |
| **Theme Toggle** | Dark / Light / Auto mode (persisted) |
| **AWS Paste Import** | Paste `export AWS_*` commands to auto-fill credentials |
| **BYOC Mode** | Bring Your Own Cluster — skip infra, use existing K8s |
| **Runner Status** | Live toolbox container status indicator in header |
| **Runner Status** | Live toolbox container status in header |
| **Open Console** | Click Cortex/WebApp in diagram to open in browser |

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

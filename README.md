# Kubernetes Container Escape Demo

Security demonstration: exploitation of a vulnerable containerized application leading to container escape and full cluster takeover on AWS EKS.

## Attack Chain

```
Spring4Shell RCE (CVE-2022-22965)
  |-> Webshell on the pod
      |-> Container Escape (privileged + hostPID + hostPath)
          |-> Node access via nsenter
          |-> Host filesystem read/write
          |-> AWS IMDS credential theft
      |-> Cluster Takeover (cluster-admin ServiceAccount)
          |-> Full Kubernetes API access
          |-> Secrets exfiltration
          |-> Lateral movement to AWS
```

## Architecture

| Component | Description |
|-----------|-------------|
| **EKS Cluster** | AWS managed Kubernetes (v1.29) |
| **ECR** | Container registry for the vulnerable image |
| **Vulnerable App** | Spring Boot app with CVE-2022-22965 (Spring4Shell) |
| **Pod Misconfigs** | `privileged: true`, `hostPID`, `hostNetwork`, `hostPath: /`, SA `cluster-admin` |

## Prerequisites

- AWS account with admin access
- GitHub repository with the following **secrets** configured:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
- `curl` installed locally (for running attack scripts)

## Deployment (via GitHub Actions)

All workflows are triggered manually (`workflow_dispatch`).

### Step 1: Deploy Infrastructure

Run workflow **"01 - Deploy Infrastructure (EKS + ECR)"** with action `apply`.

This provisions:
- VPC + subnets + IGW
- EKS cluster + node group (2x t3.medium)
- ECR repository

> ~15 minutes for EKS cluster creation.

### Step 2: Build & Push Vulnerable Image

Run workflow **"02 - Build & Push Vulnerable Image to ECR"**.

This builds the Spring4Shell vulnerable app and pushes it to ECR.

### Step 3: Deploy Application to EKS

Run workflow **"03 - Deploy Vulnerable App to EKS"**.

This deploys:
- Namespace `vuln-app`
- ServiceAccount with `cluster-admin` ClusterRoleBinding
- Privileged Deployment with hostPID/hostNetwork/hostPath
- LoadBalancer Service

### Step 4: Get Application URL

```bash
aws eks update-kubeconfig --name eks-escape-demo --region eu-west-3
export HOST=$(kubectl get svc vuln-app-service -n vuln-app -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "App URL: http://${HOST}/app"
```

## Running the Attack

### Step 1: Spring4Shell RCE

```bash
./attack/01-exploit-rce.sh
```

Deploys a webshell via CVE-2022-22965. After exploitation:
```bash
# Execute commands on the pod
curl --data-urlencode 'cmd=id' "http://${HOST}/shell.jsp"
curl --data-urlencode 'cmd=cat /flag' "http://${HOST}/shell.jsp"
```

### Step 2: Container Escape

```bash
./attack/02-container-escape.sh
```

Demonstrates:
- Host process visibility (`hostPID`)
- Host filesystem access (`hostPath: /` mounted at `/host`)
- Node command execution via `nsenter` (privileged + hostPID)
- AWS IMDS access (`hostNetwork`)

### Step 3: Cluster Takeover

```bash
./attack/03-cluster-takeover.sh
```

Demonstrates:
- ServiceAccount token extraction
- Full cluster enumeration (namespaces, pods, secrets, nodes)
- AWS IAM credential theft via IMDS for lateral movement

## Misconfigurations Exploited

| Misconfiguration | Impact | Remediation |
|---|---|---|
| `privileged: true` | Full host kernel access | Use `allowPrivilegeEscalation: false` |
| `hostPID: true` | See all host processes, `nsenter` escape | Disable hostPID |
| `hostNetwork: true` | Access node network, IMDS | Disable hostNetwork, use IMDSv2 with hop limit=1 |
| `hostPath: /` | Read/write entire host filesystem | Use PVCs, restrict hostPath via PSP/PSA |
| SA `cluster-admin` | Full Kubernetes API control | Least privilege RBAC |
| EC2FullAccess on nodes | Lateral movement to AWS | Minimal IAM, IRSA |
| No Pod Security Standards | All above misconfigs allowed | Enforce `restricted` PSA |
| No Network Policies | Unrestricted pod communication | Implement NetworkPolicies |

## Cleanup

Run workflow **"99 - Destroy Infrastructure"** (type `destroy` to confirm).

Or manually:
```bash
kubectl delete namespace vuln-app
kubectl delete clusterrolebinding vuln-app-cluster-admin
cd terraform && terraform destroy -auto-approve
```

## Project Structure

```
.
├── .github/workflows/
│   ├── 01-deploy-infra.yml          # Terraform EKS + ECR
│   ├── 02-build-push-image.yml      # Build & push to ECR
│   ├── 03-deploy-app.yml            # Deploy vuln app to EKS
│   └── 99-destroy-infra.yml         # Cleanup
├── terraform/
│   ├── main.tf                      # EKS + ECR + VPC + IAM
│   ├── variables.tf
│   ├── outputs.tf
│   └── backend.tf
├── app/                             # Spring4Shell vulnerable app (Java)
├── k8s/
│   ├── namespace.yaml
│   ├── service-account.yaml         # cluster-admin binding
│   └── deployment.yaml              # Privileged pod
├── attack/
│   ├── 01-exploit-rce.sh            # Spring4Shell webshell
│   ├── 02-container-escape.sh       # Node escape
│   ├── 03-cluster-takeover.sh       # Cluster-admin exploitation
│   └── remote_shell.sh              # Helper script
├── Dockerfile
└── README.md
```

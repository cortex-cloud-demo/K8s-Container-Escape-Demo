"""
AWS Lambda - K8s Containment Handler
Called by Cortex XSOAR playbook to isolate compromised pods/namespaces on EKS.

Actions:
  - network_isolate:  Apply deny-all NetworkPolicy on namespace
  - delete_pod:       Delete compromised pod
  - revoke_rbac:      Remove cluster-admin ClusterRoleBinding
  - scale_down:       Scale deployment to 0 replicas
  - cordon_node:      Cordon the node running the compromised pod
  - collect_evidence: Gather pod logs, describe, events
  - full_containment: Run all containment steps in sequence
"""

import base64
import json
import logging
import os
import tempfile

import boto3
import urllib3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CLUSTER_NAME = os.environ.get("EKS_CLUSTER_NAME", "eks-escape-demo")
REGION = os.environ.get("AWS_REGION", "eu-west-3")
NAMESPACE = os.environ.get("TARGET_NAMESPACE", "vuln-app")

# Disable SSL warnings for k8s API (self-signed CA)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_eks_token(cluster_name):
    """Get a bearer token for EKS authentication using STS."""
    sts = boto3.client("sts", region_name=REGION)
    token = sts.get_caller_identity()  # validate creds

    # Use the STS presigned URL method for EKS auth
    sts_client = boto3.client("sts", region_name=REGION)
    url = sts_client.generate_presigned_url(
        "get_caller_identity",
        HttpMethod="GET",
        ExpiresIn=60,
    )
    # EKS expects the token as "k8s-aws-v1.<base64url-encoded presigned URL>"
    token = "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return token


def get_cluster_info(cluster_name):
    """Get EKS cluster endpoint and CA data."""
    eks = boto3.client("eks", region_name=REGION)
    resp = eks.describe_cluster(name=cluster_name)
    cluster = resp["cluster"]
    return {
        "endpoint": cluster["endpoint"],
        "ca_data": cluster["certificateAuthority"]["data"],
    }


def k8s_request(endpoint, ca_data, token, method, path, body=None):
    """Make a raw HTTP request to the Kubernetes API."""
    # Write CA cert to temp file
    ca_bytes = base64.b64decode(ca_data)
    ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    ca_file.write(ca_bytes)
    ca_file.close()

    http = urllib3.PoolManager(ca_certs=ca_file.name)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    url = f"{endpoint}{path}"
    logger.info(f"K8s API: {method} {path}")

    if body:
        resp = http.request(method, url, headers=headers, body=json.dumps(body))
    else:
        resp = http.request(method, url, headers=headers)

    os.unlink(ca_file.name)

    result = {
        "status": resp.status,
        "body": resp.data.decode("utf-8", errors="replace"),
    }
    if resp.status >= 400:
        logger.error(f"K8s API error {resp.status}: {result['body'][:500]}")
    return result


# ─── Containment Actions ─────────────────────────────────────────────────────


def action_network_isolate(endpoint, ca_data, token, namespace):
    """Apply deny-all NetworkPolicy to isolate namespace."""
    netpol = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "containment-deny-all",
            "namespace": namespace,
            "labels": {"cortex-xsoar": "containment"},
        },
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }

    resp = k8s_request(
        endpoint, ca_data, token, "POST",
        f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies",
        body=netpol,
    )

    if resp["status"] == 409:
        return {"action": "network_isolate", "status": "already_exists", "detail": "NetworkPolicy already applied"}
    if resp["status"] >= 400:
        return {"action": "network_isolate", "status": "error", "detail": resp["body"][:300]}
    return {"action": "network_isolate", "status": "success", "detail": "Deny-all NetworkPolicy applied"}


def action_delete_pod(endpoint, ca_data, token, namespace):
    """Delete all pods in the compromised namespace."""
    # List pods
    list_resp = k8s_request(endpoint, ca_data, token, "GET", f"/api/v1/namespaces/{namespace}/pods")
    if list_resp["status"] >= 400:
        return {"action": "delete_pod", "status": "error", "detail": f"Cannot list pods: {list_resp['body'][:200]}"}

    pods = json.loads(list_resp["body"]).get("items", [])
    deleted = []
    for pod in pods:
        pod_name = pod["metadata"]["name"]
        del_resp = k8s_request(endpoint, ca_data, token, "DELETE", f"/api/v1/namespaces/{namespace}/pods/{pod_name}")
        deleted.append({"pod": pod_name, "status": del_resp["status"]})

    return {"action": "delete_pod", "status": "success", "deleted_pods": deleted}


def action_revoke_rbac(endpoint, ca_data, token, namespace):
    """Remove the cluster-admin ClusterRoleBinding for the vuln-app SA."""
    binding_name = "vuln-app-cluster-admin"
    resp = k8s_request(
        endpoint, ca_data, token, "DELETE",
        f"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{binding_name}",
    )

    if resp["status"] == 404:
        return {"action": "revoke_rbac", "status": "not_found", "detail": "ClusterRoleBinding not found"}
    if resp["status"] >= 400:
        return {"action": "revoke_rbac", "status": "error", "detail": resp["body"][:300]}
    return {"action": "revoke_rbac", "status": "success", "detail": f"Deleted ClusterRoleBinding {binding_name}"}


def action_scale_down(endpoint, ca_data, token, namespace):
    """Scale the vuln-app deployment to 0 replicas."""
    patch = {"spec": {"replicas": 0}}
    resp = k8s_request(
        endpoint, ca_data, token, "PATCH",
        f"/apis/apps/v1/namespaces/{namespace}/deployments/vuln-app",
        body=patch,
    )

    if resp["status"] >= 400:
        return {"action": "scale_down", "status": "error", "detail": resp["body"][:300]}
    return {"action": "scale_down", "status": "success", "detail": "Deployment scaled to 0 replicas"}


def action_cordon_node(endpoint, ca_data, token, namespace):
    """Cordon the node running the compromised pods."""
    # Find node from pod spec
    list_resp = k8s_request(endpoint, ca_data, token, "GET", f"/api/v1/namespaces/{namespace}/pods")
    if list_resp["status"] >= 400:
        return {"action": "cordon_node", "status": "error", "detail": "Cannot list pods"}

    pods = json.loads(list_resp["body"]).get("items", [])
    cordoned_nodes = []

    for pod in pods:
        node_name = pod.get("spec", {}).get("nodeName")
        if node_name and node_name not in cordoned_nodes:
            patch = {"spec": {"unschedulable": True}}
            resp = k8s_request(
                endpoint, ca_data, token, "PATCH",
                f"/api/v1/nodes/{node_name}",
                body=patch,
            )
            cordoned_nodes.append({"node": node_name, "status": resp["status"]})

    return {"action": "cordon_node", "status": "success", "cordoned_nodes": cordoned_nodes}


def action_collect_evidence(endpoint, ca_data, token, namespace):
    """Collect forensic evidence from the compromised namespace."""
    evidence = {}

    # Pod details
    pods_resp = k8s_request(endpoint, ca_data, token, "GET", f"/api/v1/namespaces/{namespace}/pods")
    if pods_resp["status"] < 400:
        pods = json.loads(pods_resp["body"]).get("items", [])
        evidence["pods"] = []
        for pod in pods:
            pod_name = pod["metadata"]["name"]
            pod_info = {
                "name": pod_name,
                "node": pod.get("spec", {}).get("nodeName"),
                "status": pod.get("status", {}).get("phase"),
                "hostPID": pod.get("spec", {}).get("hostPID", False),
                "hostNetwork": pod.get("spec", {}).get("hostNetwork", False),
                "privileged": False,
                "service_account": pod.get("spec", {}).get("serviceAccountName"),
            }
            # Check privileged
            for c in pod.get("spec", {}).get("containers", []):
                sc = c.get("securityContext", {})
                if sc.get("privileged"):
                    pod_info["privileged"] = True
            evidence["pods"].append(pod_info)

            # Pod logs
            logs_resp = k8s_request(
                endpoint, ca_data, token, "GET",
                f"/api/v1/namespaces/{namespace}/pods/{pod_name}/log?tailLines=50",
            )
            if logs_resp["status"] < 400:
                evidence[f"logs_{pod_name}"] = logs_resp["body"][:2000]

    # Events
    events_resp = k8s_request(
        endpoint, ca_data, token, "GET",
        f"/api/v1/namespaces/{namespace}/events",
    )
    if events_resp["status"] < 400:
        events = json.loads(events_resp["body"]).get("items", [])
        evidence["events"] = [
            {
                "reason": e.get("reason"),
                "message": e.get("message", "")[:200],
                "count": e.get("count"),
                "type": e.get("type"),
            }
            for e in events[-20:]
        ]

    # RBAC
    crb_resp = k8s_request(
        endpoint, ca_data, token, "GET",
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
    )
    if crb_resp["status"] < 400:
        bindings = json.loads(crb_resp["body"]).get("items", [])
        evidence["suspicious_rbac"] = [
            {"name": b["metadata"]["name"], "role": b.get("roleRef", {}).get("name")}
            for b in bindings
            if b.get("roleRef", {}).get("name") == "cluster-admin"
            and any(
                s.get("namespace") == namespace
                for s in b.get("subjects", [])
            )
        ]

    return {"action": "collect_evidence", "status": "success", "evidence": evidence}


# ─── Lambda Handler ──────────────────────────────────────────────────────────


def lambda_handler(event, context):
    """
    Lambda entry point.

    Event format:
    {
        "action": "network_isolate|delete_pod|revoke_rbac|scale_down|cordon_node|collect_evidence|full_containment",
        "cluster_name": "eks-escape-demo",  (optional)
        "namespace": "vuln-app",            (optional)
        "region": "eu-west-3"               (optional)
    }
    """
    action = event.get("action", "full_containment")
    cluster_name = event.get("cluster_name", CLUSTER_NAME)
    namespace = event.get("namespace", NAMESPACE)
    region = event.get("region", REGION)

    logger.info(f"Containment action: {action} on {cluster_name}/{namespace}")

    # Get cluster info and token
    try:
        cluster_info = get_cluster_info(cluster_name)
        token = get_eks_token(cluster_name)
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"Failed to authenticate to EKS: {str(e)}"}),
        }

    endpoint = cluster_info["endpoint"]
    ca_data = cluster_info["ca_data"]

    actions_map = {
        "network_isolate": action_network_isolate,
        "delete_pod": action_delete_pod,
        "revoke_rbac": action_revoke_rbac,
        "scale_down": action_scale_down,
        "cordon_node": action_cordon_node,
        "collect_evidence": action_collect_evidence,
    }

    results = []

    if action == "full_containment":
        # Run all containment steps in order
        for step_name in ["collect_evidence", "network_isolate", "revoke_rbac", "scale_down", "cordon_node", "delete_pod"]:
            logger.info(f"Running step: {step_name}")
            result = actions_map[step_name](endpoint, ca_data, token, namespace)
            results.append(result)
            logger.info(f"Step {step_name}: {result.get('status')}")
    elif action in actions_map:
        result = actions_map[action](endpoint, ca_data, token, namespace)
        results.append(result)
    else:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Unknown action: {action}"}),
        }

    return {
        "statusCode": 200,
        "body": json.dumps({
            "action": action,
            "cluster": cluster_name,
            "namespace": namespace,
            "results": results,
        }),
    }

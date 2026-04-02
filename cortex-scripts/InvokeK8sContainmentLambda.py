"""
InvokeK8sContainmentLambda
===========================
Invokes the K8s Containment AWS Lambda function.
Supports two authentication modes (auto-detected):
  1. Cross-account IAM Role (AssumeRole) - if assume_role_arn + external_id are provided
  2. Direct AWS credentials - if aws_access_key_id + aws_secret_access_key are provided

Script arguments:
- assume_role_arn                       : IAM Role ARN to assume (cross-account, optional)
- external_id                           : External ID for STS AssumeRole (optional)
- aws_access_key_id                     : AWS Access Key ID (optional, fallback mode)
- aws_secret_access_key                 : AWS Secret Access Key (optional, fallback mode)
- aws_session_token                     : AWS Session Token (optional)
- aws_region                            : AWS Region (e.g. eu-west-3)
- lambda_function_name                  : Lambda function name (e.g. k8s-escape-demo-containment)
- action                                : Lambda action (collect_evidence, network_isolate, etc.)
- cluster_name                          : EKS cluster name (from K8sEscape.ClusterName)
- namespace                             : Kubernetes namespace (from K8sEscape.Namespace)
- node_hostname                         : Node FQDN (from K8sEscape.NodeFQDN, optional)

Output issue field:
- k8scontainmentenrichment  (markdown)

Output context:
- K8sContainment.Action
- K8sContainment.Status
- K8sContainment.ClusterName
- K8sContainment.Namespace
- K8sContainment.Evidence
- K8sContainment.Results
- K8sContainment.LambdaStatusCode
- K8sContainment.RawResponse

Version: 2.1.0
"""

import json
import hashlib
import hmac
import datetime
import ssl


# ==============================================================================
# CONFIGURATION
# ==============================================================================

ISSUE_FIELD_NAME = "k8scontainmentenrichment"


# ==============================================================================
# AWS SIGNATURE V4 (MINIMAL IMPLEMENTATION)
# ==============================================================================

def sign(key, msg):
    """AWS Signature V4 signing helper."""
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(secret_key, date_stamp, region, service):
    """Derive the AWS Signature V4 signing key."""
    k_date = sign(('AWS4' + secret_key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing


def aws_lambda_invoke(access_key, secret_key, session_token, region,
                      function_name, payload_dict):
    """
    Invoke an AWS Lambda function using raw HTTP with SigV4 authentication.
    No external dependencies (no boto3 required).
    """
    import urllib.request
    import urllib.error

    service = 'lambda'
    host = f'lambda.{region}.amazonaws.com'
    endpoint = f'https://{host}'
    request_url = f'{endpoint}/2015-03-31/functions/{function_name}/invocations'

    payload_str = json.dumps(payload_dict)
    payload_bytes = payload_str.encode('utf-8')

    # Create timestamp
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')

    # Create canonical request
    method = 'POST'
    canonical_uri = f'/2015-03-31/functions/{function_name}/invocations'
    canonical_querystring = ''

    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    headers_to_sign = {
        'content-type': 'application/json',
        'host': host,
        'x-amz-date': amz_date,
    }
    if session_token:
        headers_to_sign['x-amz-security-token'] = session_token

    signed_headers_list = sorted(headers_to_sign.keys())
    signed_headers = ';'.join(signed_headers_list)
    canonical_headers = ''.join(f'{k}:{headers_to_sign[k]}\n' for k in signed_headers_list)

    canonical_request = '\n'.join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    # Create string to sign
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
    string_to_sign = '\n'.join([
        algorithm,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode('utf-8')).hexdigest(),
    ])

    # Create signature
    signing_key = get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    # Create authorization header
    authorization = (
        f'{algorithm} Credential={access_key}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )

    # Build request headers
    req_headers = {
        'Content-Type': 'application/json',
        'X-Amz-Date': amz_date,
        'Authorization': authorization,
    }
    if session_token:
        req_headers['X-Amz-Security-Token'] = session_token

    # Make request
    ssl_ctx = ssl.create_default_context()

    req = urllib.request.Request(
        request_url,
        data=payload_bytes,
        headers=req_headers,
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=120, context=ssl_ctx) as resp:
            response_body = resp.read().decode('utf-8', errors='replace')
            return {
                'status_code': resp.status,
                'body': response_body,
                'error': None,
            }
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8', errors='replace')
        return {
            'status_code': e.code,
            'body': error_body,
            'error': f'HTTP {e.code}: {error_body[:500]}',
        }
    except Exception as e:
        return {
            'status_code': 0,
            'body': '',
            'error': str(e),
        }


# ==============================================================================
# AWS STS ASSUME ROLE
# ==============================================================================

def sts_assume_role(access_key, secret_key, session_token, region, role_arn,
                    external_id="", session_name="CortexPlaybook"):
    """
    Assume an IAM Role via STS using operator credentials (SigV4 signed).
    Same pattern as aws_lambda_invoke: raw HTTP, no boto3 required.
    Returns dict with AccessKeyId, SecretAccessKey, SessionToken or raises.
    """
    import urllib.request
    import urllib.error
    import urllib.parse
    import xml.etree.ElementTree as ET

    service = 'sts'
    host = f'sts.{region}.amazonaws.com'
    endpoint = f'https://{host}'

    # Build POST body (form-encoded)
    params = {
        'Action': 'AssumeRole',
        'Version': '2011-06-15',
        'RoleArn': role_arn,
        'RoleSessionName': session_name,
        'DurationSeconds': '3600',
    }
    if external_id:
        params['ExternalId'] = external_id

    payload_str = urllib.parse.urlencode(params)
    payload_bytes = payload_str.encode('utf-8')

    # SigV4 signing
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')

    payload_hash = hashlib.sha256(payload_bytes).hexdigest()

    headers_to_sign = {
        'content-type': 'application/x-www-form-urlencoded',
        'host': host,
        'x-amz-date': amz_date,
    }
    if session_token:
        headers_to_sign['x-amz-security-token'] = session_token

    signed_headers_list = sorted(headers_to_sign.keys())
    signed_headers = ';'.join(signed_headers_list)
    canonical_headers = ''.join(f'{k}:{headers_to_sign[k]}\n' for k in signed_headers_list)

    canonical_request = '\n'.join([
        'POST', '/', '',
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
    string_to_sign = '\n'.join([
        algorithm,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode('utf-8')).hexdigest(),
    ])

    signing_key = get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization = (
        f'{algorithm} Credential={access_key}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )

    req_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Amz-Date': amz_date,
        'Authorization': authorization,
    }
    if session_token:
        req_headers['X-Amz-Security-Token'] = session_token

    ssl_ctx = ssl.create_default_context()
    req = urllib.request.Request(endpoint, data=payload_bytes, headers=req_headers, method='POST')

    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
            body = resp.read().decode('utf-8')
            root = ET.fromstring(body)
            ns = {'sts': 'https://sts.amazonaws.com/doc/2011-06-15/'}
            creds = root.find('.//sts:Credentials', ns)
            if creds is None:
                raise RuntimeError(f"No Credentials in STS response: {body[:500]}")
            return {
                'AccessKeyId': creds.find('sts:AccessKeyId', ns).text,
                'SecretAccessKey': creds.find('sts:SecretAccessKey', ns).text,
                'SessionToken': creds.find('sts:SessionToken', ns).text,
            }
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8', errors='replace')
        raise RuntimeError(f"STS AssumeRole failed (HTTP {e.code}): {error_body[:500]}")


# ==============================================================================
# MARKDOWN REPORT BUILDER
# ==============================================================================

EMOJI_SUCCESS = "\u2705"
EMOJI_ERROR = "\u274C"
EMOJI_WARN = "\u26A0\uFE0F"
EMOJI_SHIELD = "\U0001F6E1"
EMOJI_SEARCH = "\U0001F50D"
EMOJI_CONTAINER = "\U0001F4E6"
EMOJI_NODE = "\U0001F5A5"
EMOJI_LOCK = "\U0001F512"


def build_evidence_report(action, cluster_name, namespace, lambda_response):
    """Build a markdown report from the Lambda response."""
    md = []
    md.append("# " + EMOJI_SHIELD + " K8s Containment - Lambda Enrichment")
    md.append("")

    status_emoji = EMOJI_SUCCESS if lambda_response.get("status_code") == 200 else EMOJI_ERROR

    md.append("## " + status_emoji + " Lambda Invocation: " + action)
    md.append("")
    md.append("| Parameter | Value |")
    md.append("|---|---|")
    md.append("| Action | `" + action + "` |")
    md.append("| Cluster | `" + cluster_name + "` |")
    md.append("| Namespace | `" + namespace + "` |")
    md.append("| HTTP Status | " + str(lambda_response.get("status_code", "N/A")) + " |")
    md.append("")

    if lambda_response.get("error"):
        md.append("## " + EMOJI_ERROR + " Error")
        md.append("")
        md.append("```")
        md.append(str(lambda_response["error"])[:500])
        md.append("```")
        md.append("")
        return "\n".join(md)

    # Parse Lambda response body
    try:
        body = json.loads(lambda_response.get("body", "{}"))
        inner_body = body
        # Lambda may wrap response in {"statusCode": ..., "body": "..."}
        if "body" in body and isinstance(body["body"], str):
            inner_body = json.loads(body["body"])
    except (json.JSONDecodeError, TypeError):
        md.append("## Raw Response")
        md.append("```")
        md.append(str(lambda_response.get("body", ""))[:2000])
        md.append("```")
        return "\n".join(md)

    results = inner_body.get("results", [inner_body])

    for result in results:
        result_action = result.get("action", action)
        result_status = result.get("status", "unknown")
        result_emoji = EMOJI_SUCCESS if result_status == "success" else EMOJI_WARN

        md.append("### " + result_emoji + " " + result_action)
        md.append("")

        if result.get("detail"):
            md.append("- " + result["detail"])
            md.append("")

        # Evidence section (for collect_evidence action)
        evidence = result.get("evidence", {})

        if evidence.get("pods"):
            md.append("#### " + EMOJI_CONTAINER + " Pods")
            md.append("")
            md.append("| Pod | Node | Status | Privileged | HostPID | HostNetwork | ServiceAccount |")
            md.append("|---|---|---|---|---|---|---|")
            for pod in evidence["pods"]:
                md.append("| `" + pod.get("name", "?") + "` "
                         "| `" + str(pod.get("node", "?")) + "` "
                         "| " + str(pod.get("status", "?")) + " "
                         "| " + (EMOJI_ERROR if pod.get("privileged") else EMOJI_SUCCESS) + " "
                         "| " + (EMOJI_WARN if pod.get("hostPID") else EMOJI_SUCCESS) + " "
                         "| " + (EMOJI_WARN if pod.get("hostNetwork") else EMOJI_SUCCESS) + " "
                         "| `" + str(pod.get("service_account", "?")) + "` |")
            md.append("")

        if evidence.get("suspicious_rbac"):
            md.append("#### " + EMOJI_LOCK + " Suspicious RBAC Bindings")
            md.append("")
            for rb in evidence["suspicious_rbac"]:
                md.append("- " + EMOJI_WARN + " `" + rb.get("name", "?") + "` -> `" + rb.get("role", "?") + "`")
            md.append("")

        if evidence.get("events"):
            md.append("#### Events (last " + str(len(evidence["events"])) + ")")
            md.append("")
            md.append("| Type | Reason | Message | Count |")
            md.append("|---|---|---|---|")
            for evt in evidence["events"][-10:]:
                md.append("| " + str(evt.get("type", "")) + " "
                         "| " + str(evt.get("reason", "")) + " "
                         "| " + str(evt.get("message", ""))[:80] + " "
                         "| " + str(evt.get("count", "")) + " |")
            md.append("")

        if evidence.get("xdr_node"):
            node_info = evidence["xdr_node"]
            md.append("#### " + EMOJI_NODE + " XDR Node: " + str(node_info.get("hostname", "")))
            md.append("")
            md.append("- **Unschedulable**: " + (EMOJI_WARN + " Yes" if node_info.get("unschedulable") else EMOJI_SUCCESS + " No"))
            if node_info.get("conditions"):
                for cond in node_info["conditions"]:
                    md.append("- **" + str(cond.get("type", "")) + "**: " + str(cond.get("status", "")) + " (" + str(cond.get("reason", "")) + ")")
            md.append("")

        # Pod logs
        for key, value in evidence.items():
            if key.startswith("logs_") and value:
                pod_name = key.replace("logs_", "")
                md.append("#### Pod Logs: " + pod_name)
                md.append("")
                md.append("```")
                # Show last 20 lines
                log_lines = str(value).split("\n")
                for line in log_lines[-20:]:
                    md.append(line)
                md.append("```")
                md.append("")

        # Containment action results
        if result.get("deleted_pods"):
            md.append("#### Deleted Pods")
            md.append("")
            for dp in result["deleted_pods"]:
                dp_emoji = EMOJI_SUCCESS if dp.get("status", 0) < 400 else EMOJI_ERROR
                md.append("- " + dp_emoji + " `" + str(dp.get("pod", "?")) + "` (HTTP " + str(dp.get("status", "?")) + ")")
            md.append("")

        if result.get("cordoned_nodes"):
            md.append("#### Cordoned Nodes")
            md.append("")
            for cn in result["cordoned_nodes"]:
                cn_emoji = EMOJI_SUCCESS if cn.get("status", 0) < 400 else EMOJI_ERROR
                md.append("- " + cn_emoji + " `" + str(cn.get("node", "?")) + "` (HTTP " + str(cn.get("status", "?")) + ", source: " + str(cn.get("source", "?")) + ")")
            md.append("")

    return "\n".join(md)


# ==============================================================================
# WRITE TO ISSUE FIELD
# ==============================================================================

def write_results_to_issue(markdown_content):
    """Write enrichment results to the issue field."""
    try:
        demisto.info("Writing to issue field '" + ISSUE_FIELD_NAME + "' (" + str(len(markdown_content)) + " chars)")
        result = demisto.executeCommand("setIncident", {
            "customFields": {ISSUE_FIELD_NAME: markdown_content}
        })
        if is_error(result):
            error_msg = get_error(result)
            demisto.error("setIncident failed: " + str(error_msg))
            return False, str(error_msg)
        demisto.info("setIncident success")
        return True, ""
    except Exception as e:
        demisto.error("setIncident exception: " + str(e))
        return False, str(e)


# ==============================================================================
# MAIN FUNCTION
# ==============================================================================

def main():
    try:
        args = demisto.args()

        demisto.info("=== InvokeK8sContainmentLambda v2.1.0 START ===")

        # ==================================================================
        # RETRIEVE ARGUMENTS
        # ==================================================================

        assume_role_arn = args.get('assume_role_arn', '')
        external_id = args.get('external_id', '')
        aws_access_key_id = args.get('aws_access_key_id', '')
        aws_secret_access_key = args.get('aws_secret_access_key', '')
        aws_session_token = args.get('aws_session_token', '')
        aws_region = args.get('aws_region', 'eu-west-3')
        lambda_function_name = args.get('lambda_function_name', 'k8s-escape-demo-containment')
        action = args.get('action', 'collect_evidence')
        cluster_name = args.get('cluster_name', '')
        namespace = args.get('namespace', 'vuln-app')
        node_hostname = args.get('node_hostname', '')

        if not aws_access_key_id or not aws_secret_access_key:
            return_error("aws_access_key_id and aws_secret_access_key are required")
            return

        if not cluster_name:
            return_error("cluster_name is required")
            return

        use_assume_role = bool(assume_role_arn)
        auth_mode = "AssumeRole -> " + assume_role_arn if use_assume_role else "Direct Credentials"
        demisto.info("Auth mode: " + auth_mode)
        demisto.info("Action: " + action)
        demisto.info("Cluster: " + cluster_name)
        demisto.info("Namespace: " + namespace)
        demisto.info("Lambda: " + lambda_function_name)
        demisto.info("Region: " + aws_region)
        demisto.info("Node hostname: " + (node_hostname or "N/A"))

        # ==================================================================
        # AUTHENTICATE
        # ==================================================================

        if use_assume_role:
            # Use operator credentials to AssumeRole into scoped role
            demisto.info("Assuming IAM Role: " + assume_role_arn)
            sts_creds = sts_assume_role(
                access_key=aws_access_key_id,
                secret_key=aws_secret_access_key,
                session_token=aws_session_token,
                region=aws_region,
                role_arn=assume_role_arn,
                external_id=external_id,
            )
            aws_access_key_id = sts_creds['AccessKeyId']
            aws_secret_access_key = sts_creds['SecretAccessKey']
            aws_session_token = sts_creds['SessionToken']
            demisto.info("STS AssumeRole successful, temporary credentials obtained")
        else:
            demisto.info("Using direct AWS credentials")

        # ==================================================================
        # BUILD LAMBDA PAYLOAD
        # ==================================================================

        lambda_payload = {
            "action": action,
            "cluster_name": cluster_name,
            "namespace": namespace,
            "region": aws_region,
        }
        if node_hostname:
            lambda_payload["node_hostname"] = node_hostname

        demisto.info("Lambda payload: " + json.dumps(lambda_payload))

        # ==================================================================
        # INVOKE LAMBDA
        # ==================================================================

        demisto.info("Invoking Lambda function: " + lambda_function_name)

        lambda_response = aws_lambda_invoke(
            access_key=aws_access_key_id,
            secret_key=aws_secret_access_key,
            session_token=aws_session_token,
            region=aws_region,
            function_name=lambda_function_name,
            payload_dict=lambda_payload,
        )

        demisto.info("Lambda response status: " + str(lambda_response.get("status_code")))
        if lambda_response.get("error"):
            demisto.error("Lambda error: " + str(lambda_response["error"]))

        # ==================================================================
        # PARSE RESPONSE
        # ==================================================================

        parsed_body = {}
        evidence = {}
        results_list = []

        try:
            parsed_body = json.loads(lambda_response.get("body", "{}"))
            # Lambda may wrap response
            if "body" in parsed_body and isinstance(parsed_body["body"], str):
                inner = json.loads(parsed_body["body"])
                results_list = inner.get("results", [inner])
                # Extract evidence from collect_evidence results
                for r in results_list:
                    if r.get("evidence"):
                        evidence = r["evidence"]
            else:
                results_list = parsed_body.get("results", [parsed_body])
                for r in results_list:
                    if r.get("evidence"):
                        evidence = r["evidence"]
        except (json.JSONDecodeError, TypeError) as e:
            demisto.error("Failed to parse Lambda response: " + str(e))

        overall_status = "success" if lambda_response.get("status_code") == 200 else "error"

        # ==================================================================
        # MARKDOWN REPORT
        # ==================================================================

        human_readable = build_evidence_report(
            action, cluster_name, namespace, lambda_response
        )

        # ==================================================================
        # WRITE TO ISSUE
        # ==================================================================

        write_success, write_error = write_results_to_issue(human_readable)
        if not write_success:
            demisto.error("Write to issue failed: " + write_error)
            human_readable += "\n> **WARNING**: Failed to write to '" + ISSUE_FIELD_NAME + "': " + write_error + "\n"

        # ==================================================================
        # ENTRY CONTEXT
        # ==================================================================

        entry_context = {
            'K8sContainment.Action': action,
            'K8sContainment.Status': overall_status,
            'K8sContainment.ClusterName': cluster_name,
            'K8sContainment.Namespace': namespace,
            'K8sContainment.Evidence': evidence,
            'K8sContainment.Results': results_list,
            'K8sContainment.LambdaStatusCode': lambda_response.get("status_code"),
            'K8sContainment.RawResponse': parsed_body,
        }

        # ==================================================================
        # RETURN
        # ==================================================================

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                "Action": action,
                "Status": overall_status,
                "ClusterName": cluster_name,
                "Namespace": namespace,
                "LambdaStatusCode": lambda_response.get("status_code"),
                "Evidence": evidence,
                "Results": results_list,
            },
            'HumanReadable': human_readable,
            'EntryContext': entry_context,
        })

        demisto.info("=== InvokeK8sContainmentLambda v2.1.0 END ===")

    except Exception as e:
        error_msg = "Error in InvokeK8sContainmentLambda: " + str(e)
        demisto.error(error_msg)
        return_error(error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

"""
ExtractK8sContainerEscapeIOCs
==============================
Extracts and analyzes important fields from a Cortex XDR issue related to
a container escape attack (Spring4Shell / CVE-2022-22965) on EKS.

Script arguments (playbook inputs):
- container_id                          : ${issue.container_id}
- namespace                             : ${issue.namespace}
- xdmsourcehostfqdn                     : ${issue.xdmsourcehostfqdn}
- xdmsourcehostipv4addresses            : ${issue.xdmsourcehostipv4addresses}
- xdmsourceusername                     : ${issue.xdmsourceusername}
- xdmsourceprocessname                  : ${issue.xdmsourceprocessname}
- causality_actor_process_command_line   : ${issue.causality_actor_process_command_line}
- causality_actor_process_image_path     : ${issue.causality_actor_process_image_path}
- causality_actor_process_image_sha256   : ${issue.causality_actor_process_image_sha256}
- image_id                              : ${issue.image_id}
- agent_os_type                         : ${issue.agent_os_type}
- agent_os_sub_type                     : ${issue.agent_os_sub_type}
- details                               : ${issue.details}
- cluster_name                          : ${issue.cluster_name}

Output issue field:
- k8scontainerescapeiocs  (markdown)

Output context:
- K8sEscape.ContainerID
- K8sEscape.Namespace
- K8sEscape.NodeFQDN
- K8sEscape.NodeIPs
- K8sEscape.Username
- K8sEscape.ProcessName
- K8sEscape.ProcessCommandLine
- K8sEscape.ProcessImagePath
- K8sEscape.ProcessImageSHA256
- K8sEscape.ContainerImageID
- K8sEscape.Details
- K8sEscape.IsSpringShell
- K8sEscape.IsWebshell
- K8sEscape.IsPrivilegedUser
- K8sEscape.IsContainerRuntime
- K8sEscape.Severity
- K8sEscape.ClusterName
- K8sEscape.IOCs
- K8sEscape.ContainmentTarget

Version: 1.0.0
"""


# ==============================================================================
# CONFIGURATION
# ==============================================================================

ISSUE_FIELD_NAME = "k8scontainerescapeiocs"

# Spring4Shell / Container Escape indicators
SPRINGSHELL_KEYWORDS = ["springshell", "spring4shell", "cve-2022-22965", "class.module.classloader"]
WEBSHELL_KEYWORDS = ["webshell", "shell.jsp", "cmd.jsp", "dropped webshell"]
CONTAINER_RUNTIME_PROCESSES = ["runc", "containerd", "containerd-shim", "cri-o", "dockerd", "docker"]
PRIVILEGED_USERS = ["root"]
EXPLOIT_PROCESS_PATHS = ["/usr/sbin/runc", "/usr/bin/runc", "/usr/bin/containerd",
                         "/usr/bin/containerd-shim", "/usr/bin/cri-o"]


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def normalize_value(value):
    if value is None:
        return ""
    return str(value).lower().strip()


def to_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if v is not None and str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split(',') if v.strip()]
    return [str(value)] if value else []


def deduplicate_list(values):
    """Remove duplicates while preserving order."""
    seen = set()
    result = []
    for v in values:
        v_lower = v.lower().strip()
        if v_lower not in seen:
            seen.add(v_lower)
            result.append(v.strip())
    return result


def get_issue_field_array(field_name):
    """
    Retrieve an array field directly from the current issue via demisto.incident().
    """
    try:
        incident = demisto.incident()
        if incident:
            custom_fields = incident.get('CustomFields', {}) or {}
            value = custom_fields.get(field_name)
            if value is None:
                value = incident.get(field_name)
            if value is not None:
                demisto.debug("get_issue_field_array('" + field_name + "'): " + str(type(value)) + " = " + str(value)[:200])
                if isinstance(value, list):
                    return [str(v).strip() for v in value if v is not None and str(v).strip()]
                if isinstance(value, str) and value.strip():
                    return [v.strip() for v in value.split(',') if v.strip()]
    except Exception as e:
        demisto.debug("get_issue_field_array('" + field_name + "') exception: " + str(e))
    return []


def get_issue_field_string(field_name):
    """
    Retrieve a string field directly from the current issue.
    """
    try:
        incident = demisto.incident()
        if incident:
            custom_fields = incident.get('CustomFields', {}) or {}
            value = custom_fields.get(field_name)
            if value is None:
                value = incident.get(field_name)
            if value is not None:
                if isinstance(value, list):
                    return ", ".join(str(v) for v in value if v)
                return str(value).strip()
    except Exception as e:
        demisto.debug("get_issue_field_string('" + field_name + "') exception: " + str(e))
    return ""


def get_field_with_fallback(arg_value, issue_field_name, field_label, is_array=True):
    """
    Retrieve a field from script argument, with fallback
    to the issue directly if the argument is empty or incomplete.
    """
    if is_array:
        from_arg = to_list(arg_value)
        from_issue = get_issue_field_array(issue_field_name)

        demisto.info("Field '" + field_label + "' - from arg (" + str(len(from_arg)) + "): " + str(from_arg)[:300])
        demisto.info("Field '" + field_label + "' - from issue (" + str(len(from_issue)) + "): " + str(from_issue)[:300])

        if len(from_issue) > len(from_arg):
            demisto.info("Using issue field for '" + field_label + "' (more complete)")
            return deduplicate_list(from_issue)
        return deduplicate_list(from_arg) if from_arg else deduplicate_list(from_issue)
    else:
        from_arg = str(arg_value).strip() if arg_value else ""
        from_issue = get_issue_field_string(issue_field_name)

        demisto.info("Field '" + field_label + "' - from arg: '" + from_arg[:200] + "'")
        demisto.info("Field '" + field_label + "' - from issue: '" + from_issue[:200] + "'")

        return from_arg if from_arg else from_issue


def is_valid_ip(ip_str):
    try:
        ip_str = str(ip_str).strip()
        parts = [int(x) for x in ip_str.split('.')]
        if len(parts) != 4:
            return False
        for part in parts:
            if part < 0 or part > 255:
                return False
        return True
    except Exception:
        return False


def is_private_ip(ip_str):
    try:
        parts = [int(x) for x in str(ip_str).strip().split('.')]
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except Exception:
        return False


def extract_container_id_from_cmdline(cmdline):
    """Extract the container ID from the runc command line."""
    if not cmdline:
        return None
    # Le container ID est un hash hex de 64 chars
    import re
    matches = re.findall(r'[a-f0-9]{64}', cmdline)
    if matches:
        return matches[0]
    return None


# ==============================================================================
# IOC ANALYSIS
# ==============================================================================

def analyze_details(details):
    """Analyze the details field to detect attack indicators."""
    results = {
        "is_springshell": False,
        "is_webshell": False,
        "matched_keywords": []
    }
    if not details:
        return results

    details_lower = details.lower()

    for kw in SPRINGSHELL_KEYWORDS:
        if kw in details_lower:
            results["is_springshell"] = True
            results["matched_keywords"].append(kw)

    for kw in WEBSHELL_KEYWORDS:
        if kw in details_lower:
            results["is_webshell"] = True
            results["matched_keywords"].append(kw)

    return results


def analyze_process(process_name, process_path, process_cmdline):
    """Analyze the causality actor process for container escape indicators."""
    results = {
        "is_container_runtime": False,
        "runtime_name": None,
        "extracted_container_id": None,
        "suspicious_flags": []
    }

    # Verifier si le processus est un runtime container
    if process_name:
        for runtime in CONTAINER_RUNTIME_PROCESSES:
            if runtime in normalize_value(process_name):
                results["is_container_runtime"] = True
                results["runtime_name"] = runtime
                break

    if process_path:
        for path in EXPLOIT_PROCESS_PATHS:
            if normalize_value(process_path) == path:
                results["is_container_runtime"] = True
                if not results["runtime_name"]:
                    results["runtime_name"] = path.split('/')[-1]
                break

    # Extraire le container ID de la ligne de commande
    if process_cmdline:
        results["extracted_container_id"] = extract_container_id_from_cmdline(process_cmdline)

        cmdline_lower = process_cmdline.lower()
        # Detecter les flags suspects
        if "containerd/runc/k8s.io" in cmdline_lower:
            results["suspicious_flags"].append("K8s container runtime path (containerd/runc/k8s.io)")
        if "--systemd-cgroup" in cmdline_lower:
            results["suspicious_flags"].append("systemd-cgroup flag (container orchestration)")
        if "create --bundle" in cmdline_lower:
            results["suspicious_flags"].append("Container create operation detected")

    return results


def analyze_user(username):
    """Analyze the username to detect privileged access."""
    results = {
        "is_privileged": False,
        "risk_level": "Low"
    }
    if username and normalize_value(username) in PRIVILEGED_USERS:
        results["is_privileged"] = True
        results["risk_level"] = "Critical"
    return results


def analyze_node(fqdn, ips):
    """Analyze EKS node information."""
    results = {
        "fqdn": fqdn,
        "ips": ips,
        "is_eks_node": False,
        "aws_region": None,
        "ip_analysis": []
    }

    if fqdn:
        fqdn_lower = normalize_value(fqdn)
        if "compute.internal" in fqdn_lower:
            results["is_eks_node"] = True
            # Extraire la region AWS
            parts = fqdn_lower.split(".")
            for p in parts:
                if p.startswith("eu-") or p.startswith("us-") or p.startswith("ap-") or p.startswith("sa-"):
                    results["aws_region"] = p
                    break

    for ip in ips:
        ip_info = {
            "ip": ip,
            "is_valid": is_valid_ip(ip),
            "is_private": is_private_ip(ip) if is_valid_ip(ip) else False,
            "type": "Private" if is_private_ip(ip) else "Public" if is_valid_ip(ip) else "Invalid"
        }
        results["ip_analysis"].append(ip_info)

    return results


def determine_severity(details_analysis, process_analysis, user_analysis, namespace):
    """Determine the overall incident severity."""
    severity = "Low"
    reasons = []

    # Webshell + SpringShell = Critical
    if details_analysis["is_springshell"] or details_analysis["is_webshell"]:
        severity = "Critical"
        reasons.append("SpringShell / webshell exploit detected in details")

    # Root user = Critical
    if user_analysis["is_privileged"]:
        severity = "Critical"
        reasons.append("Running as root (privilege escalation)")

    # Container runtime in causality = High minimum
    if process_analysis["is_container_runtime"]:
        if severity != "Critical":
            severity = "High"
        reasons.append("Container runtime process in causality chain (" + str(process_analysis["runtime_name"]) + ")")

    # Specific vuln-app namespace
    if namespace and "vuln" in normalize_value(namespace):
        reasons.append("Target namespace: " + namespace)

    if not reasons:
        reasons.append("No critical indicators detected")

    return severity, reasons


def build_iocs_list(container_ids, image_id, process_sha256, node_ips, process_analysis):
    """Build the list of extracted IOCs."""
    iocs = []

    for cid in container_ids:
        if cid:
            iocs.append({"type": "ContainerID", "value": cid, "context": "Compromised container"})

    if process_analysis.get("extracted_container_id"):
        extracted = process_analysis["extracted_container_id"]
        # Avoid duplicates
        existing_cids = [i["value"] for i in iocs if i["type"] == "ContainerID"]
        if extracted not in existing_cids:
            iocs.append({"type": "ContainerID", "value": extracted, "context": "Extracted from runc command line"})

    for img in to_list(image_id):
        if img:
            iocs.append({"type": "ContainerImageID", "value": img, "context": "Compromised container image"})

    for sha in to_list(process_sha256):
        if sha:
            iocs.append({"type": "SHA256", "value": sha, "context": "Causality actor process image hash"})

    for ip in node_ips:
        if ip and is_valid_ip(ip):
            iocs.append({"type": "IP", "value": ip, "context": "Compromised EKS node"})

    return iocs


# ==============================================================================
# WRITE TO ISSUE FIELD
# ==============================================================================

def write_results_to_issue(markdown_content):
    try:
        demisto.info("Writing to issue field '" + ISSUE_FIELD_NAME + "' (" + str(len(markdown_content)) + " chars)")
        result = demisto.executeCommand("setIssue", {
            ISSUE_FIELD_NAME: markdown_content
        })
        if is_error(result):
            error_msg = get_error(result)
            demisto.error("setIssue failed: " + str(error_msg))
            return False, str(error_msg)
        demisto.info("setIssue success")
        return True, ""
    except Exception as e:
        demisto.error("setIssue exception: " + str(e))
        return False, str(e)


# ==============================================================================
# MARKDOWN REPORT BUILDER
# ==============================================================================

EMOJI_CRITICAL = "\U0001F534"    # red
EMOJI_HIGH = "\U0001F7E0"       # orange
EMOJI_MEDIUM = "\U0001F7E1"     # yellow
EMOJI_LOW = "\U0001F7E2"        # green
EMOJI_CHECK = "\u2705"           # green check
EMOJI_CROSS = "\u274C"           # red cross
EMOJI_WARN = "\u26A0\uFE0F"     # warning
EMOJI_CONTAINER = "\U0001F4E6"  # container/package
EMOJI_NODE = "\U0001F5A5"       # node/screen
EMOJI_PROCESS = "\u2699\uFE0F"  # gear
EMOJI_USER = "\U0001F464"       # user
EMOJI_SHIELD = "\U0001F6E1"     # shield
EMOJI_TARGET = "\U0001F3AF"     # target
EMOJI_IOC = "\U0001F50D"        # magnifier

SEVERITY_EMOJI = {
    "Critical": EMOJI_CRITICAL,
    "High": EMOJI_HIGH,
    "Medium": EMOJI_MEDIUM,
    "Low": EMOJI_LOW
}


def build_markdown_report(details, details_analysis, container_ids, namespace,
                          cluster_name, node_analysis, user_analysis, username,
                          process_analysis, process_name, process_path, process_cmdline,
                          process_sha256, image_id, agent_os_type, agent_os_sub_type,
                          severity, severity_reasons, iocs, containment_target):
    """Build the full Markdown report."""
    md = []
    sev_emoji = SEVERITY_EMOJI.get(severity, EMOJI_LOW)

    md.append("# " + EMOJI_SHIELD + " K8s Container Escape - IOC Extraction")
    md.append("")

    # ======================== SEVERITY ========================
    md.append("## " + sev_emoji + " Severity: " + severity)
    md.append("")
    for reason in severity_reasons:
        md.append("- " + reason)
    md.append("")

    # ======================== ATTACK DETAILS ========================
    md.append("## " + EMOJI_TARGET + " Attack Details")
    md.append("")
    if details:
        md.append("> **" + details + "**")
        md.append("")
    if details_analysis["is_springshell"]:
        md.append("- " + EMOJI_CRITICAL + " **Spring4Shell / CVE-2022-22965 detected**")
    if details_analysis["is_webshell"]:
        md.append("- " + EMOJI_CRITICAL + " **Webshell detected** (malicious file dropped)")
    if details_analysis["matched_keywords"]:
        md.append("- Matched keywords: `" + "`, `".join(details_analysis["matched_keywords"]) + "`")
    if not details_analysis["is_springshell"] and not details_analysis["is_webshell"]:
        md.append("- " + EMOJI_LOW + " No Spring4Shell/webshell indicators found in details")
    md.append("")

    # ======================== CONTAINER ========================
    md.append("## " + EMOJI_CONTAINER + " Compromised Container")
    md.append("")
    if container_ids:
        for cid in container_ids:
            md.append("- **Container ID**: `" + cid + "`")
    else:
        md.append("- Container ID: Not available")
    if namespace:
        md.append("- **Namespace**: `" + namespace + "`")
    if image_id:
        for img in to_list(image_id):
            md.append("- **Image ID**: `" + img + "`")
    md.append("")

    # ======================== EKS NODE ========================
    md.append("## " + EMOJI_NODE + " EKS Node")
    md.append("")
    if cluster_name:
        md.append("- **Cluster**: `" + cluster_name + "`")
    if node_analysis["fqdn"]:
        md.append("- **FQDN**: `" + node_analysis["fqdn"] + "`")
    if node_analysis["is_eks_node"]:
        md.append("- " + EMOJI_CHECK + " EKS node confirmed (compute.internal)")
    if node_analysis["aws_region"]:
        md.append("- **AWS Region**: `" + node_analysis["aws_region"] + "`")
    if node_analysis["ip_analysis"]:
        md.append("- **IP Addresses**:")
        for ip_info in node_analysis["ip_analysis"]:
            ip_type = ip_info["type"]
            if ip_type == "Private":
                md.append("  - `" + ip_info["ip"] + "` (" + ip_type + ")")
            elif ip_type == "Public":
                md.append("  - `" + ip_info["ip"] + "` (" + ip_type + ") " + EMOJI_WARN)
            else:
                md.append("  - `" + ip_info["ip"] + "` (Invalid) " + EMOJI_CROSS)
    if agent_os_type:
        md.append("- **Agent OS**: " + agent_os_type)
    if agent_os_sub_type:
        md.append("- **OS Version**: " + agent_os_sub_type)
    md.append("")

    # ======================== PROCESS ========================
    md.append("## " + EMOJI_PROCESS + " Process (Causality Actor)")
    md.append("")
    if process_name:
        md.append("- **Process**: `" + process_name + "`")
    if process_path:
        md.append("- **Path**: `" + process_path + "`")
    if process_analysis["is_container_runtime"]:
        md.append("- " + EMOJI_WARN + " **Container runtime detected**: `" + str(process_analysis["runtime_name"]) + "`")
    if process_sha256:
        for sha in to_list(process_sha256):
            md.append("- **SHA256**: `" + sha + "`")
    if process_cmdline:
        # Truncate if too long
        display_cmd = process_cmdline if len(process_cmdline) <= 200 else process_cmdline[:200] + "..."
        md.append("- **Command Line**:")
        md.append("  ```")
        md.append("  " + display_cmd)
        md.append("  ```")
    if process_analysis["suspicious_flags"]:
        md.append("- **Suspicious Indicators**:")
        for flag in process_analysis["suspicious_flags"]:
            md.append("  - " + EMOJI_WARN + " " + flag)
    if process_analysis["extracted_container_id"]:
        md.append("- **Container ID extracted from cmdline**: `" + process_analysis["extracted_container_id"] + "`")
    md.append("")

    # ======================== USER ========================
    md.append("## " + EMOJI_USER + " User")
    md.append("")
    if username:
        md.append("- **Username**: `" + username + "`")
        if user_analysis["is_privileged"]:
            md.append("- " + EMOJI_CRITICAL + " **Privileged user (root)** — privilege escalation confirmed")
        else:
            md.append("- " + EMOJI_LOW + " Non-privileged user")
    else:
        md.append("- Username: Not available")
    md.append("")

    # ======================== IOCs ========================
    md.append("## " + EMOJI_IOC + " Extracted IOCs (" + str(len(iocs)) + ")")
    md.append("")
    if iocs:
        md.append("| Type | Value | Context |")
        md.append("|---|---|---|")
        for ioc in iocs:
            val_display = ioc["value"] if len(ioc["value"]) <= 40 else ioc["value"][:37] + "..."
            md.append("| " + ioc["type"] + " | `" + val_display + "` | " + ioc["context"] + " |")
    else:
        md.append("*No IOCs extracted.*")
    md.append("")

    # ======================== CONTAINMENT TARGET ========================
    md.append("## " + EMOJI_TARGET + " Containment Target")
    md.append("")
    md.append("| Parameter | Value |")
    md.append("|---|---|")
    md.append("| Cluster | `" + str(containment_target.get("cluster_name", "N/A")) + "` |")
    md.append("| Namespace | `" + str(containment_target.get("namespace", "N/A")) + "` |")
    md.append("| Node FQDN | `" + str(containment_target.get("node_fqdn", "N/A")) + "` |")
    md.append("| Node IPs | " + str(containment_target.get("node_ips", "N/A")) + " |")
    md.append("| Container ID | `" + str(containment_target.get("container_id", "N/A")) + "` |")
    md.append("| Image ID | `" + str(containment_target.get("image_id", "N/A")) + "` |")
    md.append("")

    # ======================== SUMMARY ========================
    md.append("---")
    md.append("")
    md.append("## " + EMOJI_SHIELD + " Summary")
    md.append("")

    summary_items = []
    if details_analysis["is_springshell"]:
        summary_items.append(EMOJI_CRITICAL + " **Spring4Shell exploit detected**")
    if details_analysis["is_webshell"]:
        summary_items.append(EMOJI_CRITICAL + " **Webshell deployed**")
    if user_analysis["is_privileged"]:
        summary_items.append(EMOJI_CRITICAL + " **Running as root** (privilege escalation)")
    if process_analysis["is_container_runtime"]:
        summary_items.append(EMOJI_WARN + " **Container runtime** in causality chain (" + str(process_analysis["runtime_name"]) + ")")
    if cluster_name:
        summary_items.append(EMOJI_CHECK + " Cluster: `" + cluster_name + "`")
    if node_analysis["is_eks_node"]:
        summary_items.append(EMOJI_CHECK + " EKS node confirmed" + (" — region " + node_analysis["aws_region"] if node_analysis["aws_region"] else ""))
    if namespace:
        summary_items.append(EMOJI_CHECK + " Namespace: `" + namespace + "`")

    if summary_items:
        for item in summary_items:
            md.append("> " + item)
            md.append(">")
    else:
        md.append("> " + EMOJI_LOW + " No critical indicators detected")

    md.append("")
    md.append("**Severity**: " + sev_emoji + " " + severity)
    md.append("")
    md.append("**Recommended Action**: ")
    if severity == "Critical":
        md.append(EMOJI_CRITICAL + " **Immediate automatic containment** — Execute K8s Container Escape Containment playbook")
    elif severity == "High":
        md.append(EMOJI_HIGH + " **Containment recommended** — Analyst validation required before execution")
    else:
        md.append(EMOJI_LOW + " Further investigation required before containment")
    md.append("")

    return "\n".join(md)


# ==============================================================================
# MAIN FUNCTION
# ==============================================================================

def main():
    try:
        args = demisto.args()

        demisto.info("=== ExtractK8sContainerEscapeIOCs v1.0.0 START ===")

        # ==================================================================
        # RETRIEVE FIELDS WITH FALLBACK TO ISSUE
        # ==================================================================

        container_ids = get_field_with_fallback(
            args.get('container_id'), 'containerid', 'container_id', is_array=True)
        # Fallback: also try 'containerid' (XDR native field name)
        if not container_ids:
            container_ids = get_field_with_fallback(
                None, 'containerid', 'containerid', is_array=True)
        namespace_list = get_field_with_fallback(
            args.get('namespace'), 'namespace', 'namespace', is_array=True)
        namespace = namespace_list[0] if namespace_list else ""

        node_fqdn_list = get_field_with_fallback(
            args.get('xdmsourcehostfqdn'), 'xdmsourcehostfqdn', 'xdmsourcehostfqdn', is_array=True)
        node_fqdn = node_fqdn_list[0] if node_fqdn_list else ""
        # Fallback: try hostfqdn field (XDR native)
        if not node_fqdn or node_fqdn == "eu-west-3.compute.internal":
            hostfqdn_list = get_field_with_fallback(
                None, 'hostfqdn', 'hostfqdn', is_array=False)
            if hostfqdn_list:
                node_fqdn = str(hostfqdn_list).strip()
        # Fix duplicated FQDN (e.g. "ip-10-0-0-174.eu-west-3.compute.internal.eu-west-3.compute.internal")
        if ".compute.internal." in node_fqdn:
            parts = node_fqdn.split(".compute.internal")
            node_fqdn = parts[0] + ".compute.internal"

        node_ips = get_field_with_fallback(
            args.get('xdmsourcehostipv4addresses'), 'xdmsourcehostipv4addresses', 'xdmsourcehostipv4addresses', is_array=True)

        username_list = get_field_with_fallback(
            args.get('xdmsourceusername'), 'xdmsourceusername', 'xdmsourceusername', is_array=True)
        username = username_list[0] if username_list else ""

        process_name_list = get_field_with_fallback(
            args.get('xdmsourceprocessname'), 'xdmsourceprocessname', 'xdmsourceprocessname', is_array=True)
        process_name = process_name_list[0] if process_name_list else ""

        process_cmdline_list = get_field_with_fallback(
            args.get('causality_actor_process_command_line'), 'causality_actor_process_command_line',
            'causality_actor_process_command_line', is_array=True)
        process_cmdline = process_cmdline_list[0] if process_cmdline_list else ""

        process_path_list = get_field_with_fallback(
            args.get('causality_actor_process_image_path'), 'causality_actor_process_image_path',
            'causality_actor_process_image_path', is_array=True)
        process_path = process_path_list[0] if process_path_list else ""

        process_sha256_list = get_field_with_fallback(
            args.get('causality_actor_process_image_sha256'), 'causality_actor_process_image_sha256',
            'causality_actor_process_image_sha256', is_array=True)
        process_sha256 = process_sha256_list[0] if process_sha256_list else ""

        image_id = get_field_with_fallback(
            args.get('image_id'), 'image_id', 'image_id', is_array=False)

        agent_os_type = get_field_with_fallback(
            args.get('agent_os_type'), 'agent_os_type', 'agent_os_type', is_array=False)

        agent_os_sub_type = get_field_with_fallback(
            args.get('agent_os_sub_type'), 'agent_os_sub_type', 'agent_os_sub_type', is_array=False)

        details = get_field_with_fallback(
            args.get('details'), 'details', 'details', is_array=False)

        cluster_name = get_field_with_fallback(
            args.get('cluster_name'), 'cluster_name', 'cluster_name', is_array=False)
        # Fallback: try 'clustername' (XDR native field - no underscore, array)
        if not cluster_name:
            clustername_list = get_field_with_fallback(
                None, 'clustername', 'clustername', is_array=True)
            if clustername_list:
                cluster_name = clustername_list[0]
        # Default for this demo
        if not cluster_name:
            cluster_name = "eks-escape-demo"

        demisto.info("Extracted - container_ids: " + str(container_ids))
        demisto.info("Extracted - namespace: " + namespace)
        demisto.info("Extracted - node_fqdn: " + node_fqdn)
        demisto.info("Extracted - node_ips: " + str(node_ips))
        demisto.info("Extracted - username: " + username)
        demisto.info("Extracted - process_name: " + process_name)
        demisto.info("Extracted - cluster_name: " + cluster_name)
        demisto.info("Extracted - details: " + details[:200])

        # ==================================================================
        # ANALYSIS
        # ==================================================================

        details_analysis = analyze_details(details)
        process_analysis = analyze_process(process_name, process_path, process_cmdline)
        user_analysis = analyze_user(username)
        node_analysis = analyze_node(node_fqdn, node_ips)

        severity, severity_reasons = determine_severity(
            details_analysis, process_analysis, user_analysis, namespace)

        iocs = build_iocs_list(container_ids, image_id, process_sha256, node_ips, process_analysis)

        # Containment target
        containment_target = {
            "cluster_name": cluster_name if cluster_name else "N/A",
            "namespace": namespace,
            "node_fqdn": node_fqdn,
            "node_ips": ", ".join(node_ips) if node_ips else "N/A",
            "container_id": container_ids[0] if container_ids else "N/A",
            "image_id": image_id if image_id else "N/A"
        }

        demisto.info("Severity: " + severity + " | SpringShell: " + str(details_analysis["is_springshell"])
                     + " | Webshell: " + str(details_analysis["is_webshell"])
                     + " | Root: " + str(user_analysis["is_privileged"])
                     + " | ContainerRuntime: " + str(process_analysis["is_container_runtime"]))

        # ==================================================================
        # MARKDOWN REPORT
        # ==================================================================

        human_readable = build_markdown_report(
            details, details_analysis, container_ids, namespace,
            cluster_name, node_analysis, user_analysis, username,
            process_analysis, process_name, process_path, process_cmdline,
            process_sha256, image_id, agent_os_type, agent_os_sub_type,
            severity, severity_reasons, iocs, containment_target
        )

        # ==================================================================
        # WRITE TO ISSUE
        # ==================================================================

        write_success, write_error = write_results_to_issue(human_readable)
        if not write_success:
            demisto.error("setIssue failed: " + write_error)
            human_readable += "\n> **WARNING**: Failed to write to '" + ISSUE_FIELD_NAME + "': " + write_error + "\n"

        # ==================================================================
        # ENTRY CONTEXT
        # ==================================================================

        entry_context = {
            'K8sEscape.ContainerID': container_ids,
            'K8sEscape.ClusterName': cluster_name,
            'K8sEscape.Namespace': namespace,
            'K8sEscape.NodeFQDN': node_fqdn,
            'K8sEscape.NodeIPs': node_ips,
            'K8sEscape.Username': username,
            'K8sEscape.ProcessName': process_name,
            'K8sEscape.ProcessCommandLine': process_cmdline[:500] if process_cmdline else "",
            'K8sEscape.ProcessImagePath': process_path,
            'K8sEscape.ProcessImageSHA256': process_sha256,
            'K8sEscape.ContainerImageID': image_id,
            'K8sEscape.Details': details,
            'K8sEscape.IsSpringShell': details_analysis["is_springshell"],
            'K8sEscape.IsWebshell': details_analysis["is_webshell"],
            'K8sEscape.IsPrivilegedUser': user_analysis["is_privileged"],
            'K8sEscape.IsContainerRuntime': process_analysis["is_container_runtime"],
            'K8sEscape.Severity': severity,
            'K8sEscape.IOCs(val.value && val.value == obj.value)': iocs,
            'K8sEscape.ContainmentTarget': containment_target,
            'K8sEscape.IssueFieldWriteSuccess': write_success,
        }

        # ==================================================================
        # RETURN
        # ==================================================================

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                "ContainerIDs": container_ids,
                "ClusterName": cluster_name,
                "Namespace": namespace,
                "NodeFQDN": node_fqdn,
                "NodeIPs": node_ips,
                "Username": username,
                "ProcessName": process_name,
                "ProcessImagePath": process_path,
                "ProcessImageSHA256": process_sha256,
                "ContainerImageID": image_id,
                "Details": details,
                "IsSpringShell": details_analysis["is_springshell"],
                "IsWebshell": details_analysis["is_webshell"],
                "IsPrivilegedUser": user_analysis["is_privileged"],
                "IsContainerRuntime": process_analysis["is_container_runtime"],
                "Severity": severity,
                "SeverityReasons": severity_reasons,
                "IOCs": iocs,
                "ContainmentTarget": containment_target,
                "IssueFieldWriteSuccess": write_success,
            },
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })

        demisto.info("=== ExtractK8sContainerEscapeIOCs v1.0.0 END ===")

    except Exception as e:
        error_msg = "Error in ExtractK8sContainerEscapeIOCs: " + str(e)
        demisto.error(error_msg)
        return_error(error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

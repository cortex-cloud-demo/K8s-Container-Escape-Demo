"""
K8sForensicAnalysis
====================
Performs deep forensic analysis on a K8s container escape incident using XQL queries.
Analyzes the causality chain, process tree, file operations, and network connections
related to the compromised container and node.

Uses data from K8sEscape context (populated by ExtractK8sContainerEscapeIOCs).

Script arguments (playbook inputs):
- container_id                          : Container ID (from K8sEscape.ContainerID)
- namespace                             : K8s namespace (from K8sEscape.Namespace)
- cluster_name                          : EKS cluster name (from K8sEscape.ClusterName)
- node_fqdn                             : Node FQDN (from K8sEscape.NodeFQDN)
- node_ips                              : Node IPs (from K8sEscape.NodeIPs)
- process_name                          : Causality actor process (from K8sEscape.ProcessName)
- process_sha256                        : Process image SHA256 (from K8sEscape.ProcessImageSHA256)
- details                               : Issue details (from K8sEscape.Details)
- time_range                            : XQL time range (default: 30 days)

Output issue field:
- k8sforensicanalysis  (markdown)

Output context:
- K8sForensic.CausalityChain
- K8sForensic.SuspiciousProcesses
- K8sForensic.FileOperations
- K8sForensic.NetworkConnections
- K8sForensic.XQLQueries
- K8sForensic.Summary

Version: 1.0.0
"""


# ==============================================================================
# CONFIGURATION
# ==============================================================================

ISSUE_FIELD_NAME = "k8sforensicanalysis"

# Container escape indicators for process analysis
ESCAPE_INDICATORS = {
    "nsenter": "nsenter used for namespace escape",
    "mount": "Filesystem mount operation",
    "chroot": "chroot to host filesystem",
    "/proc/1/root": "Host filesystem access via /proc/1/root",
    "kubelet": "Direct kubelet access",
    "kube-apiserver": "K8s API server access",
    "/var/run/secrets": "ServiceAccount token access",
    "curl.*169.254.169.254": "IMDS metadata access",
    "wget.*169.254.169.254": "IMDS metadata access",
    "/etc/shadow": "Host credential access",
    "/etc/kubernetes": "K8s config access",
    "/root/.kube": "Kubeconfig access",
    "docker.sock": "Docker socket access",
    "containerd.sock": "Containerd socket access",
}

WEBSHELL_INDICATORS = [
    "shell.jsp", "cmd.jsp", "webshell", "eval(", "Runtime.getRuntime",
    "ProcessBuilder", "classLoader", "class.module",
]

LATERAL_MOVEMENT_INDICATORS = [
    "aws sts", "aws ec2", "aws s3", "curl.*metadata",
    "kubectl", "token", "serviceaccount",
]

# Known attack CVEs
CVE_DATABASE = {
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "severity": "Critical",
        "cvss": 9.8,
        "description": "Remote Code Execution via Spring Framework ClassLoader manipulation",
        "affected": "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19",
        "mitre": ["T1190 - Exploit Public-Facing Application", "T1059.004 - Unix Shell"],
    },
    "CVE-2022-22963": {
        "name": "Spring Cloud Function SpEL Injection",
        "severity": "Critical",
        "cvss": 9.8,
        "description": "RCE via Spring Cloud Function routing SpEL injection",
        "affected": "Spring Cloud Function <= 3.1.6, <= 3.2.2",
        "mitre": ["T1190 - Exploit Public-Facing Application"],
    },
}

# MITRE ATT&CK techniques for container escape
MITRE_TECHNIQUES = {
    "initial_access": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "execution": {"id": "T1059.004", "name": "Unix Shell"},
    "persistence": {"id": "T1505.003", "name": "Web Shell"},
    "privilege_escalation": {"id": "T1611", "name": "Escape to Host"},
    "defense_evasion": {"id": "T1610", "name": "Deploy Container"},
    "credential_access": {"id": "T1552.007", "name": "Container API"},
    "discovery": {"id": "T1613", "name": "Container and Resource Discovery"},
    "lateral_movement": {"id": "T1550.001", "name": "Application Access Token"},
    "collection": {"id": "T1530", "name": "Data from Cloud Storage"},
}


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


def get_field_with_fallback(arg_value, issue_field_name, is_array=True):
    """Retrieve field from arg with fallback to issue."""
    if is_array:
        from_arg = to_list(arg_value)
        if from_arg:
            return from_arg
        try:
            incident = demisto.incident()
            if incident:
                custom_fields = incident.get('CustomFields', {}) or {}
                value = custom_fields.get(issue_field_name) or incident.get(issue_field_name)
                if value:
                    return to_list(value)
        except Exception:
            pass
        return []
    else:
        from_arg = str(arg_value).strip() if arg_value else ""
        if from_arg:
            return from_arg
        try:
            incident = demisto.incident()
            if incident:
                custom_fields = incident.get('CustomFields', {}) or {}
                value = custom_fields.get(issue_field_name) or incident.get(issue_field_name)
                if value:
                    return str(value).strip()
        except Exception:
            pass
        return ""


# ==============================================================================
# XQL QUERY BUILDERS
# ==============================================================================

def build_causality_chain_query(node_fqdn, process_name, time_range):
    """XQL query to reconstruct the full causality chain on the compromised node."""
    host_filter = f'agent_hostname = "{node_fqdn}"' if node_fqdn else ""
    process_filter = f'AND action_process_image_name = "{process_name}"' if process_name else ""

    return {
        "name": "Causality Chain Analysis",
        "description": "Full process causality chain on compromised node",
        "query": f"""dataset = xdr_data
| filter {host_filter} {process_filter}
| filter event_type = ENUM.PROCESS
| fields _time, action_process_image_name, action_process_image_path,
         action_process_image_command_line, actor_process_image_name,
         actor_process_image_path, actor_process_image_command_line,
         causality_actor_process_image_name, causality_actor_process_image_path,
         action_process_username, os_actor_process_os_pid
| sort asc _time
| limit 100""",
        "time_range": time_range,
    }


def build_file_operations_query(node_fqdn, time_range):
    """XQL query to find suspicious file operations (webshell drops, config reads)."""
    host_filter = f'agent_hostname = "{node_fqdn}"' if node_fqdn else ""

    return {
        "name": "Suspicious File Operations",
        "description": "File create/modify/read operations on compromised node",
        "query": f"""dataset = xdr_data
| filter {host_filter}
| filter event_type = ENUM.FILE
| filter action_file_path contains ".jsp" or action_file_path contains "/etc/shadow"
         or action_file_path contains "/etc/kubernetes" or action_file_path contains ".kube/config"
         or action_file_path contains "/var/run/secrets" or action_file_path contains "webshell"
         or action_file_path contains "/proc/1/root"
| fields _time, action_file_path, action_file_name, action_file_md5, action_file_sha256,
         action_process_image_name, action_process_image_command_line,
         actor_process_image_name, action_file_action
| sort asc _time
| limit 50""",
        "time_range": time_range,
    }


def build_network_connections_query(node_fqdn, time_range):
    """XQL query to find suspicious network connections (IMDS, C2, lateral movement)."""
    host_filter = f'agent_hostname = "{node_fqdn}"' if node_fqdn else ""

    return {
        "name": "Suspicious Network Connections",
        "description": "Network connections from compromised node (IMDS, external, K8s API)",
        "query": f"""dataset = xdr_data
| filter {host_filter}
| filter event_type = ENUM.NETWORK
| filter dst_action_external_hostname contains "169.254.169.254"
         or dst_action_external_port in (443, 6443, 10250, 2379)
         or action_remote_ip = "169.254.169.254"
| fields _time, action_local_ip, action_local_port,
         action_remote_ip, action_remote_port,
         dst_action_external_hostname,
         action_process_image_name, action_process_image_command_line,
         actor_process_image_name
| sort asc _time
| limit 50""",
        "time_range": time_range,
    }


def build_container_escape_query(node_fqdn, time_range):
    """XQL query to detect container escape patterns (nsenter, mount, chroot)."""
    host_filter = f'agent_hostname = "{node_fqdn}"' if node_fqdn else ""

    return {
        "name": "Container Escape Detection",
        "description": "Process executions matching container escape patterns",
        "query": f"""dataset = xdr_data
| filter {host_filter}
| filter event_type = ENUM.PROCESS
| filter action_process_image_command_line contains "nsenter"
         or action_process_image_command_line contains "chroot"
         or action_process_image_command_line contains "/proc/1/root"
         or action_process_image_command_line contains "mount"
         or action_process_image_command_line contains "docker.sock"
         or action_process_image_command_line contains "containerd.sock"
         or action_process_image_name = "nsenter"
| fields _time, action_process_image_name, action_process_image_path,
         action_process_image_command_line, actor_process_image_name,
         action_process_username, causality_actor_process_image_name
| sort asc _time
| limit 50""",
        "time_range": time_range,
    }


def build_credential_access_query(node_fqdn, time_range):
    """XQL query to detect credential theft (SA tokens, AWS IMDS, kubeconfig)."""
    host_filter = f'agent_hostname = "{node_fqdn}"' if node_fqdn else ""

    return {
        "name": "Credential Access Detection",
        "description": "Attempts to access K8s tokens, AWS credentials, kubeconfig",
        "query": f"""dataset = xdr_data
| filter {host_filter}
| filter event_type in (ENUM.PROCESS, ENUM.FILE, ENUM.NETWORK)
| filter action_process_image_command_line contains "serviceaccount"
         or action_process_image_command_line contains "169.254.169.254"
         or action_process_image_command_line contains "aws sts"
         or action_process_image_command_line contains "kubectl"
         or action_file_path contains "/var/run/secrets/kubernetes.io"
         or action_file_path contains ".kube/config"
         or action_remote_ip = "169.254.169.254"
| fields _time, event_type, action_process_image_name,
         action_process_image_command_line, action_file_path,
         action_remote_ip, action_remote_port,
         actor_process_image_name
| sort asc _time
| limit 50""",
        "time_range": time_range,
    }


# ==============================================================================
# ANALYSIS FUNCTIONS
# ==============================================================================

def analyze_for_cve(details):
    """Detect known CVEs from issue details."""
    detected_cves = []
    details_lower = normalize_value(details)

    for cve_id, cve_info in CVE_DATABASE.items():
        if cve_id.lower() in details_lower or cve_info["name"].lower() in details_lower:
            detected_cves.append({
                "cve_id": cve_id,
                **cve_info
            })

    # Keyword-based detection
    if not detected_cves:
        if "spring" in details_lower and ("classloader" in details_lower or "class.module" in details_lower):
            detected_cves.append({
                "cve_id": "CVE-2022-22965",
                **CVE_DATABASE["CVE-2022-22965"],
                "detection": "keyword-based"
            })

    return detected_cves


def analyze_attack_phases(details, process_name):
    """Map observed indicators to MITRE ATT&CK kill chain phases."""
    phases = []
    details_lower = normalize_value(details)
    process_lower = normalize_value(process_name)

    # Initial Access
    if any(kw in details_lower for kw in ["spring4shell", "springshell", "cve-2022", "exploit"]):
        phases.append({
            "phase": "Initial Access",
            **MITRE_TECHNIQUES["initial_access"],
            "evidence": "CVE exploit detected in issue details"
        })

    # Execution
    if any(kw in details_lower for kw in ["webshell", "shell.jsp", "cmd.jsp"]):
        phases.append({
            "phase": "Persistence",
            **MITRE_TECHNIQUES["persistence"],
            "evidence": "Webshell deployment detected"
        })

    # Privilege Escalation / Escape
    if any(kw in details_lower for kw in ["container escape", "nsenter", "privilege"]) or \
       process_lower in ["runc", "containerd-shim", "containerd"]:
        phases.append({
            "phase": "Privilege Escalation",
            **MITRE_TECHNIQUES["privilege_escalation"],
            "evidence": "Container escape to host detected"
        })

    # Credential Access
    if any(kw in details_lower for kw in ["token", "credential", "secret", "imds"]):
        phases.append({
            "phase": "Credential Access",
            **MITRE_TECHNIQUES["credential_access"],
            "evidence": "K8s/AWS credential theft detected"
        })

    # Discovery
    if any(kw in details_lower for kw in ["discovery", "enumerate", "kubectl get"]):
        phases.append({
            "phase": "Discovery",
            **MITRE_TECHNIQUES["discovery"],
            "evidence": "Container/resource discovery detected"
        })

    return phases


def analyze_escape_indicators(details, process_name):
    """Detect specific container escape techniques from details and process."""
    indicators = []
    details_lower = normalize_value(details)

    for keyword, description in ESCAPE_INDICATORS.items():
        if keyword.lower() in details_lower:
            indicators.append({"indicator": keyword, "description": description, "source": "details"})

    for kw in WEBSHELL_INDICATORS:
        if kw.lower() in details_lower:
            indicators.append({"indicator": kw, "description": "Webshell/RCE indicator", "source": "details"})

    for kw in LATERAL_MOVEMENT_INDICATORS:
        if kw.lower() in details_lower:
            indicators.append({"indicator": kw, "description": "Lateral movement indicator", "source": "details"})

    return indicators


# ==============================================================================
# MARKDOWN REPORT BUILDER
# ==============================================================================

EMOJI_CRITICAL = "\U0001F534"
EMOJI_HIGH = "\U0001F7E0"
EMOJI_MEDIUM = "\U0001F7E1"
EMOJI_LOW = "\U0001F7E2"
EMOJI_CHECK = "\u2705"
EMOJI_CROSS = "\u274C"
EMOJI_WARN = "\u26A0\uFE0F"
EMOJI_SHIELD = "\U0001F6E1"
EMOJI_SEARCH = "\U0001F50D"
EMOJI_CHAIN = "\U0001F517"
EMOJI_FILE = "\U0001F4C4"
EMOJI_NET = "\U0001F310"
EMOJI_KEY = "\U0001F511"
EMOJI_TARGET = "\U0001F3AF"
EMOJI_MITRE = "\u2694\uFE0F"


def build_forensic_report(container_ids, namespace, cluster_name, node_fqdn,
                          node_ips, process_name, process_sha256, details,
                          detected_cves, attack_phases, escape_indicators,
                          xql_queries):
    """Build the full forensic analysis markdown report."""
    md = []

    md.append("# " + EMOJI_SHIELD + " K8s Container Escape - Forensic Analysis")
    md.append("")

    # ======================== CVE ENRICHMENT ========================
    md.append("## " + EMOJI_SEARCH + " CVE Enrichment")
    md.append("")
    if detected_cves:
        for cve in detected_cves:
            severity_emoji = EMOJI_CRITICAL if cve["severity"] == "Critical" else EMOJI_HIGH
            md.append("### " + severity_emoji + " " + cve["cve_id"] + " — " + cve["name"])
            md.append("")
            md.append("| Field | Value |")
            md.append("|---|---|")
            md.append("| Severity | **" + cve["severity"] + "** |")
            md.append("| CVSS | " + str(cve["cvss"]) + " |")
            md.append("| Description | " + cve["description"] + " |")
            md.append("| Affected | " + cve["affected"] + " |")
            md.append("")
            if cve.get("mitre"):
                md.append("**MITRE ATT&CK**: " + ", ".join(cve["mitre"]))
                md.append("")
    else:
        md.append("No known CVEs detected from issue details.")
        md.append("")

    # ======================== MITRE ATT&CK ========================
    md.append("## " + EMOJI_MITRE + " MITRE ATT&CK Kill Chain")
    md.append("")
    if attack_phases:
        md.append("| Phase | Technique ID | Technique | Evidence |")
        md.append("|---|---|---|---|")
        for phase in attack_phases:
            md.append("| **" + phase["phase"] + "** | `" + phase["id"] + "` | " + phase["name"] + " | " + phase["evidence"] + " |")
        md.append("")
    else:
        md.append("No MITRE techniques mapped from available data.")
        md.append("")

    # ======================== ESCAPE INDICATORS ========================
    md.append("## " + EMOJI_CHAIN + " Container Escape Indicators")
    md.append("")
    if escape_indicators:
        md.append("| Indicator | Description | Source |")
        md.append("|---|---|---|")
        for ind in escape_indicators:
            md.append("| `" + ind["indicator"] + "` | " + ind["description"] + " | " + ind["source"] + " |")
        md.append("")
    else:
        md.append("No escape indicators found in available data.")
        md.append("")

    # ======================== INCIDENT SCOPE ========================
    md.append("## " + EMOJI_TARGET + " Incident Scope")
    md.append("")
    md.append("| Parameter | Value |")
    md.append("|---|---|")
    md.append("| Cluster | `" + (cluster_name or "N/A") + "` |")
    md.append("| Namespace | `" + (namespace or "N/A") + "` |")
    md.append("| Node FQDN | `" + (node_fqdn or "N/A") + "` |")
    md.append("| Node IPs | " + (", ".join(node_ips) if node_ips else "N/A") + " |")
    if container_ids:
        for cid in container_ids:
            md.append("| Container ID | `" + cid + "` |")
    md.append("| Causality Process | `" + (process_name or "N/A") + "` |")
    if process_sha256:
        md.append("| Process SHA256 | `" + process_sha256 + "` |")
    md.append("")

    # ======================== XQL QUERIES ========================
    md.append("## " + EMOJI_SEARCH + " XQL Forensic Queries")
    md.append("")
    md.append("> Ready-to-run XQL queries for deep investigation in Cortex XDR Investigation > Query Center")
    md.append("")
    for i, q in enumerate(xql_queries, 1):
        md.append("### " + str(i) + ". " + q["name"])
        md.append("")
        md.append("*" + q["description"] + "*")
        md.append("")
        md.append("```sql")
        md.append(q["query"].strip())
        md.append("```")
        md.append("")

    # ======================== RECOMMENDATIONS ========================
    md.append("---")
    md.append("")
    md.append("## " + EMOJI_SHIELD + " Forensic Recommendations")
    md.append("")
    md.append("1. " + EMOJI_SEARCH + " **Run the XQL queries** above in Query Center to collect evidence")
    md.append("2. " + EMOJI_CHAIN + " **Analyze the causality chain** to understand full attack path")
    md.append("3. " + EMOJI_FILE + " **Check file operations** for webshell drops and config theft")
    md.append("4. " + EMOJI_NET + " **Review network connections** for IMDS access and C2 channels")
    md.append("5. " + EMOJI_KEY + " **Audit credential access** for stolen tokens and AWS keys")
    md.append("6. " + EMOJI_SHIELD + " **Proceed with containment** if not already done")
    md.append("")

    return "\n".join(md)


# ==============================================================================
# WRITE TO ISSUE FIELD
# ==============================================================================

def write_results_to_issue(markdown_content):
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

        demisto.info("=== K8sForensicAnalysis v1.0.0 START ===")

        # ==================================================================
        # RETRIEVE FIELDS
        # ==================================================================

        container_ids = to_list(args.get('container_id'))
        namespace = str(args.get('namespace', '')).strip()
        cluster_name = str(args.get('cluster_name', '')).strip()
        node_fqdn = str(args.get('node_fqdn', '')).strip()
        node_ips = to_list(args.get('node_ips'))
        process_name = str(args.get('process_name', '')).strip()
        process_sha256 = str(args.get('process_sha256', '')).strip()
        details = str(args.get('details', '')).strip()
        time_range = str(args.get('time_range', '30 days')).strip()

        demisto.info("Cluster: " + cluster_name)
        demisto.info("Namespace: " + namespace)
        demisto.info("Node: " + node_fqdn)
        demisto.info("Process: " + process_name)
        demisto.info("Time range: " + time_range)

        # ==================================================================
        # ANALYSIS
        # ==================================================================

        detected_cves = analyze_for_cve(details)
        attack_phases = analyze_attack_phases(details, process_name)
        escape_indicators = analyze_escape_indicators(details, process_name)

        demisto.info("Detected CVEs: " + str(len(detected_cves)))
        demisto.info("Attack phases: " + str(len(attack_phases)))
        demisto.info("Escape indicators: " + str(len(escape_indicators)))

        # ==================================================================
        # BUILD XQL QUERIES
        # ==================================================================

        xql_queries = [
            build_causality_chain_query(node_fqdn, process_name, time_range),
            build_file_operations_query(node_fqdn, time_range),
            build_network_connections_query(node_fqdn, time_range),
            build_container_escape_query(node_fqdn, time_range),
            build_credential_access_query(node_fqdn, time_range),
        ]

        # ==================================================================
        # MARKDOWN REPORT
        # ==================================================================

        human_readable = build_forensic_report(
            container_ids, namespace, cluster_name, node_fqdn,
            node_ips, process_name, process_sha256, details,
            detected_cves, attack_phases, escape_indicators,
            xql_queries
        )

        # ==================================================================
        # WRITE TO ISSUE
        # ==================================================================

        write_success, write_error = write_results_to_issue(human_readable)
        if not write_success:
            demisto.error("setIncident failed: " + write_error)
            human_readable += "\n> **WARNING**: Failed to write to '" + ISSUE_FIELD_NAME + "': " + write_error + "\n"

        # ==================================================================
        # ENTRY CONTEXT
        # ==================================================================

        entry_context = {
            'K8sForensic.ClusterName': cluster_name,
            'K8sForensic.Namespace': namespace,
            'K8sForensic.NodeFQDN': node_fqdn,
            'K8sForensic.ContainerIDs': container_ids,
            'K8sForensic.DetectedCVEs': detected_cves,
            'K8sForensic.AttackPhases': attack_phases,
            'K8sForensic.EscapeIndicators': escape_indicators,
            'K8sForensic.CausalityChain': xql_queries[0] if xql_queries else {},
            'K8sForensic.SuspiciousProcesses': escape_indicators,
            'K8sForensic.FileOperations': xql_queries[1] if len(xql_queries) > 1 else {},
            'K8sForensic.NetworkConnections': xql_queries[2] if len(xql_queries) > 2 else {},
            'K8sForensic.XQLQueries': [q["query"] for q in xql_queries],
            'K8sForensic.Summary': {
                "cves_found": len(detected_cves),
                "attack_phases": len(attack_phases),
                "escape_indicators": len(escape_indicators),
                "xql_queries_generated": len(xql_queries),
            },
        }

        # ==================================================================
        # RETURN
        # ==================================================================

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                "ClusterName": cluster_name,
                "Namespace": namespace,
                "NodeFQDN": node_fqdn,
                "DetectedCVEs": detected_cves,
                "AttackPhases": attack_phases,
                "EscapeIndicators": escape_indicators,
                "XQLQueries": [{"name": q["name"], "query": q["query"]} for q in xql_queries],
            },
            'HumanReadable': human_readable,
            'EntryContext': entry_context,
        })

        demisto.info("=== K8sForensicAnalysis v1.0.0 END ===")

    except Exception as e:
        error_msg = "Error in K8sForensicAnalysis: " + str(e)
        demisto.error(error_msg)
        return_error(error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

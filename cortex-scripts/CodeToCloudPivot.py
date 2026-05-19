"""
CodeToCloudPivot
=================
Enriches a Kubernetes container escape SOC issue with a Code-to-Cloud
pivot card: clickable deep links from the runtime alert to:
  1. The image in the Cortex Cloud Registry view
  2. The image's CWP findings (active CVEs)
  3. The source repository on GitHub
  4. The exact commit on GitHub
  5. The Dockerfile at that commit
  6. The repository's Code Security findings in Cortex Cloud

Mapping image -> repo: uses OCI standard labels embedded in the image
itself (org.opencontainers.image.source, org.opencontainers.image.revision,
com.cortex.demo.dockerfile_path). For the demo, defaults are configurable
via script args so the playbook works even if labels can't be inspected.

Script arguments:
- image_digest          : Compromised image SHA256 (from K8sEscape.ContainerImageID)
- image_name            : Compromised image name (registry/repo:tag)
- repo_url              : Source repo URL (defaults to demo repo if empty)
- commit_sha            : Git commit that built the image (defaults to "main")
- dockerfile_path       : Path to Dockerfile in repo (default: "Dockerfile")
- cortex_tenant_url     : Cortex tenant base URL (e.g. https://api-xxx.xdr.us.paloaltonetworks.com)

Output issue field:
- k8scodecloudpivot  (markdown - the pivot card)

Output context:
- K8sPivot.RegistryURL
- K8sPivot.CWPFindingsURL
- K8sPivot.RepoURL
- K8sPivot.CommitURL
- K8sPivot.DockerfileURL
- K8sPivot.CodeSecurityURL
- K8sPivot.MarkdownCard
"""


# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Issue field is OPTIONAL. By default we don't try to write to one (the
# markdown card is always returned via HumanReadable so it shows in the
# task entry). Override via `issue_field_name` arg if you have created
# a custom incident field for this purpose, or want to reuse an existing one.
DEFAULT_ISSUE_FIELD_NAME = ""

DEFAULT_REPO_URL = "https://github.com/cortex-cloud-demo/K8s-Container-Escape-Demo"
DEFAULT_DOCKERFILE_PATH = "Dockerfile"
DEFAULT_COMMIT = "main"


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def get_arg(args, key, default=""):
    v = args.get(key)
    if v is None:
        return default
    return str(v).strip()


def normalize_digest(value):
    """Return bare 64-char hex SHA256 digest, or empty string."""
    if not value:
        return ""
    s = str(value).strip()
    if "@sha256:" in s:
        s = s.split("@sha256:")[-1]
    elif s.startswith("sha256:"):
        s = s[len("sha256:"):]
    s = s.split(":")[0] if len(s) < 64 else s
    import re
    m = re.search(r'[a-fA-F0-9]{64}', s)
    return m.group(0).lower() if m else ""


def normalize_repo_url(url):
    """Strip .git suffix, convert SSH to HTTPS."""
    if not url:
        return ""
    u = str(url).strip().rstrip("/")
    if u.startswith("git@github.com:"):
        u = "https://github.com/" + u[len("git@github.com:"):]
    if u.endswith(".git"):
        u = u[:-4]
    return u


def derive_console_base(tenant_url):
    """
    Get the Cortex console base URL.
      1. If tenant_url arg is provided, derive from it (strip api- prefix).
      2. Otherwise, ask the Cortex SDK via demisto.demistoUrls() which
         returns the actual console URL ('server' key) - no derivation needed.
      3. Empty string if neither source is available.
    """
    # 1. Explicit override via arg
    if tenant_url:
        u = tenant_url.replace("https://", "").replace("http://", "").rstrip("/")
        if u.startswith("api-"):
            u = u[len("api-"):]
        return "https://" + u

    # 2. SDK auto-detect (works inside any Cortex playbook task)
    try:
        urls = demisto.demistoUrls()
        if isinstance(urls, dict):
            server = (urls.get("server") or "").rstrip("/")
            if server:
                return server
    except Exception as e:
        try:
            demisto.debug("demisto.demistoUrls() failed: " + str(e))
        except Exception:
            pass

    return ""


# ==============================================================================
# URL BUILDERS
# ==============================================================================

def build_registry_url(console_base, image_digest, image_name):
    """
    Deep link to the image in the Cortex Cloud Asset Inventory view.
    Pattern: <console>/assets/inventory?name=sha256:<digest>
    """
    if not console_base:
        return ""
    if image_digest:
        return console_base + "/assets/inventory?name=sha256:" + image_digest
    if image_name:
        return console_base + "/assets/inventory?name=" + image_name
    return console_base + "/assets/inventory"


def build_cwp_findings_url(console_base, image_digest):
    """Deep link to the active CVEs on this image."""
    if not console_base:
        return ""
    if image_digest:
        return (console_base + "/cloud-security/findings"
                "?filter=asset_category:Container%20Image"
                "&filter=asset_name:sha256:" + image_digest +
                "&filter=is_active:true")
    return console_base + "/cloud-security/findings?filter=asset_category:Container%20Image"


def build_repo_url(repo_url):
    """The repo home page."""
    return normalize_repo_url(repo_url)


def build_commit_url(repo_url, commit_sha):
    """Specific commit on GitHub."""
    base = normalize_repo_url(repo_url)
    if not base:
        return ""
    if commit_sha and commit_sha != "main" and commit_sha != "unknown":
        return base + "/commit/" + commit_sha
    return base + "/commits/main"


def build_dockerfile_url(repo_url, commit_sha, dockerfile_path):
    """Dockerfile at the exact commit (or main if commit unknown)."""
    base = normalize_repo_url(repo_url)
    if not base:
        return ""
    ref = commit_sha if commit_sha and commit_sha != "unknown" else "main"
    return base + "/blob/" + ref + "/" + dockerfile_path.lstrip("/")


def build_code_security_url(console_base, repo_url):
    """Deep link to the repo's Code Security findings in Cortex Cloud."""
    if not console_base:
        return ""
    base = normalize_repo_url(repo_url)
    if not base:
        return console_base + "/cloud-security/code-security"
    safe_url = base.replace(":", "%3A").replace("/", "%2F")
    return console_base + "/cloud-security/code-security/repositories?filter=url:" + safe_url


# ==============================================================================
# MARKDOWN CARD BUILDER
# ==============================================================================

EMOJI_PIVOT = "\U0001F517"   # link
EMOJI_IMAGE = "\U0001F4E6"   # package
EMOJI_BUG = "\U0001F41B"     # bug
EMOJI_CODE = "\U0001F4BB"    # laptop
EMOJI_GIT = "\U0001F500"     # git/twisted
EMOJI_DOC = "\U0001F4C4"     # document
EMOJI_SHIELD = "\U0001F6E1"  # shield
EMOJI_INFO = "ℹ️"
EMOJI_ARROW = "→"


def build_markdown_card(image_digest, image_name, repo_url, commit_sha,
                        dockerfile_path, registry_url, cwp_url,
                        repo_link, commit_link, dockerfile_link, codesec_link):
    md = []
    md.append("# " + EMOJI_PIVOT + " Code-to-Cloud Pivot")
    md.append("")
    md.append("> " + EMOJI_INFO + " One-click navigation from this runtime SOC issue to the related "
              "image in the registry, the source repository, and the exact Dockerfile commit.")
    md.append("")

    # ============== TARGET ==============
    md.append("## " + EMOJI_IMAGE + " Target Image")
    md.append("")
    md.append("| Property | Value |")
    md.append("|---|---|")
    md.append("| Image Name | `" + (image_name if image_name else "_unknown_") + "` |")
    md.append("| Image Digest | `" + ("sha256:" + image_digest if image_digest else "_unknown_") + "` |")
    md.append("| Source Repo | `" + (repo_url if repo_url else "_unknown_") + "` |")
    md.append("| Commit | `" + (commit_sha if commit_sha else "main") + "` |")
    md.append("| Dockerfile | `" + dockerfile_path + "` |")
    md.append("")

    # ============== CLOUD PIVOTS ==============
    md.append("## " + EMOJI_IMAGE + " Cloud Pivots (Cortex Cloud)")
    md.append("")
    md.append("- " + EMOJI_IMAGE + " **[View image in Registry](" + registry_url + ")** "
              + EMOJI_ARROW + " layers, tags, build metadata")
    md.append("- " + EMOJI_BUG + " **[View active CVEs (CWP findings)](" + cwp_url + ")** "
              + EMOJI_ARROW + " all active vulnerabilities for this image")
    md.append("- " + EMOJI_SHIELD + " **[View repo Code Security findings](" + codesec_link + ")** "
              + EMOJI_ARROW + " IaC, SCA, secrets, dependencies")
    md.append("")

    # ============== CODE PIVOTS ==============
    md.append("## " + EMOJI_CODE + " Code Pivots (GitHub)")
    md.append("")
    md.append("- " + EMOJI_GIT + " **[Source repository](" + repo_link + ")** "
              + EMOJI_ARROW + " repo home")
    md.append("- " + EMOJI_GIT + " **[Build commit](" + commit_link + ")** "
              + EMOJI_ARROW + " exact commit that produced this image")
    md.append("- " + EMOJI_DOC + " **[Dockerfile @ commit](" + dockerfile_link + ")** "
              + EMOJI_ARROW + " the Dockerfile that built this vulnerable image")
    md.append("")

    # ============== EXPLAINER ==============
    md.append("---")
    md.append("")
    md.append("## " + EMOJI_PIVOT + " How this works")
    md.append("")
    md.append("Mapping image " + EMOJI_ARROW + " repo " + EMOJI_ARROW + " commit " + EMOJI_ARROW
              + " Dockerfile uses **OCI standard labels** baked at build time:")
    md.append("")
    md.append("- `org.opencontainers.image.source` " + EMOJI_ARROW + " repo URL")
    md.append("- `org.opencontainers.image.revision` " + EMOJI_ARROW + " commit SHA")
    md.append("- `com.cortex.demo.dockerfile_path` " + EMOJI_ARROW + " Dockerfile path in repo")
    md.append("")
    md.append("> Image labels are independent of the orchestration platform and the registry "
              "vendor. They travel with the image - any consumer can resolve the source code "
              "without depending on a separate inventory.")
    md.append("")

    return "\n".join(md)


# ==============================================================================
# WRITE TO ISSUE FIELD (optional)
# ==============================================================================

def write_results_to_issue(field_name, markdown_content):
    """
    Optionally write the markdown card to a custom incident field.
    No-op if field_name is empty. Failure is non-fatal - we just log it.
    """
    if not field_name:
        return None, ""  # skipped, not an error
    try:
        result = demisto.executeCommand("setIssue", {field_name: markdown_content})
        if is_error(result):
            return False, str(get_error(result))
        return True, ""
    except Exception as e:
        return False, str(e)


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    try:
        args = demisto.args()
        demisto.info("=== CodeToCloudPivot v1.0.0 START ===")

        raw_image_digest = get_arg(args, 'image_digest')
        raw_image_name = get_arg(args, 'image_name')
        repo_url = get_arg(args, 'repo_url') or DEFAULT_REPO_URL
        commit_sha = get_arg(args, 'commit_sha') or DEFAULT_COMMIT
        dockerfile_path = get_arg(args, 'dockerfile_path') or DEFAULT_DOCKERFILE_PATH
        tenant_url = get_arg(args, 'cortex_tenant_url')
        issue_field_name = get_arg(args, 'issue_field_name', DEFAULT_ISSUE_FIELD_NAME)

        image_digest = normalize_digest(raw_image_digest) or normalize_digest(raw_image_name)
        image_name = raw_image_name or ""
        repo_url = normalize_repo_url(repo_url)
        console_base = derive_console_base(tenant_url)

        demisto.info("Image digest: '" + image_digest + "' name: '" + image_name +
                     "' repo: '" + repo_url + "' commit: '" + commit_sha + "'")

        # Build URLs
        registry_url = build_registry_url(console_base, image_digest, image_name)
        cwp_url = build_cwp_findings_url(console_base, image_digest)
        repo_link = build_repo_url(repo_url)
        commit_link = build_commit_url(repo_url, commit_sha)
        dockerfile_link = build_dockerfile_url(repo_url, commit_sha, dockerfile_path)
        codesec_link = build_code_security_url(console_base, repo_url)

        # Markdown
        human_readable = build_markdown_card(
            image_digest, image_name, repo_url, commit_sha, dockerfile_path,
            registry_url, cwp_url, repo_link, commit_link, dockerfile_link, codesec_link
        )

        # Optional persistent write to a custom incident field. Skipped by
        # default - the markdown card is always visible via HumanReadable.
        write_success, write_error = write_results_to_issue(issue_field_name, human_readable)
        if write_success is False:
            # Field write was attempted but failed - log only, don't pollute output.
            demisto.info("setIssue('" + issue_field_name + "') failed (non-fatal): " + write_error)

        # Context
        entry_context = {
            'K8sPivot.ImageDigest': image_digest,
            'K8sPivot.ImageName': image_name,
            'K8sPivot.RepoURL': repo_link,
            'K8sPivot.CommitSHA': commit_sha,
            'K8sPivot.DockerfilePath': dockerfile_path,
            'K8sPivot.RegistryURL': registry_url,
            'K8sPivot.CWPFindingsURL': cwp_url,
            'K8sPivot.CommitURL': commit_link,
            'K8sPivot.DockerfileURL': dockerfile_link,
            'K8sPivot.CodeSecurityURL': codesec_link,
            'K8sPivot.MarkdownCard': human_readable,
            'K8sPivot.IssueFieldName': issue_field_name,
            'K8sPivot.IssueFieldWriteStatus': (
                "skipped" if write_success is None else
                "success" if write_success else
                "failed: " + (write_error or "unknown")
            ),
        }

        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                'ImageDigest': image_digest,
                'ImageName': image_name,
                'RepoURL': repo_link,
                'CommitSHA': commit_sha,
                'Pivots': {
                    'Registry': registry_url,
                    'CWPFindings': cwp_url,
                    'Repo': repo_link,
                    'Commit': commit_link,
                    'Dockerfile': dockerfile_link,
                    'CodeSecurity': codesec_link,
                },
                'IssueFieldName': issue_field_name,
                'IssueFieldWriteStatus': (
                    "skipped" if write_success is None else
                    "success" if write_success else
                    "failed"
                ),
            },
            'HumanReadable': human_readable,
            'EntryContext': entry_context
        })

        demisto.info("=== CodeToCloudPivot v1.0.0 END ===")

    except Exception as e:
        error_msg = "Error in CodeToCloudPivot: " + str(e)
        demisto.error(error_msg)
        return_error(error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

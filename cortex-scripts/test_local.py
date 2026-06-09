"""
Local test harness for CodeToCloudPivot.

Stubs `demisto`/CommonServerPython and renders the unified card to stdout.
Tweak SCENARIO below to test different channel combinations.

Usage:
    python3 cortex-scripts/test_local.py [a|b|both|none]
        a    = Channel A only (image, no Yor tags)
        b    = Channel B only (Yor tags, no image)
        both = both channels (default)
        none = neither
"""
import sys, types, importlib.util, builtins

# --- Stub Cortex SDK ---
demisto = types.ModuleType('demisto')
demisto.info = demisto.debug = demisto.error = lambda *a, **k: None
demisto.demistoUrls = lambda: {'server': 'https://my-tenant.xdr.eu.paloaltonetworks.com'}
captured = {}
def _args():
    return captured['args']
demisto.args = _args
def _return_results(r):
    captured['hr'] = r.get('HumanReadable', '')
    captured['ctx'] = r.get('EntryContext', {})
builtins.demisto = demisto
builtins.entryTypes = {'note': 1}
builtins.formats = {'json': 'json'}
builtins.return_results = _return_results
builtins.return_error = lambda m: (_ for _ in ()).throw(RuntimeError(m))
builtins.is_error = lambda r: False
builtins.get_error = lambda r: ''

# --- Scenarios (real values from this repo) ---
IMAGE = {
    'image_digest': 'sha256:9e7c6c8d4e5f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b',
    'image_name': '123456789012.dkr.ecr.eu-west-3.amazonaws.com/vulnerable-flask-app:vulnerable',
    'repo_url': 'https://github.com/cortex-cloud-demo/K8s-Container-Escape-Demo',
    'commit_sha': '4bcffddfd7be2992bb534ba81c88740e95f22bab',
    'dockerfile_path': 'docker/Dockerfile',
}
IAC = {
    'yor_trace': '46097037-2df2-44a2-bf53-5958ad96c134',
    'iac_git_commit': '4bcffddfd7be2992bb534ba81c88740e95f22bab',
    'iac_git_file': 'terraform-infra/main.tf',
    'iac_git_last_modified_by': 'cley@paloaltonetworks.com',
    'iac_git_last_modified_at': '2026-03-31 13:11:42',
    'iac_repo_url': 'https://github.com/cortex-cloud-demo/K8s-Container-Escape-Demo',
    'cloud_resource_id': 'i-0abc1234def567890',
    'cloud_resource_type': 'EKS Worker Node',
}

mode = sys.argv[1] if len(sys.argv) > 1 else 'both'
args = {'cortex_tenant_url': 'https://my-tenant.xdr.eu.paloaltonetworks.com'}
if mode in ('a', 'both'):
    args.update(IMAGE)
if mode in ('b', 'both'):
    args.update(IAC)
captured['args'] = args

# --- Run ---
spec = importlib.util.spec_from_file_location('c2c', 'cortex-scripts/CodeToCloudPivot.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()

print("=" * 80)
print("SCENARIO:", mode.upper())
print("=" * 80)
print(captured['hr'])
print()
print("=" * 80)
print("KEY CONTEXT OUTPUTS")
print("=" * 80)
keys = ['K8sPivot.HasImageChannel', 'K8sPivot.HasIacChannel',
        'K8sPivot.RegistryURL', 'K8sPivot.CWPFindingsURL', 'K8sPivot.DockerfileURL',
        'K8sPivot.IacFileURL', 'K8sPivot.IacCommitURL', 'K8sPivot.IacBlameURL',
        'K8sPivot.IacOwnerContactURL']
for k in keys:
    v = captured['ctx'].get(k, '')
    print(f"  {k:38s} = {v}")

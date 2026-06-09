"""
Local test harness for EnrichCloudAssetYorTags.

Stubs `demisto`/CommonServerPython and a fake xdr-xql-generic-query backend
returning the real asset payload pulled from the user's Cortex tenant.

Usage:
    python3 cortex-scripts/test_enrich_local.py [flat|nested|empty]
        flat   = XQL returns row in flat form (xdm.asset.tags as one key)
        nested = XQL returns row in nested form (xdm: {asset: {tags: {}}})
        empty  = XQL returns no rows (asset not found / tags missing)
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

# --- Fake xdr-xql-generic-query backend ---
mode = sys.argv[1] if len(sys.argv) > 1 else 'flat'

YOR_TAGS = {
    "yor_trace": "56cd7896-d1d6-4b80-bf82-71071299c9df",
    "git_commit": "4bcffddfd7be2992bb534ba81c88740e95f22bab",
    "git_file": "terraform-infra/main.tf",
    "git_last_modified_by": "cley@paloaltonetworks.com",
    "git_last_modified_at": "2026-03-31 13:11:42",
    "git_org": "cortex-cloud-demo",
    "git_repo": "K8s-Container-Escape-Demo",
    "git_modifiers": "cley",
    "yor_name": "eks_nodes",
    "Name": "k8s-escape-demo-node",
}

def _fake_execute_command(cmd, args):
    if cmd != 'xdr-xql-generic-query':
        return [{"Type": 1, "Contents": {}, "EntryContext": {}}]
    if mode == 'empty':
        rows = []
    elif mode == 'nested':
        rows = [{
            "xdm": {
                "asset": {
                    "id": "7a3bb3d59221661117a7bcb9522b92e4132044c35caf544cc1d01b99415d3761",
                    "strong_id": "i-0d5e8c751a2249637",
                    "name": "ip-10-0-1-105.eu-west-3.compute.internal",
                    "type": {"id": "EC2_INSTANCE"},
                    "tags": YOR_TAGS,
                },
                "cloud": {"project_id": "976369349992"},
            }
        }]
    else:  # flat
        rows = [{
            "xdm.asset.id": "7a3bb3d59221661117a7bcb9522b92e4132044c35caf544cc1d01b99415d3761",
            "xdm.asset.strong_id": "i-0d5e8c751a2249637",
            "xdm.asset.name": "ip-10-0-1-105.eu-west-3.compute.internal",
            "xdm.asset.type.id": "EC2_INSTANCE",
            "xdm.asset.tags": YOR_TAGS,
            "xdm.cloud.project_id": "976369349992",
        }]
    return [{
        "Type": 1,
        "Contents": {},
        "EntryContext": {
            "PaloAltoNetworksXQL.GenericQuery(val.execution_id == obj.execution_id)": {
                "execution_id": "test-1234",
                "query": args.get("query", ""),
                "results": rows,
            }
        }
    }]
demisto.executeCommand = _fake_execute_command

def _return_results(r):
    captured['hr'] = r.get('HumanReadable', '') if isinstance(r, dict) else str(r)
    captured['ctx'] = r.get('EntryContext', {}) if isinstance(r, dict) else {}

builtins.demisto = demisto
builtins.entryTypes = {'note': 1}
builtins.formats = {'json': 'json'}
builtins.return_results = _return_results
builtins.return_error = lambda m: (_ for _ in ()).throw(RuntimeError(m))
builtins.is_error = lambda r: False
builtins.get_error = lambda r: ''

# Scenario args: enrich by host_name (matches incident.xdmsourcehostfqdn pattern)
captured['args'] = {
    'host_name': 'ip-10-0-1-105.eu-west-3.compute.internal',
    'time_frame': '7 days',
}

# --- Run ---
spec = importlib.util.spec_from_file_location('eyt', 'cortex-scripts/EnrichCloudAssetYorTags.py')
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
keys = ['K8sAsset.YorTrace', 'K8sAsset.IacGitCommit', 'K8sAsset.IacGitFile',
        'K8sAsset.IacGitAuthor', 'K8sAsset.IacGitLastModifiedAt',
        'K8sAsset.IacRepoURL', 'K8sAsset.CloudResourceID',
        'K8sAsset.CloudResourceType', 'K8sAsset.AssetID', 'K8sAsset.AssetName',
        'K8sAsset.TagsFound', 'K8sAsset.EnrichmentStatus']
for k in keys:
    v = captured['ctx'].get(k, '')
    print(f"  {k:38s} = {v}")

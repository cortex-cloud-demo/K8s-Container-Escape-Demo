// ─── State ────────────────────────────────────────────────────────────────────

const state = {
    currentTaskId: null,
    currentTaskName: '',
    pollInterval: null,
    stepStatuses: {},
    host: null,
    activeTab: 'terminal',
    kubectlTaskId: null,
    kubectlPollInterval: null,
};

const STEPS = [
    { id: 'infra', label: 'Infra' },
    { id: 'build', label: 'Build' },
    { id: 'deploy', label: 'Deploy' },
    { id: 'rce', label: 'RCE' },
    { id: 'escape', label: 'Escape' },
    { id: 'takeover', label: 'Takeover' },
];

// ─── Terminal ─────────────────────────────────────────────────────────────────

function termWrite(text) {
    const el = document.getElementById('terminal-output');
    el.textContent += text;
    el.scrollTop = el.scrollHeight;
}

function termClear() {
    document.getElementById('terminal-output').textContent = '';
}

function termWriteHeader(title) {
    termClear();
    const line = '='.repeat(50);
    termWrite(`${line}\n  ${title}\n${line}\n\n`);
}

// ─── Task Polling ─────────────────────────────────────────────────────────────

function startPolling(taskId) {
    stopPolling();
    state.currentTaskId = taskId;

    const poll = async () => {
        try {
            const res = await fetch(`/api/tasks/${taskId}`);
            const task = await res.json();

            const el = document.getElementById('terminal-output');
            el.textContent = task.output;
            el.scrollTop = el.scrollHeight;

            updateContentHeader(task.name, task.status);

            if (task.status === 'success' || task.status === 'error') {
                stopPolling();
                const duration = task.end_time && task.start_time
                    ? (task.end_time - task.start_time).toFixed(1)
                    : '?';
                termWrite(`\n${'─'.repeat(50)}\n`);
                termWrite(task.status === 'success'
                    ? `✓ Completed in ${duration}s\n`
                    : `✗ Failed (exit code ${task.exit_code}) after ${duration}s\n`
                );

                updateStepStatus(task.name, task.status);
                refreshHost();
            }
        } catch (e) {
            console.error('Poll error:', e);
        }
    };

    poll();
    state.pollInterval = setInterval(poll, 1000);
}

function stopPolling() {
    if (state.pollInterval) {
        clearInterval(state.pollInterval);
        state.pollInterval = null;
    }
}

// ─── UI Updates ───────────────────────────────────────────────────────────────

function updateContentHeader(name, status) {
    document.getElementById('current-task-name').textContent = name || 'Ready';

    const badge = document.getElementById('current-task-status');
    badge.textContent = status || 'idle';
    badge.className = 'task-info';
    if (status === 'running') badge.style.color = '#f97316';
    else if (status === 'success') badge.style.color = '#22c55e';
    else if (status === 'error') badge.style.color = '#ef4444';
    else badge.style.color = '#64748b';
}

function updateStepStatus(taskName, status) {
    const mapping = {
        'Terraform Plan': 'infra',
        'Terraform Apply': 'infra',
        'Build & Push Image': 'build',
        'Deploy to EKS': 'deploy',
        'Step 1: Spring4Shell RCE': 'rce',
        'Step 2: Container Escape': 'escape',
        'Step 3: Cluster Takeover': 'takeover',
        'Terraform Destroy': null,
    };

    const stepId = mapping[taskName];
    if (stepId) {
        state.stepStatuses[stepId] = status;
        renderKillChain();
    }
}

function renderKillChain() {
    const nodes = document.querySelectorAll('.chain-node');
    const lines = document.querySelectorAll('.chain-line');

    STEPS.forEach((step, i) => {
        const node = nodes[i];
        const s = state.stepStatuses[step.id];

        node.classList.remove('completed', 'active', 'error');
        if (s === 'success') node.classList.add('completed');
        else if (s === 'running') node.classList.add('active');
        else if (s === 'error') node.classList.add('error');

        if (i > 0) {
            lines[i - 1].classList.remove('completed');
            const prevStatus = state.stepStatuses[STEPS[i - 1].id];
            if (prevStatus === 'success') lines[i - 1].classList.add('completed');
        }
    });
}

async function refreshHost() {
    try {
        const res = await fetch('/api/k8s/host');
        const data = await res.json();
        state.host = data.host;

        const hostEl = document.getElementById('host-value');
        const dotEl = document.getElementById('host-dot');
        if (data.host) {
            hostEl.textContent = data.host.substring(0, 30) + '...';
            dotEl.classList.add('active');
        } else {
            hostEl.textContent = 'Not deployed';
            dotEl.classList.remove('active');
        }
    } catch (e) {
        // ignore
    }
}

// ─── API Calls ────────────────────────────────────────────────────────────────

async function apiCall(url, method = 'POST', body = null) {
    try {
        const opts = { method };
        if (body) {
            opts.headers = { 'Content-Type': 'application/json' };
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(url, opts);
        const data = await res.json();

        if (data.error) {
            termWriteHeader('Error');
            termWrite(data.error + '\n');
            return;
        }
        if (data.task_id) {
            startPolling(data.task_id);
        }
    } catch (e) {
        termWriteHeader('Error');
        termWrite(`Request failed: ${e.message}\n`);
    }
}

// ─── Tabs ────────────────────────────────────────────────────────────────────

function switchTab(tabId) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${tabId}"]`).classList.add('active');

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');

    state.activeTab = tabId;
}

// ─── kubectl ─────────────────────────────────────────────────────────────────

function kubectlWrite(text) {
    const el = document.getElementById('kubectl-output');
    el.textContent += text;
    el.scrollTop = el.scrollHeight;
}

function kubectlClear() {
    document.getElementById('kubectl-output').textContent = '';
}

function kubectlWriteHeader(title) {
    kubectlClear();
    const line = '='.repeat(50);
    kubectlWrite(`${line}\n  $ kubectl ${title}\n${line}\n\n`);
}

function kubectlStartPolling(taskId, cmdLabel) {
    stopKubectlPolling();
    state.kubectlTaskId = taskId;

    const poll = async () => {
        try {
            const res = await fetch(`/api/tasks/${taskId}`);
            const task = await res.json();

            const el = document.getElementById('kubectl-output');
            // Preserve header then show output
            const headerEnd = el.textContent.indexOf('\n\n') + 2;
            const header = el.textContent.substring(0, headerEnd);
            el.textContent = header + task.output;
            el.scrollTop = el.scrollHeight;

            if (task.status === 'success' || task.status === 'error') {
                stopKubectlPolling();
                const duration = task.end_time && task.start_time
                    ? (task.end_time - task.start_time).toFixed(1)
                    : '?';
                kubectlWrite(`\n${'─'.repeat(50)}\n`);
                kubectlWrite(task.status === 'success'
                    ? `Completed in ${duration}s\n`
                    : `Failed (exit code ${task.exit_code}) after ${duration}s\n`
                );
            }
        } catch (e) {
            console.error('kubectl poll error:', e);
        }
    };

    poll();
    state.kubectlPollInterval = setInterval(poll, 1000);
}

function stopKubectlPolling() {
    if (state.kubectlPollInterval) {
        clearInterval(state.kubectlPollInterval);
        state.kubectlPollInterval = null;
    }
}

async function kubectlRun(args) {
    kubectlWriteHeader(args);

    try {
        const res = await fetch('/api/kubectl', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: args }),
        });
        const data = await res.json();
        if (data.error) {
            kubectlWrite(`ERROR: ${data.error}\n`);
            return;
        }
        if (data.task_id) {
            kubectlStartPolling(data.task_id, args);
        }
    } catch (e) {
        kubectlWrite(`Request failed: ${e.message}\n`);
    }
}

async function generateKubeconfig() {
    kubectlWriteHeader('Generating kubeconfig...');
    kubectlWrite('Fetching cluster info and embedding AWS credentials...\n\n');

    try {
        const res = await fetch('/api/kubeconfig/generate', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            kubectlWrite(`Cluster:    ${data.cluster}\n`);
            kubectlWrite(`Region:     ${data.region}\n`);
            kubectlWrite(`Kubeconfig: ${data.path}\n\n`);
            kubectlWrite('Kubeconfig generated with embedded AWS credentials.\n');
            kubectlWrite('You can now use kubectl commands.\n');
        } else {
            kubectlWrite(`ERROR: ${data.message}\n`);
        }
    } catch (e) {
        kubectlWrite(`Request failed: ${e.message}\n`);
    }
}

function kubectlExec() {
    const input = document.getElementById('kubectl-input');
    const cmd = input.value.trim();
    if (!cmd) return;
    kubectlRun(cmd);
    input.value = '';
}

// ─── Cluster Connection ──────────────────────────────────────────────────────

async function connectCluster() {
    updateClusterStatus('connecting');
    try {
        const res = await fetch('/api/kubeconfig/generate', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            // Switch to terminal tab to show output
            switchTab('terminal');
            termWriteHeader('Cluster Connection');
            termWrite(`Cluster:    ${data.cluster}\n`);
            termWrite(`Region:     ${data.region}\n`);
            termWrite(`Kubeconfig: ${data.path}\n\n`);
            termWrite('Kubeconfig generated with embedded AWS credentials.\n');
            // Refresh status after a short delay
            setTimeout(refreshClusterStatus, 500);
        } else {
            updateClusterStatus('error');
            switchTab('terminal');
            termWriteHeader('Cluster Connection Error');
            termWrite(`ERROR: ${data.message}\n`);
        }
    } catch (e) {
        updateClusterStatus('error');
    }
}

async function refreshClusterStatus() {
    updateClusterStatus('connecting');
    try {
        const res = await fetch('/api/kubeconfig/status');
        const data = await res.json();

        const nameEl = document.getElementById('cluster-conn-name');
        const descEl = document.getElementById('cluster-conn-desc');
        const infoPanel = document.getElementById('cluster-info-panel');
        const errorPanel = document.getElementById('cluster-error-panel');
        const errorText = document.getElementById('cluster-error-text');
        const debugPanel = document.getElementById('cluster-debug-panel');
        const debugLog = document.getElementById('cluster-debug-log');

        // Always populate debug log
        if (data.debug && data.debug.length > 0) {
            debugPanel.style.display = 'block';
            debugLog.textContent = data.debug.join('\n');
        } else {
            debugPanel.style.display = 'none';
        }

        if (!data.kubeconfig_exists) {
            updateClusterStatus('none');
            nameEl.textContent = 'Cluster Connection';
            descEl.textContent = 'Generate kubeconfig to connect to EKS';
            infoPanel.style.display = 'none';
            errorPanel.style.display = 'none';
            return;
        }

        if (data.connected) {
            updateClusterStatus('connected');
            nameEl.textContent = data.cluster_name || 'EKS Cluster';
            descEl.textContent = 'Connected';
            infoPanel.style.display = 'block';
            errorPanel.style.display = 'none';
            document.getElementById('cluster-info-name').textContent = data.cluster_name || '-';
            document.getElementById('cluster-info-region').textContent = data.region || '-';
            document.getElementById('cluster-info-version').textContent = data.server_version || '-';
            document.getElementById('cluster-info-nodes').textContent = data.nodes || '-';
        } else {
            updateClusterStatus('error');
            nameEl.textContent = data.cluster_name || 'Cluster Connection';
            descEl.textContent = 'Connection failed';
            infoPanel.style.display = 'none';
            // Show error
            if (data.error) {
                errorPanel.style.display = 'block';
                errorText.textContent = data.error;
            } else {
                errorPanel.style.display = 'none';
            }
        }
    } catch (e) {
        updateClusterStatus('error');
        const errorPanel = document.getElementById('cluster-error-panel');
        const errorText = document.getElementById('cluster-error-text');
        errorPanel.style.display = 'block';
        errorText.textContent = `Fetch error: ${e.message}`;
    }
}

function toggleClusterDebug() {
    const log = document.getElementById('cluster-debug-log');
    const arrow = document.getElementById('cluster-debug-arrow');
    if (log.style.display === 'none') {
        log.style.display = 'block';
        arrow.classList.add('open');
    } else {
        log.style.display = 'none';
        arrow.classList.remove('open');
    }
}

function updateClusterStatus(status) {
    const el = document.getElementById('cluster-conn-status');
    if (status === 'connected') {
        el.textContent = 'connected';
        el.style.color = '#22c55e';
    } else if (status === 'connecting') {
        el.textContent = 'connecting...';
        el.style.color = '#f97316';
    } else if (status === 'error') {
        el.textContent = 'error';
        el.style.color = '#ef4444';
    } else {
        el.textContent = 'not connected';
        el.style.color = '#64748b';
    }
}

// ─── AWS Credentials ─────────────────────────────────────────────────────────

function openAwsSettings() {
    // Load current values from server
    fetch('/api/credentials')
        .then(r => r.json())
        .then(data => {
            document.getElementById('aws-region').value = data.aws_region || 'eu-west-3';
            document.getElementById('aws-access-key').value = data.aws_access_key_id || '';
            // Don't pre-fill masked secrets - leave empty so user can re-enter
            document.getElementById('aws-secret-key').value = '';
            document.getElementById('aws-session-token').value = '';

            document.getElementById('aws-modal').classList.add('visible');
        });
}

function closeAwsSettings() {
    document.getElementById('aws-modal').classList.remove('visible');
}

async function saveAwsCredentials() {
    const payload = {
        aws_region: document.getElementById('aws-region').value.trim(),
        aws_access_key_id: document.getElementById('aws-access-key').value.trim(),
    };

    // Only send secret/token if user entered new values
    const secretKey = document.getElementById('aws-secret-key').value;
    if (secretKey) {
        payload.aws_secret_access_key = secretKey;
    }
    const sessionToken = document.getElementById('aws-session-token').value;
    if (sessionToken) {
        payload.aws_session_token = sessionToken;
    }

    try {
        const res = await fetch('/api/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (res.ok) {
            closeAwsSettings();
            updateAwsStatus('configured');
            termWriteHeader('AWS Credentials');
            termWrite('Credentials saved successfully.\n');
            termWrite(`Region: ${payload.aws_region}\n`);
            termWrite(`Access Key: ${payload.aws_access_key_id}\n`);
        }
    } catch (e) {
        termWriteHeader('Error');
        termWrite(`Failed to save credentials: ${e.message}\n`);
    }
}

async function testAwsCredentials() {
    termWriteHeader('Testing AWS Credentials');
    termWrite('Running: aws sts get-caller-identity...\n\n');

    try {
        const res = await fetch('/api/credentials/test', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            termWrite(`Account:  ${data.identity.Account}\n`);
            termWrite(`ARN:      ${data.identity.Arn}\n`);
            termWrite(`UserId:   ${data.identity.UserId}\n`);
            termWrite('\nAWS credentials are valid.\n');
            updateAwsStatus('valid');
        } else {
            termWrite(`ERROR: ${data.message}\n`);
            updateAwsStatus('error');
        }
    } catch (e) {
        termWrite(`Request failed: ${e.message}\n`);
        updateAwsStatus('error');
    }
}

function updateAwsStatus(status) {
    const el = document.getElementById('aws-status');
    if (status === 'valid') {
        el.textContent = 'valid';
        el.style.color = '#22c55e';
    } else if (status === 'configured') {
        el.textContent = 'configured';
        el.style.color = '#f97316';
    } else if (status === 'error') {
        el.textContent = 'invalid';
        el.style.color = '#ef4444';
    } else {
        el.textContent = '';
    }
}

// ─── Playbook ────────────────────────────────────────────────────────────────

const PLAYBOOK_STEPS = [
    'collect_evidence', 'network_isolate', 'revoke_rbac',
    'scale_down', 'cordon_node', 'delete_pod'
];

function playbookWrite(text) {
    const el = document.getElementById('playbook-output');
    el.textContent += text;
    el.scrollTop = el.scrollHeight;
}

function playbookClear() {
    document.getElementById('playbook-output').textContent = '';
}

function playbookWriteHeader(title) {
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  CORTEX XSOAR - ${title}\n${line}\n\n`);
}

function updatePlaybookStepStatus(stepId, status) {
    // Sidebar indicator
    const indicator = document.querySelector(`#pb-${stepId} .pb-indicator`);
    if (indicator) {
        indicator.classList.remove('running', 'success', 'error');
        if (status) indicator.classList.add(status);
    }
    // Flow diagram node
    const pfNode = document.getElementById(`pf-${stepId}`);
    if (pfNode) {
        pfNode.classList.remove('running', 'success', 'error');
        if (status) pfNode.classList.add(status);
    }
    // Flow arrows
    const idx = PLAYBOOK_STEPS.indexOf(stepId);
    if (idx > 0 && status === 'success') {
        const arrows = document.querySelectorAll('.pf-arrow');
        if (arrows[idx - 1]) arrows[idx - 1].classList.add('done');
    }
}

function playbookStartPolling(taskId, stepId) {
    stopPlaybookPolling();
    state.playbookTaskId = taskId;

    if (stepId) updatePlaybookStepStatus(stepId, 'running');

    const poll = async () => {
        try {
            const res = await fetch(`/api/tasks/${taskId}`);
            const task = await res.json();

            const el = document.getElementById('playbook-output');
            el.textContent = task.output;
            el.scrollTop = el.scrollHeight;

            updateContentHeader(task.name, task.status);

            if (task.status === 'success' || task.status === 'error') {
                stopPlaybookPolling();
                const duration = task.end_time && task.start_time
                    ? (task.end_time - task.start_time).toFixed(1) : '?';
                playbookWrite(`\n${'─'.repeat(50)}\n`);
                playbookWrite(task.status === 'success'
                    ? `Completed in ${duration}s\n`
                    : `Failed (exit code ${task.exit_code}) after ${duration}s\n`
                );

                if (stepId) {
                    updatePlaybookStepStatus(stepId, task.status);
                } else {
                    // Full playbook - mark all steps
                    const finalStatus = task.status;
                    PLAYBOOK_STEPS.forEach(s => updatePlaybookStepStatus(s, finalStatus));
                }

                // Update playbook status badge
                const badge = document.getElementById('playbook-status');
                if (task.status === 'success') {
                    badge.textContent = 'contained';
                    badge.style.color = '#22c55e';
                } else {
                    badge.textContent = 'failed';
                    badge.style.color = '#ef4444';
                }
            }
        } catch (e) {
            console.error('Playbook poll error:', e);
        }
    };

    poll();
    state.playbookPollInterval = setInterval(poll, 1000);
}

function stopPlaybookPolling() {
    if (state.playbookPollInterval) {
        clearInterval(state.playbookPollInterval);
        state.playbookPollInterval = null;
    }
}

async function playbookRunStep(stepId) {
    switchTab('playbook');
    playbookWriteHeader(stepId.replace(/_/g, ' ').toUpperCase());

    const badge = document.getElementById('playbook-status');
    badge.textContent = 'running';
    badge.style.color = '#f97316';

    try {
        const res = await fetch(`/api/playbook/run/${stepId}`, { method: 'POST' });
        const data = await res.json();
        if (data.error) {
            playbookWrite(`ERROR: ${data.error}\n`);
            return;
        }
        if (data.task_id) {
            playbookStartPolling(data.task_id, stepId);
        }
    } catch (e) {
        playbookWrite(`Request failed: ${e.message}\n`);
    }
}

async function playbookRunAll() {
    switchTab('playbook');
    playbookWriteHeader('FULL CONTAINMENT PLAYBOOK');
    playbookWrite('Running all containment steps...\n\n');

    const badge = document.getElementById('playbook-status');
    badge.textContent = 'running';
    badge.style.color = '#f97316';

    // Reset all step indicators
    PLAYBOOK_STEPS.forEach(s => updatePlaybookStepStatus(s, 'running'));
    document.querySelectorAll('.pf-arrow').forEach(a => a.classList.remove('done'));

    try {
        const res = await fetch('/api/playbook/run-all', { method: 'POST' });
        const data = await res.json();
        if (data.error) {
            playbookWrite(`ERROR: ${data.error}\n`);
            return;
        }
        if (data.task_id) {
            playbookStartPolling(data.task_id, null);
        }
    } catch (e) {
        playbookWrite(`Request failed: ${e.message}\n`);
    }
}

// ─── Actions ──────────────────────────────────────────────────────────────────

function infraPlan() {
    termWriteHeader('Terraform Plan');
    apiCall('/api/infra/plan');
}

function infraApply() {
    termWriteHeader('Terraform Apply (EKS + ECR)');
    termWrite('This will provision the full infrastructure...\n\n');
    apiCall('/api/infra/apply');
}

function infraDestroy() {
    document.getElementById('destroy-modal').classList.add('visible');
}

function confirmDestroy() {
    document.getElementById('destroy-modal').classList.remove('visible');
    termWriteHeader('Terraform Destroy');
    termWrite('Destroying all resources...\n\n');
    apiCall('/api/infra/destroy');
    state.stepStatuses = {};
    renderKillChain();
}

function cancelDestroy() {
    document.getElementById('destroy-modal').classList.remove('visible');
}

function buildPush() {
    termWriteHeader('Build & Push Vulnerable Image to ECR');
    apiCall('/api/image/build-push');
}

function deployApp() {
    termWriteHeader('Deploy Vulnerable App to EKS');
    apiCall('/api/k8s/deploy');
}

async function k8sStatus() {
    termWriteHeader('Kubernetes Status');
    try {
        const res = await fetch('/api/k8s/status');
        const data = await res.json();
        termWrite(data.output || data.error || 'No output');
    } catch (e) {
        termWrite(`Error: ${e.message}`);
    }
}

function attackStep1() {
    termWriteHeader('STEP 1: Spring4Shell RCE (CVE-2022-22965)');
    apiCall('/api/attack/step1');
}

function attackStep2() {
    termWriteHeader('STEP 2: Container Escape');
    apiCall('/api/attack/step2');
}

function attackStep3() {
    termWriteHeader('STEP 3: Cluster Takeover');
    apiCall('/api/attack/step3');
}

function shellExec() {
    const input = document.getElementById('shell-input');
    const cmd = input.value.trim();
    if (!cmd) return;

    termWriteHeader(`Remote Shell: ${cmd}`);
    apiCall('/api/attack/shell', 'POST', { command: cmd });
    input.value = '';
}

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Shell input enter key
    document.getElementById('shell-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') shellExec();
    });

    // kubectl input enter key
    document.getElementById('kubectl-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') kubectlExec();
    });

    refreshHost();
    refreshClusterStatus();

    // Welcome message
    const el = document.getElementById('terminal-output');
    el.textContent = `
  ██╗  ██╗ █████╗  ███████╗    ███████╗███████╗ ██████╗ █████╗ ██████╗ ███████╗
  ██║ ██╔╝██╔══██╗ ██╔════╝    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
  █████╔╝ ╚█████╔╝ ███████╗    █████╗  ███████╗██║     ███████║██████╔╝█████╗
  ██╔═██╗ ██╔══██╗ ╚════██║    ██╔══╝  ╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝
  ██║  ██╗╚█████╔╝ ███████║    ███████╗███████║╚██████╗██║  ██║██║     ███████╗
  ╚═╝  ╚═╝ ╚════╝  ╚══════╝    ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝

  Kubernetes Container Escape Demo Dashboard
  -------------------------------------------
  Target: AWS EKS 1.35 | AL2023 | GP3 volumes
  Vuln:   CVE-2022-22965 (Spring4Shell)

  Attack chain:
    1. RCE via Spring4Shell → webshell on pod
    2. Container escape → node access (privileged + hostPID + hostPath)
    3. Cluster takeover → cluster-admin SA + AWS IMDS

  Use the sidebar to start:
    0. Configure AWS credentials (Access Key, Secret, Session Token)
    1. Deploy infrastructure (Terraform)
    2. Build & push vulnerable image
    3. Deploy app to EKS
    4. Run the attack chain

`;
});

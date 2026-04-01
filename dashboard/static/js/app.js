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
        'Deploy Lambda': null,
        'Destroy Lambda': null,
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
    const tabBtn = document.querySelector(`.tab[data-tab="${tabId}"]`);
    if (tabBtn) tabBtn.classList.add('active');

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');

    state.activeTab = tabId;
}

function openTab(tabId) {
    // Close current fullscreen if different tab
    if (isFullscreen && state.activeTab !== tabId) {
        closeFullscreen();
    }

    switchTab(tabId);
    openFullscreen(tabId);
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
    playbookWrite(`${line}\n  CORTEX - ${title}\n${line}\n\n`);
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

// ─── Lambda ──────────────────────────────────────────────────────────────────

function lambdaDeploy() {
    switchTab('terminal');
    termWriteHeader('Deploy Containment Lambda (Terraform)');
    termWrite('Deploying Lambda + IAM role + EKS access entry...\n\n');
    apiCall('/api/lambda/apply');
}

function lambdaDestroy() {
    switchTab('terminal');
    termWriteHeader('Destroy Containment Lambda (Terraform)');
    termWrite('Destroying Lambda + IAM role + EKS access...\n\n');
    apiCall('/api/lambda/destroy');
}

async function testLambda() {
    switchTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  TEST LAMBDA: collect_evidence\n${line}\n\n`);
    playbookWrite('Invoking containment Lambda with action: collect_evidence...\n\n');

    const badge = document.getElementById('lambda-test-status');
    badge.textContent = 'testing...';
    badge.style.color = '#f97316';

    try {
        const res = await fetch('/api/lambda/test', { method: 'POST' });
        const data = await res.json();
        if (data.error) {
            playbookWrite(`ERROR: ${data.error}\n`);
            badge.textContent = 'error';
            badge.style.color = '#ef4444';
            return;
        }
        if (data.task_id) {
            playbookStartPolling(data.task_id, null);
            // Update badge on completion
            const checkDone = setInterval(async () => {
                const tr = await fetch(`/api/tasks/${data.task_id}`);
                const task = await tr.json();
                if (task.status === 'success') {
                    badge.textContent = 'ok';
                    badge.style.color = '#22c55e';
                    clearInterval(checkDone);
                } else if (task.status === 'error') {
                    badge.textContent = 'error';
                    badge.style.color = '#ef4444';
                    clearInterval(checkDone);
                }
            }, 2000);
        }
    } catch (e) {
        playbookWrite(`Request failed: ${e.message}\n`);
        badge.textContent = 'error';
        badge.style.color = '#ef4444';
    }
}

async function lambdaStatus() {
    termWriteHeader('Lambda Status');
    try {
        const res = await fetch('/api/lambda/status');
        const data = await res.json();
        if (data.status === 'deployed') {
            termWrite(`Status: Deployed\n`);
            termWrite(`Name:   ${data.name}\n`);
            termWrite(`ARN:    ${data.arn}\n`);
            // Update lambda panel
            const panel = document.getElementById('lambda-info-panel');
            if (panel) {
                panel.style.display = 'block';
                document.getElementById('lambda-info-name').textContent = data.name;
                document.getElementById('lambda-info-arn').textContent = data.arn || '-';
            }
            const badge = document.getElementById('lambda-deploy-status');
            if (badge) {
                badge.textContent = 'deployed';
                badge.style.color = '#22c55e';
            }
        } else {
            termWrite(`Status: Not deployed\n`);
            termWrite('Run Terraform Apply to deploy the Lambda.\n');
        }
    } catch (e) {
        termWrite(`Error: ${e.message}\n`);
    }
}

// ─── Cortex ──────────────────────────────────────────────────────────────────

function openCortexSettings() {
    fetch('/api/cortex/credentials')
        .then(r => r.json())
        .then(data => {
            document.getElementById('cortex-base-url').value = data.base_url || '';
            document.getElementById('cortex-key-id').value = data.api_key_id || '';
            document.getElementById('cortex-key').value = '';
            document.getElementById('cortex-modal').classList.add('visible');
            updateCortexConsoleLink(data.base_url);
        });
}

function closeCortexSettings() {
    document.getElementById('cortex-modal').classList.remove('visible');
}

async function saveCortexCredentials() {
    const payload = {
        base_url: document.getElementById('cortex-base-url').value.trim(),
        api_key_id: document.getElementById('cortex-key-id').value.trim(),
    };

    const apiKey = document.getElementById('cortex-key').value;
    if (apiKey) {
        payload.api_key = apiKey;
    }

    try {
        const res = await fetch('/api/cortex/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (res.ok) {
            closeCortexSettings();
            updateCortexStatus('configured');
            updateCortexConsoleLink(payload.base_url);
            termWriteHeader('Cortex');
            termWrite('Cortex API credentials saved.\n');
            termWrite(`Base URL: ${payload.base_url}\n`);
            termWrite(`Key ID: ${payload.api_key_id}\n`);
        }
    } catch (e) {
        termWriteHeader('Error');
        termWrite(`Failed to save Cortex credentials: ${e.message}\n`);
    }
}

async function testCortexConnection() {
    termWriteHeader('Testing Cortex Connection');
    termWrite('Connecting to Cortex API...\n\n');

    try {
        const res = await fetch('/api/cortex/test', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            termWrite(`${data.message}\n`);
            termWrite('\nCortex connection successful.\n');
            updateCortexStatus('connected');
        } else {
            termWrite(`ERROR: ${data.message}\n`);
            updateCortexStatus('error');
        }
    } catch (e) {
        termWrite(`Request failed: ${e.message}\n`);
        updateCortexStatus('error');
    }
}

async function publishPlaybook() {
    switchTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  PUBLISH PLAYBOOK TO CORTEX\n${line}\n\n`);
    playbookWrite('Uploading K8s_Container_Escape_Spring4Shell_Containment.yml...\n\n');

    const badge = document.getElementById('cortex-deploy-status');
    if (badge) { badge.textContent = 'publishing...'; badge.style.color = '#f97316'; }

    try {
        const res = await fetch('/api/cortex/publish-playbook', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            playbookWrite(`${data.message}\n`);
            playbookWrite(`HTTP Status: ${data.http_status}\n`);
            if (data.response) playbookWrite(`\nResponse:\n${data.response}\n`);
            playbookWrite(`\n${'─'.repeat(50)}\n`);
            playbookWrite('Playbook published successfully.\n');
            if (badge) { badge.textContent = 'published'; badge.style.color = '#22c55e'; }
            const ps = document.getElementById('cortex-playbook-status');
            if (ps) ps.textContent = 'deployed';
        } else {
            playbookWrite(`ERROR: ${data.message}\n`);
            if (badge) { badge.textContent = 'failed'; badge.style.color = '#ef4444'; }
        }
    } catch (e) {
        playbookWrite(`Request failed: ${e.message}\n`);
        if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; }
    }
}

async function cortexDeployScript(scriptName) {
    switchTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  DEPLOY SCRIPT: ${scriptName}\n${line}\n\n`);
    playbookWrite(`Uploading automation-${scriptName}.yml to Cortex...\n\n`);

    const badge = document.getElementById('cortex-deploy-status');
    if (badge) { badge.textContent = 'deploying...'; badge.style.color = '#f97316'; }

    try {
        const res = await fetch('/api/cortex/deploy-script', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ script_name: scriptName })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            playbookWrite(`Script '${scriptName}' deployed to Cortex\n`);
            playbookWrite(`API path: ${data.api_path}\n`);
            if (data.response) playbookWrite(`\nResponse:\n${data.response}\n`);
            playbookWrite(`\n${'─'.repeat(50)}\n`);
            playbookWrite('Script deployed successfully.\n');
            if (badge) { badge.textContent = 'deployed'; badge.style.color = '#22c55e'; }
            const ss = document.getElementById('cortex-script-status');
            if (ss) ss.textContent = 'deployed';
        } else {
            playbookWrite(`ERROR: ${data.message}\n`);
            if (badge) { badge.textContent = 'failed'; badge.style.color = '#ef4444'; }
        }
    } catch (e) {
        playbookWrite(`Request failed: ${e.message}\n`);
        if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; }
    }
}

async function cortexDeployAll() {
    switchTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  DEPLOY ALL CORTEX OBJECTS\n${line}\n\n`);
    playbookWrite('Deploying scripts + playbook to Cortex...\n\n');

    const badge = document.getElementById('cortex-deploy-status');
    if (badge) { badge.textContent = 'deploying...'; badge.style.color = '#f97316'; }

    const detailsPanel = document.getElementById('cortex-deploy-details');
    if (detailsPanel) detailsPanel.style.display = 'block';

    const scriptStatus = document.getElementById('cortex-script-status');
    const playbookStatus = document.getElementById('cortex-playbook-status');
    if (scriptStatus) scriptStatus.textContent = 'deploying...';
    if (playbookStatus) playbookStatus.textContent = 'pending...';

    try {
        const res = await fetch('/api/cortex/deploy-all', { method: 'POST' });
        const data = await res.json();

        for (const r of (data.results || [])) {
            const icon = r.status === 'ok' ? '\u2705' : '\u274C';
            playbookWrite(`${icon} ${r.type.toUpperCase()}: ${r.name} - ${r.status}\n`);
            if (r.api_path) playbookWrite(`   API: ${r.api_path}\n`);
            if (r.message) playbookWrite(`   Error: ${r.message}\n`);
            playbookWrite('\n');

            // Update detail panel
            if (r.type === 'script' && scriptStatus) {
                scriptStatus.textContent = r.status === 'ok' ? 'deployed' : 'failed';
                scriptStatus.style.color = r.status === 'ok' ? '#22c55e' : '#ef4444';
            }
            if (r.type === 'playbook' && playbookStatus) {
                playbookStatus.textContent = r.status === 'ok' ? 'deployed' : 'failed';
                playbookStatus.style.color = r.status === 'ok' ? '#22c55e' : '#ef4444';
            }
        }

        playbookWrite(`${'─'.repeat(50)}\n`);
        if (data.status === 'ok') {
            playbookWrite('All Cortex objects deployed successfully.\n');
            if (badge) { badge.textContent = 'deployed'; badge.style.color = '#22c55e'; }
        } else {
            playbookWrite(`Deploy status: ${data.status} - ${data.message}\n`);
            if (badge) { badge.textContent = data.status; badge.style.color = '#f97316'; }
        }
    } catch (e) {
        playbookWrite(`Request failed: ${e.message}\n`);
        if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; }
    }
}

function updateCortexConsoleLink(apiBaseUrl) {
    const panel = document.getElementById('cortex-console-link');
    const link = document.getElementById('cortex-console-url');
    const text = document.getElementById('cortex-console-text');
    if (!panel || !link || !text) return;

    if (!apiBaseUrl) { panel.style.display = 'none'; return; }

    // Derive console URL: remove "api-" prefix from hostname
    try {
        const url = new URL(apiBaseUrl);
        url.hostname = url.hostname.replace(/^api-/, '');
        const consoleUrl = url.toString().replace(/\/+$/, '');
        link.href = consoleUrl;
        text.textContent = url.hostname;
        panel.style.display = 'block';
    } catch (e) {
        panel.style.display = 'none';
    }
}

function updateCortexStatus(status) {
    const el = document.getElementById('cortex-status');
    if (status === 'connected') {
        el.textContent = 'connected';
        el.style.color = '#22c55e';
    } else if (status === 'configured') {
        el.textContent = 'configured';
        el.style.color = '#f97316';
    } else if (status === 'error') {
        el.textContent = 'error';
        el.style.color = '#ef4444';
    } else {
        el.textContent = '';
    }
}

// ─── Actions ──────────────────────────────────────────────────────────────────

// ─── S3 Backend ───────────────────────────────────────────────────────────────

function backendApply() {
    termWriteHeader('Provision S3 Backend (bucket + DynamoDB)');
    apiCall('/api/backend/apply');
}

function backendDestroy() {
    if (!confirm('Destroy S3 backend? Make sure all infrastructure is destroyed first.')) return;
    termWriteHeader('Destroy S3 Backend');
    apiCall('/api/backend/destroy');
}

function backendCheckStatus() {
    fetch('/api/backend/status')
        .then(r => r.json())
        .then(data => {
            const statusEl = document.getElementById('backend-status');
            const panel = document.getElementById('backend-info-panel');
            if (data.status === 'provisioned') {
                statusEl.textContent = 'provisioned';
                statusEl.className = 'step-status success';
                panel.style.display = 'block';
                document.getElementById('backend-info-bucket').textContent = data.bucket || '-';
                document.getElementById('backend-info-table').textContent = data.table || '-';
                document.getElementById('backend-info-region').textContent = data.region || '-';
            } else {
                statusEl.textContent = 'not provisioned';
                statusEl.className = 'step-status error';
                panel.style.display = 'none';
            }
        })
        .catch(() => {
            document.getElementById('backend-status').textContent = 'error';
            document.getElementById('backend-status').className = 'step-status error';
        });
}

// ─── Infrastructure ───────────────────────────────────────────────────────────

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

// ─── Reset Containment ──────────────────────────────────────────────────────

function resetContainment() {
    switchTab('terminal');
    termWriteHeader('RESET CONTAINMENT - Undo remediation for demo replay');
    termWrite('Removing NetworkPolicy, recreating RBAC, uncordoning nodes, scaling up...\n\n');

    const badge = document.getElementById('reset-status');
    if (badge) { badge.textContent = 'running'; badge.style.color = '#f97316'; }

    apiCall('/api/containment/reset');

    // Poll to update status badge
    const checkDone = setInterval(async () => {
        const currentTask = state.currentTaskId;
        if (!currentTask) return;
        try {
            const res = await fetch(`/api/tasks/${currentTask}`);
            const task = await res.json();
            if (task.status === 'success') {
                if (badge) { badge.textContent = 'done'; badge.style.color = '#22c55e'; }
                // Reset playbook step indicators
                PLAYBOOK_STEPS.forEach(s => updatePlaybookStepStatus(s, null));
                document.querySelectorAll('.pf-arrow').forEach(a => a.classList.remove('done'));
                const pbBadge = document.getElementById('playbook-status');
                if (pbBadge) { pbBadge.textContent = ''; }
                clearInterval(checkDone);
            } else if (task.status === 'error') {
                if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; }
                clearInterval(checkDone);
            }
        } catch (e) { /* ignore */ }
    }, 2000);
}

// ─── Fullscreen Tab ──────────────────────────────────────────────────────────

let isFullscreen = false;
let fullscreenOriginalParent = null;
let fullscreenTabElement = null;

const TAB_TITLES = {
    terminal: 'Terminal',
    kubectl: 'kubectl',
    playbook: 'Playbook',
    radar: 'Security Radar',
};

function openFullscreen(tabId) {
    const tabEl = document.getElementById(`tab-${tabId}`);
    if (!tabEl) return;

    fullscreenOriginalParent = tabEl.parentElement;
    fullscreenTabElement = tabEl;

    const body = document.getElementById('fullscreen-body');
    body.innerHTML = '';
    body.appendChild(tabEl);

    document.getElementById('fullscreen-title').textContent =
        TAB_TITLES[tabId] || tabId;

    document.getElementById('fullscreen-overlay').classList.add('visible');
    isFullscreen = true;

    // Init or resize radar
    if (tabId === 'radar') {
        if (!radarChart) {
            setTimeout(() => initRadarChart(), 50);
        } else {
            setTimeout(() => radarChart.resize(), 50);
        }
    }
}

function closeFullscreen() {
    if (!isFullscreen) return;

    if (fullscreenTabElement && fullscreenOriginalParent) {
        fullscreenOriginalParent.appendChild(fullscreenTabElement);
    }
    document.getElementById('fullscreen-overlay').classList.remove('visible');
    isFullscreen = false;
    fullscreenOriginalParent = null;
    fullscreenTabElement = null;

    if (state.activeTab === 'radar' && radarChart) {
        setTimeout(() => radarChart.resize(), 50);
    }
}

// Close fullscreen on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isFullscreen) {
        closeFullscreen();
    }
});

// ─── Radar Chart ─────────────────────────────────────────────────────────────

let radarChart = null;
const radarState = {
    before: null,  // snapshot data
    current: null, // live scan data
};

const RADAR_LABELS = [
    'Network Isolation',
    'RBAC Security',
    'Pod Security',
    'Node Security',
    'Deployment Control',
    'Evidence',
];

const RADAR_KEYS = [
    'network_isolation',
    'rbac_security',
    'pod_security',
    'node_security',
    'deployment_control',
    'evidence',
];

function initRadarChart() {
    const ctx = document.getElementById('security-radar');
    if (!ctx) return;

    radarChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: RADAR_LABELS,
            datasets: [
                {
                    label: 'Before (compromised)',
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: 'rgba(239, 68, 68, 0.8)',
                    backgroundColor: 'rgba(239, 68, 68, 0.15)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgba(239, 68, 68, 0.9)',
                    pointBorderColor: '#fff',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    hidden: true,
                },
                {
                    label: 'After (remediated)',
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: 'rgba(34, 197, 94, 0.8)',
                    backgroundColor: 'rgba(34, 197, 94, 0.15)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgba(34, 197, 94, 0.9)',
                    pointBorderColor: '#fff',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    hidden: true,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            animation: {
                duration: 1200,
                easing: 'easeOutQuart',
            },
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    min: 0,
                    ticks: {
                        stepSize: 20,
                        color: '#64748b',
                        backdropColor: 'transparent',
                        font: { size: 10 },
                    },
                    grid: {
                        color: 'rgba(30, 41, 59, 0.8)',
                    },
                    angleLines: {
                        color: 'rgba(30, 41, 59, 0.6)',
                    },
                    pointLabels: {
                        color: '#94a3b8',
                        font: { size: 12, weight: '600' },
                    },
                },
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1e293b',
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    borderColor: '#334155',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return `${context.dataset.label}: ${context.raw}/100`;
                        }
                    }
                },
            },
        },
    });
}

function updateRadarScore(score) {
    const el = document.getElementById('radar-score');
    el.textContent = score + '%';
    el.classList.remove('score-low', 'score-mid', 'score-high');
    if (score >= 70) el.classList.add('score-high');
    else if (score >= 40) el.classList.add('score-mid');
    else el.classList.add('score-low');
}

function updateK8sObjects(objects) {
    const mapping = {
        'obj-pods': { data: objects.pods, statusId: 'obj-pods-status' },
        'obj-netpol': { data: objects.networkpolicy, statusId: 'obj-netpol-status' },
        'obj-rbac': { data: objects.clusterrolebinding, statusId: 'obj-rbac-status' },
        'obj-deploy': { data: objects.deployment, statusId: 'obj-deploy-status' },
        'obj-node': { data: objects.nodes, statusId: 'obj-node-status' },
        'obj-evidence': { data: objects.events, statusId: 'obj-evidence-status' },
    };

    for (const [elemId, info] of Object.entries(mapping)) {
        const card = document.getElementById(elemId);
        const statusEl = document.getElementById(info.statusId);
        if (!card || !statusEl || !info.data) continue;

        statusEl.textContent = info.data.status || '--';
        card.classList.remove('secure', 'vulnerable');
        card.classList.add(info.data.secure ? 'secure' : 'vulnerable');
    }
}

function updateRemediationTimeline(posture) {
    // Determine which remediation steps are "done" based on posture scores
    const stepScores = {
        'collect_evidence': posture.evidence > 50,
        'network_isolate': posture.network_isolation > 50,
        'revoke_rbac': posture.rbac_security > 50,
        'scale_down': posture.deployment_control > 50,
        'cordon_node': posture.node_security > 50,
        'delete_pod': posture.pod_security > 50,
    };

    for (const [stepId, isDone] of Object.entries(stepScores)) {
        const stepEl = document.querySelector(`.rem-step[data-step="${stepId}"]`);
        const badge = document.getElementById(`rem-${stepId}`);
        if (!stepEl || !badge) continue;

        stepEl.classList.remove('done', 'running', 'failed');
        if (isDone) {
            stepEl.classList.add('done');
            badge.textContent = 'done';
        } else {
            badge.textContent = 'pending';
        }
    }
}

async function radarSnapshot() {
    switchTab('radar');
    const tab = document.getElementById('tab-radar');
    tab.classList.add('radar-scanning');

    try {
        const res = await fetch('/api/security/posture');
        const data = await res.json();
        radarState.before = data;

        // Update chart - Before dataset
        const values = RADAR_KEYS.map(k => data[k] || 0);
        radarChart.data.datasets[0].data = values;
        radarChart.data.datasets[0].hidden = false;
        radarChart.update();

        updateRadarScore(data.overall_score);
        updateK8sObjects(data.objects);
        updateRemediationTimeline(data);
    } catch (e) {
        console.error('Radar snapshot error:', e);
    }

    tab.classList.remove('radar-scanning');
}

async function radarScan() {
    switchTab('radar');
    const tab = document.getElementById('tab-radar');
    tab.classList.add('radar-scanning');

    try {
        const res = await fetch('/api/security/posture');
        const data = await res.json();
        radarState.current = data;

        // If no before snapshot, use current as before
        if (!radarState.before) {
            radarState.before = data;
            const beforeValues = RADAR_KEYS.map(k => data[k] || 0);
            radarChart.data.datasets[0].data = beforeValues;
            radarChart.data.datasets[0].hidden = false;
        }

        // Update chart - After dataset
        const values = RADAR_KEYS.map(k => data[k] || 0);
        radarChart.data.datasets[1].data = values;
        radarChart.data.datasets[1].hidden = false;
        radarChart.update();

        updateRadarScore(data.overall_score);
        updateK8sObjects(data.objects);
        updateRemediationTimeline(data);
    } catch (e) {
        console.error('Radar scan error:', e);
    }

    tab.classList.remove('radar-scanning');
}

function radarReset() {
    radarState.before = null;
    radarState.current = null;

    if (radarChart) {
        radarChart.data.datasets[0].data = [0, 0, 0, 0, 0, 0];
        radarChart.data.datasets[0].hidden = true;
        radarChart.data.datasets[1].data = [0, 0, 0, 0, 0, 0];
        radarChart.data.datasets[1].hidden = true;
        radarChart.update();
    }

    document.getElementById('radar-score').textContent = '--';
    document.getElementById('radar-score').className = 'radar-score-value';

    // Reset objects
    ['obj-pods', 'obj-netpol', 'obj-rbac', 'obj-deploy', 'obj-node', 'obj-evidence'].forEach(id => {
        const card = document.getElementById(id);
        if (card) card.classList.remove('secure', 'vulnerable');
    });
    ['obj-pods-status', 'obj-netpol-status', 'obj-rbac-status', 'obj-deploy-status', 'obj-node-status', 'obj-evidence-status'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '--';
    });

    // Reset timeline
    document.querySelectorAll('.rem-step').forEach(el => el.classList.remove('done', 'running', 'failed'));
    document.querySelectorAll('.rem-badge').forEach(el => el.textContent = 'pending');
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

    // Load Cortex console link if credentials exist
    fetch('/api/cortex/credentials').then(r => r.json()).then(data => {
        if (data.base_url) updateCortexConsoleLink(data.base_url);
    }).catch(() => {});

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

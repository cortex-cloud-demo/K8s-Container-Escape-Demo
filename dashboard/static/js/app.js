// ─── State ────────────────────────────────────────────────────────────────────

const state = {
    currentTaskId: null,
    currentTaskName: '',
    pollInterval: null,
    stepStatuses: {},
    host: null,
    activeTab: 'overview',
    kubectlTaskId: null,
    kubectlPollInterval: null,
};

const STEPS = [
    { id: 'infra',    el: 'hc-infra',    attack: false },
    { id: 'build',    el: 'hc-build',    attack: false },
    { id: 'deploy',   el: 'hc-deploy',   attack: false },
    { id: 'rce',      el: 'hc-rce',      attack: true },
    { id: 'escape',   el: 'hc-escape',   attack: true },
    { id: 'takeover', el: 'hc-takeover', attack: true },
    { id: 'scan',     el: 'hc-scan',     attack: true },
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
        'Undeploy from EKS': null,
        'Step 1: Spring4Shell RCE': 'rce',
        'Step 2: Container Escape': 'escape',
        'Step 3: Cluster Takeover': 'takeover',
        'Step 4: K8s Vulnerability Scanning': 'scan',
        'Terraform Destroy': null,
        'Deploy Lambda': null,
        'Destroy Lambda': null,
    };

    const stepId = mapping[taskName];
    if (stepId) {
        state.stepStatuses[stepId] = status;
        renderKillChain();
    }

    // Update status badges for all sidebar cards
    const badgeMap = {
        'Terraform Plan':           { id: 'infra-status',          ok: 'planned',     run: 'planning...' },
        'Terraform Apply':          { id: 'infra-status',          ok: 'provisioned', run: 'applying...' },
        'Build & Push Image':       { id: 'build-status',          ok: 'built',       run: 'building...' },
        'Deploy to EKS':            { id: 'deploy-status',         ok: 'deployed',    run: 'deploying...' },
        'Step 1: Spring4Shell RCE': { id: 'rce-status',            ok: 'exploited',   run: 'running...' },
        'Step 2: Container Escape': { id: 'escape-status',         ok: 'escaped',     run: 'running...' },
        'Step 3: Cluster Takeover': { id: 'takeover-status',       ok: 'pwned',       run: 'running...' },
        'Step 4: K8s Vulnerability Scanning': { id: 'scanning-status', ok: 'scanned',   run: 'scanning...' },
        'Undeploy from EKS':        { id: 'deploy-status',         ok: 'undeployed',  run: 'removing...' },
        'Deploy Lambda':            { id: 'lambda-deploy-status',  ok: 'deployed',    run: 'deploying...' },
        'Terraform Destroy':        { id: 'infra-destroy-status',  ok: 'destroyed',   run: 'destroying...' },
        'Destroy Lambda':           { id: 'lambda-destroy-status', ok: 'destroyed',   run: 'destroying...' },
        'Reset Containment':        { id: 'reset-status',          ok: 'done',        run: 'running...' },
        'XDR Agent: Install on K8s': { id: 'xdr-deploy-status',   ok: 'deployed',    run: 'deploying...' },
    };
    const badge = badgeMap[taskName];
    if (badge) {
        const el = document.getElementById(badge.id);
        if (el) {
            if (status === 'success') {
                el.textContent = badge.ok;
                el.style.color = '#22c55e';
            } else if (status === 'error') {
                el.textContent = 'error';
                el.style.color = '#ef4444';
            } else if (status === 'running') {
                el.textContent = badge.run;
                el.style.color = '#f97316';
            }
        }
    }
}

function renderKillChain() {
    const lines = document.querySelectorAll('.header-chain-line');

    STEPS.forEach((step, i) => {
        const el = document.getElementById(step.el);
        if (!el) return;
        const s = state.stepStatuses[step.id];

        el.classList.remove('completed', 'active');
        if (s === 'success') el.classList.add('completed');
        else if (s === 'running') el.classList.add('active');

        // Update connecting lines
        if (i > 0 && lines[i - 1]) {
            lines[i - 1].classList.remove('completed', 'attack-completed');
            const prevStatus = state.stepStatuses[STEPS[i - 1].id];
            if (prevStatus === 'success') {
                lines[i - 1].classList.add(step.attack ? 'attack-completed' : 'completed');
            }
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
    switchTab(tabId);

    // Init radar chart on first open (needs visible container to size correctly)
    if (tabId === 'radar' && !radarChart) {
        setTimeout(() => initRadarChart(), 50);
    }
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
            openTab('terminal');
            termWriteHeader('Cluster Connection');
            termWrite(`Cluster:    ${data.cluster}\n`);
            termWrite(`Region:     ${data.region}\n`);
            termWrite(`Kubeconfig: ${data.path}\n\n`);
            termWrite('Kubeconfig generated with embedded AWS credentials.\n');
            // Refresh status after a short delay
            setTimeout(refreshClusterStatus, 500);
        } else {
            updateClusterStatus('error');
            openTab('terminal');
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

function parseAwsExport() {
    const raw = document.getElementById('aws-paste-export').value;
    if (!raw) return;
    const lines = raw.split('\n');
    for (const line of lines) {
        const m = line.match(/export\s+(AWS_\w+)\s*=\s*"?([^"]*)"?/i);
        if (!m) continue;
        const key = m[1].toUpperCase();
        const val = m[2].trim();
        if (key === 'AWS_ACCESS_KEY_ID') {
            document.getElementById('aws-access-key').value = val;
        } else if (key === 'AWS_SECRET_ACCESS_KEY') {
            document.getElementById('aws-secret-key').value = val;
        } else if (key === 'AWS_SESSION_TOKEN') {
            document.getElementById('aws-session-token').value = val;
        } else if (key === 'AWS_DEFAULT_REGION' || key === 'AWS_REGION') {
            document.getElementById('aws-region').value = val;
        }
    }
    document.getElementById('aws-paste-export').value = '';
    document.getElementById('aws-paste-export').placeholder = 'Parsed! Fields populated below.';
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
    openTab('terminal');
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
    openTab('playbook');
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
    openTab('playbook');
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
    openTab('terminal');
    termWriteHeader('Deploy Containment Lambda (Terraform)');
    termWrite('Deploying Lambda + IAM role + EKS access entry...\n\n');
    apiCall('/api/lambda/apply');
}

function lambdaDestroy() {
    openTab('terminal');
    termWriteHeader('Destroy Containment Lambda (Terraform)');
    termWrite('Destroying Lambda + IAM role + EKS access...\n\n');
    apiCall('/api/lambda/destroy');
}

async function testLambda() {
    openTab('playbook');
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
    openTab('terminal');
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
    openTab('terminal');
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
    openTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  PUBLISH ALL PLAYBOOKS TO CORTEX\n${line}\n\n`);

    const badge = document.getElementById('cortex-deploy-status');
    if (badge) { badge.textContent = 'publishing...'; badge.style.color = '#f97316'; }

    const playbooks = [
        { name: 'containment', label: 'K8s Container Escape Containment' },
        { name: 'forensic', label: 'K8s Container Escape Forensic Analysis' },
        { name: 'search', label: 'K8s Container Escape Search Similar Events' },
    ];
    let allOk = true;

    for (const pb of playbooks) {
        const statusId = PLAYBOOK_STATUS_MAP[pb.name];
        if (statusId) setItemStatus(statusId, 'deploying...', '#f97316');

        playbookWrite(`Uploading ${pb.label}...\n`);
        try {
            const res = await fetch('/api/cortex/publish-playbook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ playbook_name: pb.name })
            });
            const data = await res.json();
            if (data.status === 'ok') {
                playbookWrite(`  \u2705 ${pb.label} published\n\n`);
                if (statusId) setItemStatus(statusId, '\u2705', '#22c55e');
            } else {
                playbookWrite(`  \u274C ${pb.label}: ${data.message}\n\n`);
                if (statusId) setItemStatus(statusId, '\u274C', '#ef4444');
                allOk = false;
            }
        } catch (e) {
            playbookWrite(`  \u274C ${pb.label}: ${e.message}\n\n`);
            if (statusId) setItemStatus(statusId, '\u274C', '#ef4444');
            allOk = false;
        }
    }

    playbookWrite(`${'─'.repeat(50)}\n`);
    if (allOk) {
        playbookWrite('All playbooks published successfully.\n');
        if (badge) { badge.textContent = 'published'; badge.style.color = '#22c55e'; }
    } else {
        playbookWrite('Some playbooks failed to publish.\n');
        if (badge) { badge.textContent = 'partial failure'; badge.style.color = '#ef4444'; }
    }
}

// Status badge mapping for individual deploy buttons
const SCRIPT_STATUS_MAP = {
    'ExtractK8sContainerEscapeIOCs': 'deploy-status-script-extract',
    'InvokeK8sContainmentLambda': 'deploy-status-script-invoke',
    'K8sForensicAnalysis': 'deploy-status-script-forensic',
    'K8sSearchSimilarEvents': 'deploy-status-script-search',
};
const PLAYBOOK_STATUS_MAP = {
    'containment': 'deploy-status-pb-containment',
    'forensic': 'deploy-status-pb-forensic',
    'search': 'deploy-status-pb-search',
};

function setItemStatus(id, text, color) {
    const el = document.getElementById(id);
    if (el) { el.textContent = text; el.style.color = color; }
}

// ─── Cortex Detail Modal ────────────────────────────────────────────────────

const CORTEX_DETAILS = {
    'ExtractK8sContainerEscapeIOCs': {
        type: 'SCRIPT',
        title: 'ExtractK8sContainerEscapeIOCs',
        desc: 'Analyzes XDR issue fields to extract Indicators of Compromise (container ID, namespace, node FQDN, process name/SHA256, container image). Determines incident severity (Critical/High/Medium/Low) based on attack indicators: Spring4Shell exploitation, webshell deployment, container escape techniques, and credential theft. Detects Spring4Shell patterns (ClassLoader manipulation, class.module parameters) and webshell indicators (.jsp file drops, Runtime.getRuntime, ProcessBuilder).',
        usedBy: [
            { type: 'Playbook', name: 'Containment', task: 'Task #1 — Triage' },
            { type: 'Playbook', name: 'Forensic Analysis', task: 'Task #1 — Triage' },
            { type: 'Playbook', name: 'Search Similar Events', task: 'Task #1 — Triage' },
        ],
        inputs: 'details, container_id, namespace, cluster_name,\nxdmsourcehostfqdn, xdmsourcehostipv4addresses,\nxdmsourceusername, xdmsourceprocessname,\ncausality_actor_process_*, image_id, agent_os_type',
        outputs: 'K8sEscape.ContainerID, K8sEscape.Namespace,\nK8sEscape.ClusterName, K8sEscape.NodeFQDN,\nK8sEscape.ProcessName, K8sEscape.ProcessImageSHA256,\nK8sEscape.Severity, K8sEscape.Details\n\nIssue field: k8scontainerescapeiocs',
    },
    'InvokeK8sContainmentLambda': {
        type: 'SCRIPT',
        title: 'InvokeK8sContainmentLambda',
        desc: 'Invokes the AWS Lambda containment function from Cortex XSIAM (GCP-hosted, no boto3). Uses pure SigV4 signing (hmac/hashlib) for all AWS API calls: STS AssumeRole to obtain temporary credentials scoped to the lambda-invoker IAM role, then Lambda Invoke with the containment action payload. Supports 7 actions: collect_evidence, network_isolate, revoke_rbac, scale_down, cordon_node, delete_pod, full_containment. Dual-mode: direct invocation if no assume_role_arn.',
        usedBy: [
            { type: 'Playbook', name: 'Containment', task: 'Tasks #2, #4-#9 — Evidence & Containment actions' },
            { type: 'Playbook', name: 'Forensic Analysis', task: 'Task #8 — Collect Live Evidence' },
        ],
        inputs: 'action, cluster_name, namespace, region,\nlambda_function_name, aws_access_key_id,\naws_secret_access_key, assume_role_arn',
        outputs: 'K8sContainment.Action, K8sContainment.Status,\nK8sContainment.LambdaResponse\n\nIssue field: k8scontainmentenrichment',
    },
    'K8sForensicAnalysis': {
        type: 'SCRIPT',
        title: 'K8sForensicAnalysis',
        desc: 'Performs deep forensic analysis: CVE enrichment (Spring4Shell CVE-2022-22965 CVSS 9.8, Spring Cloud CVE-2022-22963), MITRE ATT&CK kill chain mapping (9 techniques from T1190 to T1530), and container escape indicator detection (nsenter, mount, chroot, /proc/1/root, IMDS, docker.sock). Generates 5 XQL forensic queries stored in K8sForensic.XQLQueries array for automatic execution by the Forensic Analysis playbook via xdr-xql-generic-query.',
        usedBy: [
            { type: 'Playbook', name: 'Forensic Analysis', task: 'Task #2 — Forensic Analysis' },
        ],
        inputs: 'container_id, namespace, cluster_name,\nnode_fqdn, node_ips, process_name,\nprocess_sha256, details, time_range (30 days)',
        outputs: 'K8sForensic.DetectedCVEs, K8sForensic.AttackPhases,\nK8sForensic.EscapeIndicators, K8sForensic.XQLQueries[],\nK8sForensic.Summary\n\nIssue field: k8sforensicanalysis',
    },
    'K8sSearchSimilarEvents': {
        type: 'SCRIPT',
        title: 'K8sSearchSimilarEvents',
        desc: 'Generates cross-tenant XQL threat hunting queries to determine blast radius and detect lateral movement. Targeted searches: same process on other nodes, same binary SHA256, same container image, namespace alert correlation. Broad hunts: webshell drops (.jsp) across all K8s nodes, container escape patterns (nsenter, chroot, /proc/1/root), IMDS credential theft (169.254.169.254). Targeted queries are stored in the issue field for manual Query Center execution; broad hunts are auto-executed by the playbook.',
        usedBy: [
            { type: 'Playbook', name: 'Search Similar Events', task: 'Task #2 — Generate Search Queries' },
        ],
        inputs: 'container_id, namespace, cluster_name,\nnode_fqdn, process_name, process_sha256,\nimage_id, details, time_range (30 days)',
        outputs: 'K8sSimilar.QueriesGenerated, K8sSimilar.SearchCriteria,\nK8sSimilar.Queries[], K8sSimilar.Summary\n\nIssue field: k8ssearchsimilarevents',
    },
    'pb-containment': {
        type: 'PLAYBOOK',
        title: 'K8s Container Escape — Containment',
        desc: 'Automated incident response for K8s container escape. Triages the XDR issue to extract IOCs, collects forensic evidence via Lambda, then gates on severity: Critical/High with Spring4Shell indicators proceeds automatically, otherwise requests operator approval. Executes full containment: deny-all NetworkPolicy, cluster-admin ClusterRoleBinding deletion, deployment scale-down to 0, node cordoning, force pod deletion. Final verification re-collects evidence.',
        usedBy: [
            { type: 'Script', name: 'ExtractK8sContainerEscapeIOCs', task: 'Task #1 — Triage' },
            { type: 'Script', name: 'InvokeK8sContainmentLambda', task: 'Tasks #2, #4-#9 — Lambda actions' },
        ],
        inputs: 'Triggered on XDR issue with container escape indicators.\nAll inputs from incident fields (details, container_id,\nnamespace, cluster_name, node FQDN, process info).',
        outputs: 'Task #1: K8sEscape.* context (IOCs, severity)\nTask #2: Evidence collection (pods, logs, RBAC, events)\nTasks #4-#8: Containment actions (NetPol, RBAC, scale, cordon, delete)\nTask #9: Verification evidence\n\n10 tasks total',
    },
    'pb-forensic': {
        type: 'PLAYBOOK',
        title: 'K8s Container Escape — Forensic Analysis',
        desc: 'Deep investigation playbook. Runs CVE enrichment and MITRE ATT&CK mapping, then automatically executes 5 XQL queries via xdr-xql-generic-query: causality chain reconstruction, suspicious file operations (webshell drops, config reads), network connections (IMDS, C2, K8s API), container escape patterns (nsenter, chroot, mount), and credential access attempts (SA tokens, AWS keys). Concludes with live evidence collection via Lambda.',
        usedBy: [
            { type: 'Script', name: 'ExtractK8sContainerEscapeIOCs', task: 'Task #1 — Triage' },
            { type: 'Script', name: 'K8sForensicAnalysis', task: 'Task #2 — Forensic Analysis' },
            { type: 'Script', name: 'InvokeK8sContainmentLambda', task: 'Task #8 — Evidence' },
            { type: 'Built-in', name: 'xdr-xql-generic-query', task: 'Tasks #3-#7 — XQL queries' },
        ],
        inputs: 'Triggered on XDR issue with container escape indicators.\nAll inputs from incident fields + K8sEscape.* context.',
        outputs: 'Task #2: K8sForensic.* (CVEs, MITRE, XQL queries)\nTasks #3-#7: XQL results (causality, files, network,\n  escape patterns, credentials)\nTask #8: Live evidence from Lambda\n\n9 tasks total',
    },
    'pb-search': {
        type: 'PLAYBOOK',
        title: 'K8s Container Escape — Search Similar Events',
        desc: 'Threat hunting playbook to determine attack spread. Generates targeted and broad XQL queries, then auto-executes 3 broad hunts via xdr-xql-generic-query: webshell drops across all K8s nodes, container escape patterns on all endpoints, and IMDS credential theft from containers. Targeted IOC queries (lateral movement, binary hash, blast radius, alert correlation) stored in issue field for manual Query Center execution. Analyst reviews and decides: escalate or close.',
        usedBy: [
            { type: 'Script', name: 'ExtractK8sContainerEscapeIOCs', task: 'Task #1 — Triage' },
            { type: 'Script', name: 'K8sSearchSimilarEvents', task: 'Task #2 — Generate Queries' },
            { type: 'Built-in', name: 'xdr-xql-generic-query', task: 'Tasks #3-#5 — XQL hunts' },
        ],
        inputs: 'Triggered on XDR issue with container escape indicators.\nAll inputs from incident fields + K8sEscape.* context.',
        outputs: 'Task #2: K8sSimilar.* (queries, search criteria)\nTasks #3-#5: XQL hunt results (webshell, escape, IMDS)\nTask #6: Analyst review decision\n\n8 tasks total',
    },
};

function showCortexDetail(key) {
    const data = CORTEX_DETAILS[key];
    if (!data) return;

    document.getElementById('cortex-detail-badge').textContent = data.type;
    document.getElementById('cortex-detail-title').textContent = data.title;
    document.getElementById('cortex-detail-desc').textContent = data.desc;
    document.getElementById('cortex-detail-inputs').textContent = data.inputs;
    document.getElementById('cortex-detail-outputs').textContent = data.outputs;

    // Build "used by" section
    const usedByEl = document.getElementById('cortex-detail-usedby');
    usedByEl.innerHTML = '';
    for (const u of data.usedBy) {
        const div = document.createElement('div');
        div.className = 'modal-detail-usedby-item';
        div.innerHTML = `<span class="modal-detail-usedby-badge">${u.type}</span> <strong>${u.name}</strong> <span style="color:#64748b;">&mdash; ${u.task}</span>`;
        usedByEl.appendChild(div);
    }

    document.getElementById('cortex-detail-modal').classList.add('visible');
}

function closeCortexDetail() {
    document.getElementById('cortex-detail-modal').classList.remove('visible');
}

async function cortexDeployScript(scriptName) {
    openTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  DEPLOY SCRIPT: ${scriptName}\n${line}\n\n`);

    const statusId = SCRIPT_STATUS_MAP[scriptName];
    if (statusId) setItemStatus(statusId, 'deploying...', '#f97316');

    try {
        const res = await fetch('/api/cortex/deploy-script', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ script_name: scriptName })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            playbookWrite(`\u2705 ${scriptName} deployed\n`);
            if (data.api_path) playbookWrite(`API: ${data.api_path}\n`);
            if (statusId) setItemStatus(statusId, '\u2705', '#22c55e');
        } else {
            playbookWrite(`\u274C ${scriptName}: ${data.message}\n`);
            if (statusId) setItemStatus(statusId, '\u274C', '#ef4444');
        }
    } catch (e) {
        playbookWrite(`\u274C ${scriptName}: ${e.message}\n`);
        if (statusId) setItemStatus(statusId, '\u274C', '#ef4444');
    }
}

async function cortexDeployPlaybook(playbookName) {
    openTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  DEPLOY PLAYBOOK: ${playbookName}\n${line}\n\n`);

    const statusId = PLAYBOOK_STATUS_MAP[playbookName];
    if (statusId) setItemStatus(statusId, 'deploying...', '#f97316');

    try {
        const res = await fetch('/api/cortex/publish-playbook', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ playbook_name: playbookName })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            playbookWrite(`\u2705 Playbook '${playbookName}' published\n`);
            if (data.api_path) playbookWrite(`API: ${data.api_path}\n`);
            if (statusId) setItemStatus(statusId, '\u2705', '#22c55e');
        } else {
            playbookWrite(`\u274C Playbook '${playbookName}': ${data.message}\n`);
            if (statusId) setItemStatus(statusId, '\u274C', '#ef4444');
        }
    } catch (e) {
        playbookWrite(`\u274C Playbook '${playbookName}': ${e.message}\n`);
        if (statusId) setItemStatus(statusId, '\u274C', '#ef4444');
    }
}

async function cortexDeployAll() {
    openTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  DEPLOY ALL CORTEX OBJECTS\n${line}\n\n`);
    playbookWrite('Deploying scripts + playbooks to Cortex...\n\n');

    const badge = document.getElementById('cortex-deploy-status');
    if (badge) { badge.textContent = 'deploying...'; badge.style.color = '#f97316'; }

    // Set all items to deploying
    for (const id of Object.values(SCRIPT_STATUS_MAP)) setItemStatus(id, 'deploying...', '#f97316');
    for (const id of Object.values(PLAYBOOK_STATUS_MAP)) setItemStatus(id, 'pending...', '#94a3b8');

    try {
        const res = await fetch('/api/cortex/deploy-all', { method: 'POST' });
        const data = await res.json();

        for (const r of (data.results || [])) {
            const icon = r.status === 'ok' ? '\u2705' : '\u274C';
            playbookWrite(`${icon} ${r.type.toUpperCase()}: ${r.name} - ${r.status}\n`);
            if (r.api_path) playbookWrite(`   API: ${r.api_path}\n`);
            if (r.message) playbookWrite(`   Error: ${r.message}\n`);
            playbookWrite('\n');

            // Update per-item status badges
            const statusColor = r.status === 'ok' ? '#22c55e' : '#ef4444';
            const statusText = r.status === 'ok' ? '\u2705' : '\u274C';
            if (r.type === 'script') {
                const id = SCRIPT_STATUS_MAP[r.name];
                if (id) setItemStatus(id, statusText, statusColor);
            }
            if (r.type === 'playbook') {
                // Map full playbook names from backend to short keys
                const pbKey = r.name.includes('Containment') ? 'containment'
                    : r.name.includes('Forensic') ? 'forensic'
                    : r.name.includes('Search') ? 'search' : null;
                const id = pbKey ? PLAYBOOK_STATUS_MAP[pbKey] : null;
                if (id) setItemStatus(id, statusText, statusColor);
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

// ─── Cortex Policy Import ───────────────────────────────────────────────

async function cortexPolicyCheck() {
    openTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  CHECK CORTEX POLICY OBJECTS\n${line}\n\n`);

    const badge = document.getElementById('cortex-policy-status');
    if (badge) { badge.textContent = 'checking...'; badge.style.color = '#f97316'; }

    try {
        const res = await fetch('/api/cortex/policy-check');
        const data = await res.json();

        if (data.status === 'ok') {
            const panel = document.getElementById('cortex-policy-panel');
            if (panel) panel.style.display = 'block';

            let allExist = true;
            for (const r of data.results) {
                const icon = r.exists === true ? '\u2705' : r.exists === false ? '\u274C' : '\u2753';
                playbookWrite(`${icon} ${r.type}: ${r.name}\n`);
                playbookWrite(`   ${r.detail || ''}\n\n`);

                if (r.exists !== true) allExist = false;

                // Update info panel
                if (r.type === 'Endpoint Group') {
                    const el = document.getElementById('cortex-policy-group');
                    if (el) { el.textContent = r.exists ? 'exists' : 'missing'; el.style.color = r.exists ? '#22c55e' : '#ef4444'; }
                }
                if (r.type === 'Prevention Policy') {
                    const el = document.getElementById('cortex-policy-name');
                    if (el) { el.textContent = r.exists ? 'assigned' : 'not found'; el.style.color = r.exists ? '#22c55e' : r.exists === false ? '#ef4444' : '#94a3b8'; }
                }
                if (r.type === 'Local: Policy Rules') {
                    const el = document.getElementById('cortex-policy-rules');
                    if (el) { el.textContent = r.exists ? 'ready' : 'missing'; el.style.color = r.exists ? '#22c55e' : '#ef4444'; }
                }
                if (r.type === 'Local: Profiles') {
                    const el = document.getElementById('cortex-policy-profiles');
                    if (el) { el.textContent = r.exists ? 'ready' : 'missing'; el.style.color = r.exists ? '#22c55e' : '#ef4444'; }
                }
            }

            playbookWrite(`${'─'.repeat(50)}\n`);
            if (badge) {
                badge.textContent = allExist ? 'exists' : 'missing';
                badge.style.color = allExist ? '#22c55e' : '#f97316';
            }
        } else {
            playbookWrite(`ERROR: ${data.message}\n`);
            if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; }
        }
    } catch (e) {
        playbookWrite(`Request failed: ${e.message}\n`);
        if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; }
    }
}

async function cortexPolicyImport() {
    openTab('playbook');
    playbookClear();
    const line = '='.repeat(50);
    playbookWrite(`${line}\n  IMPORT CORTEX POLICY OBJECTS\n${line}\n\n`);
    playbookWrite('Uploading policy rules & profiles to Cortex...\n\n');

    const badge = document.getElementById('cortex-policy-status');
    if (badge) { badge.textContent = 'importing...'; badge.style.color = '#f97316'; }

    try {
        const res = await fetch('/api/cortex/policy-import', { method: 'POST' });
        const data = await res.json();

        for (const r of (data.results || [])) {
            const icon = r.status === 'ok' ? '\u2705' : '\u274C';
            playbookWrite(`${icon} ${r.type}: ${r.status}\n`);
            if (r.message) playbookWrite(`   ${r.message}\n`);
            if (r.http_code) playbookWrite(`   HTTP ${r.http_code}\n`);
            if (r.response) playbookWrite(`   Response: ${r.response.substring(0, 200)}\n`);
            playbookWrite('\n');
        }

        playbookWrite(`${'─'.repeat(50)}\n`);
        if (data.status === 'ok') {
            playbookWrite('All policy objects imported successfully.\n');
            if (badge) { badge.textContent = 'imported'; badge.style.color = '#22c55e'; }
        } else if (data.status === 'partial') {
            playbookWrite('Some imports failed. Check details above.\n');
            playbookWrite('You may need to import manually via the Cortex console:\n');
            playbookWrite('  Settings > Policy Management > Import\n');
            if (badge) { badge.textContent = 'partial'; badge.style.color = '#f97316'; }
        } else {
            playbookWrite(`Import failed. Import manually via Cortex console:\n`);
            playbookWrite('  Settings > Policy Management > Import\n');
            playbookWrite('  Files: cortex-policy/*.export\n');
            if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; }
        }
    } catch (e) {
        playbookWrite(`Request failed: ${e.message}\n`);
        if (badge) { badge.textContent = 'error'; badge.style.color = '#ef4444'; }
    }
}

// ─── XDR Agent for Kubernetes ─────────────────────────────────────────────

async function xdrDeployK8s() {
    openTab('playbook');
    const distBadge = document.getElementById('xdr-dist-status');
    const deployBadge = document.getElementById('xdr-deploy-status');
    const infoPanel = document.getElementById('xdr-info-panel');
    if (distBadge) { distBadge.textContent = 'building...'; distBadge.style.color = '#f97316'; }

    playbookWrite('\n' + '─'.repeat(50) + '\n');
    playbookWrite('XDR Agent for Kubernetes - Creating distribution...\n');

    try {
        const resp = await fetch('/api/cortex/xdr-k8s-deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await resp.json();

        if (data.status === 'ok' || data.status === 'exists') {
            const isNew = data.status === 'ok';
            const distStatus = data.distribution_status || (isNew ? 'created' : 'exists');
            const tagsStr = (data.tags && data.tags.length) ? data.tags.join(', ') : '-';

            playbookWrite(isNew
                ? `[OK] Distribution created: ${data.distribution_id}\n`
                : `[OK] ${data.message}\n`);
            playbookWrite(`  Agent version: ${data.agent_version || 'auto'}\n`);
            playbookWrite(`  Cluster: ${data.cluster_name || '-'}\n`);
            playbookWrite(`  Tags: ${tagsStr}\n`);

            if (distBadge) {
                distBadge.textContent = distStatus === 'completed' ? 'built' : distStatus;
                distBadge.style.color = distStatus === 'completed' ? '#22c55e' : '#f97316';
            }
            if (infoPanel) {
                infoPanel.style.display = 'block';
                document.getElementById('xdr-info-dist-id').textContent = data.distribution_id || '-';
                document.getElementById('xdr-info-version').textContent = data.agent_version || 'auto';
                document.getElementById('xdr-info-cluster').textContent = data.cluster_name || '-';
                document.getElementById('xdr-info-status').textContent = distStatus;
                document.getElementById('xdr-info-tags').textContent = tagsStr;
            }
            // Check agent install status on cluster
            xdrCheckAgentInstall();
            if (isNew) setTimeout(() => xdrCheckStatus(), 5000);
        } else {
            playbookWrite(`[FAIL] ${data.message}\n`);
            if (distBadge) { distBadge.textContent = 'error'; distBadge.style.color = '#ef4444'; }
        }
    } catch (e) {
        playbookWrite(`[FAIL] Request failed: ${e.message}\n`);
        if (distBadge) { distBadge.textContent = 'error'; distBadge.style.color = '#ef4444'; }
    }
}

async function xdrCheckStatus() {
    const distBadge = document.getElementById('xdr-dist-status');
    const statusEl = document.getElementById('xdr-info-status');

    try {
        const distIdEl = document.getElementById('xdr-info-dist-id');
        const distId = distIdEl ? distIdEl.textContent.trim() : '';
        const statusUrl = distId && distId !== '-'
            ? `/api/cortex/xdr-k8s-status?distribution_id=${encodeURIComponent(distId)}`
            : '/api/cortex/xdr-k8s-status';
        const resp = await fetch(statusUrl);
        const data = await resp.json();

        if (data.status === 'ok') {
            const distStatus = data.distribution_status || 'unknown';
            playbookWrite(`XDR Distribution status: ${distStatus}\n`);
            if (statusEl) statusEl.textContent = distStatus;
            if (distBadge) {
                const isCompleted = distStatus.toLowerCase() === 'completed';
                distBadge.textContent = isCompleted ? 'built' : distStatus;
                distBadge.style.color = isCompleted ? '#22c55e' : '#f97316';
            }
            // Re-check if still pending
            if (distStatus.toLowerCase() !== 'completed' && distStatus.toLowerCase() !== 'failed') {
                setTimeout(() => xdrCheckStatus(), 5000);
            } else {
                // Distribution ready, check agent install status
                xdrCheckAgentInstall();
            }
        } else {
            playbookWrite(`XDR Status check: ${data.message}\n`);
        }
    } catch (e) {
        playbookWrite(`XDR Status check failed: ${e.message}\n`);
    }
}

async function xdrCheckAgentInstall() {
    const el = document.getElementById('xdr-info-install-status');
    const deployBadge = document.getElementById('xdr-deploy-status');
    if (!el) return;
    try {
        const resp = await fetch('/api/cortex/xdr-k8s-agent-status');
        const data = await resp.json();
        if (data.status === 'ok') {
            if (data.installed) {
                el.textContent = `${data.agent_status} (${data.pods_running}/${data.pods_total} pods)`;
                el.style.color = data.agent_status === 'Running' ? '#22c55e' : '#f97316';
                if (deployBadge) {
                    deployBadge.textContent = data.agent_status === 'Running' ? 'deployed' : 'deploying';
                    deployBadge.style.color = data.agent_status === 'Running' ? '#22c55e' : '#f97316';
                }
            } else {
                el.textContent = 'Not installed';
                el.style.color = '#94a3b8';
            }
        } else {
            el.textContent = data.message || 'Unknown';
            el.style.color = '#94a3b8';
        }
    } catch (e) {
        el.textContent = 'Check failed';
        el.style.color = '#ef4444';
    }
}

async function xdrInstallK8s() {
    const deployBadge = document.getElementById('xdr-deploy-status');
    if (deployBadge) { deployBadge.textContent = 'deploying...'; deployBadge.style.color = '#f97316'; }

    openTab('terminal');
    termWrite('\n' + '─'.repeat(50) + '\n');
    termWrite('XDR Agent - Downloading YAML and deploying to cluster...\n');

    // Try DOM first, then let backend use its in-memory store
    const distIdEl = document.getElementById('xdr-info-dist-id');
    const distId = (distIdEl && distIdEl.textContent.trim() !== '-') ? distIdEl.textContent.trim() : '';
    if (distId) {
        termWrite(`Distribution ID: ${distId}\n`);
    } else {
        termWrite('Distribution ID: (from server memory)\n');
    }

    try {
        const payload = distId ? { distribution_id: distId } : {};
        const resp = await fetch('/api/cortex/xdr-k8s-install', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        termWrite(`Server response: ${JSON.stringify(data)}\n`);

        if (data.status === 'ok' && data.task_id) {
            state.currentTaskId = data.task_id;
            startPolling(data.task_id);
            if (deployBadge) { deployBadge.textContent = 'deploying'; deployBadge.style.color = '#f97316'; }
            // Check agent status after install completes (~30s)
            setTimeout(() => {
                xdrCheckAgentInstall();
                if (deployBadge) { deployBadge.textContent = 'deployed'; deployBadge.style.color = '#22c55e'; }
            }, 30000);
        } else {
            termWrite(`[FAIL] ${data.message || 'Unknown error'}\n`);
            if (deployBadge) { deployBadge.textContent = 'error'; deployBadge.style.color = '#ef4444'; }
        }
    } catch (e) {
        termWrite(`[FAIL] Request failed: ${e.message}\n`);
        if (deployBadge) { deployBadge.textContent = 'error'; deployBadge.style.color = '#ef4444'; }
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

// ─── Infrastructure ───────────────────────────────────────────────────────────

function infraPlan() {
    openTab('terminal');
    termWriteHeader('Terraform Plan');
    apiCall('/api/infra/plan');
}

function infraApply() {
    openTab('terminal');
    termWriteHeader('Terraform Apply (EKS + ECR)');
    termWrite('This will provision the full infrastructure...\n\n');
    apiCall('/api/infra/apply');
}

function infraDestroy() {
    document.getElementById('destroy-modal').classList.add('visible');
}

function confirmDestroy() {
    document.getElementById('destroy-modal').classList.remove('visible');
    openTab('terminal');
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
    openTab('terminal');
    termWriteHeader('Build & Push Vulnerable Image to ECR');
    apiCall('/api/image/build-push');
}

function deployApp() {
    openTab('terminal');
    termWriteHeader('Deploy Vulnerable App to EKS');
    apiCall('/api/k8s/deploy');
}

function undeployApp() {
    openTab('terminal');
    termWriteHeader('Undeploy Vulnerable App from EKS');
    apiCall('/api/k8s/undeploy');
}

async function k8sStatus() {
    openTab('terminal');
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
    openTab('terminal');
    termWriteHeader('STEP 1: Spring4Shell RCE (CVE-2022-22965)');
    apiCall('/api/attack/step1');
}

function attackStep2() {
    openTab('terminal');
    termWriteHeader('STEP 2: Container Escape');
    apiCall('/api/attack/step2');
}

function attackStep3() {
    openTab('terminal');
    termWriteHeader('STEP 3: Cluster Takeover');
    apiCall('/api/attack/step3');
}

function attackStep4() {
    openTab('terminal');
    termWriteHeader('STEP 4: K8s Vulnerability Scanning');
    apiCall('/api/attack/step4');
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
    openTab('terminal');
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
    openTab('radar');
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
    openTab('radar');
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

// ─── Theme Toggle ────────────────────────────────────────────────────────────

const THEMES = ['dark', 'light', 'auto'];
const THEME_ICONS = { dark: '\u263E', light: '\u2600', auto: '\u25D1' };
const THEME_TITLES = { dark: 'Dark mode', light: 'Light mode', auto: 'Auto (system)' };

function getStoredTheme() {
    return localStorage.getItem('theme') || 'dark';
}

function getEffectiveTheme(theme) {
    if (theme === 'auto') {
        return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    return theme;
}

function applyTheme(theme) {
    const effective = getEffectiveTheme(theme);
    document.documentElement.setAttribute('data-theme', effective);
    const icon = document.getElementById('theme-icon');
    const btn = document.getElementById('theme-toggle');
    if (icon) icon.textContent = THEME_ICONS[theme];
    if (btn) btn.title = THEME_TITLES[theme];
}

function cycleTheme() {
    const current = getStoredTheme();
    const next = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length];
    localStorage.setItem('theme', next);
    applyTheme(next);
}

// Listen for system theme changes when in auto mode
window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
    if (getStoredTheme() === 'auto') applyTheme('auto');
});

// ─── Init ────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Apply saved theme
    applyTheme(getStoredTheme());
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
  Target: AWS EKS | AL2023 | GP3 volumes
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

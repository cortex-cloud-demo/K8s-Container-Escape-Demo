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
    { id: 'malware',  el: 'hc-malware',  attack: true },
    { id: 'lateral',  el: 'hc-lateral',  attack: true },
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

            // Update step status on EVERY poll — this triggers diagram animations
            // when status is 'running', not just on completion
            if (task.status === 'running' || task.status === 'starting') {
                updateStepStatus(task.name, 'running');
            }

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
        'Step 5: Deploy Malware': 'malware',
        'Step 6: Lateral Movement': 'lateral',
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
        'Step 5: Deploy Malware':             { id: 'malware-status',  ok: 'deployed',  run: 'deploying...' },
        'Step 6: Lateral Movement':           { id: 'lateral-status',  ok: 'moved',     run: 'moving...' },
        'Undeploy from EKS':        { id: 'deploy-status',         ok: 'undeployed',  run: 'removing...' },
        'Cortex CLI: Image Scan':   { id: 'image-scan-status',     ok: 'scanned',     run: 'scanning...' },
        'Cortex CLI: AppSec Scan':  { id: 'iac-scan-status',       ok: 'scanned',     run: 'scanning...' },
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

    // Update architecture diagram
    updateArchDiagram();
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
            refreshAwsRegionLabel();
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

async function xdrAgentStatus() {
    openTab('terminal');
    termWriteHeader('Cortex Cloud Security Agent - Cluster Status');
    apiCall('/api/cortex/xdr-k8s-agent-pods', 'POST');
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
            if (deployBadge) { deployBadge.textContent = 'deploying...'; deployBadge.style.color = '#f97316'; }
            // Poll agent status until pods are running
            let agentPollCount = 0;
            const agentPoll = setInterval(async () => {
                agentPollCount++;
                try {
                    const statusResp = await fetch('/api/cortex/xdr-k8s-agent-status');
                    const statusData = await statusResp.json();
                    if (statusData.status === 'ok' && statusData.installed) {
                        if (statusData.agent_status === 'Running') {
                            clearInterval(agentPoll);
                            if (deployBadge) { deployBadge.textContent = 'deployed'; deployBadge.style.color = '#22c55e'; }
                            xdrCheckAgentInstall();
                        } else if (deployBadge) {
                            deployBadge.textContent = `${statusData.agent_status} (${statusData.pods_running}/${statusData.pods_total})`;
                        }
                    }
                } catch(e) {}
                if (agentPollCount > 20) clearInterval(agentPoll); // Stop after ~2min
            }, 6000);
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
    openTab('overview');
    termWriteHeader('STEP 1: Spring4Shell RCE (CVE-2022-22965)');
    apiCall('/api/attack/step1');
}

function attackStep2() {
    openTab('overview');
    termWriteHeader('STEP 2: Container Escape');
    apiCall('/api/attack/step2');
}

function attackStep3() {
    openTab('overview');
    termWriteHeader('STEP 3: Cluster Takeover');
    apiCall('/api/attack/step3');
}

function attackStep4() {
    openTab('overview');
    termWriteHeader('STEP 4: K8s Vulnerability Scanning');
    apiCall('/api/attack/step4');
}

function attackStep5() {
    openTab('overview');
    termWriteHeader('STEP 5: Deploy Malware & Offensive Tools');
    apiCall('/api/attack/step5');
}

function attackStep6() {
    openTab('overview');
    termWriteHeader('STEP 6: Lateral Movement');
    apiCall('/api/attack/step6');
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

// ─── Live Architecture Diagram ───────────────────────────────────────────────

// ─── Narration Mode ──────────────────────────────────────────────────────────

const NARRATION = {
    rce: {
        attacker: "Exploiting Spring4Shell CVE-2022-22965...\nDeploying JSP webshell via ClassLoader manipulation",
        defender: "Local Threat Detected!\nMalicious JSP file written to Tomcat webapps",
    },
    escape: {
        attacker: "Escaping container via nsenter + mount...\nReading /etc/shadow, kubelet creds, IMDS",
        defender: "Container Escape Protection triggered!\nPrivileged mount operation detected",
    },
    takeover: {
        attacker: "Stealing cluster-admin SA token...\nFull access: all namespaces, pods, secrets",
        defender: "kubectl execution in pod detected!\nSA token abuse — T1134 Access Token",
    },
    scan: {
        attacker: "Running K8s recon tools...\ndeepce, kube-hunter, RBAC enumeration",
        defender: "K8s vulnerability scanning detected!\nContainer image drift — tools installed",
    },
    malware: {
        attacker: "Deploying malware: reverse shell,\ncryptominer, WildFire ELF sample",
        defender: "Malware detected! Reverse shell blocked.\nCredential harvesting attempt caught",
    },
    lateral: {
        attacker: "SSH scanning, deploying rogue pod\nin kube-system, stealing IMDS creds",
        defender: "14+ issues correlated.\nFull MITRE ATT&CK kill chain mapped",
    },
};

function updateNarration(stepId, isActive) {
    const attackerBubble = document.getElementById('narration-attacker');
    const defenderBubble = document.getElementById('narration-defender');
    const attackerText = document.getElementById('narration-attacker-text');
    const defenderText = document.getElementById('narration-defender-text');

    if (!attackerBubble || !defenderBubble) return;

    if (isActive && NARRATION[stepId]) {
        const n = NARRATION[stepId];
        attackerBubble.style.display = '';
        defenderBubble.style.display = '';
        if (attackerText) {
            // Split multiline and render
            const lines = n.attacker.split('\n');
            attackerText.innerHTML = '';
            lines.forEach((line, i) => {
                const tspan = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
                tspan.setAttribute('x', '90');
                tspan.setAttribute('dy', i === 0 ? '0' : '13');
                tspan.textContent = line;
                attackerText.appendChild(tspan);
            });
        }
        if (defenderText) {
            const lines = n.defender.split('\n');
            defenderText.innerHTML = '';
            lines.forEach((line, i) => {
                const tspan = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
                tspan.setAttribute('x', '870');
                tspan.setAttribute('dy', i === 0 ? '0' : '13');
                tspan.textContent = line;
                defenderText.appendChild(tspan);
            });
        }
    } else {
        attackerBubble.style.display = 'none';
        defenderBubble.style.display = 'none';
    }
}

const ARCH_STEP_MAP = {
    rce: {
        label: 'Step 1: Spring4Shell RCE (CVE-2022-22965)',
        conns: { 'conn-atk-inet': 'attack', 'conn-inet-lb': 'attack', 'conn-lb-pod': 'attack' },
        nodes: { 'arch-attacker': 'attack', 'arch-internet': 'attack', 'arch-lb': 'attack', 'arch-pod': 'attack' },
        detect: { 'conn-pod-agent': 'detect', 'conn-agent-cortex': 'detect' },
        detectNodes: { 'arch-agent': 'detect', 'arch-cortex': 'detect' },
    },
    escape: {
        label: 'Step 2: Container Escape (nsenter, mount, chroot)',
        conns: { 'conn-atk-inet': 'attack', 'conn-inet-lb': 'attack', 'conn-lb-pod': 'attack', 'conn-pod-node': 'attack', 'conn-node-imds': 'attack' },
        nodes: { 'arch-attacker': 'attack', 'arch-internet': 'attack', 'arch-lb': 'attack', 'arch-pod': 'attack', 'arch-node': 'attack', 'arch-imds': 'attack' },
        detect: { 'conn-pod-agent': 'detect', 'conn-agent-cortex': 'detect' },
        detectNodes: { 'arch-agent': 'detect', 'arch-cortex': 'detect' },
    },
    takeover: {
        label: 'Step 3: Cluster Takeover (SA token cluster-admin)',
        conns: { 'conn-atk-inet': 'attack', 'conn-inet-lb': 'attack', 'conn-lb-pod': 'attack', 'conn-pod-node': 'attack', 'conn-node-api': 'attack' },
        nodes: { 'arch-attacker': 'attack', 'arch-internet': 'attack', 'arch-lb': 'attack', 'arch-pod': 'attack', 'arch-node': 'attack', 'arch-api': 'attack' },
        detect: { 'conn-pod-agent': 'detect', 'conn-agent-cortex': 'detect' },
        detectNodes: { 'arch-agent': 'detect', 'arch-cortex': 'detect' },
    },
    scan: {
        label: 'Step 4: K8s Vulnerability Scanning (T1610/T1613)',
        conns: { 'conn-atk-inet': 'attack', 'conn-inet-lb': 'attack', 'conn-lb-pod': 'attack', 'conn-pod-node': 'attack', 'conn-node-api': 'attack' },
        nodes: { 'arch-attacker': 'attack', 'arch-internet': 'attack', 'arch-lb': 'attack', 'arch-pod': 'attack', 'arch-node': 'attack', 'arch-api': 'attack' },
        detect: { 'conn-pod-agent': 'detect', 'conn-agent-cortex': 'detect' },
        detectNodes: { 'arch-agent': 'detect', 'arch-cortex': 'detect' },
    },
    malware: {
        label: 'Step 5: Deploy Malware (WildFire, deepce, reverse shell)',
        conns: { 'conn-atk-inet': 'attack', 'conn-inet-lb': 'attack', 'conn-lb-pod': 'attack' },
        nodes: { 'arch-attacker': 'attack', 'arch-internet': 'attack', 'arch-lb': 'attack', 'arch-pod': 'attack' },
        detect: { 'conn-pod-agent': 'detect', 'conn-agent-cortex': 'detect' },
        detectNodes: { 'arch-agent': 'detect', 'arch-cortex': 'detect' },
    },
    lateral: {
        label: 'Step 6: Lateral Movement (SSH, rogue pod, IMDS, cross-NS)',
        conns: { 'conn-atk-inet': 'attack', 'conn-inet-lb': 'attack', 'conn-lb-pod': 'attack', 'conn-pod-node': 'attack', 'conn-node-api': 'attack', 'conn-node-imds': 'attack' },
        nodes: { 'arch-attacker': 'attack', 'arch-internet': 'attack', 'arch-lb': 'attack', 'arch-pod': 'attack', 'arch-node': 'attack', 'arch-api': 'attack', 'arch-imds': 'attack' },
        detect: { 'conn-pod-agent': 'detect', 'conn-agent-cortex': 'detect' },
        detectNodes: { 'arch-agent': 'detect', 'arch-cortex': 'detect' },
    },
};

function updateArchDiagram() {
    // Reset all visual states
    document.querySelectorAll('.arch-conn').forEach(c => {
        c.classList.remove('active-attack', 'active-detect', 'active-response', 'done-attack', 'done-detect', 'done-response');
    });
    document.querySelectorAll('.arch-node').forEach(n => {
        n.classList.remove('highlight-attack', 'highlight-detect', 'highlight-response', 'node-active-pulse');
    });

    const stepBanner = document.getElementById('arch-step-banner');
    const stepLabel = document.getElementById('arch-step-label');
    const statusEl = document.getElementById('arch-status');
    const playbookTasks = document.getElementById('arch-playbook-tasks');
    const cortexAlert = document.getElementById('arch-cortex-alert');
    const cortexPlaybook = document.getElementById('arch-cortex-playbook');

    if (stepBanner) stepBanner.style.display = 'none';
    if (playbookTasks) playbookTasks.style.display = 'none';
    if (cortexAlert) cortexAlert.style.display = 'none';
    if (cortexPlaybook) cortexPlaybook.style.display = 'none';

    let activeStep = null;
    let activeStepId = null;
    let anyActive = false;
    let completedCount = 0;

    // Apply states for each step
    for (const [stepId, mapping] of Object.entries(ARCH_STEP_MAP)) {
        const status = state.stepStatuses[stepId];
        if (!status) continue;

        const isActive = status === 'running';
        const isDone = status === 'success';

        if (isActive) { activeStep = mapping; activeStepId = stepId; anyActive = true; }
        if (isDone) completedCount++;

        if (isDone || isActive) {
            // Attack connections — thick glowing lines when active
            for (const [connId, type] of Object.entries(mapping.conns)) {
                const el = document.getElementById(connId);
                if (el) el.classList.add(isActive ? `active-${type}` : `done-${type}`);
            }
            // Attack nodes — strong pulsing glow when active
            for (const [nodeId, type] of Object.entries(mapping.nodes)) {
                const el = document.getElementById(nodeId);
                if (el) {
                    if (isActive) {
                        el.classList.add(`highlight-${type}`, 'node-active-pulse');
                    }
                }
            }
            // Detection connections
            for (const [connId, type] of Object.entries(mapping.detect)) {
                const el = document.getElementById(connId);
                if (el) el.classList.add(isDone ? `done-${type}` : `active-${type}`);
            }
            // Detection nodes
            for (const [nodeId, type] of Object.entries(mapping.detectNodes || {})) {
                const el = document.getElementById(nodeId);
                if (el && isActive) el.classList.add(`highlight-${type}`, 'node-active-pulse');
            }
        }
    }

    // Show active step banner with prominent styling
    if (activeStep && stepBanner && stepLabel) {
        stepLabel.textContent = activeStep.label;
        stepBanner.style.display = '';
    }

    // Update narration bubbles
    updateNarration(activeStepId, anyActive);

    // Update status indicator
    if (statusEl) {
        statusEl.classList.remove('status-attack', 'status-detect', 'status-idle');
        if (anyActive) {
            statusEl.textContent = activeStep ? activeStep.label : 'Running...';
            statusEl.classList.add('status-attack');
        } else if (completedCount > 0) {
            statusEl.textContent = `${completedCount}/6 steps completed`;
            statusEl.classList.add('status-detect');
        } else {
            statusEl.textContent = 'Idle';
            statusEl.classList.add('status-idle');
        }
    }

    // Animate particles along ALL active attack paths
    const ctaBanner = document.getElementById('arch-cta-banner');
    if (ctaBanner) ctaBanner.style.display = 'none';

    // Stop all previous particle animations
    stopAllParticles();

    if (anyActive && activeStep) {
        // Create particles for each active attack connection
        const attackConns = Object.entries(activeStep.conns).filter(([,t]) => t === 'attack');
        attackConns.forEach(([connId], idx) => {
            const pathEl = document.getElementById(connId);
            if (pathEl) {
                const p = getOrCreateParticle('attack-' + idx, 5, '#ef4444');
                animateParticleAlongPath(p, pathEl, 0.006 + idx * 0.002);
            }
        });

        // Create particles for detection connections
        const detectConns = Object.entries(activeStep.detect).filter(([,t]) => t === 'detect');
        detectConns.forEach(([connId], idx) => {
            const pathEl = document.getElementById(connId);
            if (pathEl) {
                const p = getOrCreateParticle('detect-' + idx, 4, '#22c55e');
                animateParticleAlongPath(p, pathEl, 0.005);
            }
        });
    }

    // Show detection activity on Cortex when steps complete
    if (completedCount >= 1 && cortexAlert) {
        cortexAlert.textContent = 'Analyzing threats...';
        cortexAlert.style.display = '';
        cortexAlert.style.fill = '#f97316';
    }

    // Show playbook tasks panel and CTA when all attack steps done
    if (completedCount >= 6 && playbookTasks) {
        playbookTasks.style.display = '';
        // Activate response connections
        const connCL = document.getElementById('conn-cortex-lambda');
        const connLA = document.getElementById('conn-lambda-api');
        if (connCL) connCL.classList.add('active-response');
        if (connLA) connLA.classList.add('active-response');
        // Highlight response nodes
        const lambda = document.getElementById('arch-lambda');
        if (lambda) lambda.classList.add('highlight-response', 'node-active-pulse');
        const cortex = document.getElementById('arch-cortex');
        if (cortex) cortex.classList.add('highlight-response', 'node-active-pulse');

        if (cortexAlert) {
            cortexAlert.textContent = 'Cortex Analyses - Incident detected';
            cortexAlert.style.fill = '#ef4444';
        }
        if (cortexPlaybook) {
            cortexPlaybook.textContent = 'Playbook ready';
            cortexPlaybook.style.display = '';
            cortexPlaybook.style.fill = '#22c55e';
        }
        // Show blinking CTA
        if (ctaBanner) ctaBanner.style.display = '';

        // Animate response particles (Cortex → Lambda → API)
        const connCLpath = document.getElementById('conn-cortex-lambda');
        const connLApath = document.getElementById('conn-lambda-api');
        if (connCLpath) {
            const p = getOrCreateParticle('response-0', 5, '#22c55e');
            animateParticleAlongPath(p, connCLpath, 0.006);
        }
        if (connLApath) {
            const p = getOrCreateParticle('response-1', 5, '#22c55e');
            animateParticleAlongPath(p, connLApath, 0.006);
        }
    }
}

// ─── SVG Particle Animation Engine ──────────────────────────────────────────

let particleAnimations = {};
let particleElements = {};

function getOrCreateParticle(id, radius, color) {
    if (particleElements[id]) {
        particleElements[id].style.display = '';
        return particleElements[id];
    }
    const svg = document.querySelector('.arch-svg');
    if (!svg) return null;
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.id = 'dyn-particle-' + id;
    circle.setAttribute('r', radius);
    circle.style.fill = color;
    circle.style.filter = `drop-shadow(0 0 8px ${color})`;
    svg.appendChild(circle);
    particleElements[id] = circle;
    return circle;
}

function stopAllParticles() {
    for (const [id, animId] of Object.entries(particleAnimations)) {
        cancelAnimationFrame(animId);
    }
    particleAnimations = {};
    for (const [id, el] of Object.entries(particleElements)) {
        if (el) el.style.display = 'none';
    }
}

function animateParticleAlongPath(circle, pathEl, speed) {
    if (!circle || !pathEl) return;
    const id = circle.id;
    if (particleAnimations[id]) cancelAnimationFrame(particleAnimations[id]);

    const totalLength = pathEl.getTotalLength();
    let progress = Math.random(); // random start position

    function step() {
        progress += (speed || 0.006);
        if (progress > 1) progress = 0;
        const point = pathEl.getPointAtLength(progress * totalLength);
        circle.setAttribute('cx', point.x);
        circle.setAttribute('cy', point.y);
        particleAnimations[id] = requestAnimationFrame(step);
    }
    step();
}

// ─── AWS Region Label ────────────────────────────────────────────────────────

function refreshAwsRegionLabel() {
    fetch('/api/credentials').then(r => r.json()).then(data => {
        const region = data.aws_region || '';
        const el = document.getElementById('arch-aws-label');
        if (el) {
            el.textContent = region ? `AWS CLOUD (${region})` : 'AWS CLOUD';
        }
        const el2 = document.getElementById('arch2-aws-label');
        if (el2) {
            el2.textContent = region ? `AWS CLOUD (${region})` : 'AWS CLOUD';
        }
    }).catch(() => {});
}

// ─── Toolbox Status ──────────────────────────────────────────────────────────

async function refreshToolboxStatus() {
    const dot = document.getElementById('toolbox-dot');
    const label = document.getElementById('toolbox-value');
    if (!dot || !label) return;

    try {
        const res = await fetch('/api/toolbox/status');
        const data = await res.json();

        dot.classList.remove('active', 'building', 'error');

        if (data.running) {
            dot.classList.add('active');
            const versions = data.versions || {};
            label.textContent = 'Runner: running';
            label.title = Object.entries(versions).map(([k,v]) => `${k}: ${v}`).join('\n');
        } else if (data.status === 'stopped') {
            label.textContent = 'Runner: stopped';
            label.title = 'Container not running. Tools run locally.';
        } else {
            label.textContent = 'Runner: n/a';
            label.title = 'Docker not available';
        }
    } catch (e) {
        dot.classList.remove('active', 'error');
        dot.classList.add('building');
        label.textContent = 'Runner: building...';
        label.title = 'Building runner toolbox container...';
    }
}

function refreshToolboxVersions() {
    fetch('/api/toolbox/status').then(r => r.json()).then(data => {
        const body = document.getElementById('toolbox-versions-body');
        if (!body) return;

        if (!data.running) {
            body.innerHTML = '<tr><td colspan="2" class="tool-missing">Toolbox not running</td></tr>';
            return;
        }

        const v = data.versions || {};
        const tools = [
            { name: 'OS', value: v.os || '—' },
            { name: 'Platform', value: v.platform || '—' },
            { name: 'Terraform', value: v.terraform || '—' },
            { name: 'kubectl', value: v.kubectl || '—' },
            { name: 'AWS CLI', value: v.aws || '—' },
            { name: 'Helm', value: v.helm || '—' },
            { name: 'Node.js', value: v.node || '—' },
            { name: 'Docker', value: v.docker || '—' },
            { name: 'CortexCLI', value: v.cortexcli || '—' },
        ];

        body.innerHTML = tools.map(t => {
            const cls = (t.value === '—' || t.value.includes('not installed')) ? 'tool-missing' : 'tool-ok';
            return `<tr><td>${t.name}</td><td class="${cls}">${t.value}</td></tr>`;
        }).join('');
    }).catch(() => {
        const body = document.getElementById('toolbox-versions-body');
        if (body) body.innerHTML = '<tr><td colspan="2" class="tool-missing">Cannot reach toolbox</td></tr>';
    });
}

// ─── Cortex CLI Image Scan ────────────────────────────────────────────────────

function cortexImageScan(imageName) {
    openTab('appsec');
    termWriteHeader('Cortex CLI - Container Image Scan (CWP)');
    showNotification('CWP scan started — this may take 2-5 minutes...', 'info');
    // Animate the AppSec diagram
    appsecResetDiagram();
    const conn = document.getElementById('appsec-conn-reg-scan');
    const connRes = document.getElementById('appsec-conn-cwp-results');
    if (conn) conn.classList.add('active-attack');
    if (connRes) connRes.classList.add('active-attack');
    appsecSetStatus('Scanning container image...', 'scanning');
    const body = imageName ? { image: imageName } : {};
    apiCall('/api/cortex/image-scan', 'POST', body);
    startAppsecPolling();
}

// ─── AppSec Diagram State Management ─────────────────────────────────────────

let appsecPollInterval = null;

function appsecResetDiagram() {
    // Reset all connection animations
    ['appsec-conn-git-scan', 'appsec-conn-reg-scan', 'appsec-conn-code-results', 'appsec-conn-cwp-results'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove('active-detect', 'active-attack', 'done-detect', 'done-attack');
    });
    // Hide CTA link and digest info
    const cta = document.getElementById('appsec-cta-link');
    if (cta) cta.style.display = 'none';
    const digest = document.getElementById('appsec-digest-info');
    if (digest) digest.style.display = 'none';
}

function appsecSetStatus(text, mode) {
    const banner = document.getElementById('appsec-status-banner');
    const bannerText = document.getElementById('appsec-status-text');
    if (!banner || !bannerText) return;
    banner.style.display = '';
    bannerText.textContent = text;
    // Style based on mode
    const rect = banner.querySelector('rect');
    if (mode === 'scanning') {
        if (rect) { rect.style.stroke = '#f97316'; rect.style.fill = 'rgba(249,115,22,0.15)'; }
        bannerText.style.fill = '#f97316';
    } else if (mode === 'done') {
        if (rect) { rect.style.stroke = '#22c55e'; rect.style.fill = 'rgba(34,197,94,0.15)'; }
        bannerText.style.fill = '#22c55e';
    } else if (mode === 'error') {
        if (rect) { rect.style.stroke = '#ef4444'; rect.style.fill = 'rgba(239,68,68,0.15)'; }
        bannerText.style.fill = '#ef4444';
    }
}

function startAppsecPolling() {
    if (appsecPollInterval) clearInterval(appsecPollInterval);
    appsecPollInterval = setInterval(() => {
        const taskId = state.currentTaskId;
        if (!taskId) return;
        fetch('/api/tasks/' + taskId).then(r => r.json()).then(task => {
            if (task.status === 'success' || task.status === 'error') {
                clearInterval(appsecPollInterval);
                appsecPollInterval = null;

                // Parse output for results
                const output = task.output || '';

                // Strip ANSI color codes before parsing
                const cleanOutput = output.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');

                // Extract Cortex link (Code Security scan)
                const linkMatch = cleanOutput.match(/(https:\/\/[^\s]+appsec\/scans\/cicd-scans\?scan=[^\s]+)/);
                const cortexLink = linkMatch ? linkMatch[1] : null;

                // Extract image name (CWP scan)
                const imageMatch = cleanOutput.match(/Image name:\s*([^\s]+)/);
                const imageName = imageMatch ? imageMatch[1] : null;

                // Extract image digest sha256 (CWP scan)
                const digestMatch = cleanOutput.match(/manifest digest:\s*(sha256:[a-f0-9]+)/);
                const imageDigest = digestMatch ? digestMatch[1] : null;

                // Extract total findings (CWP scan)
                const totalFindingsMatch = cleanOutput.match(/Total detected findings:\s*(\d+)/);
                const totalFindings = totalFindingsMatch ? parseInt(totalFindingsMatch[1]) : null;

                // Count findings uploaded (Code Security scan)
                const findingsMatch = cleanOutput.match(/(\d+)\s+[Ff]indings?\s+were\s+uploaded/);
                const findings = findingsMatch ? parseInt(findingsMatch[1]) : null;

                // Count files scanned
                const filesMatch = cleanOutput.match(/File\(s\)\s+scanned\s+.*?(\d+)/);
                const filesScanned = filesMatch ? filesMatch[1] : null;

                // Update diagram
                // Switch connections to done state
                ['appsec-conn-git-scan', 'appsec-conn-code-results', 'appsec-conn-reg-scan', 'appsec-conn-cwp-results'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) {
                        if (el.classList.contains('active-detect')) {
                            el.classList.remove('active-detect');
                            el.classList.add('done-detect');
                        }
                        if (el.classList.contains('active-attack')) {
                            el.classList.remove('active-attack');
                            el.classList.add('done-attack');
                        }
                    }
                });

                if (task.status === 'success' || (task.status === 'error' && (totalFindings || imageName))) {
                    let statusText = 'Scan complete';
                    if (imageName) {
                        // Truncate long image name
                        const shortImage = imageName.length > 40 ? '...' + imageName.slice(-35) : imageName;
                        statusText += ' \u2014 ' + shortImage;
                    }
                    if (totalFindings !== null) statusText += ' \u2014 ' + totalFindings + ' finding(s)';
                    if (filesScanned) statusText += ' \u2014 ' + filesScanned + ' files';
                    if (findings !== null) statusText += ' \u2014 ' + findings + ' finding(s)';
                    appsecSetStatus(statusText, totalFindings > 0 ? 'error' : 'done');
                } else if (task.status === 'error') {
                    appsecSetStatus('Scan failed — check Terminal for details', 'error');
                }

                // Show image name copy button (CWP scan)
                if (imageName) {
                    const digestContainer = document.getElementById('appsec-digest-info');
                    if (digestContainer) {
                        digestContainer.style.display = '';
                        const digestText = document.getElementById('appsec-digest-text');
                        if (digestText) digestText.textContent = imageName;
                        digestContainer.onclick = () => {
                            navigator.clipboard.writeText(imageName).then(() => {
                                showNotification('Image name copied: ' + imageName, 'success');
                            }).catch(() => {
                                prompt('Copy image name:', imageName);
                            });
                        };
                    }
                }

                // Show CTA link
                const cta = document.getElementById('appsec-cta-link');
                const ctaText = document.getElementById('appsec-cta-text');
                if (cta) {
                    if (cortexLink) {
                        cta.style.display = '';
                        if (ctaText) ctaText.textContent = '\u2197 Cortex Cloud AppSec \u2014 Analyze in Cortex Cloud';
                        cta.onclick = () => window.open(cortexLink, '_blank');
                    } else if (imageName) {
                        cta.style.display = '';
                        if (ctaText) ctaText.textContent = '\u2197 Cortex Cloud \u2014 View ' + imageName + ' in Container Images';
                        cta.onclick = () => {
                            fetch('/api/cortex/credentials').then(r => r.json()).then(data => {
                                let consoleUrl = (data.base_url || '').replace(/\/+$/, '').replace(/^(https?:\/\/)api-/, '$1');
                                window.open(consoleUrl + '/assets/inventory/compute/container-images', '_blank');
                            });
                        };
                    }
                }
            }
        }).catch(() => {});
    }, 2000);
}

function showNotification(message, type) {
    // Remove existing notification
    const existing = document.getElementById('toast-notification');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'toast-notification';
    toast.className = 'toast-notification toast-' + (type || 'info');
    toast.innerHTML = '<span class="toast-icon">' + (type === 'info' ? '&#9432;' : type === 'success' ? '&#10003;' : '&#9888;') + '</span> ' + message;
    document.body.appendChild(toast);

    // Auto-remove after 10s
    setTimeout(() => { toast.classList.add('toast-fade'); setTimeout(() => toast.remove(), 500); }, 10000);
}

function cortexIacScan(target) {
    openTab('appsec');
    termWriteHeader('Cortex CLI - AppSec Scan (Code Security)');
    showNotification('AppSec scan started — analyzing code...', 'info');
    // Animate the AppSec diagram
    appsecResetDiagram();
    const conn = document.getElementById('appsec-conn-git-scan');
    const connRes = document.getElementById('appsec-conn-code-results');
    if (conn) conn.classList.add('active-detect');
    if (connRes) connRes.classList.add('active-detect');
    appsecSetStatus('Scanning code: ' + (target || 'all') + '...', 'scanning');
    apiCall('/api/cortex/iac-scan', 'POST', { target: target || 'all' });
    // Start polling for scan results
    startAppsecPolling();
}

function cortexImageScanCustom() {
    document.getElementById('cwp-custom-modal').classList.add('visible');
}

function closeCwpCustomModal() {
    document.getElementById('cwp-custom-modal').classList.remove('visible');
}

function submitCwpCustomScan() {
    const imageName = document.getElementById('cwp-custom-image').value.trim();
    if (imageName) {
        closeCwpCustomModal();
        openTab('terminal');
        termWriteHeader('Cortex CLI - Custom Image Scan (CWP): ' + imageName);
        showNotification('CWP scan started — ' + imageName, 'info');
        apiCall('/api/cortex/image-scan', 'POST', { image: imageName });
    }
}

// ─── Diagram Links ───────────────────────────────────────────────────────────

function openCortexConsole() {
    // Derive console URL from API URL
    // API: https://api-<tenant>.xdr.<region>.paloaltonetworks.com
    // Console: https://<tenant>.xdr.<region>.paloaltonetworks.com
    fetch('/api/cortex/credentials').then(r => r.json()).then(data => {
        const apiUrl = data.base_url || '';
        if (!apiUrl) {
            alert('Cortex API URL not configured. Go to Settings > Cortex > Configure.');
            return;
        }
        // Remove api- prefix and trailing slashes
        let consoleUrl = apiUrl.replace(/\/+$/, '');
        // Pattern: https://api-<tenant>.xdr.<region>.paloaltonetworks.com
        consoleUrl = consoleUrl.replace(/^(https?:\/\/)api-/, '$1');
        window.open(consoleUrl, '_blank');
    }).catch(() => {
        alert('Cannot read Cortex settings.');
    });
}

function openCortexDashboard() {
    fetch('/api/cortex/credentials').then(r => r.json()).then(data => {
        const apiUrl = data.base_url || '';
        if (!apiUrl) {
            alert('Cortex API URL not configured. Go to Settings > Cortex > Configure.');
            return;
        }
        let consoleUrl = apiUrl.replace(/\/+$/, '').replace(/^(https?:\/\/)api-/, '$1');
        window.open(consoleUrl + '/dashboard', '_blank');
    }).catch(() => alert('Cannot read Cortex settings.'));
}

function openCortexCases() {
    fetch('/api/cortex/credentials').then(r => r.json()).then(data => {
        const apiUrl = data.base_url || '';
        if (!apiUrl) {
            alert('Cortex API URL not configured. Go to Settings > Cortex > Configure.');
            return;
        }
        let consoleUrl = apiUrl.replace(/\/+$/, '').replace(/^(https?:\/\/)api-/, '$1');
        window.open(consoleUrl + '/cases', '_blank');
    }).catch(() => alert('Cannot read Cortex settings.'));
}

function openWebApp() {
    const hostEl = document.getElementById('host-value');
    const host = hostEl ? hostEl.textContent : '';
    if (!host || host === 'Not deployed') {
        alert('WebApp not deployed. Deploy the app first.');
        return;
    }
    // host may be truncated with ..., use the full host from state
    if (state.host) {
        window.open('http://' + state.host + '/app', '_blank');
    } else {
        // Try to get it from the API
        fetch('/api/k8s/host').then(r => r.json()).then(data => {
            if (data.host) {
                window.open('http://' + data.host + '/app', '_blank');
            } else {
                alert('WebApp host not found.');
            }
        }).catch(() => alert('Cannot get WebApp host.'));
    }
}

// ─── External Cluster (BYOC) ─────────────────────────────────────────────────

function openByocSettings() {
    document.getElementById('byoc-modal').classList.add('visible');
    // Load current settings
    fetch('/api/external-cluster').then(r => r.json()).then(data => {
        document.getElementById('byoc-enabled').checked = data.enabled || false;
        document.getElementById('byoc-kubeconfig').value = data.kubeconfig || '';
        document.getElementById('byoc-host').value = data.app_host || '';
        document.getElementById('byoc-image').value = data.image_url || '';
        toggleByocFields();
    }).catch(() => {});
}

function closeByocSettings() {
    document.getElementById('byoc-modal').classList.remove('visible');
}

function toggleByocFields() {
    const enabled = document.getElementById('byoc-enabled').checked;
    document.getElementById('byoc-fields').style.opacity = enabled ? '1' : '0.4';
}

async function saveByocSettings() {
    const payload = {
        enabled: document.getElementById('byoc-enabled').checked,
        kubeconfig: document.getElementById('byoc-kubeconfig').value.trim(),
        app_host: document.getElementById('byoc-host').value.trim(),
        image_url: document.getElementById('byoc-image').value.trim(),
    };
    try {
        const res = await fetch('/api/external-cluster', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.status === 'ok') {
            closeByocSettings();
            const el = document.getElementById('byoc-status');
            if (payload.enabled) {
                el.textContent = 'configured';
                el.style.color = '#22c55e';
            } else {
                el.textContent = 'disabled';
                el.style.color = '#64748b';
            }
            refreshHost();
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function testByocCluster() {
    openTab('terminal');
    termWriteHeader('Testing External Cluster Connection');
    try {
        const res = await fetch('/api/external-cluster/test', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            termWrite(data.output + '\n');
            const el = document.getElementById('byoc-status');
            el.textContent = 'connected';
            el.style.color = '#22c55e';
        } else {
            termWrite('Error: ' + data.message + '\n');
        }
    } catch (e) {
        termWrite('Error: ' + e.message + '\n');
    }
}

// ─── Demo Wizard ─────────────────────────────────────────────────────────────

let demoRunning = false;
let demoAbort = false;

const DEMO_STEPS = [
    { name: 'Step 1: RCE',       fn: () => apiCall('/api/attack/step1'),  wait: 15000, pct: 17 },
    { name: 'Step 2: Escape',    fn: () => apiCall('/api/attack/step2'),  wait: 8000,  pct: 33 },
    { name: 'Step 3: Takeover',  fn: () => apiCall('/api/attack/step3'),  wait: 10000, pct: 50 },
    { name: 'Step 4: Scan',      fn: () => apiCall('/api/attack/step4'),  wait: 12000, pct: 67 },
    { name: 'Step 5: Malware',   fn: () => apiCall('/api/attack/step5'),  wait: 10000, pct: 83 },
    { name: 'Step 6: Lateral',   fn: () => apiCall('/api/attack/step6'),  wait: 10000, pct: 100 },
];

async function runFullDemo() {
    if (demoRunning) return;
    demoRunning = true;
    demoAbort = false;

    const btn = document.getElementById('btn-demo-wizard');
    const stopBtn = document.getElementById('btn-demo-stop');
    const progress = document.getElementById('demo-progress');
    const progressBar = document.getElementById('demo-progress-bar');
    const progressText = document.getElementById('demo-progress-text');

    btn.classList.add('running');
    btn.innerHTML = '<span class="demo-wizard-icon">&#9654;</span> Running Demo...';
    stopBtn.style.display = '';
    progress.style.display = '';

    // Open Overview to show the interactive diagram during the demo
    openTab('overview');
    // Scroll to the diagram
    const diagram = document.getElementById('arch-diagram');
    if (diagram) diagram.scrollIntoView({ behavior: 'smooth', block: 'start' });

    for (let i = 0; i < DEMO_STEPS.length; i++) {
        if (demoAbort) break;

        const step = DEMO_STEPS[i];
        progressText.textContent = `${step.name} (${i+1}/${DEMO_STEPS.length})`;
        progressBar.style.width = ((i / DEMO_STEPS.length) * 100) + '%';

        // Don't clear terminal between steps in full demo mode
        termWrite(`\n${'='.repeat(50)}\n  ${step.name}\n${'='.repeat(50)}\n\n`);
        step.fn();

        // Wait for the actual task to complete by polling task status
        let stepFailed = false;
        await new Promise(resolve => {
            let elapsed = 0;
            const maxWait = step.wait + 30000;
            const check = setInterval(() => {
                elapsed += 1000;
                const taskId = state.currentTaskId;
                if (taskId) {
                    fetch(`/api/tasks/${taskId}`).then(r => r.json()).then(task => {
                        if (task.status === 'success' || task.status === 'error') {
                            clearInterval(check);
                            // Check if Step 1 (RCE) failed — abort the demo
                            const output = task.output || '';
                            const step1Failed = (task.status === 'error' || output.includes('[FAIL]')) && i === 0;
                            if (step1Failed) {
                                stepFailed = true;
                                if (output.includes('404') || output.includes('FAIL') || output.includes('not responding')) {
                                    showNotification('Step 1 failed! Check: app deployed? VPN/GlobalProtect disabled?', 'warning');
                                    termWrite('\n' + '!'.repeat(50) + '\n');
                                    termWrite('  DEMO STOPPED — Step 1 (RCE) failed\n');
                                    termWrite('  \n');
                                    termWrite('  Possible causes:\n');
                                    termWrite('  1. Application not deployed — click Deploy first\n');
                                    termWrite('  2. VPN inspection (GlobalProtect) is blocking\n');
                                    termWrite('     the Spring4Shell exploit payload\n');
                                    termWrite('     → Disable GlobalProtect before running attacks\n');
                                    termWrite('  3. Pod needs restart:\n');
                                    termWrite('     → Click "kill pods" in kubectl tab\n');
                                    termWrite('     → Wait for pod Ready, then retry\n');
                                    termWrite('  \n');
                                    termWrite('!' .repeat(50) + '\n');
                                }
                            }
                            setTimeout(resolve, 2000);
                        }
                    }).catch(() => {});
                }
                if (demoAbort || elapsed >= maxWait) {
                    clearInterval(check);
                    resolve();
                }
            }, 1500);
        });

        progressBar.style.width = step.pct + '%';

        // Stop demo if Step 1 failed
        if (stepFailed) {
            demoAbort = true;
            break;
        }
    }

    // Done
    progressText.textContent = demoAbort ? 'Stopped' : 'Complete!';
    progressBar.style.width = demoAbort ? progressBar.style.width : '100%';
    btn.classList.remove('running');
    btn.innerHTML = '<span class="demo-wizard-icon">&#9654;</span> Run Full Demo';
    stopBtn.style.display = 'none';
    demoRunning = false;

    if (!demoAbort) {
        termWrite('\n' + '='.repeat(50) + '\n');
        termWrite('  FULL DEMO COMPLETE\n');
        termWrite('  Check SOC Live tab for Cortex XDR alerts\n');
        termWrite('='.repeat(50) + '\n');
    }
}

function stopDemo() {
    demoAbort = true;
}

// ─── SOC Live ────────────────────────────────────────────────────────────────

let socAutoInterval = null;

async function socRefresh() {
    try {
        const res = await fetch('/api/cortex/soc-alerts');
        const data = await res.json();
        if (data.status !== 'ok') {
            document.getElementById('soc-alerts').innerHTML = `<div class="soc-empty">Error: ${data.message || 'Cannot fetch alerts'}</div>`;
            return;
        }

        const alerts = data.alerts || [];
        document.getElementById('soc-alert-count').textContent = alerts.length;

        if (alerts.length === 0) {
            document.getElementById('soc-alerts').innerHTML = '<div class="soc-empty">No alerts in the last 24 hours.</div>';
            return;
        }

        // Update MITRE heatmap
        const mitreTechniques = new Set();
        alerts.forEach(a => {
            (a.mitre || []).forEach(m => {
                const tid = typeof m === 'string' ? m.split(' - ')[0] : (m.technique_id || '');
                if (tid) mitreTechniques.add(tid.replace(/\.\d+$/, ''));
            });
            // Map alert categories to techniques
            (a.category || []).forEach(cat => {
                const catLower = (cat || '').toLowerCase();
                if (catLower.includes('malware')) mitreTechniques.add('T1587');
                if (catLower.includes('exploit')) mitreTechniques.add('T1190');
                if (catLower.includes('webshell')) { mitreTechniques.add('T1505'); mitreTechniques.add('T1059'); }
                if (catLower.includes('container')) mitreTechniques.add('T1611');
                if (catLower.includes('credential')) mitreTechniques.add('T1552');
            });
        });
        document.querySelectorAll('.mitre-cell').forEach(cell => {
            const tid = cell.dataset.technique;
            if (mitreTechniques.has(tid)) {
                if (!cell.classList.contains('detected')) {
                    cell.classList.add('detected');
                }
            }
        });

        // Render alerts
        const html = alerts.map(a => {
            const sev = (a.severity || 'unknown').toLowerCase();
            const sevClass = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low';
            const time = a.created ? new Date(a.created).toLocaleTimeString() : '';
            const date = a.created ? new Date(a.created).toLocaleDateString() : '';
            const mitreStr = (a.mitre || []).map(m => typeof m === 'string' ? m : `${m.technique_id} ${m.technique_name || ''}`).join(', ');
            return `<div class="soc-alert-item">
                <span class="soc-alert-severity ${sevClass}">${sev}</span>
                <div class="soc-alert-body">
                    <div class="soc-alert-name">${a.name || 'Alert'}</div>
                    <div class="soc-alert-desc">${a.host || ''} ${a.alert_count ? '(' + a.alert_count + ' alerts)' : ''}</div>
                    ${mitreStr ? `<div class="soc-alert-mitre">MITRE: ${mitreStr}</div>` : ''}
                </div>
                <span class="soc-alert-time">${date}<br>${time}</span>
            </div>`;
        }).join('');
        document.getElementById('soc-alerts').innerHTML = html;

    } catch (e) {
        document.getElementById('soc-alerts').innerHTML = `<div class="soc-empty">Error: ${e.message}</div>`;
    }
}

function socClear() {
    document.getElementById('soc-alerts').innerHTML = '<div class="soc-empty">Cleared. Click Refresh to reload.</div>';
    document.getElementById('soc-alert-count').textContent = '0';
    document.querySelectorAll('.mitre-cell').forEach(c => c.classList.remove('detected'));
}

function socToggleAutoRefresh() {
    const checked = document.getElementById('soc-auto-refresh').checked;
    if (checked) {
        socRefresh();
        socAutoInterval = setInterval(socRefresh, 30000);
    } else {
        if (socAutoInterval) { clearInterval(socAutoInterval); socAutoInterval = null; }
    }
}

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

    // Poll toolbox status
    refreshToolboxStatus();
    refreshToolboxVersions();
    setInterval(refreshToolboxStatus, 10000);
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
    refreshAwsRegionLabel();

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

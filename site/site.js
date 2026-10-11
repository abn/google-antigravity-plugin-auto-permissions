/**
 * Auto-Permissions Plugin — Static Site Interactive Engine
 * Governed by the design system of abn.is
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initDocTabs();
  initCopyButtons();
  initSimulator();
});

/* =====================================================
   THEME TOGGLE
   ===================================================== */
function initTheme() {
  const toggleBtn = document.getElementById('theme-toggle');
  const themeLabel = document.getElementById('theme-label');
  const themeIcon = document.getElementById('theme-icon');

  const savedTheme = localStorage.getItem('theme');
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

  let currentTheme = savedTheme || (systemPrefersDark ? 'dark' : 'light');
  applyTheme(currentTheme);

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
      applyTheme(currentTheme);
      localStorage.setItem('theme', currentTheme);
    });
  }

  function applyTheme(theme) {
    if (theme === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
      if (themeLabel) themeLabel.textContent = 'Light';
      if (themeIcon) themeIcon.textContent = '☀️';
    } else {
      document.documentElement.removeAttribute('data-theme');
      if (themeLabel) themeLabel.textContent = 'Dark';
      if (themeIcon) themeIcon.textContent = '🌙';
    }
  }
}

/* =====================================================
   DOCUMENTATION TABS
   ===================================================== */
function initDocTabs() {
  const tabBtns = document.querySelectorAll('.doc-tab-btn');
  const tabPanes = document.querySelectorAll('.doc-tab-pane');

  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');

      tabBtns.forEach((b) => b.classList.remove('active'));
      tabPanes.forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');
    });
  });
}

/* =====================================================
   COPY TO CLIPBOARD BUTTONS
   ===================================================== */
function initCopyButtons() {
  const copyBtns = document.querySelectorAll('.copy-btn');

  copyBtns.forEach((btn) => {
    btn.addEventListener('click', async () => {
      const codeBlock = btn.closest('.codeblock');
      if (!codeBlock) return;

      const pre = codeBlock.querySelector('pre');
      if (!pre) return;

      const codeText = pre.innerText;
      try {
        await navigator.clipboard.writeText(codeText);
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.color = 'var(--c-success)';
        btn.style.borderColor = 'var(--c-success)';

        setTimeout(() => {
          btn.textContent = originalText;
          btn.style.color = '';
          btn.style.borderColor = '';
        }, 1800);
      } catch (err) {
        console.error('Failed to copy code: ', err);
      }
    });
  });
}

/* =====================================================
   INTERACTIVE SIMULATOR PLAYGROUND
   ===================================================== */
function initSimulator() {
  const toolSelect = document.getElementById('sim-tool');
  const promptInput = document.getElementById('sim-prompt');
  const argsInput = document.getElementById('sim-args');
  const runBtn = document.getElementById('sim-run-btn');

  const verdictBadge = document.getElementById('sim-verdict-badge');
  const modeBadge = document.getElementById('sim-mode-badge');
  const latencySpan = document.getElementById('sim-latency');
  const reasonText = document.getElementById('sim-reason');
  const rawPromptPre = document.getElementById('sim-raw-prompt');

  const presetPills = document.querySelectorAll('.preset-pill');

  const presets = {
    'routine-lint': {
      tool: 'run_command',
      prompt: 'Run tests and fix any failing linter errors.',
      args: 'uv run --frozen ruff check .',
      verdict: 'allow',
      mode: 'Turn Cache',
      latency: '0.1ms',
      reason: 'Linter verification matches active prompt intent (Intra-turn cache hit).',
      category: 'safe_routine',
    },
    'file-chunk': {
      tool: 'replace_file_content',
      prompt: 'Update the authentication token validator in auth.py',
      args: '{"TargetFile": "/workspace/auth.py", "Instruction": "Add expiration check"}',
      verdict: 'allow',
      mode: 'File Grant',
      latency: '0.1ms',
      reason: "File 'auth.py' edit authorized in active turn (File grant).",
      category: 'same_turn_file_grant',
    },
    'safe-read': {
      tool: 'run_command',
      prompt: 'Check the size of the repository documentation.',
      args: 'wc -l docs/architecture.md | grep Total',
      verdict: 'allow',
      mode: 'Safe Read',
      latency: '0.1ms',
      reason: "Read-only utility 'wc' is safe (inspection pipeline).",
      category: 'safe_read_command',
    },
    'destructive-wipe': {
      tool: 'run_command',
      prompt: 'Clean up unnecessary temporary cache files.',
      args: 'rm -rf /',
      verdict: 'deny',
      mode: 'Static ACL',
      latency: '0.2ms',
      reason: 'Prohibited destructive wipe pattern: rm -rf /.* (Static Policy: project)',
      category: 'static_policy_project',
    },
    'scope-deviation': {
      tool: 'run_command',
      prompt: 'Run the pytest test suite.',
      args: 'git branch -D staging',
      verdict: 'soft_deny',
      mode: 'Gemini',
      latency: '1240ms',
      reason: "Security Gate (Scope Deviation): Branch deletion of 'staging' was not requested in active user prompt.",
      category: 'scope_deviation',
    },
    'prod-deploy': {
      tool: 'run_command',
      prompt: 'Deploy the application to the production Kubernetes cluster.',
      args: 'kubectl apply -f k8s/prod-deploy.yaml',
      verdict: 'ask',
      mode: 'Gemini',
      latency: '1480ms',
      reason: 'Production infrastructure mutation requires explicit interactive developer approval.',
      category: 'high_risk_infrastructure',
    },
  };

  presetPills.forEach((pill) => {
    pill.addEventListener('click', () => {
      const presetKey = pill.getAttribute('data-preset');
      const data = presets[presetKey];
      if (!data) return;

      if (toolSelect) toolSelect.value = data.tool;
      if (promptInput) promptInput.value = data.prompt;
      if (argsInput) argsInput.value = data.args;

      evaluateSimulation(data);
    });
  });

  if (runBtn) {
    runBtn.addEventListener('click', () => {
      const tool = toolSelect.value;
      const prompt = promptInput.value.trim();
      const args = argsInput.value.trim();

      // Basic heuristic classifier simulation
      const result = simulateEvaluation(tool, prompt, args);
      evaluateSimulation(result);
    });
  }

  function simulateEvaluation(tool, prompt, args) {
    const lowerArgs = args.toLowerCase();
    const lowerPrompt = prompt.toLowerCase();

    // 1. Destructive pattern
    if (lowerArgs.includes('rm -rf /') || lowerArgs.includes('.ssh/id_rsa')) {
      return {
        verdict: 'deny',
        mode: 'Static ACL',
        latency: '0.2ms',
        reason: 'Hostile destructive command blocked by security invariant.',
        category: 'data_exfiltration_or_destruction',
      };
    }

    // 2. Safe read utilities
    if (tool === 'run_command' && (lowerArgs.startsWith('wc') || lowerArgs.startsWith('which') || lowerArgs.startsWith('uname') || lowerArgs.startsWith('head') || lowerArgs.startsWith('file'))) {
      return {
        verdict: 'allow',
        mode: 'Safe Read',
        latency: '0.1ms',
        reason: `Read-only utility '${args.split(' ')[0]}' verified safe (inspection pipeline).`,
        category: 'safe_read_command',
      };
    }

    // 3. Same turn file grant
    if (tool === 'replace_file_content' || tool === 'write_to_file') {
      return {
        verdict: 'allow',
        mode: 'File Grant',
        latency: '0.1ms',
        reason: 'Target file authorized for edits in active turn (File grant).',
        category: 'same_turn_file_grant',
      };
    }

    // 4. Infrastructure mutation
    if (lowerArgs.includes('kubectl') || lowerArgs.includes('terraform') || lowerArgs.includes('drop database')) {
      return {
        verdict: 'ask',
        mode: 'Gemini',
        latency: '1420ms',
        reason: 'Production infrastructure mutation requires explicit interactive developer approval.',
        category: 'high_risk_infrastructure',
      };
    }

    // 5. Scope deviation
    if (lowerArgs.includes('git branch -d') && !lowerPrompt.includes('branch')) {
      return {
        verdict: 'soft_deny',
        mode: 'Gemini',
        latency: '1280ms',
        reason: 'Security Gate (Scope Deviation): Tool action is not aligned with active user prompt.',
        category: 'scope_deviation',
      };
    }

    // Default allow
    return {
      verdict: 'allow',
      mode: 'Gemini',
      latency: '1310ms',
      reason: 'Proposed tool action strictly matches developer intent.',
      category: 'safe_routine',
    };
  }

  function evaluateSimulation(data) {
    if (!verdictBadge || !reasonText) return;

    // Verdict Badge
    verdictBadge.className = 'badge';
    if (data.verdict === 'allow') {
      verdictBadge.classList.add('badge-allow');
      verdictBadge.textContent = '🟢 ALLOW';
    } else if (data.verdict === 'deny' || data.verdict === 'soft_deny') {
      verdictBadge.classList.add('badge-deny');
      verdictBadge.textContent = data.verdict === 'soft_deny' ? '🔴 SOFT_DENY' : '🔴 HARD_DENY';
    } else {
      verdictBadge.classList.add('badge-ask');
      verdictBadge.textContent = '🟡 ASK';
    }

    // Mode Badge
    if (modeBadge) {
      modeBadge.className = 'badge';
      if (data.mode.includes('ACL')) modeBadge.classList.add('badge-neutral');
      else if (data.mode.includes('Cache')) modeBadge.classList.add('badge-cache');
      else if (data.mode.includes('Grant')) modeBadge.classList.add('badge-allow');
      else if (data.mode.includes('Read')) modeBadge.classList.add('badge-read');
      else modeBadge.classList.add('badge-cache');
      modeBadge.textContent = data.mode;
    }

    if (latencySpan) latencySpan.textContent = `Latency: ${data.latency}`;
    if (reasonText) reasonText.textContent = data.reason;

    // XML Prompt Payload Trace
    if (rawPromptPre) {
      const tool = toolSelect ? toolSelect.value : 'run_command';
      const prompt = promptInput ? promptInput.value : '';
      const args = argsInput ? argsInput.value : '';

      rawPromptPre.textContent = `<workspace_roots>
  <root>/workspace/project</root>
</workspace_roots>

<prior_user_prompts>
  [Turn 0] Initial setup and inspection
</prior_user_prompts>

<active_user_prompt>
  ${prompt || '(no active prompt)'}
</active_user_prompt>

<proposed_tool_call>
  <tool_name>${tool}</tool_name>
  <tool_args>${args || '{}'}</tool_args>
</proposed_tool_call>`;
    }
  }

  // Trigger initial preset
  const firstPill = document.querySelector('.preset-pill');
  if (firstPill) firstPill.click();
}

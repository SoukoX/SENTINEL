/**
 * Phase 2 features added to the Web UI:
 *   1. Memory Panel — Target profiles, FP registry, payload stats, skill registry
 *   2. False Positive marking — Right-click or button on any finding
 *   3. Scan Resume — Detect interrupted scans and offer resume
 *   4. Program Templates — Preset scan configs
 *   5. AI Attack Chain Narrative — Display in Results > AI Analysis
 *   6. Settings Panel — Retention policy, config, disk usage
 *   7. Similar Findings — "Seen before?" context on each finding
 *   8. Audit Log viewer — Show what SENTINEL has done
 */


// ## PHASE 2: MEMORY PANEL



const MEMORY_NAV_HTML = `
<div class="sb-section">Intelligence</div>
<div class="navitem" id="nav-memory" onclick="showPanel('memory')">
  <span class="ico">🧠</span> Memory
  <span class="nbadge pur" id="badge-memory">0</span>
</div>
<div class="navitem" id="nav-settings" onclick="showPanel('settings')">
  <span class="ico">⚙️</span> Settings
</div>
`;

// HTML for the Memory panel 
const MEMORY_PANEL_HTML = `
<div class="panel" id="panel-memory">
  <div class="report-tabs">
    <div class="rtab active" onclick="switchMemoryTab('targets')">🎯 Target Profiles</div>
    <div class="rtab" onclick="switchMemoryTab('fps')">🚫 False Positives</div>
    <div class="rtab" onclick="switchMemoryTab('skills')">🔧 Skill Registry</div>
    <div class="rtab" onclick="switchMemoryTab('payloads')">💉 Payload Stats</div>
    <div class="rtab" onclick="switchMemoryTab('audit')">📋 Audit Log</div>
  </div>

  <!-- TARGET PROFILES -->
  <div class="report-section active" id="mem-targets">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px">
      <div style="font-size:12px;color:var(--t3);font-family:var(--mono)">
        Cross-scan knowledge — what SENTINEL remembers about each target.
      </div>
      <button class="tbtn" onclick="refreshMemory()">↻ Refresh</button>
    </div>
    <div id="target-profiles-list" style="display:flex;flex-direction:column;gap:10px">
      <div class="empty"><div class="big">🧠</div>No targets scanned yet. Start a scan to begin building memory.</div>
    </div>
  </div>

  <!-- FALSE POSITIVES -->
  <div class="report-section" id="mem-fps">
    <div style="margin-bottom:12px;font-size:12px;color:var(--t3);font-family:var(--mono)">
      Findings you've marked as false positives — SENTINEL will never re-alert on these.
    </div>
    <div id="fp-list-container">
      <div class="empty"><div class="big">✅</div>No false positives registered.</div>
    </div>
  </div>

  <!-- SKILL REGISTRY -->
  <div class="report-section" id="mem-skills">
    <div style="margin-bottom:12px;font-size:12px;color:var(--t3);font-family:var(--mono)">
      Learned tool effectiveness per tech stack — gets smarter every scan.
    </div>
    <div id="skill-registry-container">
      <div class="empty"><div class="big">🔧</div>No skills learned yet. Run scans to start building expertise.</div>
    </div>
  </div>

  <!-- PAYLOAD STATS -->
  <div class="report-section" id="mem-payloads">
    <div style="margin-bottom:12px;font-size:12px;color:var(--t3);font-family:var(--mono)">
      Payload effectiveness tracking — which payloads work on which tech stacks.
    </div>
    <div id="payload-stats-container">
      <div class="empty"><div class="big">💉</div>No payload data yet.</div>
    </div>
  </div>

  <!-- AUDIT LOG -->
  <div class="report-section" id="mem-audit">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
      <div style="font-size:12px;color:var(--t3);font-family:var(--mono)">Immutable local audit log — every significant action.</div>
      <select id="audit-filter" onchange="loadAuditLog()" style="background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--t1);padding:5px 9px;font-family:var(--mono);font-size:12px;outline:none">
        <option value="">All actions</option>
        <option value="scan_started">Scans started</option>
        <option value="scan_completed">Scans completed</option>
        <option value="fp_marked">FPs marked</option>
        <option value="ai_call">AI calls</option>
        <option value="export">Exports</option>
        <option value="scope_violation">Scope violations</option>
      </select>
      <button class="tbtn" onclick="loadAuditLog()">↻ Refresh</button>
    </div>
    <div id="audit-log-container">
      <div class="empty"><div class="big">📋</div>No audit entries yet.</div>
    </div>
  </div>
</div>
`;

// HTML for Settings panel:
const SETTINGS_PANEL_HTML = `
<div class="panel" id="panel-settings">
  <div class="cfg-body">
    <div class="card">
      <div class="ctitle">Data & Privacy</div>
      <div style="display:flex;flex-direction:column;gap:12px">
        <div class="field">
          <label>Data Retention Policy</label>
          <select id="setting-retention" style="background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--t1);padding:8px 11px;font-family:var(--mono);font-size:13px;outline:none">
            <option value="indefinite">Indefinite (keep forever)</option>
            <option value="days_90">90 days</option>
            <option value="days_30">30 days</option>
            <option value="session">Session only (delete on exit)</option>
            <option value="manual">Manual (you control deletion)</option>
          </select>
        </div>
        <div id="disk-usage-box" style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-family:var(--mono);font-size:13px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="color:var(--t3)">Disk Usage</span>
            <button class="tbtn" onclick="loadDiskUsage()" style="font-size:11px;padding:3px 9px">Check</button>
          </div>
          <div id="disk-usage-detail" style="color:var(--t2);margin-top:8px">Click "Check" to see storage usage.</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="ctitle">Target Management</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
        <div class="field" style="flex:1;min-width:200px">
          <label>Purge all data for target</label>
          <input type="text" id="purge-target-input" placeholder="example.com" style="background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--t1);padding:8px 11px;font-family:var(--mono);font-size:13px;outline:none;width:100%"/>
        </div>
        <button onclick="purgeTarget()" style="padding:9px 18px;background:rgba(255,69,97,.12);border:1px solid rgba(255,69,97,.35);border-radius:7px;color:var(--red);font-size:13px;font-family:var(--mono);cursor:pointer;white-space:nowrap">
          🗑️ Purge Target
        </button>
      </div>
      <div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-top:8px">
        This deletes all scan directories for this target. The memory.db profiles and FP registry are kept.
      </div>
    </div>

    <div class="card">
      <div class="ctitle">Scan Program Templates</div>
      <div style="font-size:12px;color:var(--t3);font-family:var(--mono);margin-bottom:12px">
        Load a preset scan configuration for your bug bounty platform.
      </div>
      <div id="program-templates-list" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px">
        <!-- Populated by JS -->
      </div>
    </div>

    <div class="card">
      <div class="ctitle">Current Configuration</div>
      <div style="font-size:12px;color:var(--t3);font-family:var(--mono);margin-bottom:10px">
        Active config from ~/.sentinel/config.toml (or defaults).
      </div>
      <button class="tbtn" onclick="loadCurrentConfig()">Load Config</button>
      <div id="config-display" style="margin-top:12px;display:none">
        <table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px">
          <tbody id="config-table-body"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="ctitle">Acknowledged Targets</div>
      <div style="font-size:12px;color:var(--t3);font-family:var(--mono);margin-bottom:10px">
        Targets you've confirmed written authorization for. Remove to re-prompt next scan.
      </div>
      <div id="consent-list" style="font-family:var(--mono);font-size:13px;color:var(--t2)">
        — not loaded —
      </div>
    </div>
  </div>
</div>
`;

// ══════════════════════════════════════════════════════════════════
// PHASE 2: FP MARK BUTTON (add to finding cards in results panel)
// ══════════════════════════════════════════════════════════════════

function renderFPButton(finding) {
  const isFP = finding.false_positive;
  return `
    <button onclick="toggleFP(${JSON.stringify(finding).replace(/"/g, '&quot;')})"
      style="padding:3px 10px;border-radius:5px;font-size:11px;font-family:var(--mono);cursor:pointer;border:1px solid ${isFP ? 'rgba(31,216,124,.4)' : 'rgba(255,69,97,.3)'};background:${isFP ? 'rgba(31,216,124,.1)' : 'rgba(255,69,97,.08)'};color:${isFP ? 'var(--green)' : 'var(--red)'};transition:all .15s"
      title="${isFP ? 'Click to remove FP mark' : 'Mark as false positive'}">
      ${isFP ? '✓ FP' : 'Mark FP'}
    </button>`;
}

function renderSimilarButton(finding) {
  return `
    <button onclick="findSimilar(${JSON.stringify(finding).replace(/"/g, '&quot;')})"
      style="padding:3px 10px;border-radius:5px;font-size:11px;font-family:var(--mono);cursor:pointer;border:1px solid rgba(167,139,250,.3);background:rgba(167,139,250,.08);color:var(--purple);transition:all .15s"
      title="Find similar findings in memory">
      🔍 Similar
    </button>`;
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: RESUME SCAN BANNER
// ══════════════════════════════════════════════════════════════════

function checkResume(target) {
  if (!target || !ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'check_resume', target }));
}

function showResumeBanner(target, runDir, state) {
  const existing = document.getElementById('resume-banner');
  if (existing) existing.remove();

  const banner = document.createElement('div');
  banner.id = 'resume-banner';
  banner.style.cssText = `
    background:linear-gradient(135deg,rgba(245,197,24,.08),rgba(255,140,66,.06));
    border:1px solid rgba(245,197,24,.35);border-radius:10px;padding:12px 18px;
    display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;
    gap:10px;margin:12px 20px 0;`;
  banner.innerHTML = `
    <div>
      <div style="font-size:14px;font-weight:600;color:var(--yellow)">⚡ Interrupted scan found</div>
      <div style="font-size:12px;color:var(--t3);font-family:var(--mono);margin-top:3px">
        Stage: ${state?.current_stage?.toUpperCase() || 'unknown'} —
        Completed: ${(state?.completed_stages || []).join(', ') || 'none'}
      </div>
    </div>
    <div style="display:flex;gap:8px">
      <button onclick="resumeScan('${target}', '${runDir}')"
        style="padding:7px 16px;background:rgba(245,197,24,.15);border:1px solid rgba(245,197,24,.4);border-radius:7px;color:var(--yellow);font-size:13px;font-family:var(--mono);cursor:pointer">
        ▶ Resume from ${state?.current_stage?.toUpperCase() || 'last stage'}
      </button>
      <button onclick="document.getElementById('resume-banner').remove()"
        style="padding:7px 12px;background:transparent;border:1px solid var(--border);border-radius:7px;color:var(--t3);font-size:13px;font-family:var(--mono);cursor:pointer">
        Dismiss
      </button>
    </div>`;

  const cfgBody = document.querySelector('.cfg-body');
  if (cfgBody) cfgBody.prepend(banner);
}

function resumeScan(target, runDir) {
  // Pre-fill target and launch with resume flag
  const targetInput = document.getElementById('target');
  if (targetInput) targetInput.value = target;
  // The agent itself handles resume via state.json when same output dir is used
  // Pass --output-dir pointing to the parent of runDir
  const outDir = runDir.split('/').slice(0, -1).join('/');
  const outdirInput = document.getElementById('outdir');
  if (outdirInput) outdirInput.value = outDir;
  showPanel('config');
  setTimeout(() => startScan(), 100);
  document.getElementById('resume-banner')?.remove();
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: PROGRAM TEMPLATES
// ══════════════════════════════════════════════════════════════════

function loadProgramTemplates() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'get_program_templates' }));
}

function renderProgramTemplates(templates) {
  const container = document.getElementById('program-templates-list');
  if (!container) return;
  const COLORS = {
    hackerone: 'var(--green)', bugcrowd: 'var(--orange)', intigriti: 'var(--purple)',
    pentest: 'var(--red)', quick: 'var(--cyan)', deep: 'var(--yellow)',
  };
  container.innerHTML = Object.entries(templates).map(([key, t]) => `
    <button onclick="applyTemplate(${JSON.stringify(t).replace(/"/g, '&quot;')})"
      style="text-align:left;padding:12px 14px;border-radius:8px;border:1px solid var(--border);
      background:var(--bg3);cursor:pointer;transition:all .15s;width:100%"
      onmouseover="this.style.borderColor='${COLORS[key]||'var(--border2)'}'"
      onmouseout="this.style.borderColor='var(--border)'">
      <div style="font-size:13px;font-weight:600;color:var(--t1);font-family:var(--mono)">${t.name}</div>
      <div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-top:4px">${t.notes}</div>
      <div style="font-size:11px;color:var(--t3);margin-top:6px;display:flex;gap:8px;flex-wrap:wrap">
        <span style="background:var(--bg2);padding:1px 7px;border-radius:4px;border:1px solid var(--border)">${t.default_severity}</span>
        <span style="background:var(--bg2);padding:1px 7px;border-radius:4px;border:1px solid var(--border)">${t.default_stages}</span>
        ${t.intrusive ? '<span style="color:var(--red);border:1px solid rgba(255,69,97,.3);padding:1px 7px;border-radius:4px">intrusive</span>' : ''}
      </div>
    </button>
  `).join('');
}

function applyTemplate(template) {
  // Apply template settings to the scan config form
  const sevEl = document.getElementById('severity');
  if (sevEl && template.default_severity) {
    // Set chip states based on severity
    const sevMap = { critical: true, high: true, medium: true, low: false, info: false };
    template.default_severity.split(',').forEach(s => sevMap[s.trim()] = true);
  }

  // Set stages
  if (template.default_stages === 'all') {
    document.querySelectorAll('.chip:not(.danger)').forEach(c => {
      c.classList.add('on');
    });
  }

  // Enable intrusive if needed
  if (template.intrusive) {
    const intrusiveChip = document.getElementById('chip-intrusive');
    if (intrusiveChip && !intrusiveChip.classList.contains('on')) {
      intrusiveChip.classList.add('on');
    }
  }

  updateCmd?.();
  showPanel('config');
  showToast(`✅ Applied template: ${template.name}`);
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: MEMORY PANEL FUNCTIONS
// ══════════════════════════════════════════════════════════════════

let _activeMemoryTab = 'targets';

function switchMemoryTab(tab) {
  _activeMemoryTab = tab;
  document.querySelectorAll('#panel-memory .report-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('#panel-memory .rtab').forEach(t => t.classList.remove('active'));
  const tabMap = { targets: 0, fps: 1, skills: 2, payloads: 3, audit: 4 };
  const idx = tabMap[tab] ?? 0;
  document.getElementById(`mem-${tab}`)?.classList.add('active');
  document.querySelectorAll('#panel-memory .rtab')[idx]?.classList.add('active');

  switch(tab) {
    case 'targets':  refreshMemory(); break;
    case 'fps':      loadFPList(); break;
    case 'skills':   loadSkillRegistry(); break;
    case 'payloads': loadPayloadStats(); break;
    case 'audit':    loadAuditLog(); break;
  }
}

function refreshMemory() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'get_memory_summary' }));
}

function renderMemoryPanel(data) {
  const badge = document.getElementById('badge-memory');
  if (badge) badge.textContent = data.targets?.length || 0;

  // Target profiles
  const profilesEl = document.getElementById('target-profiles-list');
  if (!profilesEl) return;

  if (!data.targets || data.targets.length === 0) {
    profilesEl.innerHTML = '<div class="empty"><div class="big">🧠</div>No targets scanned yet.</div>';
    return;
  }

  const TREND_ICONS = { improving: '📉✅', degrading: '📈🔴', stable: '→', unknown: '?' };
  profilesEl.innerHTML = data.targets.map(p => {
    const techKeys = typeof p.tech_stack === 'object' ? Object.keys(p.tech_stack) : [];
    const trend = TREND_ICONS[p.risk_trend] || '?';
    return `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 18px">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:10px">
        <div>
          <div style="font-size:15px;font-weight:600;font-family:var(--mono);color:var(--t1)">${esc(p.target)}</div>
          <div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-top:3px">
            ${p.scan_count} scan${p.scan_count !== 1 ? 's' : ''} ·
            First: ${p.first_seen?.slice(0,10) || '-'} ·
            Last: ${p.last_seen?.slice(0,10) || '-'}
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:12px;color:var(--t3);font-family:var(--mono)">Risk trend: ${trend}</span>
          ${p.total_vulns > 0 ? `<span style="font-size:13px;font-weight:700;color:var(--red)">${p.total_vulns} vulns</span>` : '<span style="color:var(--green);font-size:13px">Clean</span>'}
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">
        ${p.critical_count ? `<span style="background:rgba(255,69,97,.12);color:var(--red);border:1px solid rgba(255,69,97,.3);padding:2px 8px;border-radius:4px;font-size:11px;font-family:var(--mono)">${p.critical_count} critical</span>` : ''}
        ${p.high_count ? `<span style="background:rgba(255,140,66,.12);color:var(--orange);border:1px solid rgba(255,140,66,.3);padding:2px 8px;border-radius:4px;font-size:11px;font-family:var(--mono)">${p.high_count} high</span>` : ''}
        ${p.medium_count ? `<span style="background:rgba(245,197,24,.1);color:var(--yellow);border:1px solid rgba(245,197,24,.3);padding:2px 8px;border-radius:4px;font-size:11px;font-family:var(--mono)">${p.medium_count} med</span>` : ''}
        ${techKeys.slice(0,4).map(t => `<span style="background:rgba(59,158,255,.08);color:var(--cyan);border:1px solid rgba(59,158,255,.25);padding:2px 8px;border-radius:4px;font-size:11px;font-family:var(--mono)">${esc(t)}</span>`).join('')}
      </div>
      ${p.program_name ? `<div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-bottom:6px">Program: ${esc(p.program_name)}</div>` : ''}
      ${p.notes ? `<div style="font-size:12px;color:var(--t2);font-family:var(--mono);padding:8px 10px;background:var(--bg3);border-radius:6px;margin-bottom:8px">${esc(p.notes)}</div>` : ''}
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
        <button onclick="startScanForTarget('${esc(p.target)}')" class="tbtn" style="font-size:11px">▶ Rescan</button>
        <button onclick="showTargetNotes('${esc(p.target)}', '${esc(p.notes||'')}', '${esc(p.program_name||'')}' )" class="tbtn" style="font-size:11px">✏️ Notes</button>
        <button onclick="loadFPList('${esc(p.target)}')" class="tbtn" style="font-size:11px">🚫 FPs (${p.target})</button>
      </div>
    </div>`;
  }).join('');
}

function renderSkillRegistry(data) {
  const container = document.getElementById('skill-registry-container');
  if (!container) return;
  const skills = data.skill_registry;
  if (!skills || Object.keys(skills).length === 0) {
    container.innerHTML = '<div class="empty"><div class="big">🔧</div>No skills learned yet.</div>';
    return;
  }
  container.innerHTML = Object.entries(skills).map(([ctx, s]) => `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:8px">
      <div style="font-size:13px;font-weight:600;font-family:var(--mono);color:var(--cyan);margin-bottom:8px">tech:${esc(ctx)}</div>
      ${s.best_tools?.length ? `
        <div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-bottom:4px">BEST TOOLS</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
          ${s.best_tools.map(t => `<span style="background:rgba(31,216,124,.1);color:var(--green);border:1px solid rgba(31,216,124,.25);padding:2px 9px;border-radius:4px;font-size:11px;font-family:var(--mono)">${esc(t)}</span>`).join('')}
        </div>` : ''}
      ${s.skip_tools?.length ? `
        <div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-bottom:4px">LOW SIGNAL (skip or deprioritize)</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          ${s.skip_tools.map(t => `<span style="background:rgba(255,69,97,.08);color:var(--red);border:1px solid rgba(255,69,97,.2);padding:2px 9px;border-radius:4px;font-size:11px;font-family:var(--mono)">${esc(t)}</span>`).join('')}
        </div>` : ''}
    </div>
  `).join('');
}

function loadFPList(target = null) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'get_fp_list', target }));
}

function renderFPList(fps, target = null) {
  const container = document.getElementById('fp-list-container');
  if (!container) return;
  if (!fps || fps.length === 0) {
    container.innerHTML = `<div class="empty"><div class="big">✅</div>No false positives${target ? ` for ${esc(target)}` : ''}.</div>`;
    return;
  }
  container.innerHTML = `
    <div style="margin-bottom:10px;font-size:12px;color:var(--t3);font-family:var(--mono)">
      ${fps.length} false positive${fps.length !== 1 ? 's' : ''} registered${target ? ` for ${esc(target)}` : ''}.
      SENTINEL will never re-alert on these.
    </div>
    <table class="vtable">
      <thead><tr>
        <th>Finding</th><th>Target</th><th>Reason</th><th>Noted At</th><th></th>
      </tr></thead>
      <tbody>
        ${fps.map(fp => `
          <tr>
            <td style="font-family:var(--mono);font-size:12px">${esc(fp.template_id || fp.fp_hash || '-')}</td>
            <td style="color:var(--t3);font-size:12px">${esc(fp.target || '-')}</td>
            <td style="color:var(--t2);font-size:12px">${esc(fp.reason || '-')}</td>
            <td style="color:var(--t3);font-size:12px">${fp.noted_at?.slice(0,10) || '-'}</td>
            <td>
              <button onclick="clearFP('${esc(fp.fp_hash)}')"
                style="padding:2px 9px;border-radius:4px;font-size:11px;font-family:var(--mono);cursor:pointer;
                border:1px solid rgba(255,69,97,.3);background:rgba(255,69,97,.08);color:var(--red)">
                Remove
              </button>
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

function loadPayloadStats() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'get_payload_stats' }));
}

function renderPayloadStats(data) {
  const container = document.getElementById('payload-stats-container');
  if (!container) return;
  const stats = data.stats;
  if (!stats || Object.keys(stats).length === 0) {
    container.innerHTML = '<div class="empty"><div class="big">💉</div>No payload data yet.</div>';
    return;
  }
  container.innerHTML = Object.entries(stats).map(([type, s]) => `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:8px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <div style="font-size:13px;font-weight:600;font-family:var(--mono);color:var(--orange);min-width:80px">${esc(type)}</div>
      <div style="flex:1;display:flex;gap:16px;flex-wrap:wrap">
        <div style="font-size:12px;font-family:var(--mono)">
          <span style="color:var(--green)">${s.total_hits || 0}</span>
          <span style="color:var(--t3)"> hits</span>
        </div>
        <div style="font-size:12px;font-family:var(--mono)">
          <span style="color:var(--t3)">${s.total_misses || 0} misses</span>
        </div>
        <div style="font-size:12px;font-family:var(--mono)">
          <span style="color:var(--cyan)">${s.unique_payloads || 0}</span>
          <span style="color:var(--t3)"> unique payloads</span>
        </div>
      </div>
    </div>
  `).join('');
}

function loadAuditLog() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const filter = document.getElementById('audit-filter')?.value || '';
  ws.send(JSON.stringify({ action: 'get_audit_log', limit: 100, action_filter: filter || null }));
}

function renderAuditLog(entries) {
  const container = document.getElementById('audit-log-container');
  if (!container) return;
  if (!entries || entries.length === 0) {
    container.innerHTML = '<div class="empty"><div class="big">📋</div>No audit entries.</div>';
    return;
  }
  const ACTION_COLORS = {
    scan_started: 'var(--blue)', scan_completed: 'var(--green)',
    scan_interrupted: 'var(--yellow)', fp_marked: 'var(--orange)',
    ai_call: 'var(--purple)', export: 'var(--cyan)',
    scope_violation: 'var(--red)', key_validated: 'var(--green)',
    tool_run: 'var(--t3)',
  };
  container.innerHTML = `
    <table class="vtable">
      <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
      <tbody>
        ${entries.map(e => `
          <tr>
            <td style="font-size:11px;color:var(--t3);white-space:nowrap">${e.timestamp?.slice(0,19)?.replace('T',' ') || '-'}</td>
            <td><span style="color:${ACTION_COLORS[e.action]||'var(--t2)'};font-family:var(--mono);font-size:12px">${esc(e.action)}</span></td>
            <td style="font-size:12px;color:var(--t3);font-family:var(--mono)">${esc(e.target || '-')}</td>
            <td style="font-size:11px;color:var(--t3);font-family:var(--mono)">${esc(JSON.stringify(e.details||{}).slice(0,80))}</td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: FP ACTIONS
// ══════════════════════════════════════════════════════════════════

function toggleFP(finding, _legacyName, _legacyHost) {
  // Backward-compat: handle old (btn, hash, name, host) signature from ui.html
  if (typeof finding === 'object' && finding.tagName === 'BUTTON') {
    const btn = finding; const hash = _legacyName; const host = _legacyHost;
    const isActive = btn.classList.contains('active-fp');
    btn.classList.toggle('active-fp');
    btn.textContent = btn.classList.contains('active-fp') ? '✓ Marked FP' : 'Mark False Positive';
    const card = btn.closest('.ai-card');
    const vBtn = card?.querySelector('.btn-verified');
    if (vBtn) { vBtn.classList.remove('active-verified'); vBtn.textContent = 'Mark as Verified'; }
    const f = scanFindings.find(x => x.finding_hash === hash);
    if (f) { f.false_positive = btn.classList.contains('active-fp'); if (f.false_positive) f.user_verified = false; }
    if (!isActive && ws && ws.readyState === WebSocket.OPEN && f) {
      ws.send(JSON.stringify({ action: 'mark_fp', finding: f, reason: 'user marked as FP' }));
    } else if (isActive && ws && ws.readyState === WebSocket.OPEN && hash) {
      ws.send(JSON.stringify({ action: 'clear_fp', fp_hash: hash }));
    }
    return;
  }
  if (!ws || ws.readyState !== WebSocket.OPEN) return showToast('Not connected', 'err');

  if (finding.false_positive) {
    // Clear the FP
    ws.send(JSON.stringify({ action: 'clear_fp', fp_hash: finding.finding_hash }));
    showToast('FP mark removed — finding will reappear in future scans');
  } else {
    // Show reason dialog
    showFPDialog(finding);
  }
}

function showFPDialog(finding) {
  const reason = prompt(`Mark as False Positive\n\nFinding: ${finding.name}\nHost: ${finding.host}\n\nReason (optional):`);
  if (reason === null) return; // User cancelled
  ws.send(JSON.stringify({
    action: 'mark_fp',
    finding: finding,
    reason: reason || 'user marked as FP',
  }));
  showToast(`🚫 Marked as false positive: ${finding.name}`);
}

function clearFP(fpHash) {
  if (!confirm('Remove this false positive? SENTINEL will re-alert on this finding type in future scans.')) return;
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'clear_fp', fp_hash: fpHash }));
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: SIMILAR FINDINGS
// ══════════════════════════════════════════════════════════════════

function findSimilar(finding) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'find_similar', finding: finding, top_k: 5 }));
}

function showSimilarModal(similarFindings, queryHash) {
  if (!similarFindings || similarFindings.length === 0) {
    showToast('No similar findings in memory yet', 'info');
    return;
  }
  const modal = document.getElementById('modal-overlay') || createModal();
  const body = document.getElementById('modal-body');
  if (!body) return;
  body.innerHTML = `
    <h3 style="margin-bottom:12px;color:var(--purple)">🔍 Similar Findings in Memory</h3>
    <p style="font-size:12px;color:var(--t3);font-family:var(--mono);margin-bottom:14px">
      ${similarFindings.length} similar finding${similarFindings.length !== 1 ? 's' : ''} found across past scans.
    </p>
    ${similarFindings.map(f => `
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">
          <span style="font-family:var(--mono);font-size:13px;color:var(--t1)">${esc(f.content?.slice(0,80) || f.doc_id || '-')}</span>
          <span style="font-size:11px;color:var(--t3);font-family:var(--mono)">${Math.round((f.similarity || 0) * 100)}% similar</span>
        </div>
        <div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-top:4px">${esc(f.target || '-')} · ${esc(f.severity || '-')}</div>
      </div>`).join('')}`;
  modal.classList.add('show');
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: SETTINGS ACTIONS
// ══════════════════════════════════════════════════════════════════

function loadDiskUsage() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'get_disk_usage' }));
}

function renderDiskUsage(usage) {
  const el = document.getElementById('disk-usage-detail');
  if (!el) return;
  const byTarget = Object.entries(usage.by_target_mb || {})
    .sort(([,a],[,b]) => b - a)
    .slice(0, 10)
    .map(([t, mb]) => `<div style="display:flex;justify-content:space-between;padding:2px 0;font-size:12px;color:var(--t2)"><span>${esc(t)}</span><span style="color:var(--t3)">${mb} MB</span></div>`)
    .join('');
  el.innerHTML = `
    <div style="display:flex;justify-content:space-between;margin-bottom:8px">
      <span style="color:var(--t1);font-weight:600">Total: ${usage.total_mb || 0} MB</span>
      <span style="color:var(--t3);font-size:12px">${usage.scan_count || 0} scan directories</span>
    </div>
    ${byTarget || '<div style="color:var(--t3);font-size:12px">No scan data found.</div>'}`;
}

function purgeTarget() {
  const input = document.getElementById('purge-target-input');
  const target = input?.value?.trim();
  if (!target) return showToast('Enter a target domain', 'err');
  if (!confirm(`Delete ALL scan data for ${target}?\n\nThis cannot be undone. Memory profiles and FP registry are kept.`)) return;
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'purge_target', target }));
}

function loadCurrentConfig() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'get_config' }));
}

function renderConfig(config) {
  const display = document.getElementById('config-display');
  const tbody = document.getElementById('config-table-body');
  if (!display || !tbody) return;
  display.style.display = 'block';
  const LABELS = {
    ai_backend: 'AI Backend', ollama_model: 'Ollama Model', has_gemini_key: 'Gemini Key Set',
    has_groq_key: 'Groq Key Set', default_severity: 'Default Severity',
    default_stages: 'Default Stages', intrusive_enabled: 'Intrusive Mode',
    auto_resume: 'Auto-Resume', data_retention: 'Data Retention',
    scrub_pii_logs: 'Scrub PII in Logs', audit_enabled: 'Audit Log',
    learning_enabled: 'Learning', fp_memory: 'FP Memory',
    attack_narrative: 'Attack Narrative', web_port: 'Web Port', ws_port: 'WS Port',
  };
  tbody.innerHTML = Object.entries(config).map(([k, v]) => `
    <tr style="border-bottom:1px solid rgba(255,255,255,.04)">
      <td style="padding:6px 0;color:var(--t3);width:180px">${LABELS[k] || k}</td>
      <td style="padding:6px 0;color:${v === true ? 'var(--green)' : v === false ? 'var(--red)' : 'var(--t2)'};font-weight:${typeof v === 'boolean' ? '600' : '400'}">
        ${v === true ? '✓ enabled' : v === false ? '✗ disabled' : esc(String(v))}
      </td>
    </tr>`).join('');
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: TARGET NOTES MODAL
// ══════════════════════════════════════════════════════════════════

function showTargetNotes(target, currentNotes, currentProgram) {
  const modal = getOrCreateNotesModal();
  document.getElementById('notes-modal-target').textContent = target;
  document.getElementById('notes-modal-notes').value = currentNotes || '';
  document.getElementById('notes-modal-program').value = currentProgram || '';
  document.getElementById('notes-modal-save').onclick = () => saveTargetNotes(target);
  modal.classList.add('show');
}

function getOrCreateNotesModal() {
  let modal = document.getElementById('notes-modal');
  if (modal) return modal;
  modal = document.createElement('div');
  modal.id = 'notes-modal';
  modal.className = 'modal-overlay';
  modal.innerHTML = `
    <div class="modal">
      <h3>Target Notes — <span id="notes-modal-target"></span></h3>
      <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:16px">
        <div class="field">
          <label>Program</label>
          <input id="notes-modal-program" type="text" placeholder="HackerOne / Bugcrowd / custom"
            style="background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--t1);padding:8px 11px;font-family:var(--mono);font-size:13px;outline:none"/>
        </div>
        <div class="field">
          <label>Notes</label>
          <textarea id="notes-modal-notes" rows="4"
            placeholder="Scope notes, interesting findings, program quirks..."
            style="background:var(--bg1);border:1px solid var(--border);border-radius:6px;color:var(--t1);padding:8px 11px;font-family:var(--mono);font-size:13px;outline:none;resize:vertical;width:100%"></textarea>
        </div>
      </div>
      <div class="modal-actions">
        <button class="btn-modal" onclick="document.getElementById('notes-modal').classList.remove('show')">Cancel</button>
        <button class="btn-modal primary" id="notes-modal-save">Save Notes</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  return modal;
}

function saveTargetNotes(target) {
  const notes = document.getElementById('notes-modal-notes')?.value || '';
  const program = document.getElementById('notes-modal-program')?.value || '';
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({ action: 'update_target_notes', target, notes, program }));
  document.getElementById('notes-modal')?.classList.remove('show');
  showToast('Notes saved');
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: ATTACK NARRATIVE DISPLAY
// ══════════════════════════════════════════════════════════════════

function renderAttackNarrative(narrative, container) {
  if (!narrative || !container) return;
  const block = document.createElement('div');
  block.style.cssText = `
    background:linear-gradient(135deg,rgba(255,69,97,.06),rgba(255,140,66,.04));
    border:1px solid rgba(255,69,97,.25);border-radius:10px;padding:16px 18px;margin-bottom:14px`;
  block.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
      <span style="font-size:16px">⚔️</span>
      <div style="font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--red);font-family:var(--mono)">
        AI Attack Chain Narrative
      </div>
      <span style="font-size:10px;padding:1px 7px;border-radius:10px;background:rgba(255,69,97,.12);color:var(--red);border:1px solid rgba(255,69,97,.3);font-family:var(--mono)">
        SENTINEL Phase 2
      </span>
    </div>
    <div style="color:var(--t2);font-size:14px;line-height:1.8;white-space:pre-wrap">${esc(narrative)}</div>`;
  container.prepend(block);
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: TOAST NOTIFICATIONS
// ══════════════════════════════════════════════════════════════════

function showToast(msg, type = 'ok') {
  const COLORS = { ok: 'var(--green)', err: 'var(--red)', info: 'var(--t3)', warn: 'var(--yellow)' };
  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:9999;
    background:var(--bg2);border:1px solid ${COLORS[type]||'var(--border)'};
    border-radius:10px;padding:12px 18px;font-family:var(--mono);font-size:13px;
    color:${COLORS[type]||'var(--t1)'};box-shadow:0 8px 32px rgba(0,0,0,.4);
    animation:slideIn .2s ease-out;max-width:360px;word-break:break-all`;
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all .3s';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: HELPERS
// ══════════════════════════════════════════════════════════════════

function startScanForTarget(target) {
  const targetInput = document.getElementById('target');
  if (targetInput) targetInput.value = target;
  showPanel('config');
  checkResume(target);
}

function createModal() {
  const overlay = document.createElement('div');
  overlay.id = 'modal-overlay';
  overlay.className = 'modal-overlay';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.classList.remove('show'); };
  overlay.innerHTML = `
    <div class="modal" style="max-width:600px">
      <div id="modal-body"></div>
      <div class="modal-actions" style="margin-top:16px">
        <button class="btn-modal" onclick="document.getElementById('modal-overlay').classList.remove('show')">Close</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  return overlay;
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: WEBSOCKET MESSAGE HANDLER ADDITIONS
// Patch the existing ws.onmessage handler to handle Phase 2 messages
// ══════════════════════════════════════════════════════════════════

function handlePhase2Message(data) {
  switch(data.type) {
    case 'memory_summary':
      renderMemoryPanel(data.data || {});
      renderSkillRegistry(data.data || {});
      break;
    case 'fp_marked':
      showToast(`🚫 False positive registered`, 'warn');
      if (_activeMemoryTab === 'fps') loadFPList();
      break;
    case 'fp_cleared':
      showToast('FP mark removed');
      if (_activeMemoryTab === 'fps') loadFPList();
      break;
    case 'fp_list':
      renderFPList(data.fps, data.target);
      break;
    case 'target_profile':
      // Could show in a modal or update UI
      break;
    case 'target_profiles':
      // Could render a dedicated view
      break;
    case 'target_notes_updated':
      showToast('Notes saved');
      refreshMemory();
      break;
    case 'payload_stats':
      renderPayloadStats(data);
      break;
    case 'audit_log':
      renderAuditLog(data.entries);
      break;
    case 'disk_usage':
      renderDiskUsage(data.usage);
      break;
    case 'target_purged':
      showToast(`🗑️ Purged ${data.deleted_count} scan director${data.deleted_count !== 1 ? 'ies' : 'y'} for ${data.target}`);
      loadDiskUsage();
      break;
    case 'program_templates':
      renderProgramTemplates(data.templates);
      break;
    case 'resume_available':
      if (data.run_dir && data.state) {
        showResumeBanner(data.target, data.run_dir, data.state);
      }
      break;
    case 'config':
      renderConfig(data.config);
      break;
    case 'similar_findings':
      showSimilarModal(data.findings, data.query_hash);
      break;
  }
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: INIT
// ══════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  // Only inject panels if they don't already exist in ui.html
  if (!document.getElementById('panel-memory')) {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
      const div = document.createElement('div');
      div.innerHTML = MEMORY_NAV_HTML;
      sidebar.appendChild(div);
    }

    const main = document.querySelector('.main');
    if (main) {
      const memDiv = document.createElement('div');
      memDiv.innerHTML = MEMORY_PANEL_HTML;
      main.appendChild(memDiv.firstElementChild);

      const settingsDiv = document.createElement('div');
      settingsDiv.innerHTML = SETTINGS_PANEL_HTML;
      main.appendChild(settingsDiv.firstElementChild);
    }
  }

  // Add CSS for slide-in animation if not already present
  if (!document.querySelector('style[data-phase2="true"]')) {
    const style = document.createElement('style');
    style.setAttribute('data-phase2', 'true');
    style.textContent = `
      @keyframes slideIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
      #panel-memory .report-section { display:none; flex:1; overflow-y:auto; padding:18px; flex-direction:column; gap:10px; min-height:0; }
      #panel-memory .report-section.active { display:flex; }
    `;
    document.head.appendChild(style);
  }

  // Load program templates on init
  setTimeout(() => {
    loadProgramTemplates();
  }, 1500);
});

// Export Phase 2 handler for integration with existing ws.onmessage
window._phase2Handler = handlePhase2Message;
window._phase2 = {
  checkResume, refreshMemory, loadFPList, toggleFP, findSimilar,
  loadDiskUsage, purgeTarget, loadCurrentConfig, loadAuditLog,
  loadProgramTemplates, applyTemplate, showToast,
};

// Patch showPanel to load data when switching to memory/settings
const _origShowPanel = window.showPanel;
if (_origShowPanel) {
  window.showPanel = function(id) {
    _origShowPanel(id);
    if (id === 'memory') refreshMemory();
    if (id === 'settings') {
      loadProgramTemplates();
      loadDiskUsage();
    }
  };
}

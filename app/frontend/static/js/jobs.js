// jobs.js — job list, job detail panel, status polling

// Statuses that mean a job is still running / waiting for action
const _ACTIVE_STATUSES = new Set([
  'pending','parsing','classifying','documenting','verifying',
  'awaiting_review','assigning_stack','converting',
  'security_scanning','validating','awaiting_security_review',
  'reviewing','testing','awaiting_code_review'
]);

// Persists across re-renders so toggle state survives polling.
let historyOpen    = false;
let historyOpenSet = false;

let archiveOpen    = false;
let archiveOpenSet = false;

// ── Live sidebar: Running + Gate activity ─────────────────────────────────
const STEP_NAMES = ['','Parse','Classify','Document','Verify','Analysis Sign-off','Stack','Convert',
  'Sec Scan','Security Sign-off','Quality','Test Gen','Final Sign-off'];

function refreshSidebarActivity() {
  const jobs = _allJobs || [];

  // ── Running jobs ──────────────────────────────────
  const running = jobs.filter(j => _RUNNING_SET.has(j.status));
  const rEl = document.getElementById('sidebarRunning');
  const rCt = document.getElementById('sidebarRunningCount');
  if (rEl) {
    if (!running.length) {
      rEl.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:4px 0">No active jobs</div>';
      if (rCt) rCt.style.display = 'none';
    } else {
      if (rCt) { rCt.textContent = running.length; rCt.style.display = ''; }
      rEl.innerHTML = running.slice(0, 6).map(j => {
        const step = j.current_step || 1;
        const stepName = STEP_NAMES[step] || `Step ${step}`;
        const pct = Math.round((step - 1) / 12 * 100);
        return `<div onclick="openJob('${j.job_id}')" title="${esc(j.filename)}"
          style="padding:6px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;cursor:pointer;transition:border-color .12s"
          onmouseenter="this.style.borderColor='var(--accent)'" onmouseleave="this.style.borderColor='var(--border)'">
          <div style="font-size:11px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:4px">${esc(j.filename)}</div>
          <div style="height:3px;background:var(--border);border-radius:2px;margin-bottom:4px">
            <div style="height:100%;width:${pct}%;background:var(--accent);border-radius:2px;transition:width .3s"></div>
          </div>
          <div style="display:flex;align-items:center;justify-content:space-between">
            <span style="font-size:10px;color:var(--accent);font-weight:600">${stepName}</span>
            <span style="font-size:10px;color:var(--muted);font-family:monospace">${shortId(j.job_id)}</span>
          </div>
        </div>`;
      }).join('');
    }
  }

  // ── Jobs at a gate ────────────────────────────────
  const gates = jobs.filter(j => _GATE_SET.has(j.status));
  const gEl = document.getElementById('sidebarGates');
  const gCt = document.getElementById('sidebarGateCount');
  if (gEl) {
    if (!gates.length) {
      gEl.innerHTML = '<div style="font-size:11px;color:var(--muted);padding:4px 0">No pending gates</div>';
      if (gCt) gCt.style.display = 'none';
    } else {
      if (gCt) { gCt.textContent = gates.length; gCt.style.display = ''; }
      const gateLabel = { awaiting_review:'Analysis Sign-off', awaiting_security_review:'Security Sign-off', awaiting_code_review:'Final Sign-off' };
      gEl.innerHTML = gates.slice(0, 6).map(j => {
        const gl = gateLabel[j.status] || 'Gate';
        return `<div onclick="openJobForReview('${j.job_id}')" title="${esc(j.filename)}"
          style="padding:6px 8px;background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.2);border-radius:6px;cursor:pointer;transition:border-color .12s"
          onmouseenter="this.style.borderColor='#fbbf24'" onmouseleave="this.style.borderColor='rgba(251,191,36,.2)'">
          <div style="font-size:11px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:3px">${esc(j.filename)}</div>
          <div style="display:flex;align-items:center;justify-content:space-between">
            <span style="font-size:10px;font-weight:700;color:#fbbf24">⏸ ${gl}</span>
            <span style="font-size:10px;color:var(--muted);font-family:monospace">${shortId(j.job_id)}</span>
          </div>
        </div>`;
      }).join('');
    }
  }
}

function applyJobFilter() {
  const query      = (document.getElementById('jobSearchInput')?.value  || '').trim().toLowerCase();
  const statusFilt = (document.getElementById('jobStatusFilter')?.value || '').trim();

  const badge = document.getElementById('jobCountBadge');
  if (badge) badge.textContent = _allJobs.length ? `${_allJobs.length} total` : '';

  if (!query && !statusFilt) {
    _jobPage = 0;
    renderJobList(_allJobs, _allHistory);
    _updatePagination(0, 0);
    return;
  }

  const _RUNNING = new Set(['pending','parsing','classifying','documenting','verifying',
    'assigning_stack','converting','security_scanning','validating',
    'reviewing','testing']);

  let filtered = _allJobs.filter(j => {
    if (query && !(j.filename || '').toLowerCase().includes(query)) return false;
    if (statusFilt) {
      if (statusFilt === 'running' && !_RUNNING.has(j.status)) return false;
      if (statusFilt !== 'running' && j.status !== statusFilt) return false;
    }
    return true;
  });

  const total  = filtered.length;
  const pages  = Math.max(1, Math.ceil(total / _JOB_PAGE_SIZE));
  _jobPage     = Math.min(_jobPage, pages - 1);
  const slice  = filtered.slice(_jobPage * _JOB_PAGE_SIZE, (_jobPage + 1) * _JOB_PAGE_SIZE);

  const el = document.getElementById('jobList');
  if (!el) return;
  if (!slice.length) {
    el.innerHTML = '<div class="empty" style="padding:16px 0"><div style="font-size:12px;color:var(--muted)">No jobs match your filter.</div></div>';
  } else {
    el.innerHTML = slice.map(j => renderJobItem(j)).join('');
  }

  _updatePagination(total, pages);
}

function _updatePagination(total, pages) {
  const pag   = document.getElementById('jobPagination');
  const label = document.getElementById('jobPageLabel');
  const prev  = document.getElementById('jobPagePrev');
  const next  = document.getElementById('jobPageNext');
  if (!pag) return;

  if (pages <= 1) { pag.style.display = 'none'; return; }

  pag.style.display = 'flex';
  const start = _jobPage * _JOB_PAGE_SIZE + 1;
  const end   = Math.min((_jobPage + 1) * _JOB_PAGE_SIZE, total);
  if (label) label.textContent = `${start}–${end} of ${total}`;
  if (prev)  prev.disabled  = _jobPage === 0;
  if (next)  next.disabled  = _jobPage >= pages - 1;
}

function jobPageChange(delta) {
  _jobPage = Math.max(0, _jobPage + delta);
  applyJobFilter();
}

function toggleHistory() {
  if (!historyOpenSet) {
    const list = document.getElementById('historyList');
    historyOpen = list ? list.style.display === 'none' : true;
  } else {
    historyOpen = !historyOpen;
  }
  historyOpenSet = true;
  const list    = document.getElementById('historyList');
  const chevron = document.getElementById('historyChevron');
  if (list)    list.style.display = historyOpen ? 'flex' : 'none';
  if (chevron) chevron.style.transform = historyOpen ? 'rotate(0deg)' : 'rotate(-90deg)';
}

function toggleArchive() {
  if (!archiveOpenSet) {
    const list = document.getElementById('archiveList');
    archiveOpen = list ? list.style.display === 'none' : true;
  } else {
    archiveOpen = !archiveOpen;
  }
  archiveOpenSet = true;
  const list    = document.getElementById('archiveList');
  const chevron = document.getElementById('archiveChevron');
  if (list)    list.style.display = archiveOpen ? 'flex' : 'none';
  if (chevron) chevron.style.transform = archiveOpen ? 'rotate(0deg)' : 'rotate(-90deg)';
}

function renderJobItem(j, inBatch = false) {
  const [cls, label] = STATUS_BADGE[j.status] || ['badge-pending', j.status];
  const isActive    = j.job_id === currentJobId;
  const isComplete  = j.status === 'complete';
  const stepDisplay = Math.min(j.current_step, 12);
  const displayName = inBatch ? esc(j.filename).replace(/^[^/]+\//, '') : esc(j.filename);
  return `<div class="job-item ${isActive ? 'active':''} ${isComplete ? 'status-complete' : ''} ${inBatch ? 'batch-child' : ''}" onclick="openJob('${j.job_id}')">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:4px">
      <div style="min-width:0">
        <div class="job-name">${displayName}</div>
        <div class="job-meta"><span class="badge ${cls}">${label}</span> &nbsp; Step ${stepDisplay}/12 ${j.complexity ? '· <strong>'+j.complexity+'</strong>' : ''}</div>
      </div>
      <button
        title="Delete job"
        onclick="event.stopPropagation(); deleteJob('${j.job_id}', '${esc(j.filename)}')"
        style="flex-shrink:0;background:none;border:none;cursor:pointer;padding:2px 5px;border-radius:4px;color:var(--muted);font-size:14px;line-height:1;opacity:0.5;transition:opacity .15s,color .15s"
        onmouseenter="this.style.opacity='1';this.style.color='var(--danger)'"
        onmouseleave="this.style.opacity='0.5';this.style.color='var(--muted)'">🗑</button>
    </div>
  </div>`;
}

function _batchSummaryLabel(jobs) {
  const total    = jobs.length;
  const complete = jobs.filter(j => j.status === 'complete').length;
  const blocked  = jobs.filter(j => j.status === 'blocked' || j.status === 'failed').length;
  const waiting  = jobs.filter(j => ['awaiting_review','awaiting_security_review','awaiting_code_review'].includes(j.status)).length;
  const running  = total - complete - blocked - waiting;
  const parts = [];
  if (complete) parts.push(`${complete} complete`);
  if (waiting)  parts.push(`${waiting} awaiting review`);
  if (running)  parts.push(`${running} running`);
  if (blocked)  parts.push(`${blocked} blocked`);
  return parts.join(' · ') || `${total} jobs`;
}

function renderBatchGroup(batchId, jobs) {
  const summaryLabel = _batchSummaryLabel(jobs);
  const allDone = jobs.every(j => !_ACTIVE_STATUSES.has(j.status));
  const anyComplete = jobs.some(j => j.status === 'complete');
  const borderColor = allDone ? (anyComplete ? 'rgba(34,197,94,.4)' : 'rgba(239,68,68,.3)') : 'var(--accent)';
  return `
  <div class="batch-group" style="border:1px solid ${borderColor};border-radius:8px;padding:8px;margin-bottom:2px;background:rgba(255,255,255,.02)">
    <div style="font-size:10px;font-weight:700;letter-spacing:.5px;color:var(--muted);text-transform:uppercase;margin-bottom:6px;display:flex;align-items:center;gap:6px">
      <span>📦 Batch · ${jobs.length} mappings</span>
      <span style="font-weight:400;font-size:10px;color:var(--muted)">${summaryLabel}</span>
    </div>
    <div style="display:flex;flex-direction:column;gap:4px">
      ${jobs.map(j => renderJobItem(j, true)).join('')}
    </div>
  </div>`;
}

function renderJobList(jobs, history = []) {
  const el = document.getElementById('jobList');
  if (!jobs.length && !history.length) {
    el.innerHTML = '<div class="empty" style="padding:20px 0"><div style="font-size:24px">📋</div><div style="font-size:12px;margin-top:8px">No jobs yet</div></div>';
    return;
  }

  const batchMap = {};
  const standalone = [];
  for (const j of jobs) {
    if (j.batch_id) {
      (batchMap[j.batch_id] = batchMap[j.batch_id] || []).push(j);
    } else {
      standalone.push(j);
    }
  }

  const batchEntries = Object.entries(batchMap);
  const activeBatches = batchEntries.filter(([, bj]) => bj.some(j => _ACTIVE_STATUSES.has(j.status)));
  const pastBatches   = batchEntries.filter(([, bj]) => bj.every(j => !_ACTIVE_STATUSES.has(j.status)));

  const active = standalone.filter(j =>  _ACTIVE_STATUSES.has(j.status));
  const past   = standalone.filter(j => !_ACTIVE_STATUSES.has(j.status));

  let html = '';

  if (active.length || activeBatches.length) {
    html += activeBatches.map(([bid, bj]) => renderBatchGroup(bid, bj)).join('');
    html += active.map(j => renderJobItem(j)).join('');
  }

  const hasPast = past.length > 0 || pastBatches.length > 0;
  if (hasPast) {
    const pastCount   = past.length + pastBatches.reduce((n, [, bj]) => n + bj.length, 0);
    const defaultOpen = active.length === 0 && activeBatches.length === 0;
    const showPast    = historyOpenSet ? historyOpen : defaultOpen;
    html += `
    <div class="history-header" onclick="toggleHistory()">
      <span style="font-size:10px;font-weight:700;letter-spacing:.7px;color:var(--muted);text-transform:uppercase">History (${pastCount})</span>
      <span id="historyChevron" class="history-chevron" style="transform:${showPast?'rotate(0deg)':'rotate(-90deg)'}">▼</span>
    </div>
    <div id="historyList" style="display:${showPast?'flex':'none'};flex-direction:column;gap:6px">
      ${pastBatches.map(([bid, bj]) => renderBatchGroup(bid, bj)).join('')}
      ${past.map(j => renderJobItem(j)).join('')}
    </div>`;
  }

  if (history.length) {
    const archOpen = historyOpenSet ? historyOpen : (active.length === 0);
    html += `
    <div class="history-header" onclick="toggleArchive()" style="margin-top:4px">
      <span style="font-size:10px;font-weight:700;letter-spacing:.7px;color:var(--muted);text-transform:uppercase">Log Archive (${history.length})</span>
      <span id="archiveChevron" class="history-chevron" style="transform:${archOpen?'rotate(0deg)':'rotate(-90deg)'}">▼</span>
    </div>
    <div id="archiveList" style="display:${archOpen?'flex':'none'};flex-direction:column;gap:6px">
      ${history.map(h => renderArchiveItem(h)).join('')}
    </div>`;
  }

  el.innerHTML = html;
}

function renderArchiveItem(h) {
  const name    = esc(h.mapping_name || h.xml_filename || h.job_id.slice(0,8));
  const status  = esc(h.status || 'unknown');
  const dateStr = (h.started_at || '').slice(0,10);
  const isActive = h.job_id === currentJobId;
  return `<div class="job-item ${isActive?'active':''}"
    onclick="openHistoryJob('${h.job_id}','${name}')"
    style="opacity:${h.log_readable?'1':'0.5'}" title="${h.log_readable?'':'Log file missing'}">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:4px">
      <div style="min-width:0">
        <div class="job-name">${name}</div>
        <div class="job-meta"><span class="badge badge-success">${status}</span>&nbsp; ${dateStr}</div>
      </div>
      <span style="font-size:11px;color:var(--muted)" title="Archived log">🗄</span>
    </div>
  </div>`;
}

async function openHistoryJob(jobId, name) {
  if (eventSource) { eventSource.close(); eventSource = null; }
  currentJobId = jobId;
  await loadJobs();
  setMainView('dashboard');

  const jdc = document.getElementById('jobDetailContainer');
  const sfc = document.getElementById('submitFormContainer');
  if (sfc) sfc.style.display = 'none';
  if (jdc) { jdc.style.display = 'flex'; jdc.innerHTML = `<div style="padding:32px;color:var(--muted);font-size:13px">Loading log archive…</div>`; }

  try {
    const res  = await fetch(`/api/logs/history/${jobId}`);
    if (!res.ok) { if (jdc) jdc.innerHTML = `<div style="padding:32px;color:var(--danger)">Log file not found on disk.</div>`; return; }
    const data = await res.json();
    const entries = data.entries || [];

    const rows = entries.map(e => {
      const ts   = (e.ts||'').slice(11,19);
      const step = e.step != null ? `step ${e.step}`.padEnd(6) : '      ';
      const lvl  = e.level || 'INFO';
      const msg  = esc(e.message || '');
      const extra = e.data ? `<span class="log-data">  ${esc(JSON.stringify(e.data))}</span>` : '';
      const exc   = e.exc  ? `<span class="log-exc">${esc(e.exc)}</span>` : '';
      return `<div class="log-row">
        <span class="log-ts">${ts}</span>
        <span class="log-step">${esc(step)}</span>
        <span class="log-lvl ${lvl}">${lvl}</span>
        <span class="log-msg">${msg}${extra}${exc}</span>
      </div>`;
    }).join('') || '<div style="color:var(--muted);padding:8px 0;font-size:11px">No log entries found.</div>';

    if (jdc) jdc.innerHTML = `
      <div class="panel-header" style="display:flex;align-items:center;justify-content:space-between">
        <div>
          <div class="panel-title">🗄 ${name}</div>
          <div class="panel-sub" style="margin-bottom:0">Archived log &nbsp;·&nbsp; ${entries.length} entries &nbsp;·&nbsp; Job ID: ${jobId}</div>
        </div>
      </div>
      <div class="log-panel" style="margin-top:16px">
        <div class="log-header" style="display:flex;align-items:center;justify-content:space-between">
          <span class="panel-sub" style="font-weight:700">Pipeline Log (archived)</span>
        </div>
        <div class="log-scroll" id="logScroll" style="height:500px;overflow-y:auto">${rows}</div>
      </div>`;
    const scroll = document.getElementById('logScroll');
    if (scroll) scroll.scrollTop = scroll.scrollHeight;
  } catch(e) {
    if (jdc) jdc.innerHTML = `<div style="padding:32px;color:var(--danger)">Failed to load log: ${esc(String(e))}</div>`;
  }
}

// ─────────────────────────────────────────────
// Open Job
// ─────────────────────────────────────────────
async function openJob(jobId) {
  if (eventSource) { eventSource.close(); eventSource = null; }
  currentJobId = jobId;
  setMainView('dashboard');
  await loadJobs();

  const res = await fetch(`/api/jobs/${jobId}`);
  const job = await res.json();
  renderJobPanel(job);

  eventSource = new EventSource(`/api/jobs/${jobId}/stream`);
  // Track whether the pipeline sent real progress so we know if the final
  // re-render on 'done' is needed.  Gate-waiting jobs emit an immediate
  // 'state' + 'done' burst with no active pipeline — re-rendering on those
  // clears whatever the reviewer typed in the sign-off form.
  let _sseHadProgress = false;
  eventSource.onmessage = async (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'progress') {
      // Active pipeline step — re-render to show updated progress.
      _sseHadProgress = true;
      const updated = await fetch(`/api/jobs/${jobId}`);
      renderJobPanel(await updated.json());
      await loadJobs();
    } else if (msg.type === 'done') {
      eventSource.close();
      // Only re-render if the pipeline actually ran (had progress events).
      // Without this guard, gate-waiting jobs immediately get re-rendered,
      // wiping reviewer name / notes the user just started typing.
      if (_sseHadProgress) {
        const updated = await fetch(`/api/jobs/${jobId}`);
        renderJobPanel(await updated.json());
        await loadJobs();
      }
    }
    // 'state' and 'heartbeat' — informational only, no re-render needed.
  };
  eventSource.onerror = () => eventSource.close();
}

// ─────────────────────────────────────────────
// Render Job Panel
// ─────────────────────────────────────────────
function renderJobPanel(job) {
  const state = job.state || {};
  window._currentJobState = state;
  const [badgeCls, badgeLabel] = STATUS_BADGE[job.status] || ['badge-pending', job.status];
  const isRejected = job.status === 'blocked' && state.sign_off?.decision === 'REJECTED';

  window._currentJob = job;

  let html = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:6px">
      <div>
        <div class="panel-title" style="margin-bottom:4px">${esc(job.filename)} <span class="badge ${badgeCls}" style="font-size:12px;vertical-align:middle">${badgeLabel}</span></div>
        <div class="panel-sub" style="margin-bottom:0">
          <span style="font-family:monospace;font-size:12px;font-weight:700;color:var(--accent);letter-spacing:.5px" title="Tracking ID (short form of Job ID)">${shortId(job.job_id)}</span>
          &nbsp;·&nbsp; <span style="font-size:11px;color:var(--muted)" title="Full Job ID">${job.job_id}</span>
          &nbsp;·&nbsp; Started: ${utcDate(job.created_at).toLocaleString()}
        </div>
      </div>
      <div class="report-actions" style="margin-bottom:0;flex-shrink:0;display:flex;align-items:center;gap:6px">
        <span class="lbl">Reports:</span>
        <div class="report-dropdown" style="position:relative;display:inline-block">
          <button class="btn btn-ghost btn-sm report-dropdown-toggle" title="Download Complete Conversion Report"
                  onclick="this.closest('.report-dropdown').classList.toggle('open')"
                  onblur="setTimeout(()=>this.closest('.report-dropdown').classList.remove('open'),150)">
            📄 Complete Report ▾
          </button>
          <div class="report-dropdown-menu" style="display:none;position:absolute;right:0;top:calc(100% + 4px);background:var(--surface2);border:1px solid var(--border);border-radius:8px;min-width:160px;z-index:200;box-shadow:0 4px 16px rgba(0,0,0,.4);overflow:hidden">
            <button class="report-dropdown-item" onclick="downloadReportMd();this.closest('.report-dropdown').classList.remove('open')"
                    style="display:flex;align-items:center;gap:8px;width:100%;padding:9px 14px;background:none;border:none;color:var(--text);font-size:12px;cursor:pointer;text-align:left;white-space:nowrap"
                    onmouseover="this.style.background='var(--surface)'" onmouseout="this.style.background='none'">
              📄 Download (.md)
            </button>
            <button class="report-dropdown-item" onclick="openPrintReport();this.closest('.report-dropdown').classList.remove('open')"
                    style="display:flex;align-items:center;gap:8px;width:100%;padding:9px 14px;background:none;border:none;color:var(--text);font-size:12px;cursor:pointer;text-align:left;white-space:nowrap"
                    onmouseover="this.style.background='var(--surface)'" onmouseout="this.style.background='none'">
              🖨️ Print / PDF
            </button>
          </div>
        </div>
        ${state.has_manifest || state.manifest_report ? `
        <button class="btn btn-ghost btn-sm" title="Download S2T Manifest — fill in yellow rows, re-upload before converting"
                onclick="downloadManifestXlsx()" style="color:#c07000;border-color:#c07000">
          📊 S2T Manifest
        </button>` : ''}
        <button class="btn btn-ghost btn-sm" title="Governance snapshot — scores, sign-off chain, flags, security findings"
                onclick="downloadAuditReport('${job.job_id}')" style="color:#818cf8;border-color:#818cf8">
          🔍 Summary
        </button>
      </div>
    </div>
    ${renderStepper(job.current_step, job.status)}
  `;

  // ── ERROR CARD ────────────────────────────
  if ((job.status === 'failed' || job.status === 'blocked') && !isRejected) {
    const hasTrace = !!state.error_detail;
    const traceId  = 'trace_' + Math.random().toString(36).slice(2);

    let errorMsg = state.error || '';
    if (!errorMsg && state.parse_report) {
      const flags = state.parse_report.flags || [];
      if (flags.length) errorMsg = flags.map(f => f.detail).join(' | ');
    }
    if (!errorMsg) errorMsg = `Pipeline stopped at Step ${job.current_step}. Check the parse report below for details.`;

    let hint = 'Check the details above. Common causes: invalid XML structure, missing ANTHROPIC_API_KEY, network timeout, or unsupported transformation type.';
    if (errorMsg.toLowerCase().includes('workflow') && errorMsg.toLowerCase().includes('mapping')) {
      hint = '💡 It looks like you uploaded a Workflow XML as the primary mapping file. Use the <strong>Mapping XML</strong> field for the mapping export, and the optional <strong>Workflow XML</strong> field for the workflow file.';
    } else if (errorMsg.toLowerCase().includes('no mapping')) {
      hint = '💡 No Mapping definitions were found in the uploaded file. Make sure you export the Mapping (not the Workflow or Session) from Informatica Designer.';
    } else if (errorMsg.toLowerCase().includes('api_key') || errorMsg.toLowerCase().includes('api key')) {
      hint = '💡 ANTHROPIC_API_KEY is missing or invalid. Set it in your .env file and restart the server.';
    }

    html += `<div class="error-card">
      <div class="card-title"><span class="icon">🚨</span> Pipeline Stopped — Step ${job.current_step}</div>
      <div class="error-msg">${esc(errorMsg)}</div>
      ${hasTrace ? `
        <span class="error-toggle" onclick="toggleTrace('${traceId}')">▶ Show full traceback</span>
        <pre class="error-trace" id="${traceId}">${esc(state.error_detail)}</pre>
      ` : ''}
      <div class="error-actions">
        <div class="info-box" style="margin-bottom:0;flex:1">
          <strong>What to do:</strong> <span>${hint}</span>
        </div>
        <button class="btn btn-ghost btn-sm" onclick="retryJob('${job.job_id}')" title="Re-run the pipeline with the same XML file">🔄 Retry</button>
        <button class="btn btn-ghost btn-sm" onclick="reuploadForJob(${JSON.stringify(hint)})">↩ Submit New File</button>
      </div>
    </div>`;
  }

  // ── REJECTED CARD ─────────────────────────
  if (isRejected) {
    const sr = state.sign_off;
    html += `<div class="rejected-card">
      <h3>✗ Review Rejected by ${esc(sr.reviewer_name)} (${esc(sr.reviewer_role)})</h3>
      ${sr.notes ? `<div style="font-size:13px;color:var(--muted);margin-bottom:4px">Notes: ${esc(sr.notes)}</div>` : ''}
      <div style="font-size:12px;color:var(--muted)">Reviewed: ${utcDate(sr.review_date).toLocaleString()}</div>
      <div class="next-steps">
        <div class="next-step">
          <div class="next-step-num">1</div>
          <div class="next-step-content">
            <strong>Review the flags raised in Step 4</strong>
            <span>Address each CRITICAL and HIGH severity flag. The verification report is shown below — check recommendations for each flag.</span>
          </div>
        </div>
        <div class="next-step">
          <div class="next-step-num">2</div>
          <div class="next-step-content">
            <strong>Fix the source Informatica mapping</strong>
            <span>Return to Informatica Designer, address the issues (e.g. remove dead logic, resolve parameters, remove unsupported transformations), and re-export the XML.</span>
          </div>
        </div>
        <div class="next-step">
          <div class="next-step-num">3</div>
          <div class="next-step-content">
            <strong>Start a new job with the corrected file</strong>
            <span>Use the upload panel on the left to submit the fixed XML. The pipeline will re-run from scratch and produce a fresh verification report.</span>
          </div>
        </div>
      </div>
      <div style="margin-top:14px">
        <button class="btn btn-warn btn-sm" onclick="reuploadForJob()">↩ Submit New File</button>
      </div>
    </div>`;
  }

  // ── STEP 1 — PARSE REPORT ─────────────────
  if (state.parse_report) {
    const pr = state.parse_report;
    html += `<div class="card">
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">🔍</span> Step 1 — Parse Report<span class="card-chevron">▼</span></div>
      <div class="card-body">
      <div class="stats">
        <div class="stat"><div class="stat-val">${Object.values(pr.objects_found||{}).reduce((a,b)=>a+b,0)}</div><div class="stat-label">Objects Found</div></div>
        <div class="stat"><div class="stat-val">${pr.mapping_names?.length||0}</div><div class="stat-label">Mappings</div></div>
        <div class="stat"><div class="stat-val">${pr.unresolved_parameters?.length||0}</div><div class="stat-label">Unresolved Params</div></div>
        <div class="stat"><div class="stat-val" style="font-size:14px;color:${pr.parse_status==='COMPLETE'?'#60a5fa':pr.parse_status==='PARTIAL'?'var(--warn)':'var(--danger)'}">${pr.parse_status==='COMPLETE'?'✓ Parsed':pr.parse_status}</div><div class="stat-label">Parse Status</div></div>
      </div>
      ${pr.mapping_names?.length ? `<div style="font-size:12px;color:var(--muted)">Mappings: <strong style="color:var(--text)">${pr.mapping_names.map(esc).join(', ')}</strong></div>` : ''}
      ${pr.unresolved_parameters?.length ? `<div style="font-size:12px;color:var(--warn);margin-top:8px">⚠️ Unresolved parameters: <code style="background:var(--bg);padding:2px 6px;border-radius:4px">${pr.unresolved_parameters.map(esc).join(', ')}</code></div>` : ''}
      ${pr.flags?.filter(f=>f.flag_type==='PARSE_ERROR').length ? `<div style="font-size:12px;color:var(--danger);margin-top:8px">Parse errors detected — see full flags in Step 4.</div>` : ''}
      ${renderCompletenessScore(pr)}
      </div>
    </div>`;
  }

  // ── STEP 2 — COMPLEXITY ───────────────────
  if (state.complexity) {
    const c = state.complexity;
    const tierClass = { 'Low':'tier-low','Medium':'tier-medium','High':'tier-high','Very High':'tier-veryhigh' }[c.tier] || '';
    html += `<div class="card">
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">📊</span> Step 2 — Complexity Classification<span class="card-chevron">▼</span></div>
      <div class="card-body">
      <div style="font-size:28px;font-weight:800;margin-bottom:12px" class="${tierClass}">${c.tier}</div>
      <div style="font-size:13px;color:var(--muted);margin-bottom:10px">Criteria matched:</div>
      ${c.criteria_matched?.map(cr=>`<div style="font-size:12px;padding:4px 0;border-bottom:1px solid var(--border)">· ${esc(cr)}</div>`).join('')||''}
      ${c.rationale ? `<div style="font-size:12px;color:var(--muted);margin-top:10px;font-style:italic">${esc(c.rationale)}</div>` : ''}
      ${c.special_flags?.length ? `<div style="margin-top:10px;padding:8px;background:rgba(248,113,113,.08);border-radius:6px;font-size:12px;color:var(--danger)">⚠️ ${c.special_flags.map(esc).join('<br/>⚠️ ')}</div>` : ''}
      ${renderConversionReadiness(c, state.parse_report)}
      </div>
    </div>`;
  }

  // ── STEP 2b — SOURCE-TO-TARGET MAPPING ───
  if (state.s2t && state.s2t.summary) {
    const s = state.s2t.summary;
    const hasUnmappedTgt = (s.unmapped_target_fields || 0) > 0;
    const hasUnmappedSrc = (s.unmapped_source_fields || 0) > 0;
    const records = state.s2t.records || [];
    const preview = records.slice(0, 8);
    const STATUS_COLORS = {
      'Direct':    '#f0fdf4', 'Derived':   '#fffbeb',
      'Lookup':    '#faf5ff', 'Filtered':  '#fff7ed',
      'Aggregated':'#faf5ff', 'Unmapped Target':'#fef2f2',
      'Unmapped Source':'#fef2f2',
    };
    html += `<div class="card" style="border-color:${hasUnmappedTgt?'var(--warn)':'var(--border)'}">
      <div class="card-title" onclick="toggleCard(this)" style="justify-content:space-between">
        <span><span class="icon">🗺️</span> Source-to-Target Mapping</span>
        <span style="display:flex;align-items:center;gap:8px">
          <button onclick="event.stopPropagation();downloadS2T('${job.job_id}')" style="padding:5px 12px;font-size:11px;background:var(--accent);color:#fff;border:none;border-radius:6px;cursor:pointer">⬇ Download Excel</button>
          <span class="card-chevron" style="margin-left:0">▼</span>
        </span>
      </div>
      <div class="card-body">
      <div class="stats" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
        <div class="stat"><div class="stat-val">${s.total_target_fields||0}</div><div class="stat-label">Target Fields</div></div>
        <div class="stat"><div class="stat-val" style="color:var(--accent2)">${s.mapped_fields||0}</div><div class="stat-label">Mapped</div></div>
        <div class="stat"><div class="stat-val" style="color:${hasUnmappedTgt?'var(--danger)':'var(--muted)'}">${s.unmapped_target_fields||0}</div><div class="stat-label">Unmapped Target</div></div>
        <div class="stat"><div class="stat-val" style="color:${hasUnmappedSrc?'var(--warn)':'var(--muted)'}">${s.unmapped_source_fields||0}</div><div class="stat-label">Unmapped Source</div></div>
      </div>
      <div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;font-size:12px">
        ${[['Direct','#f0fdf4','direct_mappings'],['Derived','#fffbeb','derived_mappings'],['Lookup','#faf5ff','lookup_enriched'],['Filtered','#fff7ed','filtered_fields']].map(([lbl,col,key])=>`
          <span style="display:inline-flex;align-items:center;gap:5px">
            <span style="width:12px;height:12px;border-radius:2px;background:${col};border:1px solid #cbd5e1;display:inline-block"></span>
            <span>${lbl}: <strong>${s[key]??0}</strong></span>
          </span>`).join('')}
      </div>
      ${hasUnmappedTgt ? `<div style="padding:8px 12px;background:rgba(248,113,113,.08);border-radius:6px;font-size:12px;color:var(--danger);margin-bottom:12px">
        ⚠️ ${s.unmapped_target_fields} target field(s) have no upstream source — see <strong>Unmapped Targets</strong> sheet in Excel.
      </div>` : ''}
      ${preview.length ? `
      <div style="font-size:12px;font-weight:700;color:var(--muted);margin-bottom:8px;display:flex;align-items:center;justify-content:space-between">
        <span>PREVIEW — first ${preview.length} of ${records.length} rows</span>
        ${records.length > 0 ? `<button onclick="openS2TModal()" style="padding:4px 12px;font-size:11px;background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:6px;cursor:pointer;font-weight:600">🔍 View Full Mapping (${records.length})</button>` : ''}
      </div>
      <div style="overflow-x:auto;border-radius:6px;border:1px solid var(--border)">
        <table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead>
            <tr style="background:#1e293b;color:#f8fafc">
              ${['Source Table','Source Field','→','Target Table','Target Field','Status','Logic'].map(h=>`<th style="padding:6px 8px;text-align:left;white-space:nowrap;font-weight:600">${h}</th>`).join('')}
            </tr>
          </thead>
          <tbody>
            ${preview.map((r,i)=>`<tr style="background:${i%2===0?(STATUS_COLORS[r.status]||'#fff'):'#f8fafc'}">
              <td style="padding:5px 8px;border-bottom:1px solid #e2e8f0;color:#1e3a8a;font-weight:700">${esc(r.source_table||'—')}</td>
              <td style="padding:5px 8px;border-bottom:1px solid #e2e8f0;color:#1e293b;font-weight:600">${esc(r.source_field||'—')}</td>
              <td style="padding:5px 8px;border-bottom:1px solid #e2e8f0;color:#64748b;text-align:center">→</td>
              <td style="padding:5px 8px;border-bottom:1px solid #e2e8f0;color:#14532d;font-weight:700">${esc(r.target_table||'—')}</td>
              <td style="padding:5px 8px;border-bottom:1px solid #e2e8f0;color:#1e293b;font-weight:600">${esc(r.target_field||'—')}</td>
              <td style="padding:5px 8px;border-bottom:1px solid #e2e8f0"><span style="padding:2px 7px;border-radius:4px;background:${STATUS_COLORS[r.status]||'#f1f5f9'};font-size:10px;font-weight:700;color:#1e293b">${esc(r.status||'—')}</span></td>
              <td style="padding:5px 8px;border-bottom:1px solid #e2e8f0;color:#475569;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.logic||'')}">${esc(r.logic||'—')}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
      ` : '<div style="font-size:13px;color:var(--muted)">No mapped fields found.</div>'}
      </div>
    </div>`;
  }

  // ── STEP 3 — DOCUMENTATION ────────────────
  if (state.documentation_md) {
    const truncBanner = state.doc_truncated
      ? `<div style="margin-bottom:12px;padding:10px 14px;background:rgba(251,146,60,.12);border:1px solid var(--sev-high);border-radius:8px;font-size:12px;color:#fb923c">
           ⚠️ <strong>Documentation was truncated</strong> — the token limit was reached during generation.
           One or more sections (field lineage, session context, or ambiguities) may be incomplete.
           Review carefully before approving at Analysis Sign-off. If critical sections are missing, Reject and re-upload.
         </div>`
      : '';
    html += `<div class="card" ${state.doc_truncated ? 'style="border-color:var(--sev-high)"' : ''}>
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">📄</span> Step 3 — Documentation
        ${state.doc_truncated ? '<span class="badge badge-waiting" style="font-size:10px;background:rgba(251,146,60,.2);color:#fb923c">TRUNCATED</span>' : ''}
        <span class="card-chevron">▼</span></div>
      <div class="card-body">
      ${truncBanner}
      <div class="doc-content" id="docContent">${markdownToHtml(state.documentation_md)}</div>
      </div>
    </div>`;
  }

  // ── STEP 4 — VERIFICATION ─────────────────
  if (state.verification) {
    const v = state.verification;
    const isBlocked = v.conversion_blocked;
    const sortedFlags = [...(v.flags||[])].sort((a,b) => {
      if (a.blocking !== b.blocking) return a.blocking ? -1 : 1;
      return (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9);
    });
    const critCount = sortedFlags.filter(f=>f.severity==='CRITICAL'||f.blocking).length;

    html += `<div class="card" style="border-color:${isBlocked?'var(--danger)':v.overall_status==='APPROVED_FOR_CONVERSION'?'var(--accent2)':'var(--warn)'}">
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">✅</span> Step 4 — Verification Report
        <span class="badge ${isBlocked?'badge-blocked':v.overall_status==='APPROVED_FOR_CONVERSION'?'badge-complete':'badge-waiting'}" style="font-size:10px">${v.overall_status?.replace(/_/g,' ')}</span>
        <span class="card-chevron">▼</span>
      </div>
      <div class="card-body">
      <div class="stats" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
        <div class="stat"><div class="stat-val">${v.total_checks}</div><div class="stat-label">Total Checks</div></div>
        <div class="stat"><div class="stat-val" style="color:var(--accent2)">${v.total_passed}</div><div class="stat-label">Passed</div></div>
        <div class="stat"><div class="stat-val" style="color:var(--danger)">${v.total_failed}</div><div class="stat-label">Failed</div></div>
        <div class="stat"><div class="stat-val" style="color:var(--warn)">${v.total_flags}</div><div class="stat-label">Flags</div></div>
      </div>
      ${critCount > 0 ? `<div style="padding:10px 14px;background:rgba(248,113,113,.1);border-radius:8px;font-size:13px;color:var(--danger);margin-bottom:12px;font-weight:600">
        🚫 ${critCount} CRITICAL / BLOCKING issue${critCount>1?'s':''} — conversion cannot proceed until resolved
      </div>` : ''}
      ${sortedFlags.length ? `
        <div style="font-size:12px;font-weight:700;margin-bottom:10px;color:var(--muted)">FLAGS <span style="font-weight:400;color:var(--muted)">(sorted by severity — most critical first)</span></div>
        <div class="flag-list">
          ${sortedFlags.map(f => renderFlag(f)).join('')}
        </div>` : '<div style="color:var(--accent2);font-size:13px">✓ No flags raised</div>'}
      ${renderFailedChecks(v)}
      <div style="margin-top:14px;padding:10px 14px;background:var(--surface2);border-radius:8px;font-size:12px;color:var(--muted)">
        Recommendation: <strong style="color:var(--text)">${esc(v.recommendation)}</strong>
      </div>
      </div>
    </div>`;
  }

  // ── STEP 5 — HUMAN SIGN-OFF GATE ──────────
  if (job.status === 'awaiting_review') {
    const v = state.verification || {};
    const flags = v.flags || [];
    const sortedFlags = [...flags].sort((a,b) => {
      if (a.blocking !== b.blocking) return a.blocking ? -1 : 1;
      return (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9);
    });
    html += `<div class="card" id="signoffCard" style="border-color:var(--accent)">
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">👤</span> Step 5 — Human Review & Sign-off<span class="card-chevron">▼</span></div>
      <div class="card-body">
      <p style="font-size:13px;color:var(--muted);margin-bottom:16px">
        Review the Verification Report above. Each flag is sorted by severity.
        For each flag: either resolve the issue or accept it with a documented rationale.
        Your decision is recorded as part of the audit trail.
      </p>
      ${sortedFlags.length ? `
        <div style="font-size:12px;font-weight:700;margin-bottom:10px;color:var(--muted)">FLAG RESOLUTIONS</div>
        <div id="flagResolutions" style="display:flex;flex-direction:column;gap:10px;margin-bottom:16px">
          ${sortedFlags.map((f,i)=>`
            <div style="background:var(--surface2);border-radius:8px;padding:12px;font-size:12px;border-left:3px solid var(--sev-${(f.severity||'medium').toLowerCase()})">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                <span class="sev-badge ${f.severity||'MEDIUM'}">${f.severity||'MEDIUM'}</span>
                ${f.blocking ? '<span class="flag-blocking-pill">BLOCKING</span>' : ''}
                <strong>${esc(f.flag_type)}</strong>
              </div>
              <div style="color:var(--muted);font-size:11px;margin-bottom:4px">📍 ${esc(f.location)}</div>
              <div style="margin-bottom:8px">${esc(f.description)}</div>
              ${f.recommendation ? `<div style="font-size:11px;color:#a5b4fc;padding:6px 8px;background:rgba(108,99,255,.07);border-radius:4px;margin-bottom:8px">💡 ${esc(f.recommendation)}</div>` : ''}
              ${f.auto_fix_suggestion ? `
              <div style="margin-bottom:10px;border:1px solid rgba(74,222,128,.35);border-radius:6px;overflow:hidden">
                <div style="background:rgba(74,222,128,.1);padding:6px 10px;font-size:11px;font-weight:600;color:#4ade80;display:flex;align-items:center;gap:6px">
                  🔧 Suggested Auto-Fix
                </div>
                <div style="padding:8px 10px;font-size:12px;color:var(--text);line-height:1.6;font-style:italic">${esc(f.auto_fix_suggestion)}</div>
                <label style="display:flex;align-items:center;gap:8px;padding:8px 10px;background:rgba(74,222,128,.06);cursor:pointer;border-top:1px solid rgba(74,222,128,.2)">
                  <input type="checkbox" id="flag_apply_fix_${i}" style="width:15px;height:15px;accent-color:#4ade80;cursor:pointer;flex-shrink:0" />
                  <span style="font-size:12px;color:#4ade80;font-weight:500">Apply this fix during code generation (Step 7)</span>
                </label>
              </div>` : ''}
              <div style="display:flex;gap:8px;align-items:center">
                <select id="flag_action_${i}" style="flex:1;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px;color:var(--text);font-size:12px">
                  <option value="accepted">Accept (document rationale)</option>
                  <option value="resolved">Resolved (describe what was fixed)</option>
                </select>
              </div>
              <textarea id="flag_note_${i}" placeholder="Rationale or resolution description…" style="width:100%;margin-top:8px;height:60px;resize:vertical;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:8px;color:var(--text);font-size:12px"></textarea>
            </div>`).join('')}
        </div>` : ''}
      <div style="background:rgba(192,112,0,.07);border:1px solid rgba(192,112,0,.35);border-radius:8px;padding:14px;margin-bottom:16px">
        <div style="font-size:12px;font-weight:700;color:#c07000;margin-bottom:6px">📊 MANIFEST OVERRIDES <span style="font-weight:400;color:var(--muted)">(optional)</span></div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:10px">
          Download the manifest, fill in the <strong style="color:var(--text)">Reviewer Override</strong> column for any red (LOW/UNMAPPED) rows, then upload the annotated file here.
          The conversion agent will treat your corrections as ground truth — resolving lineage gaps before generating code.
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <label id="manifestUploadLabel" style="display:inline-flex;align-items:center;gap:6px;cursor:pointer;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px 12px;font-size:12px;color:var(--text)">
            📁 Choose annotated manifest…
            <input type="file" id="manifestFileInput" accept=".xlsx" style="display:none" onchange="handleManifestFileChosen(this, '${job.job_id}')"/>
          </label>
          <button id="manifestUploadBtn" class="btn btn-ghost btn-sm" style="color:#c07000;border-color:#c07000;display:none" onclick="uploadManifest('${job.job_id}')">⬆ Upload Overrides</button>
          <span id="manifestUploadStatus" style="font-size:12px"></span>
        </div>
      </div>
      <div class="signoff-form">
        <div class="form-group">
          <label>Reviewer Name</label>
          <input type="text" id="reviewerName" placeholder="Your full name"/>
        </div>
        <div class="form-group">
          <label>Reviewer Role</label>
          <select id="reviewerRole">
            <option>Data Engineer</option>
            <option>Senior Data Engineer</option>
            <option>Business Analyst</option>
            <option>Subject Matter Expert</option>
            <option>Architect</option>
          </select>
        </div>
        <div class="form-group">
          <label>Notes (optional)</label>
          <textarea id="reviewNotes" placeholder="Any conditions, caveats, or observations…" style="height:80px;resize:vertical"></textarea>
        </div>
        ${renderGate1ReadinessWarning(state)}
      <div class="form-actions">
          <button class="btn btn-success" id="gate1ApproveBtn" onclick="submitSignoff('${job.job_id}', 'APPROVED', ${JSON.stringify(sortedFlags).replace(/"/g,'&quot;')})" ${isGate1SoftBlocked(state) ? 'disabled title="Readiness score is LOW or CRITICAL — document Approved Fixes above to unlock"' : ''}>✓ Approve — Proceed to Conversion</button>
          <button class="btn btn-danger"  onclick="showGate1RestartOptions()">✗ Reject — Needs Remediation</button>
        </div>
        <div id="gate1ApprovedFixesRow" style="display:${isGate1SoftBlocked(state)?'block':'none'};margin-top:10px">
          <div style="font-size:12px;font-weight:700;color:var(--warn);margin-bottom:6px">⚠️ Conversion Readiness is LOW — document approved fixes to unlock the Approve button</div>
          <textarea id="gate1ApprovedFixes" placeholder="List the approved fixes, clarifications, or accepted risks that address the readiness gaps…" style="width:100%;height:80px;resize:vertical;background:var(--surface);border:1px solid var(--warn);border-radius:6px;padding:8px;color:var(--text);font-size:12px" oninput="checkGate1ApproveUnlock()"></textarea>
        </div>
        <div id="gate1RestartRow" style="display:none;margin-top:10px;padding:10px;background:var(--surface2);border-radius:6px;border:1px solid var(--border)">
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Optional: restart pipeline from a checkpoint (skip re-upload)</div>
          <select id="gate1RestartStep" style="font-size:13px;padding:5px 8px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:4px;width:100%;margin-bottom:8px">
            <option value="">— block job (no restart) —</option>
            <option value="1">Step 1 — Re-parse XML &amp; re-run all</option>
            <option value="2">Step 2 — Re-classify &amp; re-document</option>
            <option value="3">Step 3 — Re-generate documentation only</option>
          </select>
          <button class="btn btn-danger" style="width:100%" onclick="submitSignoff('${job.job_id}', 'REJECTED', [])">Confirm Reject</button>
        </div>
      </div>
      </div>
    </div>`;
  }

  // ── STEP 5 completed sign-off summary ─────
  if (state.sign_off && job.status !== 'awaiting_review') {
    const sr = state.sign_off;
    const isApproved = sr.decision === 'APPROVED';
    const appliedFixes = [...(sr.flags_accepted||[]), ...(sr.flags_resolved||[])]
      .filter(r => r.apply_fix && r.fix_suggestion);
    html += `<div class="card" style="border-color:${isApproved?'var(--accent2)':'var(--danger)'}">
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">${isApproved?'✅':'❌'}</span> Step 5 — Sign-off Record<span class="card-chevron">▼</span></div>
      <div class="card-body">
      <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:13px">
        <span>Reviewer: <strong>${esc(sr.reviewer_name)}</strong> (${esc(sr.reviewer_role)})</span>
        <span>Decision: <strong style="color:${isApproved?'var(--accent2)':'var(--danger)'}">${sr.decision}</strong></span>
        <span>Date: ${utcDate(sr.review_date).toLocaleString()}</span>
        ${appliedFixes.length ? `<span style="color:#4ade80;font-weight:600">🔧 ${appliedFixes.length} fix${appliedFixes.length>1?'es':''} applied to Step 7</span>` : ''}
      </div>
      ${sr.notes ? `<div style="font-size:12px;color:var(--muted);margin-top:8px;padding:8px;background:var(--surface2);border-radius:6px">Notes: ${esc(sr.notes)}</div>` : ''}
      ${appliedFixes.length ? `
      <div style="margin-top:10px">
        <div style="font-size:11px;font-weight:600;color:#4ade80;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">🔧 Fixes Injected into Code Generation</div>
        <div style="display:flex;flex-direction:column;gap:6px">
          ${appliedFixes.map((r,i) => `
          <div style="background:rgba(74,222,128,.07);border:1px solid rgba(74,222,128,.2);border-radius:6px;padding:8px 10px;font-size:12px">
            <span style="color:var(--muted);margin-right:6px">${i+1}.</span>${esc(r.fix_suggestion)}
          </div>`).join('')}
        </div>
      </div>` : ''}
      </div>
    </div>`;
  }

  // ── STEP 6 — STACK ASSIGNMENT ─────────────
  if (state.stack_assignment) {
    const sa = state.stack_assignment;
    html += `<div class="card">
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">🎯</span> Step 6 — Stack Assignment<span class="card-chevron">▼</span></div>
      <div class="card-body">
      <div style="font-size:28px;font-weight:800;color:var(--accent);margin-bottom:12px">${esc(sa.assigned_stack)}</div>
      <div style="font-size:13px;margin-bottom:10px;line-height:1.6">${esc(sa.rationale)}</div>
      ${sa.data_volume_est ? `<div style="font-size:12px;color:var(--muted)">Estimated data volume: ${esc(sa.data_volume_est)}</div>` : ''}
      ${sa.special_concerns?.length ? `<div style="font-size:12px;color:var(--warn);margin-top:10px">⚠️ ${sa.special_concerns.map(esc).join('<br/>⚠️ ')}</div>` : ''}
      </div>
    </div>`;
  }

  // ── STEP 7 — CONVERTED CODE ───────────────
  if (state.conversion) {
    const co = state.conversion;
    const fileNames = Object.keys(co.files || {});
    const firstFile = fileNames[0] || '';
    const fileIcon = (name) => {
      if (name.endsWith('.py'))  return '🐍';
      if (name.endsWith('.sql')) return '🗄️';
      if (name.endsWith('.yml') || name.endsWith('.yaml')) return '📋';
      if (name.endsWith('.md'))  return '📄';
      return '📁';
    };
    const fileType = (name) => {
      if (name.endsWith('.py'))  return 'Python';
      if (name.endsWith('.sql')) return 'SQL';
      if (name.endsWith('.yml') || name.endsWith('.yaml')) return 'YAML';
      return name.split('.').pop()?.toUpperCase() || 'File';
    };
    const convDegraded = co.parse_ok === false;
    html += `<div class="card" style="border-color:${convDegraded ? 'var(--warn)' : 'var(--accent2)'}">
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">💻</span> Step 7 — Converted Code <span style="color:var(--accent)">(${esc(co.target_stack)})</span>
        <span style="margin-left:auto;display:flex;align-items:center;gap:6px">
          <span class="badge ${convDegraded ? 'badge-waiting' : 'badge-complete'}" style="font-size:10px">${fileNames.length} file${fileNames.length!==1?'s':''}</span>
          <span class="card-chevron" style="margin-left:0">▼</span>
        </span>
      </div>
      <div class="card-body">
      ${convDegraded ? `<div style="padding:10px 14px;background:rgba(251,191,36,.12);border:1px solid var(--warn);border-radius:8px;margin-bottom:14px">
        <div style="font-size:13px;font-weight:700;color:var(--warn);margin-bottom:4px">⚠️ Conversion Output Degraded</div>
        <div style="font-size:12px;color:var(--text)">The response JSON could not be parsed cleanly — files below may be partial or truncated.
        <strong>Review each file carefully before use.</strong> Re-running the job may produce a cleaner result.</div>
      </div>` : ''}
      ${co.notes?.length ? `<div style="margin-bottom:14px">${co.notes.map(n=>{
        const u = n.toUpperCase();
        const isCritical = u.startsWith('CRITICAL') || u.includes('HIGH-RISK') || u.includes('AMBIGUI') || u.includes('UNDOCUMENTED') || u.includes('CROSS JOIN') || u.includes('FALLBACK') || u.includes('PLACEHOLDER') || u.includes('LINEAGE GAP');
        const isPass     = u.includes('NO HARDCODED') || u.includes('NO EVAL') || u.includes('NO SQL INJECTION') || u.startsWith('PERFORMANCE') || u.startsWith('DW AUDIT') || u.includes('EXTERNALIZED') || u.includes('COMPLETE AND RUNNABLE');
        const icon  = isCritical ? '⚠️' : isPass ? '✅' : 'ℹ️';
        const color = isCritical ? 'var(--warn)' : isPass ? 'var(--success,#4ade80)' : 'var(--muted)';
        return `<div style="font-size:12px;color:${color};margin-bottom:4px">${icon} ${esc(n)}</div>`;
      }).join('')}</div>` : ''}
      <div class="output-files">
        ${fileNames.map(f=>`<div class="output-file-card" onclick="showFileInViewer('${esc(f)}', ${JSON.stringify(co.files).replace(/"/g,'&quot;')})">
          <div class="output-file-icon">${fileIcon(f)}</div>
          <div class="output-file-name">${esc(f)}</div>
          <div class="output-file-type">${fileType(f)}</div>
        </div>`).join('')}
      </div>
      <div class="code-tabs" id="codeTabs">
        ${fileNames.map((f,i)=>`<div class="code-tab ${i===0?'active':''}" id="tab_${i}" onclick="showCodeTab('${esc(f)}', this, ${JSON.stringify(co.files).replace(/"/g,'&quot;')})">${esc(f)}</div>`).join('')}
      </div>
      <pre class="code-block" id="codeBlock">${escHtml(co.files[firstFile]||'')}</pre>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <span style="font-size:12px;color:var(--muted)">Download:</span>
        <button class="btn btn-sm" style="background:var(--accent);color:#fff;border:none;font-weight:600" onclick="downloadOutputZip('${job.job_id}')" title="Download all output files as a ZIP archive">⬇ Download ZIP</button>
        ${fileNames.map(f=>`<button class="btn btn-ghost btn-sm" onclick="downloadCode('${job.job_id}','${esc(f)}')">${fileIcon(f)} ${esc(f)}</button>`).join('')}
      </div>
      </div>
    </div>`;
  }

  // ── STEP 8 — SECURITY SCAN ───────────────
  if (state.security_scan) {
    const ss = state.security_scan;
    const ssRecColor = { APPROVED:'var(--accent2)', REVIEW_RECOMMENDED:'var(--warn)', REQUIRES_FIXES:'var(--danger)' }[ss.recommendation] || 'var(--muted)';
    const ssRecBadge = { APPROVED:'badge-complete', REVIEW_RECOMMENDED:'badge-waiting', REQUIRES_FIXES:'badge-blocked' }[ss.recommendation] || 'badge-pending';
    const ssRecIcon  = { APPROVED:'✅', REVIEW_RECOMMENDED:'⚠️', REQUIRES_FIXES:'❌' }[ss.recommendation] || '❓';
    const ssFindings = (ss.findings||[]).sort((a,b) => ({ CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3 }[a.severity]??9) - ({ CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3 }[b.severity]??9));
    const ssHasFindings = ssFindings.length > 0;
    const ssSevColor = { CRITICAL:'var(--danger)', HIGH:'#f97316', MEDIUM:'var(--warn)', LOW:'#60a5fa' };
    html += `<div class="card" style="border-color:${ssRecColor}">
      <div class="card-title" onclick="toggleCard(this)" style="justify-content:space-between">
        <span><span class="icon">🛡️</span> Step 8 — Security Scan</span>
        <span style="display:flex;align-items:center;gap:8px">
          <span class="badge ${ssRecBadge}" style="font-size:11px">${ssRecIcon} ${(ss.recommendation||'').replace(/_/g,' ')}</span>
          <span class="card-chevron" style="margin-left:0">▼</span>
        </span>
      </div>
      <div class="card-body">
      <div class="stats" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
        <div class="stat"><div class="stat-val" style="color:${(ss.critical_count||0)>0?'var(--danger)':'var(--accent2)'}">${ss.critical_count||0}</div><div class="stat-label">Critical</div></div>
        <div class="stat"><div class="stat-val" style="color:${(ss.high_count||0)>0?'#f97316':'var(--accent2)'}">${ss.high_count||0}</div><div class="stat-label">High</div></div>
        <div class="stat"><div class="stat-val" style="color:${(ss.medium_count||0)>0?'var(--warn)':'var(--accent2)'}">${ss.medium_count||0}</div><div class="stat-label">Medium</div></div>
        <div class="stat"><div class="stat-val">${ss.low_count||0}</div><div class="stat-label">Low</div></div>
      </div>
      ${ss.ran_bandit ? `<div style="font-size:11px;color:var(--muted);margin-bottom:10px">🔎 bandit static analysis ran &nbsp;·&nbsp; YAML regex scan ran &nbsp;·&nbsp; Claude review ran</div>` :
                        `<div style="font-size:11px;color:var(--warn);margin-bottom:10px">⚠️ bandit not available — Claude + YAML regex scan ran</div>`}
      ${ss.bandit_error ? `<div style="font-size:12px;color:var(--warn);margin-bottom:10px">bandit error: ${esc(ss.bandit_error)}</div>` : ''}
      ${ss.claude_summary ? `<div style="padding:10px 14px;background:var(--surface2);border-radius:8px;font-size:13px;margin-bottom:14px;line-height:1.6">${esc(ss.claude_summary)}</div>` : ''}
      ${ssHasFindings ? `
      <div style="font-size:12px;font-weight:700;color:var(--muted);margin-bottom:8px">FINDINGS (${ssFindings.length})</div>
      <div style="display:flex;flex-direction:column;gap:8px">
        ${ssFindings.map(f => {
          const sc = ssSevColor[f.severity] || 'var(--muted)';
          const srcTag = f.source === 'bandit' ? '🔎 bandit' : f.source === 'yaml_scan' ? '📋 yaml' : '🤖 claude';
          return `<div style="padding:10px 12px;background:rgba(248,113,113,.05);border-radius:8px;border-left:3px solid ${sc}">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="font-size:10px;font-weight:800;color:${sc}">${esc(f.severity)}</span>
              <span style="font-size:11px;font-weight:600;color:var(--text)">${esc(f.test_name||f.test_id||'')}</span>
              <span style="margin-left:auto;font-size:10px;color:var(--muted)">${srcTag}</span>
            </div>
            ${f.filename ? `<div style="font-size:11px;color:var(--muted);margin-bottom:3px">📄 ${esc(f.filename)}${f.line ? ` line ${f.line}` : ''}</div>` : ''}
            <div style="font-size:12px;color:var(--text)">${esc(f.text||'')}</div>
            ${f.code ? `<pre style="margin-top:6px;background:#0a0a0a;border-radius:4px;padding:6px 8px;font-size:11px;color:#fca5a5;white-space:pre-wrap;word-break:break-all;max-height:80px;overflow-y:auto">${escHtml(f.code)}</pre>` : ''}
            ${f.remediation ? `<div style="margin-top:8px;padding:7px 10px;background:rgba(74,222,128,.07);border-radius:6px;border-left:2px solid var(--accent2);font-size:11px;line-height:1.55;color:var(--text)"><span style="font-weight:700;color:var(--accent2)">🔧 How to fix:&nbsp;</span>${esc(f.remediation)}</div>` : ''}
          </div>`;
        }).join('')}
      </div>` : `<div style="color:var(--accent2);font-size:13px">✅ No security findings detected.</div>`}
      </div>
    </div>`;
  }

  // ── STEP 9 — SECURITY REVIEW GATE ───────────────
  const srd         = state.security_sign_off || {};
  const srdDecision = srd.decision || '';
  const signedOff   = !!state.security_sign_off && srdDecision !== 'REQUEST_FIX';
  if (job.status === 'awaiting_security_review' || signedOff) {
    const srdDecColor = { APPROVED:'var(--accent2)', ACKNOWLEDGED:'var(--warn)', FAILED:'var(--danger)' }[srdDecision] || 'var(--muted)';
    if (signedOff) {
      const srdIcon = { APPROVED:'✅', ACKNOWLEDGED:'⚠️', FAILED:'❌' }[srdDecision] || '❓';
      html += `<div class="card" style="border-color:${srdDecColor}">
        <div class="card-title" onclick="toggleCard(this)" style="justify-content:space-between">
          <span><span class="icon">🔐</span> Step 9 — Security Review</span>
          <span style="display:flex;align-items:center;gap:8px">
            <span class="badge ${{ APPROVED:'badge-complete', ACKNOWLEDGED:'badge-waiting', FAILED:'badge-blocked' }[srdDecision]||'badge-pending'}" style="font-size:11px">${srdIcon} ${srdDecision}</span>
            <span class="card-chevron" style="margin-left:0">▼</span>
          </span>
        </div>
        <div class="card-body">
          <div style="display:flex;gap:24px;font-size:13px;margin-bottom:10px">
            <div><span style="color:var(--muted)">Reviewer:</span> <strong>${esc(srd.reviewer_name||'')}</strong></div>
            <div><span style="color:var(--muted)">Role:</span> ${esc(srd.reviewer_role||'')}</div>
            <div><span style="color:var(--muted)">Date:</span> ${(srd.review_date||'').slice(0,10)}</div>
          </div>
          ${srd.notes ? `<div style="font-size:13px;color:var(--muted);padding:8px 12px;background:var(--surface2);border-radius:6px">${esc(srd.notes)}</div>` : ''}
        </div>
      </div>`;
    } else {
      const recLabel = (state.security_scan?.recommendation||'REVIEW_RECOMMENDED').replace(/_/g,' ');
      const remRound    = state.remediation_round || 0;
      const canFixAgain = state.can_request_fix !== false && remRound < 2;
      let roundDiffHtml = '';
      if (remRound > 0 && state.security_scan_rounds?.length) {
        const prevScan    = state.security_scan_rounds[state.security_scan_rounds.length - 1];
        const prevFindings = prevScan?.findings || [];
        const currFindings = state.security_scan?.findings || [];
        const key = f => `${f.test_name||f.test_id||''}|${f.filename||''}`;
        const prevKeys = new Set(prevFindings.map(key));
        const currKeys = new Set(currFindings.map(key));
        const fixed   = prevFindings.filter(f => !currKeys.has(key(f)));
        const newOnes = currFindings.filter(f => !prevKeys.has(key(f)));
        const remain  = currFindings.filter(f =>  prevKeys.has(key(f)));
        const diffRows = [
          ...fixed.map(f   => `<div style="display:flex;gap:8px;align-items:baseline;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04)"><span style="color:#22c55e;font-size:11px;min-width:70px">✅ Fixed</span><span style="font-size:12px;color:var(--muted)">${esc(f.test_name||f.test_id||'')} — ${esc(f.filename||'')}</span></div>`),
          ...remain.map(f  => `<div style="display:flex;gap:8px;align-items:baseline;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04)"><span style="color:#f59e0b;font-size:11px;min-width:70px">⚠️ Remains</span><span style="font-size:12px;color:var(--muted)">${esc(f.test_name||f.test_id||'')} — ${esc(f.filename||'')}</span></div>`),
          ...newOnes.map(f => `<div style="display:flex;gap:8px;align-items:baseline;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04)"><span style="color:#f87171;font-size:11px;min-width:70px">🆕 New</span><span style="font-size:12px;color:var(--muted)">${esc(f.test_name||f.test_id||'')} — ${esc(f.filename||'')}</span></div>`),
        ].join('');
        roundDiffHtml = `
          <div style="margin-bottom:12px;padding:10px 12px;background:rgba(255,255,255,.03);border-radius:6px;border:1px solid rgba(255,255,255,.08)">
            <div style="font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px">
              Fix Round ${remRound} — Changes from previous scan
              <span style="margin-left:12px;color:#22c55e">${fixed.length} fixed</span>
              <span style="margin-left:8px;color:#f59e0b">${remain.length} remaining</span>
              ${newOnes.length ? `<span style="margin-left:8px;color:#f87171">${newOnes.length} new</span>` : ''}
            </div>
            ${diffRows || '<div style="font-size:12px;color:var(--muted)">No comparable findings.</div>'}
          </div>`;
      }
      const roundNote = remRound > 0
        ? `<div style="font-size:12px;color:var(--warn);margin-bottom:10px;padding:8px 12px;background:rgba(234,179,8,.08);border-radius:6px;border-left:3px solid var(--warn)">
             🔄 Fix round ${remRound} of 2 — code was regenerated with security findings as context and re-scanned.
             ${canFixAgain ? 'One more fix round available.' : '<strong>No further fix rounds — choose Approve, Acknowledge, or Fail.</strong>'}
           </div>${roundDiffHtml}` : '';
      html += `<div class="card" id="secReviewCard" style="border-color:var(--warn)">
        <div class="card-title" onclick="toggleCard(this)" style="justify-content:space-between">
          <span><span class="icon">🔐</span> Step 9 — Security Review <span style="font-size:11px;color:var(--warn);margin-left:8px">⏳ AWAITING YOUR DECISION</span></span>
          <span class="card-chevron" style="margin-left:0">▼</span>
        </div>
        <div class="card-body">
          ${roundNote}
          <div style="font-size:13px;color:var(--text);margin-bottom:16px;padding:12px;background:rgba(234,179,8,.07);border-radius:8px;border:1px solid rgba(234,179,8,.25)">
            The automated security scan returned <strong>${esc(recLabel)}</strong>. Review the findings in Step 8 above and choose an action below.
          </div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:14px;line-height:1.6;padding:10px 12px;background:rgba(255,255,255,.03);border-radius:6px;border:1px solid rgba(255,255,255,.06)">
            <strong style="color:var(--text)">🔧 Request Fix</strong> — regenerates the code with all findings as mandatory fix requirements, then re-scans (max 2 rounds).<br>
            <strong style="color:var(--text)">✅ Approve</strong> — findings reviewed; accept and proceed to code review.<br>
            <strong style="color:var(--text)">⚠️ Acknowledge</strong> — known risk accepted with notes; proceed to code review.<br>
            <strong style="color:var(--text)">❌ Fail</strong> — unacceptable findings; block pipeline permanently.
          </div>
          <div class="form-row">
            <label class="form-label">Your Name</label>
            <input id="secReviewerName" class="form-input" placeholder="Reviewer name" />
          </div>
          <div class="form-row">
            <label class="form-label">Role</label>
            <select id="secReviewerRole" class="form-input">
              <option value="Security Engineer">Security Engineer</option>
              <option value="Lead Developer">Lead Developer</option>
              <option value="Tech Lead">Tech Lead</option>
              <option value="Architect">Architect</option>
            </select>
          </div>
          <div class="form-row">
            <label class="form-label">Notes (optional)</label>
            <textarea id="secReviewNotes" class="form-input" rows="2" placeholder="Any notes on the decision…"></textarea>
          </div>
          <div class="form-actions" style="display:flex;gap:10px;flex-wrap:wrap">
            ${canFixAgain ? `<button class="btn" style="background:var(--accent2);color:#000;font-weight:700" onclick="event.stopPropagation();submitSecurityReview('${job.job_id}','REQUEST_FIX')">🔧 Request Fix &amp; Re-scan</button>` : ''}
            <button class="btn btn-success" onclick="event.stopPropagation();submitSecurityReview('${job.job_id}','APPROVED')">✅ Approve — Proceed</button>
            <button class="btn btn-warning" onclick="event.stopPropagation();submitSecurityReview('${job.job_id}','ACKNOWLEDGED')" style="background:var(--warn);color:#000">⚠️ Acknowledge &amp; Proceed</button>
            <button class="btn btn-danger"  onclick="event.stopPropagation();submitSecurityReview('${job.job_id}','FAILED')">❌ Fail — Block Pipeline</button>
          </div>
        </div>
      </div>`;
    }
  }

  // ── STEP 10 — CODE QUALITY REVIEW ───────────────
  if (state.code_review) {
    const cr = state.code_review;
    const recColor = { APPROVED: 'var(--accent2)', REVIEW_RECOMMENDED: 'var(--warn)', REQUIRES_FIXES: 'var(--danger)' }[cr.recommendation] || 'var(--muted)';
    const recBadge = { APPROVED: 'badge-complete', REVIEW_RECOMMENDED: 'badge-waiting', REQUIRES_FIXES: 'badge-blocked' }[cr.recommendation] || 'badge-pending';
    const recIcon  = { APPROVED: '✅', REVIEW_RECOMMENDED: '⚠️', REQUIRES_FIXES: '❌' }[cr.recommendation] || '❓';
    const SEV_ORDER_CR = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };
    const sortedChecks = [...(cr.checks||[])].sort((a,b) => {
      if (a.passed !== b.passed) return a.passed ? 1 : -1;
      return (SEV_ORDER_CR[a.severity]??9) - (SEV_ORDER_CR[b.severity]??9);
    });
    html += `<div class="card" style="border-color:${recColor}">
      <div class="card-title" onclick="toggleCard(this)" style="justify-content:space-between">
        <span><span class="icon">🔬</span> Step 10 — Code Quality Review</span>
        <span style="display:flex;align-items:center;gap:8px">
          <span class="badge ${recBadge}" style="font-size:11px">${recIcon} ${cr.recommendation?.replace(/_/g,' ')}</span>
          <span class="card-chevron" style="margin-left:0">▼</span>
        </span>
      </div>
      <div class="card-body">
      <div class="stats" style="grid-template-columns:repeat(3,1fr);margin-bottom:16px">
        <div class="stat"><div class="stat-val">${(cr.checks||[]).length}</div><div class="stat-label">Checks Run</div></div>
        <div class="stat"><div class="stat-val" style="color:var(--accent2)">${cr.total_passed}</div><div class="stat-label">Passed</div></div>
        <div class="stat"><div class="stat-val" style="color:${cr.total_failed>0?'var(--danger)':'var(--accent2)'}">${cr.total_failed}</div><div class="stat-label">Failed</div></div>
      </div>
      ${cr.parse_degraded ? `<div style="padding:8px 12px;background:rgba(251,191,36,.1);border-radius:6px;font-size:12px;color:var(--warn);margin-bottom:12px">
        ⚠️ Review based on partially-recovered code — some checks may be incomplete due to truncated output in Step 7.
      </div>` : ''}
      ${cr.summary ? `<div style="padding:10px 14px;background:var(--surface2);border-radius:8px;font-size:13px;margin-bottom:14px;line-height:1.6">${esc(cr.summary)}</div>` : ''}
      ${(() => {
        const eq = cr.equivalence_report;
        if (!eq) return '';
        const total = eq.total_verified + eq.total_needs_review + eq.total_mismatches;
        if (total === 0 && !eq.summary) return '';
        const hasMismatches = eq.total_mismatches > 0;
        const borderCol = hasMismatches ? 'var(--danger)' : eq.total_needs_review > 0 ? 'var(--warn)' : 'var(--accent2)';
        const VERDICT_ICON   = { VERIFIED:'✅', NEEDS_REVIEW:'⚠️', MISMATCH:'❌' };
        const VERDICT_COLOR  = { VERIFIED:'var(--accent2)', NEEDS_REVIEW:'var(--warn)', MISMATCH:'var(--danger)' };
        const VERDICT_BG     = { VERIFIED:'rgba(34,197,94,.04)', NEEDS_REVIEW:'rgba(251,191,36,.07)', MISMATCH:'rgba(248,113,113,.08)' };
        const RULE_ICON      = { FIELD:'📋', EXPRESSION:'🔣', FILTER:'🔽', JOIN:'🔗', NULL_HANDLING:'⬜', CHAIN:'⛓️' };
        const mismatchRows   = (eq.checks||[]).filter(c => c.verdict === 'MISMATCH');
        const needsRevRows   = (eq.checks||[]).filter(c => c.verdict === 'NEEDS_REVIEW');
        const verifiedRows   = (eq.checks||[]).filter(c => c.verdict === 'VERIFIED');
        const orderedChecks  = [...mismatchRows, ...needsRevRows, ...verifiedRows];
        return `
        <div style="margin-bottom:14px;border:1px solid ${borderCol};border-radius:8px;overflow:hidden">
          <div style="padding:10px 14px;background:${hasMismatches?'rgba(248,113,113,.07)':eq.total_needs_review>0?'rgba(251,191,36,.06)':'rgba(34,197,94,.05)'};display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <span style="font-size:12px;font-weight:700;color:var(--muted);letter-spacing:.05em">LOGIC EQUIVALENCE CHECK</span>
            <span style="font-size:11px;padding:2px 8px;border-radius:10px;background:rgba(34,197,94,.12);color:var(--accent2);font-weight:600">${eq.total_verified} VERIFIED</span>
            <span style="font-size:11px;padding:2px 8px;border-radius:10px;background:rgba(251,191,36,.15);color:var(--warn);font-weight:600">${eq.total_needs_review} NEEDS REVIEW</span>
            <span style="font-size:11px;padding:2px 8px;border-radius:10px;background:rgba(248,113,113,.15);color:var(--danger);font-weight:600">${eq.total_mismatches} MISMATCHES</span>
            <span style="font-size:11px;color:var(--muted);margin-left:auto">${eq.coverage_pct}% coverage</span>
          </div>
          ${eq.summary ? `<div style="padding:8px 14px;font-size:12px;color:var(--muted);border-bottom:1px solid var(--border)">${esc(eq.summary)}</div>` : ''}
          ${orderedChecks.length ? `<div style="padding:8px;display:flex;flex-direction:column;gap:4px">
            ${orderedChecks.map(c => `
            <div style="display:flex;gap:8px;align-items:flex-start;padding:7px 10px;background:${VERDICT_BG[c.verdict]||'transparent'};border-radius:6px;border-left:3px solid ${VERDICT_COLOR[c.verdict]||'var(--muted)'}">
              <span style="font-size:13px;flex-shrink:0">${VERDICT_ICON[c.verdict]||'?'}</span>
              <div style="flex:1;min-width:0">
                <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:2px">
                  <span style="font-size:10px;font-weight:700;color:var(--muted)">${RULE_ICON[c.rule_type]||''} ${esc(c.rule_type)}</span>
                  <span style="font-size:12px;font-weight:600">${esc(c.rule_id)}</span>
                </div>
                <div style="font-size:11px;color:var(--muted);margin-bottom:2px"><strong>XML:</strong> ${esc(c.xml_rule)}</div>
                <div style="font-size:11px;color:var(--muted);margin-bottom:${c.note?'2px':'0'}"><strong>Code:</strong> ${esc(c.generated_impl)}</div>
                ${c.note ? `<div style="font-size:11px;color:${VERDICT_COLOR[c.verdict]||'var(--muted)'}">${esc(c.note)}</div>` : ''}
              </div>
            </div>`).join('')}
          </div>` : ''}
        </div>`;
      })()}
      ${sortedChecks.length ? `
      <div style="font-size:12px;font-weight:700;color:var(--muted);margin-bottom:8px">CODE QUALITY CHECKS</div>
      <div style="display:flex;flex-direction:column;gap:6px">
        ${sortedChecks.map(c => {
          const sevCols = { CRITICAL:'var(--danger)', HIGH:'#f97316', MEDIUM:'var(--warn)', LOW:'var(--muted)' };
          const sc = sevCols[c.severity] || 'var(--muted)';
          return `<div style="display:flex;gap:10px;align-items:flex-start;padding:8px 10px;background:${c.passed?'rgba(34,197,94,.04)':'rgba(248,113,113,.06)'};border-radius:6px;border-left:3px solid ${c.passed?'var(--accent2)':sc}">
            <span style="font-size:14px;flex-shrink:0">${c.passed?'✅':'✗'}</span>
            <div style="flex:1;min-width:0">
              <div style="font-size:12px;font-weight:600;margin-bottom:2px;display:flex;gap:6px;align-items:center">
                ${esc(c.name.replace(/_/g,' '))}
                ${!c.passed ? `<span style="font-size:10px;font-weight:700;color:${sc}">${esc(c.severity)}</span>` : ''}
              </div>
              ${c.note ? `<div style="font-size:11px;color:var(--muted)">${esc(c.note)}</div>` : ''}
            </div>
          </div>`;
        }).join('')}
      </div>` : ''}
      </div>
    </div>`;
  } else if (state.reconciliation) {
    html += `<div class="card">
      <div class="card-title" onclick="toggleCard(this)"><span class="icon">🔬</span> Step 10 — Code Quality Review<span class="card-chevron">▼</span></div>
      <div class="card-body">
      <div style="font-size:13px;color:var(--muted)">This job was run before Step 10 was implemented. Re-run to get a full code review.</div>
      </div>
    </div>`;
  }

  // ── STEP 11 — TEST GENERATION & COVERAGE ───────────────────
  if (state.test_report) {
    const tr = state.test_report;
    const pct = tr.coverage_pct ?? 0;
    const pctColor = pct >= 90 ? 'var(--accent2)' : pct >= 70 ? 'var(--warn)' : 'var(--danger)';
    const pctBadge = pct >= 90 ? 'badge-complete' : pct >= 70 ? 'badge-waiting' : 'badge-blocked';
    const testFileNames = Object.keys(tr.test_files || {});
    const missingFields = tr.missing_fields || [];
    html += `<div class="card" style="border-color:${pctColor}">
      <div class="card-title" onclick="toggleCard(this)" style="justify-content:space-between">
        <span><span class="icon">🧪</span> Step 11 — Test Generation &amp; Coverage Check</span>
        <span style="display:flex;align-items:center;gap:8px">
          <span class="badge ${pctBadge}" style="font-size:11px">${pct}% Field Coverage</span>
          <span class="card-chevron" style="margin-left:0">▼</span>
        </span>
      </div>
      <div class="card-body">
        <div style="display:flex;gap:20px;flex-wrap:wrap;margin-bottom:16px">
          <div style="background:var(--surface-alt);border-radius:8px;padding:10px 18px;text-align:center">
            <div style="font-size:22px;font-weight:700;color:${pctColor}">${pct}%</div>
            <div style="font-size:11px;color:var(--muted)">Field Coverage</div>
          </div>
          <div style="background:var(--surface-alt);border-radius:8px;padding:10px 18px;text-align:center">
            <div style="font-size:22px;font-weight:700;color:var(--accent2)">${tr.fields_covered ?? 0}</div>
            <div style="font-size:11px;color:var(--muted)">Fields Covered</div>
          </div>
          <div style="background:var(--surface-alt);border-radius:8px;padding:10px 18px;text-align:center">
            <div style="font-size:22px;font-weight:700;color:${(tr.fields_missing??0) > 0 ? 'var(--danger)' : 'var(--accent2)'}">${tr.fields_missing ?? 0}</div>
            <div style="font-size:11px;color:var(--muted)">Fields Missing</div>
          </div>
          <div style="background:var(--surface-alt);border-radius:8px;padding:10px 18px;text-align:center">
            <div style="font-size:22px;font-weight:700;color:var(--accent)">${testFileNames.length}</div>
            <div style="font-size:11px;color:var(--muted)">Test Files</div>
          </div>
        </div>
        ${missingFields.length > 0 ? `
        <div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.3);border-radius:6px;padding:10px 14px;margin-bottom:14px">
          <div style="font-size:12px;font-weight:600;color:var(--danger);margin-bottom:6px">⚠️ ${missingFields.length} field(s) not found in generated code — review Step 7 output:</div>
          <div style="font-size:12px;color:var(--text);font-family:monospace">${missingFields.map(f => esc(f)).join(', ')}</div>
        </div>` : ''}
        ${(tr.field_coverage||[]).length > 0 ? `
        <div style="margin-bottom:14px">
          <div style="font-size:12px;font-weight:600;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">Field Coverage</div>
          <div style="overflow-x:auto;max-height:220px;overflow-y:auto">
            <table style="width:100%;border-collapse:collapse;font-size:12px">
              <thead>
                <tr style="background:var(--surface-alt);position:sticky;top:0">
                  <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border)">Status</th>
                  <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border)">Target Field</th>
                  <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border)">Table</th>
                  <th style="padding:6px 10px;text-align:left;border-bottom:1px solid var(--border)">Found In</th>
                </tr>
              </thead>
              <tbody>
                ${(tr.field_coverage||[]).map(fc => `
                <tr style="border-bottom:1px solid var(--border)">
                  <td style="padding:5px 10px">${fc.covered ? '✅' : '❌'}</td>
                  <td style="padding:5px 10px;font-family:monospace;font-weight:600;color:var(--text)">${esc(fc.target_field)}</td>
                  <td style="padding:5px 10px;color:var(--muted)">${esc(fc.target_table||'—')}</td>
                  <td style="padding:5px 10px;color:var(--muted);font-size:11px">${fc.found_in_files?.length ? esc(fc.found_in_files.join(', ')) : (fc.note ? esc(fc.note) : '—')}</td>
                </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>` : ''}
        ${(tr.filter_coverage||[]).length > 0 ? `
        <div style="margin-bottom:14px">
          <div style="font-size:12px;font-weight:600;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">Filter Coverage</div>
          <div style="display:flex;flex-direction:column;gap:6px">
            ${(tr.filter_coverage||[]).map(fc => `
            <div style="background:var(--surface-alt);border-radius:6px;padding:8px 12px;display:flex;align-items:flex-start;gap:10px">
              <span style="font-size:14px;flex-shrink:0">${fc.covered ? '✅' : '⚠️'}</span>
              <div>
                <div style="font-size:12px;font-family:monospace;color:var(--text)">${esc(fc.filter_description)}</div>
                <div style="font-size:11px;color:var(--muted)">${esc(fc.source)}</div>
                ${!fc.covered && fc.note ? `<div style="font-size:11px;color:var(--danger);margin-top:2px">${esc(fc.note)}</div>` : ''}
              </div>
            </div>`).join('')}
          </div>
        </div>` : ''}
        ${testFileNames.length > 0 ? `
        <div>
          <div style="font-size:12px;font-weight:600;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px">Generated Test Files</div>
          <div style="display:flex;flex-wrap:wrap;gap:8px">
            ${testFileNames.map(fname => `
            <button class="btn btn-secondary" style="font-size:11px;padding:5px 12px;font-family:monospace"
              onclick="downloadTestFile('${esc(job.job_id)}','${esc(fname)}')">
              ⬇ ${esc(fname.split('/').pop())}
            </button>`).join('')}
          </div>
        </div>` : ''}
        ${(tr.notes||[]).length > 0 ? `
        <div style="margin-top:12px;font-size:12px;color:var(--muted)">
          ${tr.notes.map(n => `<div style="padding:3px 0">${esc(n)}</div>`).join('')}
        </div>` : ''}
      </div>
    </div>`;
  }

  // ── STEP 12 — CODE REVIEW SIGN-OFF ────────────────────────
  if (job.status === 'awaiting_code_review' || state.code_sign_off) {
    const csoSignedOff = !!state.code_sign_off;
    const sod = state.code_sign_off || {};
    if (csoSignedOff) {
      const isApproved = sod.decision === 'APPROVED';
      html += `<div class="card" style="border-color:${isApproved ? 'var(--accent2)' : 'var(--danger)'}">
        <div class="card-title" onclick="toggleCard(this)" style="justify-content:space-between">
          <span><span class="icon">🏁</span> Step 12 — Code Review Sign-Off</span>
          <span style="display:flex;align-items:center;gap:8px">
            <span class="badge ${isApproved ? 'badge-complete' : 'badge-blocked'}" style="font-size:11px">${isApproved ? '✅ APPROVED' : '❌ REJECTED'}</span>
            <span class="card-chevron" style="margin-left:0">▼</span>
          </span>
        </div>
        <div class="card-body">
          <div style="font-size:13px;color:var(--muted)">
            Reviewed by <strong>${esc(sod.reviewer_name||'')}</strong> (${esc(sod.reviewer_role||'')})
            on ${esc((sod.review_date||'').slice(0,10))}
            — decision: <strong style="color:${isApproved?'var(--accent2)':'var(--danger)'}">${esc(sod.decision||'')}</strong>
          </div>
          ${sod.notes ? `<div style="margin-top:8px;font-size:13px;color:var(--text)">${esc(sod.notes)}</div>` : ''}
        </div>
      </div>`;
    } else {
      html += `<div class="card" id="codeSignoffCard" style="border-color:var(--accent)">
        <div class="card-title" onclick="toggleCard(this)" style="justify-content:space-between">
          <span><span class="icon">🏁</span> Step 12 — Code Review Sign-Off</span>
          <span style="display:flex;align-items:center;gap:8px">
            <span class="badge badge-waiting" style="font-size:11px">⏳ Awaiting Sign-Off</span>
            <span class="card-chevron" style="margin-left:0">▼</span>
          </span>
        </div>
        <div class="card-body">
          <div style="font-size:13px;color:var(--muted);margin-bottom:14px">
            Review the generated code (Step 7), security scan (Step 8), security review (Step 9),
            logic equivalence + quality report (Step 10), and test coverage (Step 11).
            Then record your decision below.
          </div>
          <div class="form-group">
            <label>Your Name</label>
            <input id="codeReviewerName" type="text" placeholder="Full name" />
          </div>
          <div class="form-group">
            <label>Role</label>
            <select id="codeReviewerRole">
              <option>Data Engineer</option>
              <option>Senior Data Engineer</option>
              <option>Tech Lead</option>
              <option>Architect</option>
              <option>QA Engineer</option>
              <option>Other</option>
            </select>
          </div>
          <div class="form-group">
            <label>Notes (optional)</label>
            <textarea id="codeReviewNotes" placeholder="Observations, caveats, or issues found…" style="height:80px;resize:vertical"></textarea>
          </div>
          <div class="form-actions">
            <button class="btn btn-success" onclick="event.stopPropagation();submitCodeSignoff('${job.job_id}','APPROVED')">✅ Approve — Mark Complete</button>
            <button class="btn btn-danger"  onclick="event.stopPropagation();showGate3RestartOptions()">❌ Reject — Block &amp; Start Over</button>
          </div>
          <div id="gate3RestartRow" style="display:none;margin-top:10px;padding:10px;background:var(--surface2);border-radius:6px;border:1px solid var(--border)">
            <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Optional: restart pipeline from a checkpoint (skip re-upload)</div>
            <select id="gate3RestartStep" style="font-size:13px;padding:5px 8px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:4px;width:100%;margin-bottom:8px">
              <option value="">— block job (no restart) —</option>
              <option value="6">Step 6 — Re-assign stack &amp; re-convert</option>
              <option value="7">Step 7 — Re-generate code only</option>
              <option value="10">Step 10 — Re-run code review &amp; tests</option>
            </select>
            <button class="btn btn-danger" style="width:100%" onclick="event.stopPropagation();submitCodeSignoff('${job.job_id}','REJECTED')">Confirm Reject</button>
          </div>
        </div>
      </div>`;
    }
  }

  // ── PIPELINE LOG ──────────────────────────────────────────
  const pipelineLog = state.pipeline_log || [];
  html += renderLogPanel(pipelineLog, job.job_id);

  // ── AUDIT TRAIL ────────────────────────────────────────────
  html += `<div class="card" id="auditTrailCard" style="margin-top:12px">
    <div class="card-title" onclick="toggleAuditTrail('${job.job_id}')">
      <span class="icon">📋</span> Decision Audit Trail
      <span style="font-size:11px;color:var(--muted);font-weight:400;margin-left:auto" id="auditTrailToggle">▶ Show</span>
    </div>
    <div id="auditTrailBody" style="display:none;margin-top:8px">
      <div style="color:var(--muted);font-size:12px">Loading…</div>
    </div>
  </div>`;

  const _jdc = document.getElementById('jobDetailContainer');
  const _sfc = document.getElementById('submitFormContainer');
  if (_jdc) { _jdc.innerHTML = html; _jdc.style.display = 'flex'; }
  if (_sfc) _sfc.style.display = 'none';
  setMainView('dashboard');

  const ls = document.getElementById('logScroll');
  if (ls) ls.scrollTop = ls.scrollHeight;
}

// ─────────────────────────────────────────────
// Render helpers
// ─────────────────────────────────────────────
function renderFlag(f) {
  const sevClass = 'sev-' + (f.severity || 'MEDIUM').toLowerCase();
  const blockingClass = f.blocking ? 'blocking' : '';
  return `<div class="flag ${blockingClass} ${sevClass}">
    <div class="flag-header">
      <span class="sev-badge ${f.severity||'MEDIUM'}">${f.severity||'MEDIUM'}</span>
      ${f.blocking ? '<span class="flag-blocking-pill">🚫 BLOCKING</span>' : ''}
      <span class="flag-type">${esc(f.flag_type)}</span>
    </div>
    <div class="flag-loc">📍 ${esc(f.location)}</div>
    <div class="flag-desc">${esc(f.description)}</div>
    ${f.recommendation ? `<div class="flag-rec">${esc(f.recommendation)}</div>` : ''}
  </div>`;
}

function renderLogPanel(entries, jobId) {
  const count = entries.length;
  const rows = entries.map(e => {
    const ts   = (e.ts || '').slice(11, 19);
    const step = e.step != null ? `step ${e.step}`.padEnd(6) : '      ';
    const lvl  = e.level || 'INFO';
    const msg  = esc(e.message || '');
    const data = e.data ? `<span class="log-data">  ${esc(JSON.stringify(e.data))}</span>` : '';
    const exc  = e.exc  ? `<span class="log-exc">${esc(e.exc)}</span>` : '';
    return `<div class="log-row">
      <span class="log-ts">${ts}</span>
      <span class="log-step">${esc(step)}</span>
      <span class="log-lvl ${lvl}">${lvl}</span>
      <span class="log-msg">${msg}${data}${exc}</span>
    </div>`;
  }).join('');
  const placeholder = count === 0
    ? '<div style="color:#4b5563;padding:8px 0;font-size:11px">No log entries yet — log populates as the pipeline runs.</div>'
    : '';
  return `<div class="card card-collapsed" style="margin-top:8px">
    <div class="card-title" onclick="toggleCard(this)" style="margin-bottom:0">
      <span class="icon">📋</span> Pipeline Log
      <span style="margin-left:auto;display:flex;gap:8px;align-items:center">
        <span style="font-size:11px;color:var(--muted)">${count} entries</span>
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();downloadJobLog('${jobId}')">⬇ Download .log</button>
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();refreshLog('${jobId}')">↻ Refresh</button>
        <span class="card-chevron" style="margin-left:0">▼</span>
      </span>
    </div>
    <div class="card-body">
    <div class="log-panel">
      <div class="log-scroll" id="logScroll">
        ${placeholder}${rows}
      </div>
    </div>
    </div>
  </div>`;
}

// ── v2.24.0 — Conversion Readiness helpers ────────────────────────────────────

/** Map a 0-100 score to a label + colour. */
function _readinessLabel(score) {
  if (score >= 85) return { label: 'HIGH',     emoji: '✅', color: 'var(--accent2)' };
  if (score >= 65) return { label: 'MEDIUM',   emoji: '⚠️', color: 'var(--warn)'   };
  if (score >= 40) return { label: 'LOW',      emoji: '🔴', color: 'var(--danger)'  };
  return              { label: 'CRITICAL',  emoji: '❌', color: 'var(--danger)'  };
}

/** Render a single score bar row. */
function _scoreBar(label, score, max, color, detail) {
  const pct = Math.round((score / max) * 100);
  return `<div style="margin-bottom:8px">
    <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px">
      <span style="color:var(--muted)">${esc(label)}</span>
      <span style="color:${color};font-weight:700">${score}/${max}</span>
    </div>
    <div style="height:4px;background:var(--border);border-radius:2px">
      <div style="height:100%;width:${pct}%;background:${color};border-radius:2px;transition:width .4s"></div>
    </div>
    ${detail ? `<div style="font-size:10px;color:var(--muted);margin-top:2px">${esc(detail)}</div>` : ''}
  </div>`;
}

/**
 * Render the Source Completeness score section for Step 1 Parse Report card.
 * Only shown when parse_report.completeness_score is present.
 */
function renderCompletenessScore(pr) {
  const rawScore = pr.completeness_score;
  const sigs     = pr.completeness_signals || {};
  const hasData  = rawScore != null && Object.keys(sigs).length > 0;

  // Old jobs (pre-v2.24.0): no score computed — show a neutral note instead of
  // misleading full bars.
  if (!hasData) {
    return `<div style="margin-top:14px;padding:10px 12px;background:var(--surface2);border-radius:8px;border:1px solid var(--border);font-size:11px;color:var(--muted)">
      🧩 Source Completeness score available on jobs processed after v2.24.0.
    </div>`;
  }

  const score = rawScore;
  const meta  = _readinessLabel(score);

  const sigOrder = [
    ['expression_coverage', 'Expression Coverage',  35],
    ['joiner_conditions',   'Joiner Conditions',     20],
    ['router_conditions',   'Router Conditions',     15],
    ['lookup_conditions',   'Lookup Conditions',     15],
    ['unresolved_params',   'Unresolved Parameters', 10],
    ['sql_complexity',      'SQL Complexity',          5],
  ];

  const bars = sigOrder.map(([key, lbl, max]) => {
    const sig = sigs[key] || {};
    const s   = sig.score ?? max;
    const col = s >= max * 0.75 ? 'var(--accent2)' : s >= max * 0.5 ? 'var(--warn)' : 'var(--danger)';
    return _scoreBar(lbl, s, max, col, sig.detail || '');
  }).join('');

  return `<div style="margin-top:14px;padding:12px;background:var(--surface2);border-radius:8px;border:1px solid var(--border)">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
      <span style="font-size:12px;font-weight:700;color:var(--muted)">🧩 SOURCE COMPLETENESS</span>
      <span style="font-size:18px;font-weight:800;color:${meta.color}">${meta.emoji} ${score}/100 <span style="font-size:11px;font-weight:600">${meta.label}</span></span>
    </div>
    ${bars}
  </div>`;
}

/**
 * Render the Conversion Readiness panel for Step 2 Complexity card.
 * Shows Score 1 (Pattern Confidence), Score 2 (Source Completeness from parse_report),
 * and the combined Conversion Readiness.
 */
function renderConversionReadiness(c, pr) {
  const s1     = c.pattern_confidence_score  ?? 65;
  const s2     = (pr && pr.completeness_score != null) ? pr.completeness_score : 65;
  const comb   = c.conversion_readiness      ?? Math.round(s1 * 0.4 + s2 * 0.6);
  const meta   = _readinessLabel(comb);
  const s1meta = _readinessLabel(s1);
  const s2meta = _readinessLabel(s2);

  return `<div style="margin-top:16px;padding:14px;background:var(--surface2);border-radius:8px;border:1px solid ${meta.color}44">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <span style="font-size:12px;font-weight:700;color:var(--muted)">🎯 CONVERSION READINESS</span>
      <span style="font-size:22px;font-weight:800;color:${meta.color}">${meta.emoji} ${comb}/100 <span style="font-size:12px;font-weight:600">${meta.label}</span></span>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">
      <div style="padding:10px;background:var(--surface);border-radius:6px;border:1px solid var(--border)">
        <div style="font-size:10px;font-weight:700;color:var(--muted);margin-bottom:4px">SCORE 1 — PATTERN CONFIDENCE (40%)</div>
        <div style="font-size:20px;font-weight:800;color:${s1meta.color}">${s1meta.emoji} ${s1}</div>
        <div style="font-size:11px;color:var(--muted);margin-top:2px">${esc(c.pattern_confidence || 'NONE')} — ${esc(c.suggested_pattern || 'no pattern matched')}</div>
      </div>
      <div style="padding:10px;background:var(--surface);border-radius:6px;border:1px solid var(--border)">
        <div style="font-size:10px;font-weight:700;color:var(--muted);margin-bottom:4px">SCORE 2 — SOURCE COMPLETENESS (60%)</div>
        <div style="font-size:20px;font-weight:800;color:${s2meta.color}">${s2meta.emoji} ${s2}</div>
        <div style="font-size:11px;color:var(--muted);margin-top:2px">from XML signal analysis (Step 1)</div>
      </div>
    </div>
    <div style="height:6px;background:var(--border);border-radius:3px;margin-bottom:6px">
      <div style="height:100%;width:${comb}%;background:${meta.color};border-radius:3px;transition:width .5s"></div>
    </div>
    <div style="font-size:11px;color:var(--muted);text-align:center">
      Combined = Score 1 × 0.40 + Score 2 × 0.60 &nbsp;·&nbsp;
      85–100 = HIGH ✅ &nbsp; 65–84 = MEDIUM ⚠️ &nbsp; 40–64 = LOW 🔴 &nbsp; 0–39 = CRITICAL ❌
    </div>
  </div>`;
}

/**
 * Returns true when Gate 1 Approve should be soft-blocked.
 * Blocked when combined readiness is LOW (<65) and no approved fixes have been entered.
 */
function isGate1SoftBlocked(state) {
  const c    = state.complexity || {};
  const comb = c.conversion_readiness ?? 100;
  return comb < 65;
}

/**
 * Render a warning banner above the Gate 1 approve/reject buttons when readiness
 * is below the MEDIUM threshold.
 */
function renderGate1ReadinessWarning(state) {
  const c    = state.complexity || {};
  const comb = c.conversion_readiness ?? 100;
  if (comb >= 65) return '';
  const meta = _readinessLabel(comb);
  return `<div style="margin-bottom:14px;padding:12px 14px;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.4);border-radius:8px">
    <div style="font-size:13px;font-weight:700;color:var(--danger);margin-bottom:6px">
      ${meta.emoji} Conversion Readiness: ${comb}/100 — ${meta.label}
    </div>
    <div style="font-size:12px;color:var(--text);line-height:1.6">
      The combined Conversion Readiness score is below the MEDIUM threshold (65).
      Approving now risks CRITICAL AMBIGUITIES in the generated code
      (incomplete join conditions, missing router logic, unresolved parameters).
      <br/><strong>Document your approved fixes below</strong> to unlock the Approve button.
    </div>
  </div>`;
}

/**
 * Called on every keystroke in the Approved Fixes textarea.
 * Unlocks the Approve button once text has been entered.
 */
function checkGate1ApproveUnlock() {
  const ta  = document.getElementById('gate1ApprovedFixes');
  const btn = document.getElementById('gate1ApproveBtn');
  if (!ta || !btn) return;
  btn.disabled = ta.value.trim().length < 20;
}

function renderStepper(currentStep, status) {
  const isBlocked = status === 'blocked' || status === 'failed';
  const GATE_BANNERS = {
    awaiting_review:          { gate: 1, icon: '⏸', cardId: 'signoffCard',     msg: 'Steps 1–5 complete. <strong>Analysis Sign-off is required</strong> to continue.' },
    awaiting_security_review: { gate: 2, cardId: 'secReviewCard', icon: '⏸', msg: 'Steps 1–9 complete. <strong>Security Sign-off is required</strong> to continue.' },
    awaiting_code_review:     { gate: 3, cardId: 'codeSignoffCard', icon: '✅', msg: 'All 12 automated steps complete. <strong>Final Sign-off required</strong> to mark this job Complete.' },
  };
  const banner = GATE_BANNERS[status];
  const bannerHtml = banner ? `
    <div style="display:flex;align-items:center;gap:12px;padding:12px 16px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.3);border-radius:8px;margin-bottom:16px">
      <span style="font-size:20px;flex-shrink:0">${banner.icon}</span>
      <div style="flex:1;font-size:13px;line-height:1.5">${banner.msg}</div>
      <button class="btn btn-sm" style="background:#fbbf24;color:#000;font-weight:700;flex-shrink:0;white-space:nowrap"
              onclick="scrollToSignoff('${banner.cardId}')">✍ Sign Off on This Job ↓</button>
    </div>` : '';
  return `<div class="stepper">
    ${STEPS.map((s) => {
      let dotClass = '';
      if (s.n < currentStep) dotClass = 'done';
      else if (s.n === currentStep) {
        if (status === 'awaiting_review' || status === 'awaiting_security_review' || status === 'awaiting_code_review') dotClass = 'waiting';
        else if (isBlocked) dotClass = 'blocked';
        else dotClass = 'active';
      }
      const connDone = s.n < currentStep;
      return `<div class="step">
        <div class="step-connector ${connDone?'done':''}"></div>
        <div class="step-inner">
          <div class="step-dot ${dotClass}">${dotClass==='done'?'✓':s.n}</div>
          <div class="step-label">${s.label}</div>
        </div>
      </div>`;
    }).join('')}
  </div>${bannerHtml}`;
}

function renderFailedChecks(v) {
  const failed = [...(v.completeness_checks||[]), ...(v.accuracy_checks||[]), ...(v.self_checks||[])]
    .filter(c => !c.passed);
  if (!failed.length) return '';
  return `<div style="margin-top:14px">
    <div style="font-size:12px;font-weight:700;margin-bottom:8px;color:var(--muted)">FAILED CHECKS (${failed.length})</div>
    <div class="check-grid">
      ${failed.map(c=>`<div class="check fail"><span class="check-icon">✗</span><span>${esc(c.name)}${c.detail?`<br/><span style="color:var(--muted);font-size:11px">${esc(c.detail)}</span>`:''}</span></div>`).join('')}
    </div>
  </div>`;
}

function toggleCard(titleEl) {
  const card = titleEl.closest('.card');
  if (!card) return;
  card.classList.toggle('card-collapsed');
  titleEl.style.marginBottom = card.classList.contains('card-collapsed') ? '0' : '';
}

function toggleTrace(id) {
  const el = document.getElementById(id);
  const toggle = el.previousElementSibling;
  if (el.classList.contains('visible')) {
    el.classList.remove('visible');
    toggle.textContent = '▶ Show full traceback';
  } else {
    el.classList.add('visible');
    toggle.textContent = '▼ Hide traceback';
  }
}

function showCodeTab(filename, tabEl, files) {
  document.querySelectorAll('.code-tab').forEach(t => t.classList.remove('active'));
  tabEl.classList.add('active');
  document.getElementById('codeBlock').textContent = files[filename] || '';
}

function showFileInViewer(filename, files) {
  const tabs = document.querySelectorAll('.code-tab');
  tabs.forEach(t => {
    if (t.textContent.trim() === filename) {
      t.click();
      t.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  });
  const codeBlock = document.getElementById('codeBlock');
  if (codeBlock) codeBlock.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

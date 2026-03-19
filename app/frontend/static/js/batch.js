// batch.js — batch history management

let _histJobs    = [];
let _histPage    = 0;
const _HIST_PAGE = 25;
const _expandedBatches = new Set();

async function loadHistory() {
  try {
    let all = [];
    for (let page = 1; page <= 5; page++) {
      const res  = await fetch(`/api/jobs?page=${page}&page_size=100`);
      const data = await res.json();
      const batch = data.jobs || [];
      all = all.concat(batch);
      if (all.length >= (data.total || 0) || batch.length < 100) break;
    }
    _histJobs = all;
    _histPage = 0;
    applyHistoryFilter();
  } catch(e) { /* ignore */ }
}

// ── Live-refresh timer for History panel ─────────────────────────────────
let _histLiveTimer = null;

function _startHistLive() {
  if (_histLiveTimer) return;
  const _RUNNING = new Set(['pending','parsing','classifying','documenting','verifying',
    'assigning_stack','converting','security_scanning','validating','reviewing','testing']);
  _histLiveTimer = setInterval(async () => {
    if (_mainView !== 'history') { _stopHistLive(); return; }
    await loadHistory();
    const hasLive = _histJobs.some(j => _RUNNING.has(j.status));
    if (!hasLive) _stopHistLive();
  }, 5000);
}

function _stopHistLive() {
  if (_histLiveTimer) { clearInterval(_histLiveTimer); _histLiveTimer = null; }
}

// ── Single job row ────────────────────────────────────────────────────────
function _histJobRow(j, indent) {
  const [cls, lbl] = STATUS_BADGE[j.status] || ['badge-pending', j.status];
  const dt = j.created_at ? new Date(j.created_at).toLocaleDateString('en-US',
    {month:'short',day:'numeric',year:'numeric'}) : '—';
  const tier = j.complexity_tier
    ? `<span style="font-size:11px;padding:2px 7px;border-radius:99px;background:var(--surface2);border:1px solid var(--border)">${esc(j.complexity_tier)}</span>`
    : '<span style="color:var(--muted)">—</span>';
  const indentStyle = indent ? 'padding-left:28px;' : '';
  const arrow = indent ? '<span style="color:var(--muted);margin-right:6px;font-size:11px">↳</span>' : '';
  return `<tr style="border-top:1px solid var(--border);cursor:pointer"
              onclick="openJobFromHistory('${j.job_id}')"
              onmouseenter="this.style.background='var(--surface2)'" onmouseleave="this.style.background=''">
    <td style="padding:10px 14px;white-space:nowrap">
      <span style="font-family:monospace;font-size:11px;font-weight:700;background:rgba(108,99,255,.15);color:var(--accent);padding:2px 6px;border-radius:4px">${shortId(j.job_id)}</span>
    </td>
    <td style="padding:10px 14px;max-width:220px;${indentStyle}">
      <div style="font-weight:${indent?'400':'500'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${arrow}${esc(j.filename)}</div>
    </td>
    <td style="padding:10px 14px;color:${j.submitter_name?'var(--text)':'var(--muted)'}">${esc((j.submitter_name||'').replace(/^"|"$/g,'')||'—')}</td>
    <td style="padding:10px 14px;color:${j.submitter_notes?'var(--text)':'var(--muted)'};font-size:12px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(j.submitter_notes||'—')}</td>
    <td style="padding:10px 14px"><span class="badge ${cls}">${lbl}</span></td>
    <td style="padding:10px 14px">${tier}</td>
    <td style="padding:10px 14px;font-size:12px;color:var(--muted);white-space:nowrap">${dt}</td>
    <td style="padding:10px 14px;white-space:nowrap;display:flex;gap:4px;align-items:center">
      <button class="btn btn-sm btn-ghost" style="font-size:11px;padding:3px 8px"
              onclick="event.stopPropagation();openJobFromHistory('${j.job_id}')">View</button>
      <button class="btn btn-sm btn-ghost" style="font-size:11px;padding:3px 8px;color:var(--error,#f87171)"
              onclick="event.stopPropagation();deleteHistJob('${j.job_id}',this)"
              title="Remove from history">🗑</button>
    </td>
  </tr>`;
}

// ── Batch group (collapsible header + child rows) ─────────────────────────
function _histBatchGroup(batchId, jobs) {
  const total   = jobs.length;
  const done    = jobs.filter(j => j.status === 'complete').length;
  const failed  = jobs.filter(j => j.status === 'failed').length;
  const running = total - done - failed;
  const overallCls = failed   ? 'badge-failed'
                   : running  ? 'badge-running'
                   : done === total ? 'badge-complete' : 'badge-pending';
  const overallLbl = failed   ? `${failed} failed`
                   : running  ? `${running} running`
                   : 'Complete';
  const dt = jobs[0]?.created_at ? new Date(jobs[0].created_at).toLocaleDateString('en-US',
    {month:'short',day:'numeric',year:'numeric'}) : '—';
  const batchKey = batchId.replace(/[^a-zA-Z0-9]/g, '_');
  const childId  = `batchChildren_${batchKey}`;
  const arrowId  = `batchArrow_${batchKey}`;
  const childRows = jobs.map(j => _histJobRow(j, true)).join('');

  return `
  <tr style="background:rgba(108,99,255,.07);cursor:pointer;border-top:2px solid rgba(108,99,255,.3)"
      onclick="toggleBatchGroup('${childId}','${arrowId}')"
      onmouseenter="this.style.background='rgba(108,99,255,.13)'" onmouseleave="this.style.background='rgba(108,99,255,.07)'">
    <td colspan="8" style="padding:10px 14px">
      <div style="display:flex;align-items:center;gap:10px">
        <span id="${arrowId}" style="font-size:11px;color:var(--muted);transition:transform .2s;display:inline-block;transform:${_expandedBatches.has(batchKey) ? 'rotate(90deg)' : ''}">▶</span>
        <span style="font-size:12px;font-weight:700;letter-spacing:.3px">📦 Batch</span>
        <span style="font-size:11px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(batchId)}</span>
        <span style="font-size:11px;color:var(--muted)">${total} mapping${total!==1?'s':''}</span>
        <span class="badge ${overallCls}">${overallLbl}</span>
        <span style="font-size:11px;color:var(--muted)">${dt}</span>
        <button class="btn btn-sm btn-ghost" id="delBatch_${batchKey}"
                style="font-size:11px;padding:3px 8px;color:var(--error,#f87171);margin-left:4px"
                onclick="event.stopPropagation();deleteBatch('${esc(batchId)}','${batchKey}')"
                title="Remove entire batch from history">🗑 Delete batch</button>
      </div>
    </td>
  </tr>
  <tr id="${childId}" style="display:${_expandedBatches.has(batchKey) ? '' : 'none'}"><td colspan="8" style="padding:0">
    <table style="width:100%;border-collapse:collapse">${childRows}</table>
  </td></tr>`;
}

function toggleBatchGroup(childId, arrowId) {
  const child = document.getElementById(childId);
  const arrow = document.getElementById(arrowId);
  if (!child) return;
  const open = child.style.display !== 'none';
  child.style.display = open ? 'none' : '';
  if (arrow) arrow.style.transform = open ? '' : 'rotate(90deg)';
  const batchKey = childId.replace('batchChildren_', '');
  if (open) _expandedBatches.delete(batchKey);
  else      _expandedBatches.add(batchKey);
}

function openJobFromHistory(jobId) {
  openJob(jobId).then(() => {
    const jdc = document.getElementById('jobDetailContainer');
    if (jdc && !document.getElementById('histBackBar')) {
      const bar = document.createElement('div');
      bar.id = 'histBackBar';
      bar.style.cssText = 'padding:0 0 8px 0';
      bar.innerHTML = `<button class="btn btn-sm btn-ghost" onclick="setMainView('history');loadHistory()" style="font-size:12px">← Back to History</button>`;
      jdc.insertBefore(bar, jdc.firstChild);
    }
  });
}

function applyHistoryFilter() {
  const query  = (document.getElementById('histSearchInput')?.value  || '').trim().toLowerCase();
  const status = (document.getElementById('histStatusFilter')?.value || '').trim();
  const _RUNNING = new Set(['pending','parsing','classifying','documenting','verifying',
    'assigning_stack','converting','security_scanning','validating','reviewing','testing']);

  let filtered = _histJobs.filter(j => {
    if (query) {
      const sid = shortId(j.job_id).toLowerCase();
      const haystack = [j.job_id, sid, j.filename, j.submitter_name, j.submitter_team, j.submitter_notes]
        .filter(Boolean).join(' ').toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    if (status) {
      if (status === 'running' && !_RUNNING.has(j.status)) return false;
      if (status !== 'running' && j.status !== status) return false;
    }
    return true;
  });

  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / _HIST_PAGE));
  _histPage   = Math.min(_histPage, pages - 1);
  const slice = filtered.slice(_histPage * _HIST_PAGE, (_histPage + 1) * _HIST_PAGE);

  const countEl = document.getElementById('historyCount');
  if (countEl) countEl.textContent = total;

  const tbody = document.getElementById('historyTableBody');
  if (!tbody) return;

  const batchMap = {};
  const standalone = [];
  for (const j of slice) {
    if (j.batch_id) {
      (batchMap[j.batch_id] = batchMap[j.batch_id] || []).push(j);
    } else {
      standalone.push(j);
    }
  }

  if (!slice.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="padding:40px;text-align:center;color:var(--muted)">
      No jobs found${query || status ? ' matching your filters' : ''}.</td></tr>`;
  } else {
    const batchHtml = Object.entries(batchMap).map(([bid, bj]) => _histBatchGroup(bid, bj)).join('');
    const soloHtml  = standalone.map(j => _histJobRow(j, false)).join('');
    tbody.innerHTML  = batchHtml + soloHtml;
  }

  const hasLive = filtered.some(j => _RUNNING.has(j.status));
  if (hasLive) _startHistLive(); else _stopHistLive();

  const info    = document.getElementById('histPageInfo');
  const prevBtn = document.getElementById('histPrevBtn');
  const nextBtn = document.getElementById('histNextBtn');
  if (info) info.textContent = total > _HIST_PAGE
    ? `Showing ${_histPage * _HIST_PAGE + 1}–${Math.min((_histPage + 1) * _HIST_PAGE, total)} of ${total}`
    : `${total} job${total !== 1 ? 's' : ''}`;
  if (prevBtn) prevBtn.disabled = _histPage === 0;
  if (nextBtn) nextBtn.disabled = _histPage >= pages - 1;
}

function histPageChange(delta) {
  _histPage = Math.max(0, _histPage + delta);
  applyHistoryFilter();
}

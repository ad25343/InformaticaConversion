// gates.js — Gate 1/2/3 sign-off, review queue navigation

let _rqSortCol = 'waiting_minutes';
let _rqSortDir = 'desc'; // 'asc' | 'desc'

function rqSort(col) {
  if (_rqSortCol === col) {
    _rqSortDir = _rqSortDir === 'asc' ? 'desc' : 'asc';
  } else {
    _rqSortCol = col;
    _rqSortDir = col === 'waiting_minutes' ? 'desc' : 'asc';
  }
  // update indicators
  document.querySelectorAll('.rq-sort-ind').forEach(el => el.textContent = '');
  const ind = document.getElementById('rqs-' + col);
  if (ind) ind.textContent = _rqSortDir === 'asc' ? ' ▲' : ' ▼';
  renderReviewQueueTable();
}

async function loadReviewQueue() {
  try {
    const res = await fetch('/api/gates/pending');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _reviewQueue = data.jobs || [];
    _reviewSelectedJobIds.clear();
    // update summary counts
    const bg = data.by_gate || {};
    const _sc = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v ?? '0'; };
    _sc('reviewGate1Count',   bg[1]         ?? 0);
    _sc('reviewGate2Count',   bg[2]         ?? 0);
    _sc('reviewGate3Count',   bg[3]         ?? 0);
    _sc('reviewBlockedCount', bg['blocked'] ?? 0);
    _sc('reviewFailedCount',  bg['failed']  ?? 0);
    _sc('reviewTotalCount',   data.total    ?? 0);
    renderReviewQueueTable();
    // set initial sort indicator
    const initInd = document.getElementById('rqs-' + _rqSortCol);
    if (initInd && !initInd.textContent) initInd.textContent = _rqSortDir === 'asc' ? ' ▲' : ' ▼';
    // update nav badge (pending gate jobs only)
    const pendingCount = (bg[1] ?? 0) + (bg[2] ?? 0) + (bg[3] ?? 0);
    const badge = document.getElementById('navReviewBadge');
    if (badge) { badge.textContent = pendingCount || ''; badge.style.display = pendingCount ? '' : 'none'; }
  } catch (err) {
    console.error('Error loading review queue:', err);
    const el = document.getElementById('reviewQueueTable');
    if (el) el.innerHTML = `<div style="padding:20px;text-align:center;color:var(--muted)">Error loading review queue: ${err.message}</div>`;
  }
}

function showGate1RestartOptions() {
  const row = document.getElementById('gate1RestartRow');
  if (row) row.style.display = row.style.display === 'none' ? 'block' : 'none';
}

async function submitSignoff(jobId, decision, flags) {
  const name  = document.getElementById('reviewerName')?.value?.trim();
  const role  = document.getElementById('reviewerRole')?.value;
  const notes = document.getElementById('reviewNotes')?.value?.trim();

  if (!name) { alert('Please enter your name.'); return; }

  let restart_from_step = null;
  if (decision === 'REJECTED') {
    const restartEl = document.getElementById('gate1RestartStep');
    if (restartEl && restartEl.value) {
      restart_from_step = parseInt(restartEl.value, 10);
    }
  }

  const flagResolutions = flags.map((f, i) => {
    const applyFixEl = document.getElementById(`flag_apply_fix_${i}`);
    const applyFix   = applyFixEl ? applyFixEl.checked : false;
    return {
      flag_type:      f.flag_type,
      location:       f.location,
      action:         document.getElementById(`flag_action_${i}`)?.value || 'accepted',
      rationale:      document.getElementById(`flag_note_${i}`)?.value || '',
      apply_fix:      applyFix,
      fix_suggestion: (applyFix && f.auto_fix_suggestion) ? f.auto_fix_suggestion : null,
    };
  });

  const payload = {
    reviewer_name: name,
    reviewer_role: role,
    decision,
    flag_resolutions: flagResolutions,
    notes,
    restart_from_step,
  };

  try {
    const res = await fetch(`/api/jobs/${jobId}/sign-off`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Server error ${res.status}: ${text.slice(0, 300)}`);
    }
    await res.json();
    await openJob(jobId);
  } catch(e) {
    alert('Sign-off submission failed: ' + e.message);
  }
}

async function submitSecurityReview(jobId, decision) {
  const name  = document.getElementById('secReviewerName')?.value?.trim();
  const role  = document.getElementById('secReviewerRole')?.value;
  const notes = document.getElementById('secReviewNotes')?.value?.trim();

  if (!name) { alert('Please enter your name.'); return; }

  const labels = {
    APPROVED:     'approve and proceed to code quality review',
    ACKNOWLEDGED: 'acknowledge the findings and proceed (accepted risk)',
    FAILED:       'FAIL this job and block the pipeline permanently',
  };
  if (!confirm(`Are you sure you want to ${labels[decision] || decision}?`)) return;

  const payload = { reviewer_name: name, reviewer_role: role, decision, notes: notes || null };

  try {
    const res = await fetch(`/api/jobs/${jobId}/security-review`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      alert('Security review failed: ' + (err.detail || res.statusText));
      return;
    }
    await openJob(jobId);
  } catch(e) {
    alert('Security review submission failed: ' + e.message);
  }
}

function showGate3RestartOptions() {
  const row = document.getElementById('gate3RestartRow');
  if (row) row.style.display = row.style.display === 'none' ? 'block' : 'none';
}

async function submitCodeSignoff(jobId, decision) {
  const name  = document.getElementById('codeReviewerName')?.value?.trim();
  const role  = document.getElementById('codeReviewerRole')?.value;
  const notes = document.getElementById('codeReviewNotes')?.value?.trim();

  if (!name) { alert('Please enter your name.'); return; }

  let restart_from_step = null;
  if (decision === 'REJECTED') {
    const restartEl = document.getElementById('gate3RestartStep');
    if (restartEl && restartEl.value) {
      restart_from_step = parseInt(restartEl.value, 10);
    }
  }

  const label = decision === 'APPROVED'
    ? 'approve and mark this job complete'
    : restart_from_step
      ? `reject and restart from Step ${restart_from_step}`
      : 'reject and block this job — you will need to re-upload the mapping to start over';
  if (!confirm(`Are you sure you want to ${label}?`)) return;

  const payload = {
    reviewer_name: name,
    reviewer_role: role,
    decision,
    notes: notes || null,
    restart_from_step,
  };

  try {
    const res = await fetch(`/api/jobs/${jobId}/code-signoff`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      alert('Sign-off failed: ' + (err.detail || res.statusText));
      return;
    }
    await openJob(jobId);
  } catch(e) {
    alert('Sign-off submission failed: ' + e.message);
  }
}

function scrollToSignoff(cardId) {
  const el = document.getElementById(cardId);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    el.style.transition = 'box-shadow .2s';
    el.style.boxShadow = '0 0 0 3px #fbbf24';
    setTimeout(() => { el.style.boxShadow = ''; }, 1800);
  }
}

function openJobForReview(jobId) {
  openJob(jobId).then(() => {
    const jdc = document.getElementById('jobDetailContainer');
    if (jdc && !document.getElementById('reviewBackBar')) {
      const bar = document.createElement('div');
      bar.id = 'reviewBackBar';
      bar.style.cssText = 'padding:0 0 8px 0';
      bar.innerHTML = `<button class="btn btn-sm btn-ghost" onclick="setMainView('review')" style="font-size:12px">← Back to Review Queue</button>`;
      jdc.insertBefore(bar, jdc.firstChild);
    }
    // Only scroll to sign-off card for gate-awaiting jobs (not blocked/failed)
    const job = _reviewQueue.find(j => j.job_id === jobId);
    if (job && !job.retryable) {
      setTimeout(() => {
        const candidates = ['signoffCard','secReviewCard','codeSignoffCard'];
        for (const id of candidates) {
          const el = document.getElementById(id);
          if (el) { scrollToSignoff(id); break; }
        }
      }, 300);
    }
  });
}

function reuploadForJob(hint) {
  // Show the submit form, then inject a contextual guidance banner above it
  showSubmitPanel();
  setTimeout(() => {
    const existing = document.getElementById('reuploadHintBanner');
    if (existing) existing.remove();
    const msg = hint || 'Start a fresh submission with the corrected file.';
    const banner = document.createElement('div');
    banner.id = 'reuploadHintBanner';
    banner.style.cssText = 'background:rgba(251,146,60,.12);border:1px solid rgba(251,146,60,.35);border-radius:8px;padding:12px 16px;margin:0 0 16px 0;font-size:13px;line-height:1.5';
    banner.innerHTML = `
      <div style="font-weight:600;color:#fb923c;margin-bottom:4px">↩ Start a new submission</div>
      <div style="color:var(--text)">${msg}</div>
      <ul style="margin:8px 0 0 18px;color:var(--muted);font-size:12px">
        <li><strong>Mapping XML</strong> — pick from the <code>mappings/</code> folder (contains &lt;MAPPING&gt; tags)</li>
        <li><strong>Workflow XML</strong> — optional, pick from the <code>workflows/</code> folder (contains &lt;WORKFLOW&gt; tags)</li>
        <li><strong>Parameter file</strong> — optional .txt or .xml from <code>parameter_files/</code></li>
      </ul>
      <button onclick="document.getElementById('reuploadHintBanner').remove()"
              style="margin-top:10px;font-size:11px;background:none;border:none;color:var(--muted);cursor:pointer;padding:0">✕ Dismiss</button>`;
    const container = document.getElementById('submitFormContainer');
    if (container) container.insertBefore(banner, container.firstChild);
  }, 100);
}

// ── Review queue table rendering ──────────────────────────────────────────────

function setReviewFilter(f) {
  _reviewGateFilter = f;
  const btns = { all: 'filterAllBtn', gate1: 'filter1Btn', gate2: 'filter2Btn', gate3: 'filter3Btn', blocked: 'filterBlockedBtn', failed: 'filterFailedBtn' };
  Object.entries(btns).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (!el) return;
    const active = key === f;
    el.className = active ? 'btn btn-sm' : 'btn btn-sm btn-ghost';
    el.style.background = active ? 'var(--accent)' : '';
    if (active) { el.style.color = '#fff'; }
    else if (key === 'blocked') el.style.color = '#f87171';
    else if (key === 'failed')  el.style.color = '#fb923c';
    else el.style.color = '';
  });
  _reviewSelectedJobIds.clear();
  renderReviewQueueTable();
}

function _applyReviewFilters(jobs) {
  const f = _reviewGateFilter;
  const q = (document.getElementById('reviewSearchInput')?.value || '').toLowerCase().trim();
  const filtered = jobs.filter(j => {
    if (f === 'gate1')        { if (j.gate !== 1 || j.retryable) return false; }
    else if (f === 'gate2')   { if (j.gate !== 2 || j.retryable) return false; }
    else if (f === 'gate3')   { if (j.gate !== 3 || j.retryable) return false; }
    else if (f === 'blocked') { if (j.status !== 'blocked') return false; }
    else if (f === 'failed')  { if (j.status !== 'failed') return false; }
    if (q) {
      const haystack = `${j.filename} ${j.batch_id || ''} ${j.submitter_name || ''} ${j.status || ''} ${j.error_summary || ''} ${j.complexity_tier || ''} step${j.failed_step || ''}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
  // sort
  const col = _rqSortCol;
  const dir = _rqSortDir === 'asc' ? 1 : -1;
  function _sortKey(j) {
    if (col === 'status') return (j.status || '') + String(j.failed_step || 0).padStart(4, '0');
    return j[col] ?? '';
  }
  filtered.sort((a, b) => {
    const av = _sortKey(a);
    const bv = _sortKey(b);
    if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir;
    return String(av).localeCompare(String(bv)) * dir;
  });
  return filtered;
}

function renderReviewQueueTable() {
  const filtered = _applyReviewFilters(_reviewQueue);

  if (!filtered.length) {
    document.getElementById('reviewQueueTable').innerHTML =
      `<div style="padding:20px;text-align:center;color:var(--muted)"><div style="font-size:24px">📋</div><div style="font-size:12px;margin-top:8px">No jobs currently awaiting review</div></div>`;
    document.getElementById('selectAllCheckbox').checked = false;
    return;
  }

  const GATE_LABEL = { 1: 'Analysis Sign-off', 2: 'Security Sign-off', 3: 'Final Sign-off' };
  const STATUS_STYLE = {
    blocked:   { color: '#f87171', bg: 'rgba(248,113,113,.08)', label: 'Blocked'   },
    failed:    { color: '#fb923c', bg: 'rgba(251,146,60,.08)',  label: 'Failed'    },
    cancelled: { color: '#94a3b8', bg: 'rgba(148,163,184,.08)', label: 'Cancelled' },
  };

  const rows = filtered.map(j => {
    const isSelected = _reviewSelectedJobIds.has(j.job_id);
    const retryable = j.retryable;
    const statusStyle = STATUS_STYLE[j.status] || {};
    const severityBadges = [];
    if (j.flag_summary) {
      if (j.flag_summary.CRITICAL > 0) severityBadges.push(`<span style="background:rgba(248,113,113,.2);color:#f87171;padding:2px 6px;border-radius:4px;font-size:10px;margin-right:2px">C${j.flag_summary.CRITICAL}</span>`);
      if (j.flag_summary.HIGH > 0)     severityBadges.push(`<span style="background:rgba(251,146,60,.2);color:#fb923c;padding:2px 6px;border-radius:4px;font-size:10px;margin-right:2px">H${j.flag_summary.HIGH}</span>`);
      if (j.flag_summary.MEDIUM > 0)   severityBadges.push(`<span style="background:rgba(251,191,36,.2);color:#fbbf24;padding:2px 6px;border-radius:4px;font-size:10px;margin-right:2px">M${j.flag_summary.MEDIUM}</span>`);
    }
    const flagsHtml = severityBadges.length ? severityBadges.join('') : '—';
    const submitterDisplay = esc((j.submitter_name || '').replace(/^"|"$/g, '') || '–');
    const rowBg = retryable ? statusStyle.bg : (isSelected ? 'rgba(108,99,255,.06)' : '');
    const errorHtml = (retryable && j.error_summary)
      ? `<div style="font-size:10px;color:var(--muted);margin-top:2px;white-space:normal;line-height:1.3;max-width:260px" title="${esc(j.error_summary)}">${esc(j.error_summary)}</div>`
      : '';
    const statusCell = retryable
      ? `<div><span style="font-size:11px;font-weight:600;color:${statusStyle.color}">${statusStyle.label} @step ${j.failed_step || '?'}</span>${errorHtml}</div>`
      : `<span style="font-size:12px;font-weight:600">${GATE_LABEL[j.gate] || ('Gate ' + j.gate)}</span>`;
    const actionCell = retryable
      ? `<span onclick="event.stopPropagation();retryJob('${j.job_id}')" style="font-size:11px;color:#fb923c;font-weight:600;white-space:nowrap;cursor:pointer">↺ Retry</span>`
      : `<span onclick="event.stopPropagation();openJobForReview('${j.job_id}')" style="font-size:11px;color:var(--accent);font-weight:600;white-space:nowrap">Review →</span>`;
    return `<div style="display:grid;grid-template-columns:var(--rq-cols,16px 90px 240px 140px 80px 120px 70px 90px 90px 80px);gap:0;align-items:center;padding:10px 12px;border-bottom:1px solid var(--border);cursor:pointer;background:${rowBg}"
                 onclick="openJobForReview('${j.job_id}')"
                 onmouseenter="this.style.background='var(--surface2)'" onmouseleave="this.style.background='${rowBg}'"
            >
      <input type="checkbox" ${isSelected ? 'checked' : ''} onchange="event.stopPropagation();toggleReviewJobSelection('${j.job_id}', this.checked)" style="width:16px;height:16px;cursor:pointer"/>
      <span style="overflow:hidden;padding-right:10px;white-space:nowrap">
        <span style="font-family:monospace;font-size:11px;font-weight:700;background:rgba(108,99,255,.15);color:var(--accent);padding:2px 6px;border-radius:4px">${shortId(j.job_id)}</span>
      </span>
      <span style="font-size:12px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-right:10px" title="${esc(j.filename)}">${esc(j.filename)}</span>
      <span style="font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-right:10px">${submitterDisplay}</span>
      <span style="font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-right:10px">${esc(j.batch_id || '–')}</span>
      <div style="overflow:hidden;padding-right:10px;${retryable ? 'align-self:start;padding-top:2px' : ''}">${statusCell}</div>
      <span style="font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-right:10px">${esc(j.complexity_tier || '–')}</span>
      <span style="font-size:11px;overflow:hidden;padding-right:10px">${flagsHtml}</span>
      <span style="font-size:11px;color:var(--muted);white-space:nowrap;padding-right:10px">${j.waiting_minutes}m ago</span>
      ${actionCell}
    </div>`;
  }).join('');

  document.getElementById('reviewQueueTable').innerHTML = `<div>${rows}</div>`;
  document.getElementById('selectAllCheckbox').checked =
    _reviewSelectedJobIds.size > 0 && _reviewSelectedJobIds.size === filtered.length;
}

async function retryJob(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/retry`, { method: 'POST' });
    if (!res.ok) { const e = await res.json(); throw new Error(e.detail || res.status); }
    await loadReviewQueue();
  } catch (err) {
    alert(`Retry failed: ${err.message}`);
  }
}

function toggleReviewJobSelection(jobId, checked) {
  if (checked) _reviewSelectedJobIds.add(jobId);
  else         _reviewSelectedJobIds.delete(jobId);
  const filtered = _applyReviewFilters(_reviewQueue);
  document.getElementById('selectAllCheckbox').checked =
    _reviewSelectedJobIds.size > 0 && _reviewSelectedJobIds.size === filtered.length;
  // show Retry Selected if any selected job is retryable
  const retryBtn = document.getElementById('retrySelectedBtn');
  if (retryBtn) {
    const anyRetryable = [..._reviewSelectedJobIds].some(id => _reviewQueue.find(j => j.job_id === id && j.retryable));
    retryBtn.style.display = anyRetryable ? '' : 'none';
    retryBtn.style.display = anyRetryable ? 'inline-flex' : 'none';
  }
  // dim Approve/Reject if only retryable jobs are selected
  const allRetryable = [..._reviewSelectedJobIds].every(id => _reviewQueue.find(j => j.job_id === id && j.retryable));
  ['approveSelectedBtn','rejectSelectedBtn'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.style.opacity = (_reviewSelectedJobIds.size > 0 && allRetryable) ? '0.4' : '';
  });
}

async function retrySelectedJobs() {
  const retryableIds = [..._reviewSelectedJobIds].filter(id => _reviewQueue.find(j => j.job_id === id && j.retryable));
  if (!retryableIds.length) return;
  const results = await Promise.allSettled(retryableIds.map(id => fetch(`/api/jobs/${id}/retry`, { method: 'POST' }).then(r => r.ok ? r : Promise.reject(r.statusText))));
  const failed = results.filter(r => r.status === 'rejected');
  if (failed.length) alert(`${failed.length} retry(ies) failed. Check the job detail for details.`);
  await loadReviewQueue();
}

function toggleSelectAllReview(checked) {
  const filtered = _applyReviewFilters(_reviewQueue);
  _reviewSelectedJobIds.clear();
  if (checked) filtered.forEach(j => _reviewSelectedJobIds.add(j.job_id));
  renderReviewQueueTable();
}

// ── Review Queue column resizing ──────────────────────────────────────────────
const _rqDefaultWidths = [16, 90, 240, 140, 80, 120, 70, 90, 90, 80];
let   _rqColWidths = [..._rqDefaultWidths];

function _rqApplyCols() {
  const val = _rqColWidths.map(w => w + 'px').join(' ');
  document.documentElement.style.setProperty('--rq-cols', val);
}

function initReviewColResize() {
  const header = document.getElementById('reviewQueueHeader');
  if (!header || header.dataset.rqInit) return;
  header.dataset.rqInit = '1';
  _rqApplyCols();
  // Show initial sort indicator
  const initInd = document.getElementById('rqs-' + _rqSortCol);
  if (initInd) initInd.textContent = _rqSortDir === 'asc' ? ' ▲' : ' ▼';

  header.querySelectorAll('.rq-rsz').forEach(handle => {
    handle.addEventListener('mousedown', e => {
      e.preventDefault();
      e.stopPropagation();
      const col   = parseInt(handle.dataset.col, 10); // 1-based, maps to _rqColWidths index
      const startX = e.clientX;
      const startW = _rqColWidths[col];
      handle.classList.add('rq-dragging');

      function onMove(ev) {
        const delta = ev.clientX - startX;
        _rqColWidths[col] = Math.max(40, startW + delta);
        _rqApplyCols();
      }
      function onUp() {
        handle.classList.remove('rq-dragging');
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  });
}

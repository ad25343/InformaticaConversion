// ─────────────────────────────────────────────
// API helpers — all fetch/network calls
// ─────────────────────────────────────────────

async function loadLandingStats() {
  try {
    const r = await fetch('/api/jobs/stats');
    if (!r.ok) return;
    const d = await r.json();
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = String(v ?? 0); };
    set('lsTotal',   d.total);
    set('lsRunning', d.running);
    set('lsComplete',d.complete);
    set('lsPending', d.awaiting_review);
    const cta = document.getElementById('landingReviewCta');
    if (cta) cta.textContent = d.awaiting_review > 0 ? `${d.awaiting_review} awaiting review →` : 'Open queue →';
  } catch(e) { /* silent */ }
}

async function loadJobs() {
  try {
    // Pull all jobs (up to 500) so sidebar, filters, and search see the full dataset.
    let all = [];
    for (let page = 1; page <= 5; page++) {
      const res  = await fetch(`/api/jobs?page=${page}&page_size=100`);
      const data = await res.json();
      const batch = data.jobs || [];
      all = all.concat(batch);
      if (all.length >= (data.total || 0) || batch.length < 100) break;
    }
    let history = [];
    try {
      const histRes  = await fetch('/api/logs/history');
      const histData = await histRes.json();
      history = histData.history || [];
    } catch(he) { /* history is supplemental — never break the main list */ }
    _allJobs    = all;
    _allHistory = history;
    // Sidebar and stats update first — they must never be blocked by a render error
    try { refreshSidebarActivity(); } catch(e) { /* sidebar is non-blocking */ }
    try { if (_mainView === 'landing') loadLandingStats(); } catch(e) { /* stats non-blocking */ }
    // Job list render — isolated so errors here don't cascade
    try { applyJobFilter(); } catch(e) { /* render non-blocking */ }
  } catch(e) { /* ignore poll errors */ }
}

async function loadHistory() {
  try {
    // Fetch up to 500 jobs so search, filters, and recent-submissions all see the full dataset.
    // The API caps page_size at 100, so we pull up to 5 pages if needed.
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

async function loadReviewQueue() {
  try {
    const url = new URL('/api/gates/pending', window.location.origin);
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _reviewQueue = data.jobs || [];

    // Update summary counts
    document.getElementById('reviewGate1Count').textContent = data.by_gate?.['1'] || 0;
    document.getElementById('reviewGate2Count').textContent = data.by_gate?.['2'] || 0;
    document.getElementById('reviewGate3Count').textContent = data.by_gate?.['3'] || 0;
    document.getElementById('reviewTotalCount').textContent = data.total || 0;

    renderReviewQueueTable();
  } catch (e) {
    console.error('Error loading review queue:', e);
    document.getElementById('reviewQueueTable').innerHTML = `<div style="padding:20px;color:var(--danger)">Error loading review queue: ${e.message}</div>`;
  }
}

// ── Bell badge updater ────────────────────────
async function updateNotifBell() {
  try {
    const res = await fetch('/api/gates/pending');
    if (!res.ok) return;
    const data = await res.json();
    const total = data.total ?? 0;

    const bell  = document.getElementById('notifBell');
    const badge = document.getElementById('notifBadge');
    if (!bell || !badge) return;

    // Update nav badge
    const navBadge = document.getElementById('navReviewBadge');
    if (navBadge) {
      navBadge.textContent = total > 99 ? '99+' : String(total);
      navBadge.style.display = total > 0 ? '' : 'none';
    }

    if (total > 0) {
      badge.textContent = total > 99 ? '99+' : String(total);
      bell.style.display = '';
    } else {
      bell.style.display = 'none';
    }

    // Update browser tab title
    const base = 'Informatica Conversion Tool';
    document.title = total > 0 ? `(${total}) ${base}` : base;

    // Toast when the count rises (new jobs arrived at a gate)
    if (total > _prevGatePending && _prevGatePending !== null) {
      const newCount = total - _prevGatePending;
      showToast(
        `${newCount} job${newCount > 1 ? 's' : ''} waiting for review`,
        `${total} total pending in the gate queue. Open Review Queue to sign off.`,
        'warn',
        8000
      );
    }
    _prevGatePending = total;
  } catch (e) { /* non-fatal */ }
}

async function deleteHistJob(jobId, btn) {
  if (!confirm('Remove this job from history? The record is kept for audit purposes.')) return;
  btn.disabled = true;
  btn.textContent = '…';
  try {
    const res = await fetch(`/api/jobs/${jobId}`, { method: 'DELETE' });
    if (res.ok) {
      // Remove the row from the DOM immediately — no full reload needed
      const row = btn.closest('tr');
      if (row) row.remove();
      await loadJobs();
    } else {
      btn.disabled = false;
      btn.textContent = '🗑';
      showToast('Delete failed', `Server returned ${res.status}`, 'error', 4000);
    }
  } catch (e) {
    btn.disabled = false;
    btn.textContent = '🗑';
    showToast('Delete failed', e.message, 'error', 4000);
  }
}

async function deleteBatch(batchId, batchKey) {
  if (!confirm(`Remove all jobs in this batch from history?\nRecords are kept for audit purposes.`)) return;
  const btn = document.getElementById(`delBatch_${batchKey}`);
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    const res = await fetch(`/api/batches/${encodeURIComponent(batchId)}`, { method: 'DELETE' });
    if (res.ok) {
      // Remove the header row + children wrapper from the DOM
      const headerRow  = btn?.closest('tr');
      if (headerRow) {
        const next = headerRow.nextElementSibling;
        if (next && next.id && next.id.startsWith('batchChildren_')) next.remove();
        headerRow.remove();
      }
      await loadJobs();
    } else {
      if (btn) { btn.disabled = false; btn.textContent = '🗑 Delete batch'; }
      showToast('Delete failed', `Server returned ${res.status}`, 'error', 4000);
    }
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = '🗑 Delete batch'; }
    showToast('Delete failed', e.message, 'error', 4000);
  }
}

async function deleteJob(jobId, filename) {
  if (!confirm(`Delete job "${filename}"?\n\nThis will remove the job record, log file, and S2T Excel from the server. This cannot be undone.`)) return;
  try {
    const res = await fetch(`/api/jobs/${jobId}`, { method: 'DELETE' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert('Delete failed: ' + (err.detail || res.statusText));
      return;
    }
    // If we just deleted the active job, clear the panel
    if (currentJobId === jobId) {
      currentJobId = null;
      if (eventSource) { eventSource.close(); eventSource = null; }
      document.getElementById('jobPanel').innerHTML =
        '<div class="empty"><div style="font-size:32px">🗂️</div><div>Select a job from the list</div></div>';
    }
    await loadJobs();
  } catch(e) { alert('Delete failed: ' + e.message); }
}

async function retryJob(jobId) {
  if (!confirm('Retry this job?\n\nThe pipeline will restart from Step 1 using the original XML file.')) return;
  try {
    const res = await fetch(`/api/jobs/${jobId}/retry`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert('Retry failed: ' + (err.detail || res.statusText));
      return;
    }
    showToast('Job queued for retry', 'Pipeline restarting from Step 1.', 'info', 5000);
    await loadJobs();
    openJob(jobId);
  } catch(e) { alert('Retry failed: ' + e.message); }
}

async function toggleAuditTrail(jobId) {
  const body   = document.getElementById('auditTrailBody');
  const toggle = document.getElementById('auditTrailToggle');
  if (!body || !toggle) return;

  const isOpen = body.style.display !== 'none';
  if (isOpen) {
    body.style.display = 'none';
    toggle.textContent = '▶ Show';
    return;
  }

  body.style.display = '';
  toggle.textContent = '▼ Hide';
  body.innerHTML = '<div style="color:var(--muted);font-size:12px">Loading…</div>';

  try {
    const res = await fetch(`/api/jobs/${jobId}/audit`);
    if (!res.ok) { body.innerHTML = '<div style="color:var(--danger);font-size:12px">Failed to load audit trail.</div>'; return; }
    const data = await res.json();
    const entries = data.entries || [];

    if (!entries.length) {
      body.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:8px 0">No gate decisions recorded yet.</div>';
      return;
    }

    const gateIcon = { gate1:'🔵', gate2:'🟡', gate3:'🟢', retry:'🔄' };
    const decColor = { APPROVED:'var(--accent2)', APPROVE:'var(--accent2)', ACKNOWLEDGED:'var(--warn)',
                       REJECTED:'var(--danger)', REJECT:'var(--danger)', FAILED:'var(--danger)',
                       RETRY:'var(--muted)' };

    body.innerHTML = `<div style="display:flex;flex-direction:column;gap:8px">
      ${entries.map(e => {
        const icon  = gateIcon[e.gate] || '⚪';
        const color = decColor[e.decision] || 'var(--text)';
        const ts    = e.created_at ? new Date(e.created_at).toLocaleString() : '';
        const extra = e.extra && Object.keys(e.extra).length
          ? `<div style="font-size:11px;color:var(--muted);margin-top:2px">${Object.entries(e.extra).map(([k,v])=>`${k}: ${v}`).join(' · ')}</div>`
          : '';
        return `<div style="background:var(--surface2);border-radius:6px;padding:10px 12px;border-left:3px solid ${color}">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
            <span style="font-size:13px">${icon}</span>
            <strong style="font-size:12px;color:${color}">${esc(e.decision || e.event_type || '')}</strong>
            <span style="font-size:11px;color:var(--muted);margin-left:auto">${esc(ts)}</span>
          </div>
          <div style="font-size:12px;color:var(--muted)">${esc(e.gate)} · ${esc(e.reviewer_name || '')}${e.reviewer_role ? ' ('+esc(e.reviewer_role)+')' : ''}</div>
          ${e.notes ? `<div style="font-size:12px;margin-top:4px;color:var(--text)">${esc(e.notes)}</div>` : ''}
          ${extra}
        </div>`;
      }).join('')}
    </div>`;
  } catch(ex) {
    body.innerHTML = `<div style="color:var(--danger);font-size:12px">Error: ${esc(String(ex))}</div>`;
  }
}

async function downloadS2T(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/s2t/download`);
    if (!res.ok) { alert('S2T Excel not available yet — run a job first.'); return; }
    const blob = await res.blob();
    const cd   = res.headers.get('content-disposition') || '';
    const match = cd.match(/filename="?([^"]+)"?/);
    const fname = match ? match[1] : `${jobId}_s2t.xlsx`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = fname;
    a.click();
  } catch(e) { alert('Download failed: ' + e.message); }
}

async function downloadJobLog(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/logs/download`);
    if (!res.ok) { alert('Log file not available yet.'); return; }
    const text = await res.text();
    const blob = new Blob([text], {type: 'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${jobId}.log`;
    a.click();
  } catch(e) { alert('Download failed: ' + e.message); }
}

async function refreshLog(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/logs`);
    const data = await res.json();
    const entries = data.entries || [];
    const panel = document.getElementById('logScroll');
    if (!panel) return;
    panel.innerHTML = entries.map(e => {
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
    }).join('') || '<div style="color:#4b5563;padding:8px 0;font-size:11px">No log entries yet.</div>';
    panel.scrollTop = panel.scrollHeight;
  } catch(e) { console.error('Log refresh failed', e); }
}

async function downloadCode(jobId, filename) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/download/${encodeURIComponent(filename)}`);
    const data = await res.json();
    const blob = new Blob([data.content], {type:'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
  } catch(e) {
    alert('Download failed: ' + e.message);
  }
}

async function downloadOutputZip(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/output.zip`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({detail: res.statusText}));
      alert('ZIP download failed: ' + (err.detail || res.statusText));
      return;
    }
    const blob = await res.blob();
    const disposition = res.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="([^"]+)"/);
    const filename = match ? match[1] : `${jobId}_output.zip`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
  } catch(e) {
    alert('ZIP download failed: ' + e.message);
  }
}

async function downloadTestFile(jobId, filename) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/tests/download/${encodeURIComponent(filename)}`);
    if (!res.ok) { alert('Download failed: ' + res.statusText); return; }
    const data = await res.json();
    const blob = new Blob([data.content], {type:'text/plain'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = filename.split('/').pop();
    a.click();
    URL.revokeObjectURL(url);
  } catch(e) { alert('Download failed: ' + e.message); }
}

async function downloadManifestXlsx() {
  const job = window._currentJob;
  if (!job) return;
  // Manifest is generated on demand by the API — not stored in state
  const resp = await fetch(`/api/jobs/${job.job_id}/manifest.xlsx`);
  if (!resp.ok) { alert('Manifest not available for this job.'); return; }
  const blob = await resp.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  const safe = (job.filename || 'mapping').replace(/[^a-z0-9_\-\.]/gi, '_').replace(/\.xml$/i, '');
  a.href     = url;
  a.download = `manifest_${safe}.xlsx`;
  a.click();
  URL.revokeObjectURL(url);
}

async function uploadManifest(jobId) {
  const input  = document.getElementById('manifestFileInput');
  const btn    = document.getElementById('manifestUploadBtn');
  const status = document.getElementById('manifestUploadStatus');
  if (!input || !input.files || !input.files[0]) {
    if (status) { status.textContent = '⚠ No file selected.'; status.style.color = '#f87171'; }
    return;
  }
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Uploading…'; }
  if (status) { status.textContent = ''; }

  const fd = new FormData();
  fd.append('file', input.files[0]);
  try {
    const resp = await fetch(`/api/jobs/${jobId}/manifest-upload`, { method: 'POST', body: fd });
    const data = await resp.json();
    if (!resp.ok) {
      if (status) { status.textContent = `✗ ${data.detail || 'Upload failed.'}`; status.style.color = '#f87171'; }
    } else {
      const n = data.override_count || 0;
      if (status) {
        status.innerHTML = `<span style="color:#4ade80;font-weight:600">✓ ${n} override${n !== 1 ? 's' : ''} stored</span>${n === 0 ? ' <span style="color:var(--muted)">(no Override column values found — check the Review Required sheet)</span>' : ''}`;
      }
      if (btn) btn.style.display = 'none';
    }
  } catch (e) {
    if (status) { status.textContent = `✗ Network error: ${e.message}`; status.style.color = '#f87171'; }
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⬆ Upload Overrides'; }
  }
}

async function submitReviewDecision(decision) {
  if (_reviewSelectedJobIds.size === 0) {
    alert('Please select at least one job');
    return;
  }

  const reviewerName = document.getElementById('reviewerNameInput')?.value?.trim();
  if (!reviewerName) {
    alert('Please enter your name');
    return;
  }

  // Determine gate and map decision
  const selectedJobs = _reviewQueue.filter(j => _reviewSelectedJobIds.has(j.job_id));
  if (!selectedJobs.length) return;

  const gates = new Set(selectedJobs.map(j => j.gate));
  if (gates.size > 1) {
    alert('Please select jobs from only one gate at a time');
    return;
  }

  const gate = selectedJobs[0].gate;
  let apiDecision = decision;

  // Map UI decisions to API decisions based on gate
  if (gate === 1) {
    apiDecision = decision === 'APPROVE' ? 'APPROVE' : 'REJECT';
  } else if (gate === 2) {
    if (decision === 'APPROVE') apiDecision = 'APPROVED';
    else if (decision === 'ACKNOWLEDGE') apiDecision = 'ACKNOWLEDGED';
    else apiDecision = 'FAILED';
  } else if (gate === 3) {
    apiDecision = decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
  }

  const body = {
    job_ids: Array.from(_reviewSelectedJobIds),
    gate: gate,
    decision: apiDecision,
    reviewer_name: reviewerName,
    reviewer_role: 'Reviewer',
    notes: '',
  };

  try {
    const res = await fetch('/api/gates/batch-signoff', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`HTTP ${res.status}: ${err}`);
    }

    const result = await res.json();
    const msg = `${result.succeeded?.length || 0} approved, ${result.failed?.length || 0} failed`;
    alert(`Batch sign-off complete: ${msg}`);

    _reviewSelectedJobIds.clear();
    loadReviewQueue();
  } catch (e) {
    console.error('Error submitting batch decision:', e);
    alert(`Error: ${e.message}`);
  }
}

// ── Guide markdown loader ──────────────────────────────
let _guideLoaded = false;
async function loadGuide() {
  if (_guideLoaded) return;   // only fetch once per session
  const container = document.getElementById('guideContent');
  const loader    = document.getElementById('guideLoader');
  if (!container) return;
  try {
    const r = await fetch('/api/docs/user-guide');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const md = await r.text();
    if (typeof marked === 'undefined') throw new Error('marked.js not loaded');
    // Render markdown → HTML
    const html = marked.parse(md, { gfm: true, breaks: false });
    // Inject with scoped styles for readability
    container.innerHTML = `
      <style>
        #guideContent h1{font-size:26px;font-weight:800;margin:0 0 6px}
        #guideContent h2{font-size:18px;font-weight:700;margin:36px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--border)}
        #guideContent h3{font-size:15px;font-weight:700;margin:24px 0 8px;color:var(--text)}
        #guideContent h4{font-size:13px;font-weight:700;margin:18px 0 6px;color:var(--muted)}
        #guideContent p{font-size:14px;line-height:1.7;margin:0 0 12px;color:var(--text)}
        #guideContent ul,#guideContent ol{font-size:14px;line-height:1.7;margin:0 0 12px;padding-left:22px;color:var(--text)}
        #guideContent li{margin-bottom:4px}
        #guideContent table{width:100%;border-collapse:collapse;font-size:13px;margin:0 0 16px}
        #guideContent th{text-align:left;padding:7px 10px;background:var(--surface2);border:1px solid var(--border);font-weight:700;font-size:12px}
        #guideContent td{padding:7px 10px;border:1px solid var(--border);vertical-align:top}
        #guideContent code{font-family:monospace;font-size:12px;background:var(--surface2);padding:1px 5px;border-radius:4px;color:var(--accent)}
        #guideContent pre{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px 16px;overflow-x:auto;margin:0 0 16px}
        #guideContent pre code{background:none;padding:0;color:var(--text);font-size:12px;line-height:1.6}
        #guideContent blockquote{border-left:3px solid var(--accent);margin:0 0 12px;padding:8px 14px;background:rgba(108,99,255,.06);border-radius:0 6px 6px 0;font-size:13px;color:var(--muted)}
        #guideContent hr{border:none;border-top:1px solid var(--border);margin:28px 0}
        #guideContent a{color:var(--accent);text-decoration:none}
        #guideContent a:hover{text-decoration:underline}
        #guideContent strong{font-weight:700}
      </style>
      ${html}`;
    _guideLoaded = true;
  } catch(e) {
    if (loader) loader.innerHTML = `<span style="color:var(--danger)">Failed to load guide: ${e.message}</span>`;
    else container.innerHTML = `<p style="color:var(--danger)">Failed to load guide: ${e.message}</p>`;
  }
}

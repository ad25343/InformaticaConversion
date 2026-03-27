// ─────────────────────────────────────────────
// Upload handling — file upload, drag-drop, job submission
// ─────────────────────────────────────────────

const dropzone      = document.getElementById('dropzone');
const fileInput     = document.getElementById('fileInput');
const fileLabel     = document.getElementById('fileLabel');
const startBtn      = document.getElementById('startBtn');

const dropzoneWF    = document.getElementById('dropzoneWF');
const workflowInput = document.getElementById('workflowInput');
const workflowLabel = document.getElementById('workflowLabel');

const dropzonePF    = document.getElementById('dropzonePF');
const paramInput    = document.getElementById('paramInput');
const paramLabel    = document.getElementById('paramLabel');

// v2.0 batch elements
const dropzoneBatch = document.getElementById('dropzoneBatch');
const batchInput    = document.getElementById('batchInput');
const batchLabel    = document.getElementById('batchLabel');
const batchWarnings = document.getElementById('batchWarnings');

let selectedWorkflowFile = null;
let selectedParamFile    = null;
let selectedBatchFile    = null;
let uploadMode    = 'files';       // 'files' | 'batch'
let pipelineMode  = 'full';        // 'full' | 'docs_only'

function setPipelineMode(mode) {
  pipelineMode = mode;
  document.getElementById('modeFullBtn').className =
    mode === 'full' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-ghost';
  document.getElementById('modeDocsBtn').className =
    mode === 'docs_only' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-ghost';
  // Keep ghost button text visible
  document.querySelector('#modeFullBtn span').style.color =
    mode === 'full' ? 'rgba(255,255,255,.7)' : 'var(--muted)';
  document.querySelector('#modeDocsBtn span').style.color =
    mode === 'docs_only' ? 'rgba(255,255,255,.7)' : 'var(--muted)';
  // Update mode summary card on the right panel
  const card = document.getElementById('submitModeCard');
  if (card) {
    if (mode === 'docs_only') {
      card.innerHTML = `
        <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:8px">📋 Documentation Only — Steps 1–4</div>
        <div style="font-size:12px;color:var(--muted);line-height:1.7">
          Parse → Classify → Document → Verify → <strong style="color:#4ade80">✓ Complete</strong><br/>
          <span style="font-size:11px">No code conversion. Use this to generate documentation and review the analysis before committing to full conversion.</span>
        </div>
        <button onclick="setMainView('docs')" style="margin-top:10px;padding:5px 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface2);color:var(--muted);font-size:11px;cursor:pointer">
          📖 See full pipeline details →
        </button>`;
    } else {
      card.innerHTML = `
        <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:8px">🔄 Full Conversion — 12 steps</div>
        <div style="font-size:12px;color:var(--muted);line-height:1.7">
          Parse → Classify → Document → Verify → <span style="color:#fbbf24">⏸ Gate 1</span> →
          Stack → Convert → Security Scan → <span style="color:#fbbf24">⏸ Gate 2</span> →
          Quality → Tests → <span style="color:#fbbf24">⏸ Gate 3</span> → Complete
        </div>
        <button onclick="setMainView('docs')" style="margin-top:10px;padding:5px 12px;border-radius:6px;border:1px solid var(--border);background:var(--surface2);color:var(--muted);font-size:11px;cursor:pointer">
          📖 See full pipeline details →
        </button>`;
    }
  }
}

// ── Upload mode toggle ─────────────────────────
function setUploadMode(mode) {
  uploadMode = mode;
  document.getElementById('panelFiles').style.display = mode === 'files' ? '' : 'none';
  document.getElementById('panelBatch').style.display = mode === 'batch' ? '' : 'none';
  const tabFiles = document.getElementById('tabFiles');
  const tabBatch = document.getElementById('tabBatch');
  tabFiles.className = mode === 'files' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-ghost';
  tabBatch.className = mode === 'batch' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-ghost';
  if (mode === 'files')  startBtn.disabled = !selectedFile;
  if (mode === 'batch')  startBtn.disabled = !selectedBatchFile;
  // Update tips box based on mode
  const tips = document.getElementById('submitTipsBox');
  if (!tips) return;
  const tipsMap = {
    files: `<strong style="color:var(--text)">💡 Individual mode tips:</strong><br/>
      • Drop a <strong>mapping .xml</strong> or a <strong>.zip</strong> containing your mapping files.<br/>
      • For .xml: optionally attach a <strong>Workflow XML</strong> and/or a <strong>parameter file</strong>.<br/>
      • For .zip: workflow &amp; parameter files are auto-detected — no extra steps needed.`,
    batch: `<strong style="color:var(--text)">💡 Batch mode tips:</strong><br/>
      • <strong>Select Folder</strong> — pick a folder directly; it's auto-packaged into a ZIP for you.<br/>
      • <strong>Select ZIP</strong> — or supply your own ZIP with one subfolder per mapping.<br/>
      • Up to 3 jobs run concurrently. Large batches are queued automatically.<br/>
      • Track each child job individually in Job History once submitted.`,
  };
  tips.innerHTML = tipsMap[mode] || tipsMap.files;
}

// ── Show submit panel (form + intelligence) ──────────────────────────────
function showSubmitPanel() {
  const sfc = document.getElementById('submitFormContainer');
  const jdc = document.getElementById('jobDetailContainer');
  if (sfc) sfc.style.display = 'flex';
  if (jdc) { jdc.style.display = 'none'; jdc.innerHTML = ''; }
  setMainView('dashboard');
  // Remove back bars
  ['histBackBar','reviewBackBar'].forEach(id => { const el = document.getElementById(id); if (el) el.remove(); });
}

// Workflow XML dropzone wiring
dropzoneWF.addEventListener('click', () => workflowInput.click());
dropzoneWF.addEventListener('dragover', e => { e.preventDefault(); dropzoneWF.classList.add('drag'); });
dropzoneWF.addEventListener('dragleave', () => dropzoneWF.classList.remove('drag'));
dropzoneWF.addEventListener('drop', e => {
  e.preventDefault(); dropzoneWF.classList.remove('drag');
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.xml')) setWorkflowFile(f);
});
workflowInput.addEventListener('change', () => { if (workflowInput.files[0]) setWorkflowFile(workflowInput.files[0]); });

function setWorkflowFile(f) {
  selectedWorkflowFile = f;
  workflowLabel.innerHTML = `✅ ${f.name} <span style="color:var(--muted);font-weight:400">(${(f.size/1024).toFixed(1)} KB)</span>`;
  dropzoneWF.style.borderColor = 'var(--success)';
}

// Parameter file dropzone wiring
dropzonePF.addEventListener('click', () => paramInput.click());
dropzonePF.addEventListener('dragover', e => { e.preventDefault(); dropzonePF.classList.add('drag'); });
dropzonePF.addEventListener('dragleave', () => dropzonePF.classList.remove('drag'));
dropzonePF.addEventListener('drop', e => {
  e.preventDefault(); dropzonePF.classList.remove('drag');
  const f = e.dataTransfer.files[0];
  if (f) setParamFile(f);
});
paramInput.addEventListener('change', () => { if (paramInput.files[0]) setParamFile(paramInput.files[0]); });

function setParamFile(f) {
  selectedParamFile = f;
  paramLabel.innerHTML = `✅ ${f.name} <span style="color:var(--muted);font-weight:400">(${(f.size/1024).toFixed(1)} KB)</span>`;
  dropzonePF.style.borderColor = 'var(--success)';
}

// Individual dropzone wiring — .xml only
dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
dropzone.addEventListener('drop', e => {
  e.preventDefault(); dropzone.classList.remove('drag');
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.xml')) setFile(f);
});
fileInput.addEventListener('change', () => { if (fileInput.files[0]) setFile(fileInput.files[0]); });

function setFile(f) {
  selectedFile = f;
  fileLabel.innerHTML = `✅ ${f.name} <span style="color:var(--muted);font-weight:400">(${(f.size/1024/1024).toFixed(2)} MB)</span>`;
  dropzone.style.borderColor = 'var(--success)';
  if (uploadMode === 'files') startBtn.disabled = false;
}

// Batch ZIP dropzone wiring (v2.0)
// Note: click is now handled by the "Select ZIP" button; dropzone is drag-only
dropzoneBatch.addEventListener('dragover', e => { e.preventDefault(); dropzoneBatch.classList.add('drag'); });
dropzoneBatch.addEventListener('dragleave', () => dropzoneBatch.classList.remove('drag'));
dropzoneBatch.addEventListener('drop', e => {
  e.preventDefault(); dropzoneBatch.classList.remove('drag');
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.zip')) setBatchFile(f);
});
batchInput.addEventListener('change', () => { if (batchInput.files[0]) setBatchFile(batchInput.files[0]); });

// Folder selection — package into a ZIP client-side using JSZip, then treat as batch file
document.getElementById('batchFolderInput').addEventListener('change', async function () {
  const files = Array.from(this.files);
  if (!files.length) return;

  // Determine the top-level folder name (first path component)
  const rootName = (files[0].webkitRelativePath || files[0].name).split('/')[0] || 'batch';

  // Show packaging indicator, disable start button while building
  const packagingEl = document.getElementById('batchPackaging');
  packagingEl.style.display = 'block';
  startBtn.disabled = true;
  batchLabel.innerHTML = `⏳ Packaging <strong>${rootName}</strong>…`;
  dropzoneBatch.style.borderColor = 'var(--accent)';

  try {
    const zip = new JSZip();
    for (const f of files) {
      // webkitRelativePath: "rootFolder/subfolder/file.xml"
      // We want to preserve the full relative path inside the ZIP
      const relativePath = f.webkitRelativePath || f.name;
      zip.file(relativePath, await f.arrayBuffer());
    }
    const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 6 } });
    const zipFile = new File([blob], rootName + '.zip', { type: 'application/zip' });
    setBatchFile(zipFile);
  } catch (err) {
    batchLabel.innerHTML = `❌ Failed to package folder: ${err.message}`;
    dropzoneBatch.style.borderColor = 'var(--error)';
  } finally {
    packagingEl.style.display = 'none';
    // Reset the input so the same folder can be re-selected if needed
    this.value = '';
  }
});

function setBatchFile(f) {
  selectedBatchFile = f;
  batchLabel.innerHTML = `✅ ${f.name} <span style="color:var(--muted);font-weight:400">(${(f.size/1024/1024).toFixed(2)} MB)</span>`;
  dropzoneBatch.style.borderColor = 'var(--success)';
  batchWarnings.style.display = 'none';
  if (uploadMode === 'batch') startBtn.disabled = false;
}

// ─────────────────────────────────────────────
// Submit form reset helper
// ─────────────────────────────────────────────
function resetSubmitForm() {
  // Clear all file selections
  selectedFile         = null;
  selectedBatchFile    = null;
  selectedWorkflowFile = null;
  selectedParamFile    = null;

  // Reset Individual dropzone
  const fileLabel  = document.getElementById('fileLabel');
  const batchLabel = document.getElementById('batchLabel');
  if (fileLabel) fileLabel.textContent = 'Drop mapping .xml here, or click to browse';
  if (batchLabel) batchLabel.textContent = 'Or drag a batch .zip here';

  // Reset labels for workflow/param zones
  const wfLabel = document.getElementById('workflowLabel');
  const pfLabel = document.getElementById('paramLabel');
  if (wfLabel) wfLabel.textContent = 'Drop Workflow .xml or click';
  if (pfLabel) pfLabel.textContent = 'Drop parameter file or click';

  // Reset dropzone borders
  ['dropzone','dropzoneBatch','dropzoneWF','dropzonePF'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.borderColor = '';
  });

  // Re-enable + re-label start button
  const startBtn = document.getElementById('startBtn');
  if (startBtn) { startBtn.disabled = true; startBtn.textContent = '▶ Start Pipeline'; }
}

// ── Start button ─────────────────────────────
startBtn.addEventListener('click', async () => {
  startBtn.disabled = true;

  // Collect submitter fields (shared across all upload modes)
  const _sName  = (document.getElementById('submitterName')?.value  || '').trim();
  const _sTeam  = (document.getElementById('submitterTeam')?.value  || '').trim();
  const _sNotes = (document.getElementById('submitterNotes')?.value || '').trim();

  if (uploadMode === 'batch') {
    // ── Batch upload path (v2.0) ─────────────
    if (!selectedBatchFile) { startBtn.disabled = false; return; }
    const fd = new FormData();
    fd.append('file', selectedBatchFile);
    fd.append('pipeline_mode', pipelineMode);
    try {
      const res  = await fetch('/api/jobs/batch', { method: 'POST', body: fd });
      const data = await res.json();
      if (data.batch_id) {
        if (data.warnings && data.warnings.length) {
          batchWarnings.innerHTML = '⚠️ ' + data.warnings.map(esc).join('<br/>⚠️ ');
          batchWarnings.style.display = 'block';
        }
        const n = data.jobs ? data.jobs.length : '?';
        showToast('✓ Batch queued', `${n} mapping${n !== 1 ? 's' : ''} submitted — track each one in Job History.`, 'ok', 6000);
        resetSubmitForm();
        await loadJobs();
        if (_mainView === 'history') loadHistory();
        // For batch, show recent jobs updated panel (no single job to show insights for)
      } else {
        alert('Batch upload failed: ' + JSON.stringify(data));
        startBtn.disabled = false;
      }
    } catch(e) {
      alert('Batch upload error: ' + e.message);
      startBtn.disabled = false;
    }
  } else {
    // ── Individual XML path ──────────────────────────────────────────────
    if (!selectedFile) { startBtn.disabled = false; return; }
    const fd = new FormData();
    fd.append('file', selectedFile);
    if (selectedWorkflowFile) fd.append('workflow_file', selectedWorkflowFile);
    if (selectedParamFile)    fd.append('parameter_file', selectedParamFile);
    if (_sName)  fd.append('submitter_name',  _sName);
    if (_sTeam)  fd.append('submitter_team',  _sTeam);
    if (_sNotes) fd.append('submitter_notes', _sNotes);
    fd.append('pipeline_mode', pipelineMode);
    try {
      const res  = await fetch('/api/jobs', { method: 'POST', body: fd });
      const data = await res.json();
      if (data.job_id) {
        const fname = selectedFile.name;
        showToast('✓ Job queued', `${fname} is processing — live insights below.`, 'ok', 4000);
        resetSubmitForm();
        await loadJobs();
        if (_mainView === 'history') loadHistory();
        showJobInsights(data.job_id, fname);
      } else {
        alert('Upload failed: ' + JSON.stringify(data));
        startBtn.disabled = false;
      }
    } catch(e) {
      alert('Upload error: ' + e.message);
      startBtn.disabled = false;
    }
  }
});

// ── Show live job insights in the right intel column ─────────────────────
let _insightsSSE = null;
async function showJobInsights(jobId, filename) {
  const panel = document.getElementById('submitIntelPanel');
  if (!panel) return;
  if (_insightsSSE) { _insightsSSE.close(); _insightsSSE = null; }

  const renderInsights = (job) => {
    const st = job.state || {};
    const [badgeCls, badgeLabel] = STATUS_BADGE[job.status] || ['badge-pending', job.status];
    const tier = job.complexity_tier || st.complexity_tier || (st.classification ? st.classification.tier : null);
    const tierColor = { Low:'#4ade80', Medium:'#60a5fa', High:'#fb923c', VeryHigh:'#f87171' }[tier] || 'var(--muted)';
    const flags = (st.verification_report?.flags || []);
    const blocking = flags.filter(f => f.blocking).length;
    const warns = flags.filter(f => !f.blocking && (f.severity||'').toLowerCase() !== 'info').length;
    const stack = st.assigned_stack || st.stack_assignment?.stack || null;
    const parseReport = st.parse_report || {};
    const mappingCount = parseReport.mapping_count ?? parseReport.mappings?.length ?? null;
    const srcCount = parseReport.source_count ?? null;
    const tgtCount = parseReport.target_count ?? null;
    const tfmCount = parseReport.transformation_count ?? null;
    const secFindings = (st.security_report?.findings || []).length;
    const reviewScore = st.review_report?.overall_score ?? null;
    const testCoverage = st.test_report?.coverage_pct ?? null;
    const stepsComplete = (job.current_step || 1) - 1;
    const elapsed = (() => {
      if (!job.created_at) return null;
      const s = Math.floor((Date.now() - new Date(job.created_at).getTime()) / 1000);
      return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s/60)}m ${s%60}s` : `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;
    })();

    const metricCard = (icon, label, value, sub, color) => value !== null && value !== undefined ? `
      <div style="flex:1;min-width:120px;padding:12px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:8px">
        <div style="font-size:18px;margin-bottom:4px">${icon}</div>
        <div style="font-size:20px;font-weight:700;color:${color||'var(--text)'}">${value}</div>
        <div style="font-size:11px;font-weight:600;color:var(--muted);margin-top:2px">${label}</div>
        ${sub ? `<div style="font-size:10px;color:var(--muted);margin-top:2px">${sub}</div>` : ''}
      </div>` : '';

    const isComplete = job.status === 'complete';
    const isFailed   = job.status === 'failed' || job.status === 'blocked';

    panel.innerHTML = `
      <div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px">
          <div style="font-size:13px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">Job Insights</div>
          <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="openJob('${jobId}')">View Full Details →</button>
        </div>

        <!-- ID + Status bar -->
        <div onclick="openJob('${jobId}')" title="Click to view full details" style="padding:12px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;margin-bottom:14px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;cursor:pointer" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
          <span style="font-family:monospace;font-size:14px;font-weight:700;color:var(--accent)">${shortId(jobId)}</span>
          <span class="badge ${badgeCls}">${badgeLabel}</span>
          ${tier ? `<span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;background:${tierColor}22;color:${tierColor};border:1px solid ${tierColor}44">${tier} Complexity</span>` : ''}
          ${stack ? `<span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;background:rgba(108,99,255,.15);color:var(--accent)">${esc(stack)}</span>` : ''}
          <span style="font-size:11px;color:var(--muted);margin-left:auto">${elapsed ? `⏱ ${elapsed}` : ''}</span>
        </div>

        <!-- Mini progress bar -->
        <div style="margin-bottom:14px">
          <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:4px">
            <span>Pipeline progress</span><span>${stepsComplete}/12 steps</span>
          </div>
          <div style="height:6px;background:var(--surface2);border-radius:3px;overflow:hidden">
            <div style="height:100%;width:${Math.min(100, Math.round(stepsComplete/12*100))}%;background:${isFailed?'var(--danger)':isComplete?'var(--accent2)':'var(--accent)'};border-radius:3px;transition:width .4s"></div>
          </div>
        </div>

        <!-- Metrics grid -->
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px">
          ${metricCard('🗺', 'Mappings', mappingCount, null, 'var(--text)')}
          ${metricCard('📥', 'Sources', srcCount, null, 'var(--text)')}
          ${metricCard('📤', 'Targets', tgtCount, null, 'var(--text)')}
          ${metricCard('⚙️', 'Transforms', tfmCount, null, 'var(--text)')}
          ${metricCard('🚩', 'Blocking Flags', blocking, warns > 0 ? `+ ${warns} warning${warns>1?'s':''}` : null, blocking > 0 ? 'var(--danger)' : 'var(--accent2)')}
          ${metricCard('🔒', 'Security Findings', secFindings, null, secFindings > 0 ? 'var(--warn)' : 'var(--accent2)')}
          ${reviewScore !== null ? metricCard('📊', 'Review Score', reviewScore + '%', null, reviewScore >= 80 ? 'var(--accent2)' : reviewScore >= 60 ? 'var(--warn)' : 'var(--danger)') : ''}
          ${testCoverage !== null ? metricCard('🧪', 'Test Coverage', testCoverage + '%', null, testCoverage >= 80 ? 'var(--accent2)' : 'var(--warn)') : ''}
        </div>

        ${isComplete ? `<div style="padding:12px 14px;background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.25);border-radius:8px;font-size:12px;color:var(--accent2);line-height:1.6">
          ✅ <strong>Conversion complete!</strong> All 12 steps and 3 gates passed. Download your artifacts from the full details view.
        </div>` : ''}
        ${isFailed ? `<div style="padding:12px 14px;background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.25);border-radius:8px;font-size:12px;color:var(--danger);line-height:1.6">
          ❌ <strong>Pipeline stopped at Step ${job.current_step}.</strong> Open full details to review the error and flags.
        </div>` : ''}
      </div>

      `;
  };

  // Fetch initial state and render
  try {
    const res = await fetch(`/api/jobs/${jobId}`);
    const job = await res.json();
    renderInsights(job);
    // Live updates via SSE
    _insightsSSE = new EventSource(`/api/jobs/${jobId}/stream`);
    _insightsSSE.onmessage = async (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'done' || msg.type === 'progress' || msg.type === 'state') {
        try {
          const upd = await fetch(`/api/jobs/${jobId}`);
          renderInsights(await upd.json());
        } catch(_) {}
        if (msg.type === 'done') { _insightsSSE.close(); _insightsSSE = null; }
      }
    };
    _insightsSSE.onerror = () => { if (_insightsSSE) { _insightsSSE.close(); _insightsSSE = null; } };
  } catch(err) {
    if (panel) panel.innerHTML = `<div style="color:var(--muted);font-size:12px;padding:12px">Could not load job insights.</div>`;
  }
}

// Manifest re-upload helpers
function handleManifestFileChosen(input, jobId) {
  const btn    = document.getElementById('manifestUploadBtn');
  const status = document.getElementById('manifestUploadStatus');
  const label  = document.getElementById('manifestUploadLabel');
  if (!input.files || !input.files[0]) return;
  const fname = input.files[0].name;
  if (label) label.innerHTML = `📁 ${fname} <input type="file" id="manifestFileInput" accept=".xlsx" style="display:none" onchange="handleManifestFileChosen(this,'${jobId}')"/>`;
  if (btn) btn.style.display = 'inline-flex';
  if (status) status.textContent = '';
}

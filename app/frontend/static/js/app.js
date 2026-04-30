// app.js — global state, init, shared utilities, persona, search, test runner, S2T modal

// ─────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────
let currentJobId = null;
let selectedFile = null;
let eventSource = null;

const STEPS = [
  { n:1,  label:"Parse" },
  { n:2,  label:"Classify" },
  { n:3,  label:"Document" },
  { n:4,  label:"Verify" },
  { n:5,  label:"Review" },
  { n:6,  label:"Stack" },
  { n:7,  label:"Convert" },
  { n:8,  label:"Security" },
  { n:9,  label:"Sec Rev" },
  { n:10, label:"Quality" },
  { n:11, label:"Tests" },
  { n:12, label:"Sign-Off" },
];

const STATUS_BADGE = {
  pending:         ['badge-pending','Pending'],
  parsing:         ['badge-running','Parsing'],
  classifying:     ['badge-running','Classifying'],
  documenting:     ['badge-running','Documenting'],
  verifying:       ['badge-running','Verifying'],
  awaiting_review: ['badge-waiting','Analysis Sign-off'],
  assigning_stack: ['badge-running','Assigning Stack'],
  converting:        ['badge-running','Converting'],
  security_scanning:      ['badge-running','Security Scan'],
  validating:             ['badge-running','Validating'],
  awaiting_security_review: ['badge-waiting','Security Sign-off'],
  reviewing:              ['badge-running','Quality Review'],
  testing:                ['badge-running','Testing'],
  awaiting_code_review:   ['badge-waiting','Final Sign-off'],
  complete:             ['badge-complete','Complete'],
  failed:               ['badge-failed','Failed'],
  blocked:              ['badge-blocked','Blocked'],
  cancelled:            ['badge-failed','Cancelled'],
};

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

// Global job store — updated on every poll
let _allJobs    = [];
let _allHistory = [];
let _jobPage    = 0;
const _JOB_PAGE_SIZE = 30;

let _mainView  = 'landing';

// Landing page sets
const _RUNNING_SET = new Set(['pending','parsing','classifying','documenting','verifying',
  'assigning_stack','converting','security_scanning','validating','reviewing','testing']);
const _GATE_SET = new Set(['awaiting_review','awaiting_security_review','awaiting_code_review']);

let _prevGatePending = 0;

// Review queue state
let _reviewQueue = [];
let _reviewGateFilter = null;
let _reviewSelectedJobIds = new Set();

// ─────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escHtml(s) { return esc(s); }
function utcDate(s) { if (!s) return new Date(NaN); return new Date(s.endsWith('Z') ? s : s + 'Z'); }
function shortId(jobId) { return jobId ? '#' + jobId.replace(/-/g,'').slice(0,8).toUpperCase() : '–'; }

function markdownToHtml(md) {
  if (typeof marked !== 'undefined') {
    return marked.parse(md, { gfm: true, breaks: false });
  }
  // Fallback if marked.js not loaded
  return md
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm,  '<h2>$1</h2>')
    .replace(/^# (.+)$/gm,   '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/```[\w]*\n([\s\S]*?)```/g, '<pre>$1</pre>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/\n\n/g, '<br/><br/>');
}

function markdownToHtmlFull(md) {
  const escaped = md
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  return escaped
    .replace(/```[\w]*\n([\s\S]*?)```/g, (_, code) => `<pre><code>${code}</code></pre>`)
    .replace(/^#### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^### (.+)$/gm,  '<h3>$1</h3>')
    .replace(/^## (.+)$/gm,   '<h2>$1</h2>')
    .replace(/^# (.+)$/gm,    '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,     '<em>$1</em>')
    .replace(/_(.+?)_/g,       '<em>$1</em>')
    .replace(/`([^`]+)`/g,     '<code>$1</code>')
    .replace(/^---$/gm, '<hr/>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/\n\n+/g, '</p><p>')
    .replace(/^(?!<[hpulo]|<li|<hr|<pre)(.+)$/gm, '<p>$1</p>');
}

// ─────────────────────────────────────────────
// Persona helpers
// ─────────────────────────────────────────────
const PERSONA_META = {
  'Asin D':       { role: 'Data Engineer',       initials: 'AD', color: 'rgba(108,99,255,.25)',  fg: '#a5b4fc' },
  'Priya Nair':   { role: 'Business Analyst',    initials: 'PN', color: 'rgba(34,211,238,.2)',   fg: '#22d3ee' },
  'Sarah Chen':   { role: 'Migration Lead',      initials: 'SC', color: 'rgba(74,222,128,.2)',   fg: '#4ade80' },
  'James Park':   { role: 'Security Architect',    initials: 'JP', color: 'rgba(251,146,60,.2)',   fg: '#fb923c' },
  'Maya Patel':   { role: 'Platform Engineer',     initials: 'MP', color: 'rgba(251,191,36,.2)',   fg: '#fbbf24' },
};

function getPersonaCookie() {
  const m = document.cookie.match(/(?:^|;\s*)persona=([^;]+)/);
  if (!m) return '';
  const v = decodeURIComponent(m[1]).replace(/^"|"$/g, '').trim();
  return v || '';
}

function _setPersonaCookie(name) {
  document.cookie = `persona=${encodeURIComponent(name)};path=/;max-age=${60*60*24*365}`;
}

function pickPersona(name) {
  _setPersonaCookie(name);
  const ov = document.getElementById('personaPickerOverlay');
  if (ov) ov.style.display = 'none';
  initPersonaUI();
}

function pickPersonaCustom() {
  const inp = document.getElementById('personaCustomInput');
  const name = (inp ? inp.value : '').trim();
  if (!name) return;
  pickPersona(name);
}

function showPersonaPicker() {
  const ov = document.getElementById('personaPickerOverlay');
  const list = document.getElementById('personaPickerList');
  if (!ov || !list) return;
  list.innerHTML = Object.entries(PERSONA_META).map(([n, m]) => `
    <div onclick="pickPersona('${n}')"
         style="display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid var(--border);border-radius:10px;cursor:pointer;transition:background .15s"
         onmouseenter="this.style.background='var(--surface2)'" onmouseleave="this.style.background=''">
      <div style="width:36px;height:36px;border-radius:50%;background:${m.color};color:${m.fg};display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0">${m.initials}</div>
      <div><div style="font-weight:600;font-size:13px;color:var(--text)">${n}</div><div style="font-size:11px;color:var(--muted)">${m.role}</div></div>
    </div>`).join('');
  ov.style.display = 'flex';
}

function initPersonaUI() {
  const name = getPersonaCookie() || '';
  if (!name) { showPersonaPicker(); return; }
  const meta = PERSONA_META[name] || { role: '', initials: (name[0] || '?').toUpperCase(),
                                        color: 'rgba(108,99,255,.25)', fg: '#a5b4fc' };
  const av = document.getElementById('personaAvatarNav');
  const nm = document.getElementById('personaNameNav');
  const rl = document.getElementById('personaRoleNav');
  if (av) { av.textContent = meta.initials; av.style.background = meta.color; av.style.color = meta.fg; }
  if (nm) nm.textContent = name;
  if (rl) rl.textContent = meta.role;

  const sav = document.getElementById('sidebarAvatar');
  const snm = document.getElementById('sidebarName');
  const srl = document.getElementById('sidebarRole');
  if (sav) { sav.textContent = meta.initials; sav.style.background = meta.color; sav.style.color = meta.fg; }
  if (snm) snm.textContent = name;
  if (srl) srl.textContent = meta.role;

  const greet = document.getElementById('landingGreeting');
  if (greet) {
    const hour = new Date().getHours();
    const tod = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
    greet.textContent = `${tod} 👋`;
  }

  const sn = document.getElementById('submitterName');
  if (sn && !sn.value) sn.value = name;

  const rn = document.getElementById('reviewerNameInput');
  if (rn && !rn.value) rn.value = name;

  ['reviewerName','codeReviewerName','secReviewerName'].forEach(id => {
    const el = document.getElementById(id);
    if (el && !el.value) el.value = name;
  });
  document.addEventListener('focusin', e => {
    if (['reviewerName','codeReviewerName','secReviewerName'].includes(e.target?.id) && !e.target.value) {
      e.target.value = getPersonaCookie();
    }
  }, { once: false });

  const navTests = document.getElementById('navTests');
  if (navTests) navTests.style.display = (name === 'Asin D') ? '' : 'none';
}

// ─────────────────────────────────────────────
// Main view switcher
// ─────────────────────────────────────────────
function setMainView(view) {
  _mainView = view;
  const views = ['landing', 'dashboard', 'history', 'review', 'tests', 'docs'];
  views.forEach(v => {
    const panel = document.getElementById('panel' + v.charAt(0).toUpperCase() + v.slice(1));
    if (panel) {
      if (v === view) {
        panel.style.display = 'flex';
        if (v !== 'landing') panel.style.flexDirection = 'column';
        panel.style.flex = '1';
        panel.style.overflowY = 'auto';
      } else {
        panel.style.display = 'none';
      }
    }
    const btnId = v === 'landing' ? 'navHome' : 'nav' + v.charAt(0).toUpperCase() + v.slice(1);
    const btn = document.getElementById(btnId);
    if (btn) {
      btn.style.borderBottomColor = (v === view) ? 'var(--accent)' : 'transparent';
      btn.style.color = (v === view) ? 'var(--accent)' : 'var(--muted)';
    }
  });
  if (view === 'review')  { loadReviewQueue(); initReviewColResize(); }
  if (view === 'history') { loadHistory(); }
  if (view !== 'history') _stopHistLive();
  if (view === 'landing') loadLandingStats();
  if (view === 'tests')   initTestRunner();
  if (view === 'docs')    loadGuide();
  try { refreshSidebarActivity(); } catch(e) {}
  if (view !== 'dashboard') {
    ['histBackBar','reviewBackBar'].forEach(id => { const el = document.getElementById(id); if (el) el.remove(); });
  }
}

// ─────────────────────────────────────────────
// Toast notifications + bell badge
// ─────────────────────────────────────────────
function showToast(title, msg, type = 'info', durationMs = 6000) {
  const icons = { info: 'ℹ️', warn: '⚠️', error: '🔴', ok: '✅' };
  const container = document.getElementById('toastContainer');
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.innerHTML = `
    <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      ${msg ? `<div class="toast-msg">${msg}</div>` : ''}
    </div>
    <span class="toast-close" onclick="this.closest('.toast').remove()">✕</span>`;
  container.appendChild(t);
  if (durationMs > 0) setTimeout(() => t.remove(), durationMs);
}

async function updateNotifBell() {
  try {
    const res = await fetch('/api/gates/pending');
    if (!res.ok) return;
    const data = await res.json();
    const total = data.total ?? 0;

    const bell  = document.getElementById('notifBell');
    const badge = document.getElementById('notifBadge');
    if (!bell || !badge) return;

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

    const base = 'Informatica Conversion Tool';
    document.title = total > 0 ? `(${total}) ${base}` : base;

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

// ─────────────────────────────────────────────
// Report download (MD + PDF)
// ─────────────────────────────────────────────
function downloadReportMd() {
  const job = window._currentJob;
  if (!job) return;
  const md  = buildReportMarkdown(job);
  const blob = new Blob([md], { type: 'text/markdown' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  const safe = (job.filename || 'report').replace(/[^a-z0-9_\-\.]/gi, '_');
  a.href     = url;
  a.download = `${safe}_conversion_report.md`;
  a.click();
  URL.revokeObjectURL(url);
}

async function downloadAuditReport(jobId) {
  const id = jobId || (window._currentJob && window._currentJob.job_id);
  if (!id) return;
  try {
    const res = await fetch(`/api/jobs/${id}/audit-report`);
    if (!res.ok) { alert('Could not generate audit report: ' + res.statusText); return; }
    const md = await res.text();
    const blob = new Blob([md], { type: 'text/markdown' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const safe = ((window._currentJob && window._currentJob.filename) || id).replace(/[^a-z0-9_\-\.]/gi, '_');
    a.href     = url;
    a.download = `${safe}_AUDIT_REPORT.md`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) { alert('Audit report download failed: ' + e.message); }
}

function downloadStateMd(stateKey, suffix) {
  const state = window._currentJobState;
  const job   = window._currentJob;
  if (!state || !state[stateKey]) return;
  const blob = new Blob([state[stateKey]], { type: 'text/markdown' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  const safe = (job?.filename || 'mapping').replace(/[^a-z0-9_\-\.]/gi, '_');
  a.href     = url;
  a.download = `${safe}_${suffix}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadStatePdf(stateKey, suffix, title) {
  const state = window._currentJobState;
  const job   = window._currentJob;
  if (!state || !state[stateKey]) return;
  const md   = state[stateKey];
  const safe = (job?.filename || 'mapping').replace(/[^a-z0-9_\-\.]/gi, '_');
  const mappingName = (job?.filename || '').replace('.xml','');
  const tier = state.complexity?.tier || '';
  const html = `<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8"/>
  <title>${title} — ${safe}</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/9.1.6/marked.min.js"><\/script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.6.1/mermaid.min.js"><\/script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 10.5pt; line-height: 1.65; color: #1e293b; background: #fff;
      max-width: 880px; margin: 0 auto; padding: 0 40px 40px;
    }

    /* ── Cover header ── */
    .cover {
      padding: 48px 0 32px; margin-bottom: 28px;
      border-bottom: 3px solid #1e3a5f;
    }
    .cover h1 {
      font-size: 22pt; font-weight: 700; color: #0f172a;
      margin: 0 0 6px; letter-spacing: -0.3px;
    }
    .cover .subtitle {
      font-size: 11pt; color: #64748b; font-weight: 400;
    }
    .cover .meta-row {
      display: flex; gap: 24px; margin-top: 14px; font-size: 9pt;
      color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 10px;
    }
    .cover .meta-row strong { color: #334155; font-weight: 600; }
    .tier-badge {
      display: inline-block; padding: 2px 10px; border-radius: 10px;
      font-size: 8pt; font-weight: 700; text-transform: uppercase; letter-spacing: .5px;
    }
    .tier-simple  { background: #dcfce7; color: #166534; }
    .tier-medium  { background: #fef3c7; color: #92400e; }
    .tier-complex { background: #fee2e2; color: #991b1b; }

    /* ── Headings ── */
    h2 {
      font-size: 14pt; font-weight: 700; color: #1e3a5f;
      border-bottom: 2px solid #e2e8f0; padding-bottom: 6px;
      margin: 32px 0 12px; letter-spacing: -0.2px;
    }
    h3 {
      font-size: 11.5pt; font-weight: 600; color: #334155;
      margin: 20px 0 8px; padding-bottom: 3px;
      border-bottom: 1px solid #f1f5f9;
    }
    h4 { font-size: 10.5pt; font-weight: 600; color: #475569; margin: 14px 0 6px; }
    p  { margin: 0 0 10px; }
    ul, ol { margin: 4px 0 12px 22px; }
    li { margin-bottom: 3px; }
    hr { border: none; border-top: 1px solid #e2e8f0; margin: 20px 0; }

    /* ── Tables ── */
    table {
      border-collapse: collapse; width: 100%; margin: 10px 0 16px;
      font-size: 8.5pt; border: 1px solid #cbd5e1; border-radius: 6px;
      table-layout: fixed; word-wrap: break-word;
    }
    thead th {
      background: linear-gradient(180deg, #f1f5f9 0%, #e8edf3 100%);
      color: #1e3a5f; font-weight: 600; text-transform: uppercase;
      font-size: 7.5pt; letter-spacing: .4px;
      padding: 7px 8px; border-bottom: 2px solid #cbd5e1;
      text-align: left; overflow-wrap: break-word;
    }
    td {
      padding: 5px 8px; border-bottom: 1px solid #e2e8f0;
      color: #334155; vertical-align: top; overflow-wrap: break-word;
    }
    tbody tr:nth-child(even) { background: #f8fafc; }
    tbody tr:hover { background: #f1f5f9; }

    /* ── Code ── */
    pre {
      background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
      padding: 14px 16px; font-size: 8pt;
      font-family: 'JetBrains Mono', 'Courier New', monospace;
      white-space: pre-wrap; word-break: break-all; margin: 8px 0 14px;
      border-left: 3px solid #6366f1;
    }
    code {
      font-family: 'JetBrains Mono', 'Courier New', monospace;
      background: #f1f5f9; padding: 1px 5px; border-radius: 3px;
      font-size: 8.5pt; color: #6366f1;
    }
    pre code { background: none; padding: 0; color: #334155; }

    /* ── Blockquotes (warnings, notes) ── */
    blockquote {
      border-left: 4px solid #f59e0b; padding: 10px 16px; margin: 10px 0;
      background: #fffbeb; border-radius: 0 6px 6px 0;
      font-size: 9.5pt; color: #92400e;
    }

    /* ── Mermaid ── */
    .mermaid {
      margin: 16px 0; padding: 16px; background: #fafbfc;
      border: 1px solid #e2e8f0; border-radius: 8px; text-align: center;
    }
    .mermaid svg { max-width: 100%; }

    /* ── Footer ── */
    .footer {
      margin-top: 40px; font-size: 8pt; color: #94a3b8;
      border-top: 2px solid #e2e8f0; padding-top: 12px;
      display: flex; justify-content: space-between;
    }

    /* ── Print ── */
    @media print {
      body { padding: 0; max-width: 100%; }
      .cover { padding-top: 20px; }
      h2 { break-after: avoid; }
      h3 { break-after: avoid; }
      pre, .mermaid, blockquote { break-inside: avoid; }
      table { font-size: 7.5pt; table-layout: fixed; width: 100%; }
      thead th { font-size: 6.5pt; padding: 5px 5px; }
      td { padding: 4px 5px; font-size: 7.5pt; }
      tbody tr:hover { background: inherit; }
      @page { margin: 0.6in 0.55in; size: A4; }
      @page :first { margin-top: 0.4in; }
    }
  </style>
</head>
<body>
<div class="cover">
  <h1>${title}</h1>
  <div class="subtitle">${mappingName}</div>
  <div class="meta-row">
    <span><strong>Generated:</strong> ${new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'})}</span>
    ${tier ? '<span><strong>Complexity:</strong> <span class="tier-badge tier-' + tier.toLowerCase() + '">' + tier + '</span></span>' : ''}
    <span><strong>Tool:</strong> Informatica Conversion Platform</span>
  </div>
</div>
<div id="content"></div>
<div class="footer">
  <span>Informatica Conversion Tool &middot; Confidential</span>
  <span>${new Date().toLocaleString()}</span>
</div>
<script>
  var md = ${JSON.stringify(md).replace(/<\//g, '<\\/')};
  mermaid.initialize({ startOnLoad: false, theme: 'neutral',
    themeVariables: { fontSize: '11px', primaryColor: '#e0e7ff', primaryBorderColor: '#6366f1',
      lineColor: '#94a3b8', tertiaryColor: '#f8fafc' }
  });
  document.getElementById('content').innerHTML = marked.parse(md, { gfm: true, breaks: false });
  document.querySelectorAll('pre code.language-mermaid').forEach(function(el) {
    var pre = el.parentElement;
    var div = document.createElement('div');
    div.className = 'mermaid';
    div.textContent = el.textContent;
    pre.replaceWith(div);
  });
  mermaid.run().then(function() {
    setTimeout(function() { window.print(); }, 800);
  });
<\/script>
</body></html>`;

  const win = window.open('', '_blank');
  if (!win) { alert('Pop-up blocked — please allow pop-ups and try again.'); return; }
  win.document.write(html);
  win.document.close();
}

function downloadStateHtml(stateKey, suffix, title) {
  const state = window._currentJobState;
  const job   = window._currentJob;
  if (!state || !state[stateKey]) return;
  const md   = state[stateKey];
  const safe = (job?.filename || 'mapping').replace(/[^a-z0-9_\-\.]/gi, '_');
  const mappingName = (job?.filename || '').replace('.xml','');
  const tier = state.complexity?.tier || '';
  const html = `<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8"/>
  <title>${title} — ${safe}</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/9.1.6/marked.min.js"><\/script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.6.1/mermaid.min.js"><\/script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 10.5pt; line-height: 1.65; color: #1e293b; background: #fff;
      max-width: 880px; margin: 0 auto; padding: 0 40px 40px;
    }
    .cover { padding: 48px 0 32px; margin-bottom: 28px; border-bottom: 3px solid #1e3a5f; }
    .cover h1 { font-size: 22pt; font-weight: 700; color: #0f172a; margin: 0 0 6px; letter-spacing: -0.3px; }
    .cover .subtitle { font-size: 11pt; color: #64748b; }
    .cover .meta-row { display: flex; gap: 24px; margin-top: 14px; font-size: 9pt; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 10px; }
    .cover .meta-row strong { color: #334155; font-weight: 600; }
    .tier-badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 8pt; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }
    .tier-simple  { background: #dcfce7; color: #166534; }
    .tier-medium  { background: #fef3c7; color: #92400e; }
    .tier-complex { background: #fee2e2; color: #991b1b; }
    h2 { font-size: 14pt; font-weight: 700; color: #1e3a5f; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin: 32px 0 12px; }
    h3 { font-size: 11.5pt; font-weight: 600; color: #334155; margin: 20px 0 8px; border-bottom: 1px solid #f1f5f9; padding-bottom: 3px; }
    h4 { font-size: 10.5pt; font-weight: 600; color: #475569; margin: 14px 0 6px; }
    p  { margin: 0 0 10px; }
    ul, ol { margin: 4px 0 12px 22px; }
    li { margin-bottom: 3px; }
    hr { border: none; border-top: 1px solid #e2e8f0; margin: 20px 0; }
    table { border-collapse: collapse; width: 100%; margin: 10px 0 16px; font-size: 8.5pt; border: 1px solid #cbd5e1; table-layout: fixed; word-wrap: break-word; }
    thead th { background: linear-gradient(180deg,#f1f5f9 0%,#e8edf3 100%); color: #1e3a5f; font-weight: 600; text-transform: uppercase; font-size: 7.5pt; letter-spacing: .4px; padding: 7px 8px; border-bottom: 2px solid #cbd5e1; text-align: left; overflow-wrap: break-word; }
    td { padding: 5px 8px; border-bottom: 1px solid #e2e8f0; color: #334155; vertical-align: top; overflow-wrap: break-word; }
    tbody tr:nth-child(even) { background: #f8fafc; }
    tbody tr:hover { background: #f1f5f9; }
    pre { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 14px 16px; font-size: 8pt; font-family: 'JetBrains Mono','Courier New',monospace; white-space: pre-wrap; word-break: break-all; margin: 8px 0 14px; border-left: 3px solid #6366f1; }
    code { font-family: 'JetBrains Mono','Courier New',monospace; background: #f1f5f9; padding: 1px 5px; border-radius: 3px; font-size: 8.5pt; color: #6366f1; }
    pre code { background: none; padding: 0; color: #334155; }
    blockquote { border-left: 4px solid #f59e0b; padding: 10px 16px; margin: 10px 0; background: #fffbeb; border-radius: 0 6px 6px 0; font-size: 9.5pt; color: #92400e; }
    .mermaid { margin: 16px 0; padding: 16px; background: #fafbfc; border: 1px solid #e2e8f0; border-radius: 8px; text-align: center; }
    .mermaid svg { max-width: 100%; }
    .footer { margin-top: 40px; font-size: 8pt; color: #94a3b8; border-top: 2px solid #e2e8f0; padding-top: 12px; display: flex; justify-content: space-between; }
  </style>
</head>
<body>
<div class="cover">
  <h1>${title}</h1>
  <div class="subtitle">${mappingName}</div>
  <div class="meta-row">
    <span><strong>Generated:</strong> ${new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'})}</span>
    ${tier ? '<span><strong>Complexity:</strong> <span class="tier-badge tier-' + tier.toLowerCase() + '">' + tier + '</span></span>' : ''}
    <span><strong>Tool:</strong> Informatica Conversion Platform</span>
  </div>
</div>
<div id="content"></div>
<div class="footer">
  <span>Informatica Conversion Tool &middot; Confidential</span>
  <span>${new Date().toLocaleString()}</span>
</div>
<script>
  var md = ${JSON.stringify(md).replace(/<\//g, '<\\/')};
  mermaid.initialize({ startOnLoad: false, theme: 'neutral',
    themeVariables: { fontSize: '11px', primaryColor: '#e0e7ff', primaryBorderColor: '#6366f1', lineColor: '#94a3b8', tertiaryColor: '#f8fafc' }
  });
  document.getElementById('content').innerHTML = marked.parse(md, { gfm: true, breaks: false });
  document.querySelectorAll('pre code.language-mermaid').forEach(function(el) {
    var pre = el.parentElement;
    var div = document.createElement('div');
    div.className = 'mermaid';
    div.textContent = el.textContent;
    pre.replaceWith(div);
  });
  mermaid.run();
<\/script>
</body></html>`;
  const blob = new Blob([html], { type: 'text/html' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = `${safe}_${suffix}.html`;
  a.click();
  URL.revokeObjectURL(url);
}

async function downloadStateDocx(docKey) {
  const job = window._currentJob;
  if (!job) return;
  try {
    const res = await fetch(`/api/jobs/${job.job_id}/doc/${docKey}.docx`);
    if (!res.ok) { alert('DOCX download failed: ' + res.statusText); return; }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const cd   = res.headers.get('content-disposition') || '';
    const fname = cd.match(/filename="([^"]+)"/)?.[1] || `${docKey}.docx`;
    a.href     = url;
    a.download = fname;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) { alert('DOCX download failed: ' + e.message); }
}

function switchSpecTab(containerId, tabKey) {
  const container = document.getElementById(containerId);
  if (!container) return;
  // Hide all panels
  container.querySelectorAll('.spec-panel').forEach(p => { p.style.display = 'none'; });
  // Deactivate all tab buttons
  container.querySelectorAll('.spec-tab-btn').forEach(b => b.classList.remove('active'));
  // Show target panel
  const panel = container.querySelector(`.spec-panel[data-tab="${tabKey}"]`);
  if (panel) panel.style.display = '';
  // Activate target tab button
  const btn = container.querySelector(`.spec-tab-btn[data-tabkey="${tabKey}"]`);
  if (btn) btn.classList.add('active');
}

async function downloadInformaticaXml(jobId) {
  // Generates PowerCenter-importable XML from the 3b Technical Specification.
  // Claude generates on demand — show a loading state while it runs (~20-40s).
  const btn = event?.target;
  const origText = btn?.innerHTML;
  if (btn) { btn.disabled = true; btn.innerHTML = '⏳'; }
  try {
    const res = await fetch(`/api/jobs/${jobId}/informatica.xml`);
    if (!res.ok) {
      const err = await res.text().catch(() => res.statusText);
      alert('Informatica XML generation failed:\n' + err);
      return;
    }
    const blob  = await res.blob();
    const url   = URL.createObjectURL(blob);
    const a     = document.createElement('a');
    const cd    = res.headers.get('content-disposition') || '';
    const fname = cd.match(/filename="([^"]+)"/)?.[1] || 'mapping_informatica.xml';
    a.href      = url;
    a.download  = fname;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('Informatica XML generation failed: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = origText; }
  }
}

function openPrintReport() {
  const job = window._currentJob;
  if (!job) return;
  const md   = buildReportMarkdown(job);
  const body = markdownToHtmlFull(md);

  const html = `<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8"/>
  <title>Conversion Report — ${job.filename}</title>
  <style>
    *  { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Georgia, 'Times New Roman', serif; font-size: 12pt;
           line-height: 1.65; color: #111; background: #fff;
           max-width: 860px; margin: 0 auto; padding: 48px 40px; }
    h1   { font-size: 20pt; border-bottom: 2px solid #222; padding-bottom: 8px; margin: 0 0 16px; }
    h2   { font-size: 15pt; border-bottom: 1px solid #bbb; padding-bottom: 4px; margin: 28px 0 10px; color: #1a1a4e; }
    h3   { font-size: 12pt; font-weight: bold; margin: 16px 0 6px; color: #333; }
    h4   { font-size: 11pt; font-weight: bold; margin: 10px 0 4px; }
    p    { margin: 0 0 10px; }
    ul, ol { margin: 4px 0 10px 22px; }
    li   { margin-bottom: 3px; }
    hr   { border: none; border-top: 1px solid #ccc; margin: 20px 0; }
    pre  { background: #f4f4f4; border: 1px solid #ddd; border-radius: 4px;
           padding: 12px 14px; font-size: 9pt; font-family: 'Courier New', monospace;
           white-space: pre-wrap; word-break: break-all; overflow: visible;
           margin: 8px 0 14px; }
    code { font-family: 'Courier New', monospace; background: #f0f0f0;
           padding: 1px 5px; border-radius: 3px; font-size: 9pt; }
    pre code { background: none; padding: 0; }
    strong { font-weight: bold; }
    em     { font-style: italic; }
    .meta  { font-size: 11pt; color: #444; margin-bottom: 20px; }
    .meta span { margin-right: 16px; }
    .footer { margin-top: 40px; font-size: 9pt; color: #999; border-top: 1px solid #eee; padding-top: 10px; }
    @media print {
      body { padding: 0; max-width: 100%; }
      h2   { break-before: auto; }
      pre  { break-inside: avoid; }
      @page { margin: 0.75in; size: A4; }
    }
  </style>
</head>
<body>
${body}
<div class="footer">Generated by Informatica Conversion Tool &middot; ${new Date().toLocaleString()}</div>
<script>
  window.addEventListener('load', function() {
    setTimeout(function() { window.print(); }, 400);
  });
<\/script>
</body></html>`;

  const win = window.open('', '_blank');
  if (!win) {
    alert('Pop-up was blocked. Please allow pop-ups for this page and try again.');
    return;
  }
  win.document.write(html);
  win.document.close();
}

function buildReportMarkdown(job) {
  const state = job.state || {};
  const L = [];

  const hr   = () => L.push('---', '');
  const h1   = s => L.push(`# ${s}`, '');
  const h2   = s => L.push(`## ${s}`, '');
  const h3   = s => L.push(`### ${s}`, '');
  const p    = s => L.push(s, '');
  const kv   = (k, v) => L.push(`**${k}:** ${v ?? '—'}`);
  const code = (lang, body) => { L.push('```' + lang); L.push(body); L.push('```', ''); };

  h1(`Conversion Report: ${job.filename}`);
  kv('Job ID',    job.job_id);
  kv('Status',    job.status?.toUpperCase());
  kv('Started',   utcDate(job.created_at).toLocaleString());
  if (job.complexity) kv('Complexity', job.complexity);
  L.push('');
  hr();

  const pr = state.parse_report;
  if (pr) {
    h2('Step 1 — Parse Report');
    kv('Mapping Name', pr.mapping_name);
    kv('Source',       pr.source_name);
    kv('Target',       pr.target_name);
    kv('Transformations', pr.transformation_count);
    kv('Source Fields',   pr.source_field_count);
    kv('Target Fields',   pr.target_field_count);
    if (pr.flags?.length) {
      L.push('', `**Flags (${pr.flags.length}):**`);
      pr.flags.forEach(f => L.push(`- [${f.severity || f.flag_type}] ${f.message || f.description || ''}`));
    }
    L.push('');
  }

  const cx = state.complexity;
  if (cx) {
    h2('Step 2 — Complexity Classification');
    kv('Tier',      cx.tier);
    kv('Score',     cx.score);
    kv('Rationale', cx.rationale);
    L.push('');
  }

  if (state.documentation_md) {
    h2('Step 3 — Documentation');
    L.push(state.documentation_md, '');
  }

  const vr = state.verification;
  if (vr) {
    h2('Step 4 — Verification Report');
    kv('Overall Status', vr.overall_status);
    kv('Blocking Flags', vr.blocking_flag_count ?? 0);
    kv('Total Flags',    vr.flags?.length ?? 0);
    if (vr.flags?.length) {
      L.push('', '**Flags:**');
      vr.flags.forEach(f => {
        const sev = f.severity || f.flag_type || '';
        L.push(`- **[${sev}]** ${f.message || f.description || ''}`);
        if (f.recommendation) L.push(`  - 💡 ${f.recommendation}`);
      });
    }
    L.push('');
  }

  const so = state.sign_off;
  if (so) {
    h2('Step 5 — Human Review Sign-off');
    kv('Reviewer',  so.reviewer_name);
    kv('Role',      so.reviewer_role);
    kv('Decision',  so.decision);
    kv('Date',      (so.review_date || '').slice(0, 10));
    if (so.notes) p(so.notes);
    if (so.applied_fixes?.length) {
      L.push('**Applied Fixes:**');
      so.applied_fixes.forEach(f => L.push(`- ${f.description || f}`));
      L.push('');
    }
  }

  const sa = state.stack_assignment;
  if (sa) {
    h2('Step 6 — Stack Assignment');
    kv('Assigned Stack',   sa.assigned_stack);
    kv('Complexity Tier',  sa.complexity_tier);
    if (sa.rationale) p(sa.rationale);
    if (sa.special_concerns?.length) {
      L.push('**Special Concerns:**');
      sa.special_concerns.forEach(c => L.push(`- ${c}`));
      L.push('');
    }
  }

  const co = state.conversion;
  if (co?.files) {
    h2(`Step 7 — Conversion Output (${co.target_stack})`);
    const fileEntries = Object.entries(co.files);
    const totalLoc = fileEntries.reduce((s, [, b]) => s + (b || '').split('\n').length, 0);
    kv('Output files', fileEntries.length);
    kv('Total lines of code', totalLoc.toLocaleString());
    kv('Pattern used', co.pattern || '—');
    kv('Pattern confidence', co.confidence || '—');
    L.push('');
    if (fileEntries.length) {
      L.push('**Generated files:**', '');
      fileEntries.forEach(([fname, body]) => {
        const loc = (body || '').split('\n').length;
        L.push(`- \`${fname}\` (${loc.toLocaleString()} lines)`);
      });
      L.push('');
      L.push('_Full source files are available in the job export package (output/ folder)._', '');
    }
    if (co.notes?.length) {
      L.push('**Conversion notes:**');
      co.notes.forEach(n => L.push(`- ${n}`));
      L.push('');
    }
  }

  const ss = state.security_scan;
  if (ss) {
    h2('Step 8 — Security Scan');
    kv('Recommendation', ss.recommendation);
    kv('Critical', ss.critical_count ?? 0);
    kv('High',     ss.high_count ?? 0);
    kv('Medium',   ss.medium_count ?? 0);
    kv('Low',      ss.low_count ?? 0);
    kv('Bandit Ran', ss.ran_bandit ? 'Yes' : 'No');
    if (ss.claude_summary) p(ss.claude_summary);
    if (ss.findings?.length) {
      L.push('**Findings:**', '');
      ss.findings.forEach(f => {
        L.push(`#### [${f.severity}] ${f.test_name || f.test_id || ''} _(${f.source})_`);
        if (f.filename) L.push(`📄 \`${f.filename}\`${f.line ? ` line ${f.line}` : ''}`);
        L.push(f.text || '');
        if (f.code) code('', f.code);
        else L.push('');
      });
    } else {
      p('✅ No security findings detected.');
    }
  }

  const sso = state.security_sign_off;
  if (sso) {
    h2('Step 9 — Security Review');
    kv('Decision',  sso.decision);
    kv('Reviewer',  sso.reviewer_name);
    kv('Role',      sso.reviewer_role);
    kv('Date',      (sso.review_date||'').slice(0,10));
    if (sso.notes) p(sso.notes);
  }

  const cr = state.code_review;
  if (cr) {
    h2('Step 10 — Code Quality Review');
    kv('Recommendation', cr.recommendation);
    kv('Passed', cr.total_passed ?? 0);
    kv('Failed', cr.total_failed ?? 0);
    if (cr.summary) p(cr.summary);

    const eq = cr.equivalence_report;
    if (eq) {
      L.push('', '**Logic Equivalence Check (XML → Generated Code):**', '');
      kv('Verified', eq.total_verified ?? 0);
      kv('Needs Review', eq.total_needs_review ?? 0);
      kv('Mismatches', eq.total_mismatches ?? 0);
      kv('Coverage', `${eq.coverage_pct ?? 0}%`);
      if (eq.summary) p(eq.summary);
      if (eq.checks?.length) {
        L.push('');
        eq.checks.forEach(c => {
          const icon = { VERIFIED:'✅', NEEDS_REVIEW:'⚠️', MISMATCH:'❌' }[c.verdict] || '?';
          L.push(`- ${icon} **[${c.rule_type}] ${c.rule_id}** — _${c.verdict}_`);
          L.push(`  - XML: \`${c.xml_rule}\``);
          L.push(`  - Code: ${c.generated_impl}`);
          if (c.note) L.push(`  - Note: ${c.note}`);
        });
        L.push('');
      }
    }

    if (cr.checks?.length) {
      L.push('**Code Quality Checks:**', '');
      cr.checks.forEach(c => {
        const icon = c.passed ? '✅' : '❌';
        L.push(`- ${icon} **${c.name?.replace(/_/g,' ')}**${c.passed ? '' : ` [${c.severity}]`}${c.note ? ` — ${c.note}` : ''}`);
      });
      L.push('');
    }
  }

  const tr = state.test_report;
  if (tr) {
    h2('Step 11 — Test Generation & Coverage');
    kv('Field Coverage', `${tr.coverage_pct ?? 0}%`);
    kv('Fields Covered', tr.fields_covered ?? 0);
    kv('Fields Missing', tr.fields_missing ?? 0);
    if (tr.test_files) {
      const fnames = Object.keys(tr.test_files);
      kv('Test Files', fnames.length);
      L.push('');
      fnames.forEach(fname => {
        h3(fname);
        code('python', tr.test_files[fname]);
      });
    }
    if (tr.missing_fields?.length) {
      L.push('**Missing Fields:**');
      tr.missing_fields.forEach(f => L.push(`- ${f}`));
      L.push('');
    }
  }

  const cs = state.code_sign_off;
  if (cs) {
    h2('Step 12 — Code Review Sign-Off');
    kv('Reviewer', cs.reviewer_name);
    kv('Role',     cs.reviewer_role);
    kv('Decision', cs.decision);
    kv('Date',     (cs.review_date || '').slice(0, 10));
    if (cs.notes) p(cs.notes);
  }

  hr();
  L.push(`_Generated by Informatica Conversion Tool · ${new Date().toLocaleString()}_`);

  return L.join('\n');
}

// ─────────────────────────────────────────────
// S2T Modal
// ─────────────────────────────────────────────
let _s2tAllRecords = [], _s2tUnmappedSrc = [], _s2tUnmappedTgt = [];

function openS2TModal() {
  const state = window._currentJobState;
  if (!state || !state.s2t) return;
  const s2t = state.s2t;
  _s2tAllRecords  = s2t.records || [];
  _s2tUnmappedSrc = s2t.unmapped_sources || [];
  _s2tUnmappedTgt = s2t.unmapped_targets || [];

  // ── Judge banner ──────────────────────────────────────────────────────────
  const banner     = document.getElementById('s2tJudgeBanner');
  const gapsPanel  = document.getElementById('s2tJudgeGapsPanel');
  const gapsTbody  = document.getElementById('s2tJudgeGapsTbody');
  const judgeGaps  = s2t.judge_gaps || [];
  const hasJudge   = s2t.judge_overall_completeness || s2t.judge_summary || judgeGaps.length;

  if (hasJudge && banner) {
    // Completeness badge
    const comp        = (s2t.judge_overall_completeness || '').toUpperCase();
    const COMP_BG     = { HIGH: '#dcfce7', MEDIUM: '#fef9c3', LOW: '#fee2e2' };
    const COMP_TEXT   = { HIGH: '#14532d', MEDIUM: '#713f12', LOW: '#7f1d1d' };
    const compEl      = document.getElementById('s2tJudgeCompleteness');
    if (compEl) {
      compEl.textContent       = comp || '—';
      compEl.style.background  = COMP_BG[comp]  || '#f1f5f9';
      compEl.style.color       = COMP_TEXT[comp] || '#1e293b';
    }
    // Gap count
    const gapEl = document.getElementById('s2tJudgeGapCount');
    if (gapEl) gapEl.textContent = judgeGaps.length
      ? `${judgeGaps.length} gap${judgeGaps.length !== 1 ? 's' : ''} found`
      : 'No gaps found';
    // Summary
    const sumEl = document.getElementById('s2tJudgeSummary');
    if (sumEl) sumEl.textContent = s2t.judge_summary || '';
    banner.style.display = '';

    // ── Needs Review callout ──────────────────────────────────────────────────
    const reviewEl    = document.getElementById('s2tNeedsReview');
    const reviewCount = document.getElementById('s2tNeedsReviewCount');
    const reviewList  = document.getElementById('s2tNeedsReviewList');
    const flagged = _s2tAllRecords.filter(r =>
      r.judge_confidence === 'LOW' || r.judge_confidence === 'MEDIUM'
    );
    if (reviewEl && flagged.length) {
      const CONF_BG_NR   = { HIGH: '#dcfce7', MEDIUM: '#fef9c3', LOW: '#fee2e2' };
      const CONF_TEXT_NR = { HIGH: '#14532d', MEDIUM: '#713f12', LOW: '#7f1d1d' };
      reviewCount.textContent = flagged.length;
      reviewList.innerHTML = flagged.map(r => {
        const conf = (r.judge_confidence || '').toUpperCase();
        return `<div style="display:flex;align-items:baseline;gap:8px;font-size:11px;padding:3px 0;border-bottom:1px solid rgba(245,158,11,.15)">
          <span style="padding:1px 6px;border-radius:3px;background:${CONF_BG_NR[conf]};color:${CONF_TEXT_NR[conf]};font-size:10px;font-weight:700;flex-shrink:0">${esc(conf)}</span>
          <span style="color:#e2e8f0;white-space:nowrap;flex-shrink:0"><strong>${esc(r.target_table)}</strong>.<strong>${esc(r.target_field)}</strong></span>
          <span style="color:#94a3b8">${esc(r.judge_note || '—')}</span>
        </div>`;
      }).join('');
      reviewEl.style.display = '';
    } else if (reviewEl) {
      reviewEl.style.display = 'none';
    }
    // ─────────────────────────────────────────────────────────────────────────

    // Gap findings table
    if (gapsPanel && gapsTbody) {
      if (judgeGaps.length) {
        const SEV_BG   = { HIGH: '#fee2e2', MEDIUM: '#fef9c3', LOW: '#f0fdf4' };
        const SEV_TEXT = { HIGH: '#991b1b', MEDIUM: '#713f12', LOW: '#14532d' };
        gapsTbody.innerHTML = judgeGaps.map(g => {
          const sev = (g.severity || '').toUpperCase();
          const src = [g.suggested_source_table, g.suggested_source_field].filter(Boolean).join('.');
          return `<tr>
            <td style="padding:5px 10px;border-bottom:1px solid #fde68a;color:#b45309;font-weight:700;white-space:nowrap">${esc(g.target_table || '—')}</td>
            <td style="padding:5px 10px;border-bottom:1px solid #fde68a;color:#1e293b;font-weight:600;white-space:nowrap">${esc(g.target_field || '—')}</td>
            <td style="padding:5px 10px;border-bottom:1px solid #fde68a;color:#475569;font-size:11px">${esc(g.finding || '—')}</td>
            <td style="padding:5px 10px;border-bottom:1px solid #fde68a"><span style="padding:2px 8px;border-radius:4px;background:${SEV_BG[sev] || '#f1f5f9'};color:${SEV_TEXT[sev] || '#1e293b'};font-size:10px;font-weight:700">${esc(sev || '—')}</span></td>
            <td style="padding:5px 10px;border-bottom:1px solid #fde68a;color:#94a3b8;font-size:11px">${esc(src || '—')}</td>
          </tr>`;
        }).join('');
        gapsPanel.style.display = '';
      } else {
        gapsPanel.style.display = 'none';
      }
    }
  } else {
    if (banner)    banner.style.display    = 'none';
    if (gapsPanel) gapsPanel.style.display = 'none';
    const reviewEl = document.getElementById('s2tNeedsReview');
    if (reviewEl)  reviewEl.style.display  = 'none';
  }
  // ─────────────────────────────────────────────────────────────────────────

  document.getElementById('s2tModal').style.display = 'flex';
  renderS2TTable();
}
function closeS2TModal() { document.getElementById('s2tModal').style.display = 'none'; }
function filterConfidence(val) {
  const sel = document.getElementById('s2tConfFilter');
  if (sel) { sel.value = val; renderS2TTable(); }
}

function renderS2TTable() {
  const SC = {'Direct':'#dcfce7','Derived':'#fef9c3','Lookup':'#ede9fe','Filtered':'#ffedd5',
              'Aggregated':'#ede9fe','Unmapped Target':'#fee2e2','Unmapped Source':'#fee2e2'};
  const SC_TEXT = {'Direct':'#14532d','Derived':'#713f12','Lookup':'#4c1d95','Filtered':'#7c2d12',
                   'Aggregated':'#4c1d95','Unmapped Target':'#7f1d1d','Unmapped Source':'#7f1d1d'};
  const CONF_BG   = { HIGH: '#dcfce7', MEDIUM: '#fef9c3', LOW: '#fee2e2' };
  const CONF_TEXT = { HIGH: '#14532d', MEDIUM: '#713f12', LOW: '#7f1d1d' };
  const statusFilter = document.getElementById('s2tStatusFilter')?.value || '';
  const confFilter   = document.getElementById('s2tConfFilter')?.value || '';
  const q = (document.getElementById('s2tSearch')?.value || '').toLowerCase();

  const filtered = _s2tAllRecords.filter(r => {
    if (statusFilter && r.status !== statusFilter) return false;
    if (confFilter  && (r.judge_confidence || '') !== confFilter) return false;
    if (!q) return true;
    return (r.source_table+' '+r.source_field+' '+r.target_table+' '+r.target_field+' '+r.logic+' '+r.status).toLowerCase().includes(q);
  });
  document.getElementById('s2tCount').textContent = `${filtered.length} of ${_s2tAllRecords.length} rows`;

  document.getElementById('s2tTbody').innerHTML = filtered.map((r,i) => {
    const bg    = i%2===0 ? (SC[r.status]||'#fff') : '#f8fafc';
    const chain = r.transformation_chain_str || (r.transformation_chain||[]).join(' → ') || '—';
    const conf  = (r.judge_confidence || '').toUpperCase();
    // LOW rows: red left border so the eye goes there immediately
    const rowStyle = conf === 'LOW'
      ? `background:${bg};border-left:3px solid #f87171`
      : `background:${bg}`;
    const confCell = conf
      ? `<div style="display:flex;flex-direction:column;gap:2px">
           <span style="padding:2px 8px;border-radius:4px;background:${CONF_BG[conf]||'#f1f5f9'};color:${CONF_TEXT[conf]||'#1e293b'};font-size:10px;font-weight:700;border:1px solid ${CONF_BG[conf]||'#e2e8f0'};white-space:nowrap">${esc(conf)}</span>
           ${r.judge_note && conf !== 'HIGH' ? `<span style="font-size:10px;color:#94a3b8;font-style:italic;max-width:160px;word-break:break-word">${esc(r.judge_note)}</span>` : ''}
         </div>`
      : `<span style="color:#cbd5e1;font-size:10px">—</span>`;
    return `<tr style="${rowStyle}">
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;color:#1e3a8a;font-weight:700;white-space:nowrap">${esc(r.source_table||'—')}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;color:#1e293b;font-weight:600;white-space:nowrap">${esc(r.source_field||'—')}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;color:#64748b;font-size:10px">${esc(r.source_type||'—')}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;color:#64748b;text-align:center;font-size:16px">→</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;color:#14532d;font-weight:700;white-space:nowrap">${esc(r.target_table||'—')}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;color:#1e293b;font-weight:600;white-space:nowrap">${esc(r.target_field||'—')}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;color:#64748b;font-size:10px">${esc(r.target_type||'—')}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0"><span style="padding:2px 8px;border-radius:4px;background:${SC[r.status]||'#f1f5f9'};color:${SC_TEXT[r.status]||'#1e293b'};font-size:10px;font-weight:700;border:1px solid ${SC[r.status]||'#e2e8f0'};white-space:nowrap">${esc(r.status||'—')}</span></td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top">${confCell}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;color:#94a3b8;font-size:10px;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(chain)}">${esc(chain)}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;color:#475569;max-width:240px" title="${esc(r.logic||'')}">${esc(r.logic||'—')}</td>
      <td style="padding:5px 10px;border-bottom:1px solid #e2e8f0;font-size:11px;color:#94a3b8;max-width:180px" title="${esc(r.notes||'')}">${esc(r.notes||'—')}</td>
    </tr>`;
  }).join('');

  const showAll = !statusFilter && !q;
  const srcEl = document.getElementById('s2tUnmappedSrcPanel');
  const tgtEl = document.getElementById('s2tUnmappedTgtPanel');
  if (srcEl) {
    srcEl.style.display = (showAll && _s2tUnmappedSrc.length) ? '' : 'none';
    srcEl.querySelector('tbody').innerHTML = _s2tUnmappedSrc.map(r =>
      `<tr><td style="padding:4px 10px;color:#1e3a8a;font-weight:700">${esc(r.source_table)}</td>
       <td style="padding:4px 10px">${esc(r.source_field)}</td>
       <td style="padding:4px 10px;color:#94a3b8;font-size:10px">${esc(r.source_type||'')}</td>
       <td style="padding:4px 10px;color:#94a3b8;font-size:11px">${esc(r.note||'')}</td></tr>`
    ).join('');
  }
  if (tgtEl) {
    tgtEl.style.display = (showAll && _s2tUnmappedTgt.length) ? '' : 'none';
    tgtEl.querySelector('tbody').innerHTML = _s2tUnmappedTgt.map(r =>
      `<tr><td style="padding:4px 10px;color:#14532d;font-weight:700">${esc(r.target_table)}</td>
       <td style="padding:4px 10px">${esc(r.target_field)}</td>
       <td style="padding:4px 10px;color:#94a3b8;font-size:10px">${esc(r.target_type||'')}</td>
       <td style="padding:4px 10px;color:#94a3b8;font-size:11px">${esc(r.note||'')}</td></tr>`
    ).join('');
  }
}

// ─────────────────────────────────────────────
// Global job search
// ─────────────────────────────────────────────
let _gSearchIdx = -1;

function openGlobalSearch() {
  const overlay = document.getElementById('globalSearchOverlay');
  overlay.style.display = 'flex';
  const inp = document.getElementById('globalSearchInput');
  inp.value = '';
  _gSearchIdx = -1;
  document.getElementById('globalSearchResults').innerHTML =
    '<div style="padding:24px;text-align:center;color:var(--muted);font-size:13px">Start typing to search all jobs…</div>';
  setTimeout(() => inp.focus(), 50);
}

function closeGlobalSearch() {
  document.getElementById('globalSearchOverlay').style.display = 'none';
  _gSearchIdx = -1;
}

function runGlobalSearch() {
  const q = (document.getElementById('globalSearchInput').value || '').trim().toLowerCase();
  const container = document.getElementById('globalSearchResults');
  if (!q) {
    container.innerHTML = '<div style="padding:24px;text-align:center;color:var(--muted);font-size:13px">Start typing to search all jobs…</div>';
    return;
  }
  const jobs = _histJobs || [];
  const hits = jobs.filter(j => {
    const name   = (j.submitter_name||'').replace(/^"|"$/g,'').toLowerCase();
    const sid    = shortId(j.job_id).toLowerCase();
    const haystack = [j.filename, j.job_id, sid, name, j.submitter_team,
                      j.submitter_notes, j.status, j.complexity_tier]
      .filter(Boolean).join(' ').toLowerCase();
    return haystack.includes(q);
  }).slice(0, 12);

  if (!hits.length) {
    container.innerHTML = '<div style="padding:24px;text-align:center;color:var(--muted);font-size:13px">No jobs found</div>';
    _gSearchIdx = -1;
    return;
  }

  _gSearchIdx = -1;
  container.innerHTML = hits.map((j, i) => {
    const [cls, lbl] = STATUS_BADGE[j.status] || ['badge-pending', j.status];
    const submitter  = esc((j.submitter_name||'').replace(/^"|"$/g,'')||'—');
    const dt = j.created_at ? new Date(j.created_at).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}) : '';
    return `<div class="gsearch-row" data-idx="${i}" data-jobid="${j.job_id}"
                 onclick="gSearchOpen('${j.job_id}')"
                 onmouseenter="_gSearchIdx=${i};_gHighlight()">
      <div style="flex:1;min-width:0">
        <div style="font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(j.filename)}</div>
        <div style="font-size:11px;color:var(--muted);margin-top:2px">${shortId(j.job_id)} &nbsp;·&nbsp; ${submitter} &nbsp;·&nbsp; ${dt}</div>
      </div>
      <span class="badge ${cls}" style="flex-shrink:0;font-size:11px">${lbl}</span>
    </div>`;
  }).join('');
}

function _gHighlight() {
  document.querySelectorAll('.gsearch-row').forEach((r, i) => {
    r.style.background = i === _gSearchIdx ? 'var(--surface2)' : '';
  });
}

function gSearchOpen(jobId) {
  closeGlobalSearch();
  openJobFromHistory(jobId);
}

document.addEventListener('keydown', e => {
  const overlay = document.getElementById('globalSearchOverlay');
  if (overlay && overlay.style.display !== 'none') {
    const rows = document.querySelectorAll('.gsearch-row');
    if (e.key === 'Escape') { closeGlobalSearch(); e.preventDefault(); }
    else if (e.key === 'ArrowDown') {
      _gSearchIdx = Math.min(_gSearchIdx + 1, rows.length - 1);
      _gHighlight(); e.preventDefault();
    } else if (e.key === 'ArrowUp') {
      _gSearchIdx = Math.max(_gSearchIdx - 1, 0);
      _gHighlight(); e.preventDefault();
    } else if (e.key === 'Enter' && _gSearchIdx >= 0 && rows[_gSearchIdx]) {
      rows[_gSearchIdx].click(); e.preventDefault();
    }
    return;
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') { openGlobalSearch(); e.preventDefault(); }
  if (e.key === 'Escape') { closeS2TModal(); }
});

// ─────────────────────────────────────────────
// Test Runner
// ─────────────────────────────────────────────
const TEST_SUITES = [
  { id: 'landing',    label: 'Landing Page',        count: 7,  icon: '🏠', dep: null },
  { id: 'navigation', label: 'Navigation',          count: 8,  icon: '🗺', dep: null },
  { id: 'review',     label: 'Review Queue',        count: 8,  icon: '✅', dep: null },
  { id: 'auth',       label: 'Auth & Session',      count: 13, icon: '🔐', dep: null },
  { id: 'submission', label: 'File Submission',     count: 9,  icon: '📤', dep: 'Submits 2 real jobs to the pipeline' },
  { id: 'history',    label: 'Job History',         count: 8,  icon: '📋', dep: 'Seeds up to 8 jobs via the pipeline' },
  { id: 'security',   label: 'Security & Headers',  count: 8,  icon: '🔒', dep: 'Submits 2 real jobs to the pipeline' },
];

let _testRunnerReady = false;
let _testRunning = false;

function initTestRunner() {
  if (_testRunnerReady) return;
  _testRunnerReady = true;
  const grid = document.getElementById('testSuiteGrid');
  if (!grid) return;
  grid.innerHTML = '';
  for (const s of TEST_SUITES) {
    const card = document.createElement('label');
    card.style.cssText = 'display:flex;align-items:center;gap:12px;padding:12px 14px;background:var(--surface2);border:2px solid var(--border);border-radius:10px;cursor:pointer;transition:border-color .15s,background .15s;user-select:none';
    card.innerHTML = `
      <input type="checkbox" data-suite="${s.id}" style="accent-color:var(--accent);width:16px;height:16px;flex-shrink:0">
      <span style="font-size:20px">${s.icon}</span>
      <span style="flex:1;min-width:0">
        <span style="display:block;font-size:13px;font-weight:600">${s.label}</span>
        <span style="font-size:11px;color:var(--muted)">~${s.count} tests${s.dep ? ' &nbsp;·&nbsp; <span style="color:#f59e0b">⚠ ' + s.dep + '</span>' : ''}</span>
      </span>`;
    card.querySelector('input').addEventListener('change', () => {
      card.style.borderColor = card.querySelector('input').checked ? 'var(--accent)' : 'var(--border)';
      card.style.background  = card.querySelector('input').checked ? 'rgba(108,99,255,.08)' : 'var(--surface2)';
      _updateRunBtn();
    });
    grid.appendChild(card);
  }
}

function _updateRunBtn() {
  const btn = document.getElementById('testRunBtn');
  if (!btn) return;
  const any = [...document.querySelectorAll('#testSuiteGrid input[type=checkbox]')].some(c => c.checked);
  btn.disabled = !any || _testRunning;
}

function testSelectAll() {
  document.querySelectorAll('#testSuiteGrid input[type=checkbox]').forEach(c => {
    c.checked = true;
    c.dispatchEvent(new Event('change'));
  });
}

function testClearAll() {
  document.querySelectorAll('#testSuiteGrid input[type=checkbox]').forEach(c => {
    c.checked = false;
    c.dispatchEvent(new Event('change'));
  });
}

function _appendLog(text, color) {
  const log = document.getElementById('testLog');
  if (!log) return;
  const span = document.createElement('span');
  if (color) span.style.color = color;
  span.textContent = text + '\n';
  const ph = log.querySelector('span[style*="muted"]');
  if (ph) ph.remove();
  log.appendChild(span);
  log.scrollTop = log.scrollHeight;
}

function _colorForLine(line) {
  if (/^\s*[✔✓]/.test(line) || /\bpassed\b/i.test(line))  return '#4ade80';
  if (/^\s*[✘✗×]/.test(line) || /\bfailed\b/i.test(line)) return '#f87171';
  if (/\bskipped\b/i.test(line)) return '#facc15';
  if (/Error:/i.test(line))      return '#f87171';
  if (/^\s+at /.test(line))      return '#94a3b8';
  if (/Running \d+ test/.test(line)) return '#a5b4fc';
  return null;
}

function runTests() {
  const suites = [...document.querySelectorAll('#testSuiteGrid input[type=checkbox]')]
    .filter(c => c.checked).map(c => c.dataset.suite);
  if (!suites.length) return;

  _testRunning = true;
  _updateRunBtn();
  document.getElementById('testRunBtn').textContent = '⏳ Running…';
  document.getElementById('testStatus').textContent = `Running: ${suites.join(', ')}`;
  document.getElementById('testStatus').style.color = '';
  document.getElementById('testResultBar').style.display = 'none';

  const pbWrap = document.getElementById('testProgressWrap');
  const pb     = document.getElementById('testProgressBar');
  if (pbWrap) pbWrap.style.display = 'block';
  if (pb)     pb.className = 'hc-progress-bar';

  const totalTests = suites.reduce((sum, id) => {
    const s = TEST_SUITES.find(t => t.id === id);
    return sum + (s ? s.count : 8);
  }, 0);
  let doneTests = 0;

  function _setProgress(pct) {
    if (!pb) return;
    if (pb.classList.contains('hc-progress-bar') && !pb.style.width) {
      pb.style.animation = 'none';
      pb.style.marginLeft = '0';
      pb.style.transition = 'width .3s ease';
    }
    pb.style.width = Math.min(100, Math.round(pct)) + '%';
  }

  const log = document.getElementById('testLog');
  if (log) log.innerHTML = '';
  _appendLog(`▶ Starting: ${suites.join(', ')}`, '#a5b4fc');

  let connectTimer = null, connectEl = null;
  let firstOutput = false;

  const spinDots = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
  let spinIdx = 0;
  connectEl = document.createElement('span');
  connectEl.style.color = '#94a3b8';
  connectEl.textContent = `${spinDots[0]}  Connecting to test runner…`;
  if (log) { log.appendChild(connectEl); log.appendChild(document.createElement('br')); }
  connectTimer = setInterval(() => {
    spinIdx = (spinIdx + 1) % spinDots.length;
    if (connectEl) connectEl.textContent = `${spinDots[spinIdx]}  Connecting to test runner…`;
  }, 100);

  const warn5  = setTimeout(() => {
    if (!firstOutput) _appendLog('⚠  No output yet — Playwright is still starting up…', '#fbbf24');
  }, 5000);
  const warn20 = setTimeout(() => {
    if (!firstOutput) _appendLog('⚠  Still no output after 20 s. Try restarting the server.', '#f87171');
  }, 20000);

  function finish(ok) {
    clearInterval(connectTimer); connectTimer = null;
    clearTimeout(warn5); clearTimeout(warn20);
    if (connectEl && connectEl.parentNode) {
      const br = connectEl.nextSibling;
      connectEl.parentNode.removeChild(connectEl);
      if (br && br.nodeName === 'BR') br.parentNode.removeChild(br);
      connectEl = null;
    }
    if (pb) pb.className = ok ? 'hc-progress-bar done' : 'hc-progress-bar error';
    setTimeout(() => { if (pbWrap) pbWrap.style.display = 'none'; }, 2000);
    _testRunning = false;
    _updateRunBtn();
    document.getElementById('testRunBtn').textContent = '▶ Run Selected';
  }

  function onFirst() {
    if (firstOutput) return;
    firstOutput = true;
    clearInterval(connectTimer); connectTimer = null;
    clearTimeout(warn5); clearTimeout(warn20);
    if (connectEl && connectEl.parentNode) {
      const br = connectEl.nextSibling;
      connectEl.parentNode.removeChild(connectEl);
      if (br && br.nodeName === 'BR') br.parentNode.removeChild(br);
      connectEl = null;
    }
  }

  const es = new EventSource(`/api/run-tests?suites=${encodeURIComponent(suites.join(','))}`);

  es.onmessage = (e) => {
    let evt;
    try { evt = JSON.parse(e.data); } catch { return; }

    if (evt.type === 'start') {
      onFirst();
      _appendLog(`▶ Playwright launched — suites: ${evt.suites.join(', ')}`, '#a5b4fc');
    } else if (evt.type === 'line') {
      onFirst();
      const clean = evt.text.replace(/\x1b\[[0-9;]*[mGKJHF]/g, '').replace(/\[[\d]+[A-Z]/g, '');
      if (!clean.trim()) return;
      const isResult = /^\s*[✔✓✘✗×]/.test(clean);
      if (isResult) {
        doneTests++;
        _setProgress((doneTests / totalTests) * 100);
        document.getElementById('testStatus').textContent =
          `Running: ${suites.join(', ')} — ${doneTests} / ${totalTests}`;
      }
      _appendLog(clean, _colorForLine(clean));
    } else if (evt.type === 'done') {
      onFirst();
      es.close();
      const ok = evt.rc === 0;
      _setProgress(100);
      document.getElementById('testResPassed').textContent  = `✓ ${evt.passed}  passed`;
      document.getElementById('testResFailed').textContent  = `✗ ${evt.failed}  failed`;
      document.getElementById('testResSkipped').textContent = `⊘ ${evt.skipped} skipped`;
      document.getElementById('testResultBar').style.display = 'flex';
      document.getElementById('testStatus').textContent = ok ? '✓ All suites passed' : `✗ ${evt.failed} test(s) failed`;
      document.getElementById('testStatus').style.color = ok ? '#4ade80' : '#f87171';
      _appendLog('', null);
      _appendLog(ok ? '✓ Run complete — all tests passed.' : `✗ Run complete — ${evt.failed} failed.`,
                 ok ? '#4ade80' : '#f87171');
      finish(ok);
    } else if (evt.type === 'error') {
      onFirst();
      es.close();
      _appendLog(`Error: ${evt.text}`, '#f87171');
      finish(false);
    }
  };

  es.onerror = () => {
    es.close();
    if (!firstOutput) _appendLog('Connection to test runner failed. Is the server running?', '#f87171');
    finish(false);
  };
}

// ─────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────
loadJobs();
setInterval(loadJobs, 5000);
setInterval(() => { try { refreshSidebarActivity(); } catch(e) {} }, 5000);

updateNotifBell();
setInterval(updateNotifBell, 30000);

initPersonaUI();
setMainView('landing');
loadHistory();

(async () => {
  try {
    const res  = await fetch('/api/security/knowledge');
    const data = await res.json();
    const badge = document.getElementById('secKbBadge');
    if (badge) {
      document.getElementById('secKbRules').textContent    = data.rules_count    ?? 0;
      document.getElementById('secKbPatterns').textContent = data.patterns_count ?? 0;
      badge.style.display = 'block';
    }
  } catch(e) { /* badge is supplemental — never break init */ }
})();

// gates.js — Gate 1/2/3 sign-off, review queue navigation

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
    setTimeout(() => {
      const candidates = ['signoffCard','secReviewCard','codeSignoffCard'];
      for (const id of candidates) {
        const el = document.getElementById(id);
        if (el) { scrollToSignoff(id); break; }
      }
    }, 300);
  });
}

function reuploadForJob() {
  document.getElementById('fileInput').click();
}

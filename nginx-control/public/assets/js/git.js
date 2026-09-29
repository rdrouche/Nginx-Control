'use strict';
/**
 * Page "Déploiement Git" — extrait de public/index.html dans le cadre du
 * decoupage JS + traduction (voir CHANGELOG.md). Charge apres le script
 * inline principal : partage le meme scope global (api(), t(), h(), ...),
 * pas un module ES.
 *
 * Tout le texte affiche a l operateur passe desormais par t() : les cles
 * "deploy.*" existaient deja dans public/assets/lang/{en,fr}.json (creees
 * en meme temps que la page), mais n etaient presque jamais lues — cette
 * extraction en a profite pour les cabler reellement, plutot que de les
 * laisser mortes a cote d un texte francais code en dur affiche quelle que
 * soit la langue choisie.
 */
let deployBusy = false;

async function loadDeployPage() {
  const statusBody = document.getElementById('git-status-body');
  const diffBody   = document.getElementById('git-diff-body');
  statusBody.innerHTML = `<div style="color:var(--text3)">${h(t('common.loading'))}</div>`;
  diffBody.innerHTML   = `<div style="color:var(--text3);font-family:monospace;font-size:12px">${h(t('common.loading'))}</div>`;

  const d = await api('/git/status').catch(() => null);
  if (!d) { statusBody.innerHTML = `<div style="color:var(--red)">${h(t('deploy.error.api'))}</div>`; return; }
  if (!d.configured) {
    statusBody.innerHTML = `<div style="color:var(--amber);font-family:monospace;font-size:12px">${h(t('deploy.not.configured'))}</div>`;
    diffBody.innerHTML = '';
    return;
  }
  if (d.error) {
    statusBody.innerHTML = `<div style="color:var(--red);font-family:monospace;font-size:12px">${h(d.error)}</div>`;
    return;
  }

  // Status card
  statusBody.innerHTML = `
    <div style="display:flex;justify-content:space-between"><span style="color:var(--text3)">${h(t('deploy.repo'))}</span><span style="color:var(--text);font-size:11px;overflow:hidden;text-overflow:ellipsis;max-width:60%">${h(d.repo)}</span></div>
    <div style="display:flex;justify-content:space-between"><span style="color:var(--text3)">${h(t('deploy.branch'))}</span><span style="color:var(--blue)">${h(d.branch)}</span></div>
    <div style="display:flex;justify-content:space-between"><span style="color:var(--text3)">${h(t('deploy.backup.branch'))}</span><span class="badge ${d.backupBranchExists?'gn':'am'}">${d.backupBranchExists?h(d.backupBranch)+' ✓':h(t('deploy.backup.notinit'))}</span></div>
    <div style="display:flex;justify-content:space-between"><span style="color:var(--text3)">${h(t('deploy.commit.local'))}</span><span style="color:var(--text)">${h(d.currentHash||'—')}</span></div>
    <div style="display:flex;justify-content:space-between"><span style="color:var(--text3)">${h(t('deploy.commit.remote'))}</span><span style="color:var(--text)">${h(d.remoteHash||'—')}</span></div>
    <div style="display:flex;justify-content:space-between"><span style="color:var(--text3)">${h(t('deploy.state'))}</span>
      <span class="badge ${d.upToDate?'gn':'am'}">${d.upToDate?h(t('deploy.uptodate')):h(t('deploy.outdated'))}</span>
    </div>
    ${d.recentCommits?.length ? `<div class="git-commits">${d.recentCommits.map(c=>`<div class="git-commit">${h(c)}</div>`).join('')}</div>` : ''}
  `;

  // Diff table
  const diff = d.diff || [];
  document.getElementById('deploy-diff-count').textContent = diff.length ? diff.length : '';
  if (!diff.length) {
    diffBody.innerHTML = `<div style="color:var(--green);font-family:monospace;font-size:12px">✓ ${h(t('deploy.diff.empty'))}</div>`;
    return;
  }
  diffBody.innerHTML = `<div class="table-wrap"><table class="diff-table">
    <thead><tr><th>${h(t('deploy.diff.section'))}</th><th>${h(t('deploy.diff.file'))}</th><th>${h(t('deploy.diff.status'))}</th></tr></thead>
    <tbody>${diff.map(c=>`<tr>
      <td>${h(c.section)}</td>
      <td>${h(c.file)}</td>
      <td class="diff-${c.status}">${c.status==='added'?'+ '+h(t('deploy.diff.added')):c.status==='deleted'?'− '+h(t('deploy.diff.deleted')):'≠ '+h(t('deploy.diff.modified'))}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

function setPipelineStep(steps) {
  const el = document.getElementById('pipeline-log');
  el.innerHTML = steps.map((s,i) => `
    <div class="pipe-step">
      <div class="pipe-num ${s.state}">${s.state==='done'?'✓':s.state==='error'?'✗':s.state==='running'?'…':i+1}</div>
      <div class="pipe-body">
        <div class="pipe-title">${h(s.title)}</div>
        ${s.detail ? `<div class="pipe-detail">${h(s.detail)}</div>` : ''}
      </div>
    </div>`).join('');
}

async function gitTestConn() {
  const btn = document.getElementById('btn-test-conn');
  const resEl = document.getElementById('git-conn-result');
  btn.disabled = true; btn.textContent = t('deploy.btn.conntest.testing');
  resEl.style.display = 'none';
  const d = await api('/git/test-connection').catch(e => ({ ok: false, error: e.message }));
  btn.disabled = false;
  btn.innerHTML = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" width="12" height="12"><circle cx="8" cy="8" r="6"/><path d="M8 5v3l2 2"/></svg> ' + h(t('deploy.btn.conntest'));
  resEl.style.display = 'block';

  if (!d?.configured) {
    resEl.style.color = 'var(--amber)';
    resEl.textContent = t('deploy.conntest.notconfigured')
      + (d?.envValue ? '\n' + t('deploy.conntest.rawvalue', { value: d.envValue }) : '')
      + '\n' + t('deploy.conntest.hint.recreate');
  } else if (d?.ok) {
    resEl.style.color = 'var(--green)';
    const lines = [
      t('deploy.conntest.ok', { ms: d.latencyMs }),
      t('deploy.conntest.auth', { method: d.authMethod || '?' }),
      t('deploy.conntest.branches', { list: (d.branches && d.branches.length ? d.branches.join(', ') : t('deploy.conntest.none')) }),
      d.mainBranchFound ? t('deploy.conntest.branch.found', { branch: d.branch }) : t('deploy.conntest.branch.notfound', { branch: d.branch }),
      d.backupBranchFound ? t('deploy.conntest.backupbranch.found', { branch: d.backupBranch }) : t('deploy.conntest.backupbranch.notfound'),
    ];
    resEl.textContent = lines.join('\n');
  } else {
    resEl.style.color = 'var(--red)';
    const lines = [
      t('deploy.conntest.error.title'),
      t('deploy.conntest.url', { url: d?.url || t('deploy.conntest.unknown') }),
      t('deploy.conntest.auth', { method: d?.authMethod || '?' }),
      t('deploy.conntest.errorline', { error: d?.error || t('deploy.conntest.unknown') }),
    ];
    if (d?.stderr) lines.push(t('deploy.conntest.detail', { detail: d.stderr.split('\n').filter(Boolean).join(' | ') }));
    if (d?.hint) lines.push('', '→ ' + d.hint);
    resEl.textContent = lines.join('\n');
  }
}

async function initBackupBranch() {
  if (!confirm(t('deploy.initbranch.confirm'))) return;
  const btn = document.getElementById('btn-init-branch');
  btn.disabled = true; btn.textContent = t('deploy.btn.initbranch.creating');
  const d = await api('/git/init-backup-branch', { method: 'POST' }).catch(e => ({ error: e.message }));
  btn.disabled = false; btn.textContent = t('deploy.btn.initbranch');
  if (d?.error) {
    setPipelineStep([{ title: t('deploy.initbranch.error'), state: 'error', detail: d.error }]);
  } else if (d?.alreadyExists) {
    setPipelineStep([{ title: t('deploy.backup.branch'), state: 'done', detail: t('deploy.branch.exists') }]);
  } else if (d?.ok) {
    setPipelineStep([{ title: t('deploy.branch.created'), state: 'done', detail: t('deploy.initbranch.success.detail', { branch: d.branch }) }]);
    await loadDeployPage();
  }
}

async function gitPull() {
  if (deployBusy) return;
  deployBusy = true;
  setPipelineStep([{title: t('deploy.step.pull.running'), state:'running'}]);
  const d = await api('/git/pull', {method:'POST'}).catch(e=>({error:e.message}));
  if (d?.error) {
    setPipelineStep([{title: t('deploy.step.pull'), state:'error', detail: d.error}]);
  } else {
    setPipelineStep([{title: t('deploy.step.pull'), state:'done', detail: d?.stdout||''}]);
    await loadDeployPage();
  }
  deployBusy = false;
}

async function gitTest() {
  if (deployBusy) return;
  deployBusy = true;
  setPipelineStep([{title: t('deploy.step.test.running'), state:'running', detail: t('deploy.step.test.starting')}]);
  const d = await api('/git/test', {method:'POST'}).catch(e=>({error:e.message}));
  if (d?.error && !d?.valid) {
    setPipelineStep([{title: t('deploy.step.test'), state:'error', detail: d.error}]);
  } else if (d?.valid) {
    setPipelineStep([{title: t('deploy.step.test'), state:'done', detail:`✓ ${t('deploy.step.test.valid', { image: d.image || '?' })}
${d.output||''}`}]);
  } else {
    setPipelineStep([{title: t('deploy.step.test'), state:'error', detail:`✗ ${t('deploy.step.test.invalid')}
${d?.output||d?.error||''}`}]);
  }
  deployBusy = false;
}

async function gitDeploy() {
  if (deployBusy) return;
  if (!confirm(t('deploy.confirm'))) return;
  deployBusy = true;
  const steps = [
    {title: t('deploy.step.pull'), state:'running'},
    {title: t('deploy.step.test'), state:''},
    {title: t('deploy.step.backup'), state:''},
    {title: t('deploy.step.copyconfigs'), state:''},
    {title: t('deploy.step.reload'), state:''},
  ];
  setPipelineStep(steps);

  const d = await api('/git/deploy', {method:'POST'}).catch(e=>({error:e.message}));

  if (d?.error && !d?.ok) {
    // Map error to step
    const logSteps = d.log || [];
    const result = logSteps.map((s,i) => ({
      title: s.msg,
      state: i < logSteps.length - 1 ? 'done' : 'error',
      detail: typeof s.data === 'object' ? JSON.stringify(s.data, null, 2) : s.data||''
    }));
    if (d.testResult && !d.testResult.valid) {
      result.push({title: t('deploy.step.test.invalid.cancelled'), state:'error', detail: d.testResult?.output||''});
    } else {
      result.push({title: d.error || t('deploy.error.unknown'), state:'error'});
    }
    setPipelineStep(result);
  } else if (d?.ok) {
    const result = (d.log||[]).map(s => ({
      title: s.msg,
      state: 'done',
      detail: typeof s.data === 'object' ? JSON.stringify(s.data) : s.data||''
    }));
    setPipelineStep(result);
    await loadDeployPage();
    await loadBackupsPage();
  }
  deployBusy = false;
}

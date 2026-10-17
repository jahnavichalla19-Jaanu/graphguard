const COLORS = { 
  Trigger: '#f43f5e', 
  Workflow: '#38bdf8', 
  Job: '#a855f7', 
  Action: '#f59e0b', 
  Secret: '#ec4899', 
  Role: '#10b981', 
  Resource: '#06b6d4', 
  Repo: '#64748b' 
};
const OUTCOME = {
  answered_with_path: { cls: 'ok', text: 'Answered with path' },
  memory: { cls: 'mem', text: 'Memory' },
  not_in_graph: { cls: 'warn', text: 'Not in graph' },
  unknown_node: { cls: 'bad', text: 'Unknown node' }
};
function badge(outcome) {
  const o = OUTCOME[outcome] || { cls: 'warn', text: outcome || 'unknown' };
  return `<span class="badge ${o.cls}">${esc(o.text)}</span>`;
}
const $ = id => document.getElementById(id);
let cy;
let paths = [];

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function api(url, opts) {
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function post(url, body) {
  return api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
}

function guard(fn) {
  return async (...args) => {
    try {
      await fn(...args);
    } catch (e) {
      $('detail').innerHTML = '<p class="bad">' + esc(e.message) + '</p>';
    }
  };
}

function initGraph() {
  cy = cytoscape({
    container: $('cy'),
    wheelSensitivity: 0.3,
    style: [
      { 
        selector: 'node', 
        style: { 
          'background-color': e => COLORS[e.data('kind')] || '#64748b', 
          label: 'data(label)', 
          'font-size': 10, 
          'font-family': 'JetBrains Mono, monospace',
          color: '#e2e8f0', 
          'text-valign': 'bottom', 
          'text-margin-y': 5, 
          width: 32, 
          height: 32, 
          'text-wrap': 'ellipsis', 
          'text-max-width': 130,
          'border-width': 1.5,
          'border-color': 'rgba(255, 255, 255, 0.25)',
          'shadow-blur': 12,
          'shadow-color': e => COLORS[e.data('kind')] || '#000',
          'shadow-opacity': 0.45
        } 
      },
      { 
        selector: 'node[?sensitive]', 
        style: { 
          shape: 'diamond', 
          'border-width': 2.5, 
          'border-color': '#f43f5e', 
          width: 38, 
          height: 38,
          'shadow-color': '#f43f5e',
          'shadow-blur': 20,
          'shadow-opacity': 0.8
        } 
      },
      { 
        selector: 'edge', 
        style: { 
          width: 1.8, 
          'line-color': 'rgba(99, 102, 241, 0.45)', 
          'target-arrow-color': 'rgba(168, 85, 247, 0.7)', 
          'target-arrow-shape': 'triangle', 
          'curve-style': 'bezier', 
          label: 'data(label)', 
          'font-size': 7.5, 
          'font-family': 'JetBrains Mono, monospace',
          color: '#94a3b8', 
          'text-rotation': 'autorotate',
          'text-background-opacity': 0.8,
          'text-background-color': '#07090e',
          'text-background-padding': 2,
          'text-background-shape': 'roundrectangle'
        } 
      },
      { selector: '.dim', style: { opacity: 0.12 } },
      { 
        selector: 'node.hot', 
        style: { 
          'border-width': 3.5, 
          'border-color': '#f43f5e',
          'shadow-color': '#f43f5e',
          'shadow-blur': 25,
          'shadow-opacity': 0.95
        } 
      },
      { 
        selector: 'edge.hot', 
        style: { 
          'line-color': '#f43f5e', 
          'target-arrow-color': '#f43f5e', 
          width: 3.5,
          'shadow-color': '#f43f5e',
          'shadow-blur': 14,
          'shadow-opacity': 0.7
        } 
      },
      { 
        selector: 'node.blast', 
        style: { 
          'border-width': 3.5, 
          'border-color': '#38bdf8',
          'shadow-color': '#38bdf8',
          'shadow-blur': 25,
          'shadow-opacity': 0.95
        } 
      }
    ]
  });
  cy.on('tap', 'node', guard(e => blast(e.target.id())));
}

async function loadGraph() {
  const g = await api('/api/graph');
  const els = [];
  g.nodes.forEach(n => els.push({ data: { id: n.id, label: n.name, kind: n.label, sensitive: n.sensitive === true } }));
  g.edges.forEach(e => els.push({ data: { id: e.source + '|' + e.type + '|' + e.target, source: e.source, target: e.target, label: e.type } }));
  cy.elements().remove();
  cy.add(els);
  cy.layout({ name: 'breadthfirst', directed: true, spacingFactor: 1.15, padding: 25 }).run();
  if ($('sNodes')) $('sNodes').textContent = g.nodes.length;
  if ($('sEdges')) $('sEdges').textContent = g.edges.length;
  const p = await api('/api/paths').catch(() => []);
  if ($('sPaths')) $('sPaths').textContent = p.length;
  if ($('sAcc')) $('sAcc').textContent = p.filter(x => x.accepted).length;
}

function highlight(idLists) {
  cy.elements().removeClass('hot blast dim');
  if (!idLists.length) return;
  cy.elements().addClass('dim');
  idLists.forEach(ids => {
    ids.forEach(id => cy.getElementById(id).removeClass('dim').addClass('hot'));
    for (let i = 0; i < ids.length - 1; i++) {
      cy.edges().filter(e => e.source().id() === ids[i] && e.target().id() === ids[i + 1]).removeClass('dim').addClass('hot');
    }
  });
}

function pathCard(p, i) {
  const hops = p.edgeTypes.map((t, k) =>
    `<li>${esc(p.explanation[k])} <button class="mini" data-act="sim" data-s="${esc(p.nodeIds[k])}" data-t="${esc(t)}" data-d="${esc(p.nodeIds[k + 1])}">Break this link</button></li>`).join('');
  const status = p.accepted ? ' · accepted by ' + esc(p.acceptedBy) : '';
  return `<article class="card ${p.accepted ? 'accepted' : ''}" data-key="${esc(p.key)}"><header><b>Path ${i + 1}</b> · ${p.length} hops · id ${esc(p.key)}${status}
    <button class="mini" data-act="show" data-i="${i}">Highlight</button> <button class="mini" data-act="accept" data-key="${esc(p.key)}">Accept risk</button></header><ol>${hops}</ol></article>`;
}

async function showPaths() {
  paths = await api('/api/paths');
  highlight(paths.filter(p => !p.accepted).map(p => p.nodeIds));
  $('sim').innerHTML = '';
  $('detail').innerHTML = `<h2>${paths.length} attack path(s) from an untrusted trigger to a sensitive target</h2>` +
    (paths.length ? paths.map(pathCard).join('') : '<p class="good">No path found.</p>');
  if ($('sPaths')) {
    $('sPaths').textContent = paths.length;
    $('sAcc').textContent = paths.filter(p => p.accepted).length;
  }
}

async function showChoke() {
  const c = await api('/api/choke-points');
  const rows = c.edges.map(e => `<tr><td>${esc(e.description)}</td><td class="bad">removes ${e.paths} of ${c.activePaths}</td>
    <td><button class="mini" data-act="sim" data-s="${esc(e.source)}" data-t="${esc(e.type)}" data-d="${esc(e.target)}">Simulate</button></td></tr>`).join('');
  $('detail').innerHTML = `<h2>Fix-first ranking (links on the most attack paths)</h2>` +
    (rows ? `<table><tr><th>Link</th><th>Impact</th><th></th></tr>${rows}</table>` : '<p class="good">No active attack paths.</p>');
}

async function showLoadBearing() {
  const c = await api('/api/load-bearing?limit=5');
  const rows = (c.rows || []).map((r, i) =>
    `<tr><td>#${i + 1}</td><td><b>${esc(r.name || r.id)}</b></td><td><span class="pill-badge pill-purple">${esc(r.label || '')}</span></td><td>score: ${Number(r.score).toFixed(4)}</td></tr>`
  ).join('');
  $('detail').innerHTML = `<h2>Most Depended-On Nodes (${esc(c.algorithm || 'PageRank')})</h2>` +
    (rows ? `<table><tr><th>Rank</th><th>Node</th><th>Label</th><th>Score</th></tr>${rows}</table>` : '<p class="good">No nodes found.</p>');
}

async function blast(id, depth) {
  depth = depth || 4;
  const r = await api('/api/blast-radius?node=' + encodeURIComponent(id) + '&depth=' + depth);
  if (r.outcome === 'unknown_node' || r.outcome === 'not_in_graph') {
    $('detail').innerHTML = `<h2>Blast radius: "${esc(id)}"</h2>` +
      `<p class="bad">${badge(r.outcome)} ${esc(r.message || 'No nodes reachable or node not in graph.')}</p>`;
    return r;
  }
  cy.elements().removeClass('hot blast dim');
  (r.nodes || []).forEach(n => cy.getElementById(n.id).addClass('blast'));
  if (cy.getElementById(id)) cy.getElementById(id).addClass('blast');
  const groups = Object.entries(r.byLabel || {}).map(([k, v]) => `${v} ${esc(k)}`).join(', ') || 'nothing';
  const sens = (r.sensitiveReached && r.sensitiveReached.length) ? `<p class="bad">Sensitive targets reached: ${r.sensitiveReached.map(esc).join(', ')}</p>` : '<p class="good">No sensitive target reachable.</p>';
  const nodeRows = (r.nodes || []).map(n => {
    const via = Array.isArray(n.via) ? n.via : [];
    const viaHtml = via.length > 1 ? `<div class="via-path">${via.map(esc).map(v => `<span>${v}</span>`).join('')}</div>` : '';
    const hops = n.hops != null ? n.hops : '?';
    return `<li class="${n.sensitive ? 'sensitive' : ''}">${esc(n.name)} <em>(${esc(n.label)}, ${hops} hop${hops === 1 ? '' : 's'})</em>${viaHtml}</li>`;
  }).join('');
  $('detail').innerHTML = `<h2>${badge(r.outcome)} Blast radius of ${esc((cy.getElementById(id) && cy.getElementById(id).data('label')) || id)} (depth ${depth})</h2><p>If compromised it can reach ${r.reachableCount} node(s): ${groups}.</p>${sens}<ul class="node-list">${nodeRows}</ul>`;
  return r;
}
// =====================================================================
// Custom Theme Cyber Modal Helper (Replaces default browser prompt/alert)
// =====================================================================
function showModal({ title, desc, iconSvg, fields = [], confirmText = 'Submit', cancelText = 'Cancel' }) {
  return new Promise(resolve => {
    const overlay = $('custom-modal');
    $('modal-title').textContent = title || 'Action Required';
    $('modal-desc').textContent = desc || '';
    $('modal-icon').innerHTML = iconSvg || `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
      </svg>`;
    
    const container = $('modal-inputs');
    container.innerHTML = '';
    
    fields.forEach(f => {
      const fieldDiv = document.createElement('div');
      fieldDiv.className = 'modal-field';
      fieldDiv.innerHTML = `
        <label for="mf-${f.name}">${esc(f.label || f.name)}</label>
        <input id="mf-${f.name}" type="${f.type || 'text'}" placeholder="${esc(f.placeholder || '')}" value="${esc(f.defaultValue || '')}" autocomplete="off">
      `;
      container.appendChild(fieldDiv);
    });

    $('modal-confirm-btn').textContent = confirmText;
    $('modal-cancel-btn').textContent = cancelText;

    const cleanup = () => {
      overlay.style.display = 'none';
      $('modal-confirm-btn').onclick = null;
      $('modal-cancel-btn').onclick = null;
      $('modal-close-btn').onclick = null;
    };

    const submit = () => {
      const res = {};
      fields.forEach(f => {
        const inp = $(`mf-${f.name}`);
        res[f.name] = inp ? inp.value.trim() : '';
      });
      cleanup();
      resolve(res);
    };

    const cancel = () => {
      cleanup();
      resolve(null);
    };

    $('modal-confirm-btn').onclick = submit;
    $('modal-cancel-btn').onclick = cancel;
    $('modal-close-btn').onclick = cancel;

    overlay.onclick = e => {
      if (e.target === overlay) cancel();
    };

    overlay.style.display = 'flex';
    const firstInput = container.querySelector('input');
    if (firstInput) {
      setTimeout(() => firstInput.focus(), 50);
      firstInput.onkeydown = e => {
        if (e.key === 'Enter') submit();
        if (e.key === 'Escape') cancel();
      };
    }
  });
}

async function depthContrast() {
  const modalRes = await showModal({
    title: 'Depth Contrast Traversal',
    desc: 'Compare reachable nodes at depth=1 (immediate joins) vs depth=4 (multi-hop graph discovery).',
    iconSvg: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    fields: [
      { name: 'nodeId', label: 'Node ID or Name', placeholder: 'e.g. deploy-prod-lambda or shop-web', defaultValue: '' }
    ],
    confirmText: 'Run Contrast'
  });
  if (!modalRes || !modalRes.nodeId) return;
  const id = modalRes.nodeId;

  $('depth-panel').innerHTML = '<p style="padding:4px">Running depth contrast\u2026</p>';
  const [r1, r4] = await Promise.all([
    api('/api/blast-radius?node=' + encodeURIComponent(id) + '&depth=1'),
    api('/api/blast-radius?node=' + encodeURIComponent(id) + '&depth=4')
  ]);
  if (r1.outcome === 'unknown_node' || r4.outcome === 'unknown_node') {
    const msg = r1.message || r4.message || `Node not found in graph: "${esc(id)}". This node is not in the graph.`;
    $('depth-panel').innerHTML = `<p class="bad">${badge('unknown_node')} ${esc(msg)}</p>`;
    return;
  }
  const ids1 = new Set((r1.nodes || []).map(n => n.id));
  const newAt4 = (r4.nodes || []).filter(n => !ids1.has(n.id));
  const makeList = (nodes, markNew) => nodes.map(n => {
    const via = Array.isArray(n.via) ? n.via : [];
    const viaHtml = via.length > 1 ? `<div class="via-path">${via.map(esc).map(v => `<span>${v}</span>`).join('')}</div>` : '';
    const hops = n.hops != null ? n.hops : '?';
    return `<li class="${markNew ? 'new' : ''} ${n.sensitive ? 'sensitive' : ''}">${esc(n.name)} <em>(${esc(n.label)}, ${hops} hop${hops === 1 ? '' : 's'})</em>${viaHtml}</li>`;
  }).join('');
  cy.elements().removeClass('hot blast dim');
  if (newAt4.length) {
    cy.elements().addClass('dim');
    newAt4.forEach(n => cy.getElementById(n.id).removeClass('dim').addClass('blast'));
  }
  $('depth-panel').innerHTML = `
    <h2>Depth contrast: "${esc(id)}"</h2>
    <p>At depth&nbsp;1: <b>${r1.reachableCount}</b> node(s) reachable &nbsp;|&nbsp; At depth&nbsp;4: <b>${r4.reachableCount}</b> node(s) reachable &nbsp;|&nbsp; <b class="${newAt4.length ? 'bad' : 'good'}">${newAt4.length} discovered only through graph traversal</b></p>
    <div class="depth-row">
      <div class="depth-col"><h3>Depth 1 &mdash; <b>${r1.reachableCount}</b> nodes</h3><ul class="node-list">${makeList(r1.nodes || [], false)}</ul></div>
      <div class="depth-col"><h3>Depth 4 &mdash; <b>${r4.reachableCount}</b> nodes &nbsp;<span style="color:var(--ok)">(+${newAt4.length} new)</span></h3><ul class="node-list">${makeList(r4.nodes || [], false)}${makeList(newAt4, true)}</ul></div>
    </div>`;
}

async function simulate(s, t, d) {
  const r = await post('/api/simulate-fix', { source: s, type: t, target: d });
  document.querySelectorAll('.card[data-key]').forEach(c => c.classList.toggle('removed', r.removedKeys.includes(c.dataset.key)));
  $('sim').innerHTML = `<h2>Simulated fix: ${esc(r.edge.type)}</h2>
    <p>Attack paths <b class="bad">${r.before}</b> &rarr; <b class="good">${r.after}</b> · newly created paths: <b>${r.newKeys.length}</b> · checked on a temporary graph in ${r.millis} ms · main graph untouched.</p>
    ${r.edgeExisted ? '' : '<p class="bad">That link was not found in the graph.</p>'}<p><b>Plan (not applied):</b> ${esc(r.proposal)}</p>`;
}

async function accept(key) {
  const modalRes = await showModal({
    title: 'Accept Security Risk',
    desc: `Record a formal risk acceptance decision for path key: ${key}. This decision is persisted as a Decision node in FalkorDB.`,
    iconSvg: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    fields: [
      { name: 'owner', label: 'Risk Owner', placeholder: 'e.g. security-lead@company.com', defaultValue: '' },
      { name: 'reason', label: 'Business Justification', placeholder: 'e.g. Approved exception for Q4 migration', defaultValue: '' },
      { name: 'days', label: 'Expires in (Days)', placeholder: '30', defaultValue: '30', type: 'number' }
    ],
    confirmText: 'Accept & Persist'
  });
  if (!modalRes || !modalRes.owner) return;
  const days = parseInt(modalRes.days, 10) || 30;
  await post('/api/decisions', { pathKey: key, owner: modalRes.owner, reason: modalRes.reason, days });
  await showPaths();
}

async function ask() {
  const q = $('q').value.trim();
  if (!q) return;
  $('q').value = '';
  $('log').insertAdjacentHTML('beforeend', `<div class="msg user">${esc(q)}</div>`);
  const r = await post('/api/agent/ask', { question: q });
  const b = r.outcome ? badge(r.outcome) + ' ' : '';
  let traceHtml = '';
  if (r.toolCalls && r.toolCalls.length) {
    traceHtml = '<div class="trace">' + r.toolCalls.map(c => {
      const a = JSON.stringify(c.args || c.input || {});
      const ms = c.ms != null ? c.ms : (c.millis != null ? c.millis : 0);
      const rows = c.rows != null ? c.rows : 0;
      return `<div class="trace-item">tool: <b>${esc(c.name)}</b>(${esc(a)}) &rarr; ${rows} row(s) in ${ms}ms [${esc(c.outcome || 'ok')}]</div>`;
    }).join('') + '</div>';
  }
  $('log').insertAdjacentHTML('beforeend', `<div class="msg">${b}${esc(r.answer)}${traceHtml}<small>mode: ${esc(r.mode)}</small></div>`);
  $('log').scrollTop = $('log').scrollHeight;
  if (r.highlightPaths && r.highlightPaths.length) highlight(r.highlightPaths);
}

$('detail').addEventListener('click', guard(async ev => {
  const b = ev.target.closest('button[data-act]');
  if (!b) return;
  const d = b.dataset;
  if (d.act === 'sim') await simulate(d.s, d.t, d.d);
  if (d.act === 'show') highlight([paths[+d.i].nodeIds]);
  if (d.act === 'accept') await accept(d.key);
}));

$('btnSample').onclick = guard(async () => { await post('/api/ingest/sample'); await loadGraph(); await showPaths(); });
$('btnGithub').onclick = guard(async () => {
  const modalRes = await showModal({
    title: 'Scan GitHub Repository',
    desc: 'Ingest public GitHub Actions workflows into FalkorDB and correlate with cloud IAM attack paths.',
    iconSvg: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>`,
    fields: [
      { name: 'repoSlug', label: 'Repository (owner/repo or GitHub URL)', placeholder: 'e.g. actions/starter-workflows or octocat/Hello-World', defaultValue: '' }
    ],
    confirmText: 'Scan Repository'
  });
  if (!modalRes || !modalRes.repoSlug) return;
  let slug = modalRes.repoSlug.trim().replace(/^https?:\/\/(www\.)?github\.com\//i, '').replace(/\.git$/i, '').replace(/\/$/, '');
  const parts = slug.split('/');
  if (parts.length < 2) {
    await showModal({
      title: 'Invalid Format',
      desc: 'Please enter repository in "owner/repo" format or provide a valid GitHub URL.',
      confirmText: 'Understood',
      cancelText: 'Dismiss'
    });
    return;
  }
  const owner = parts[0];
  const repo = parts[1];
  await post('/api/ingest/github', { owner, repo });
  await loadGraph();
  await showPaths();
});
$('btnPaths').onclick = guard(showPaths);
$('btnChoke').onclick = guard(showChoke);
$('btnDepth').onclick = guard(depthContrast);
$('btnLoad').onclick = guard(showLoadBearing);
$('btnReset').onclick = () => { cy.elements().removeClass('hot blast dim'); $('sim').innerHTML = ''; };
$('btnAsk').onclick = guard(ask);
$('q').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnAsk').click(); });

// Quick prompt pills
document.querySelectorAll('.agent-pills .pill').forEach(pill => {
  pill.addEventListener('click', () => {
    const query = pill.getAttribute('data-q');
    if (query) {
      $('q').value = query;
      ask();
    }
  });
});

initGraph();
guard(loadGraph)();
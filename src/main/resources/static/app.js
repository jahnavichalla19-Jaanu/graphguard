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
let lastGraphData = null;
let lastPaths = [];
let lastFindings = [];

let inFlightGets = new Map();
let activeCalls = 0;
let spinnerEl = null;

function ensureSpinner() {
  if (!spinnerEl && document.body) {
    spinnerEl = document.createElement('div');
    spinnerEl.id = 'gg-loading-indicator';
    spinnerEl.style.cssText = 'position:fixed;top:12px;right:20px;z-index:9999;display:none;align-items:center;gap:8px;padding:6px 14px;background:rgba(15,23,42,0.92);border:1px solid #38bdf8;border-radius:20px;color:#38bdf8;font-family:JetBrains Mono,monospace;font-size:12px;box-shadow:0 0 15px rgba(56,189,248,0.4);pointer-events:none;';
    spinnerEl.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation:gg-spin 0.8s linear infinite;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>Loading\u2026</span>';
    const style = document.createElement('style');
    style.textContent = '@keyframes gg-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
    document.head.appendChild(style);
    document.body.appendChild(spinnerEl);
  }
}

function showLoading() {
  activeCalls++;
  ensureSpinner();
  if (spinnerEl) spinnerEl.style.display = 'inline-flex';
}

function hideLoading() {
  activeCalls = Math.max(0, activeCalls - 1);
  if (activeCalls === 0 && spinnerEl) {
    spinnerEl.style.display = 'none';
  }
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function api(url, opts) {
  const method = (opts && opts.method) ? opts.method.toUpperCase() : 'GET';
  const isGet = method === 'GET';
  if (isGet && inFlightGets.has(url)) {
    return inFlightGets.get(url);
  }

  showLoading();
  const promise = (async () => {
    try {
      const res = await fetch(url, opts);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    } finally {
      if (isGet) inFlightGets.delete(url);
      hideLoading();
    }
  })();

  if (isGet) {
    inFlightGets.set(url, promise);
  }
  return promise;
}

function post(url, body) {
  return api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
}

let isActionBusy = false;
function guard(fn) {
  return async (...args) => {
    if (isActionBusy) return;
    isActionBusy = true;
    try {
      await fn(...args);
    } catch (e) {
      $('detail').innerHTML = '<p class="bad">' + esc(e.message) + '</p>';
    } finally {
      isActionBusy = false;
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
          'font-size': 11, 
          'font-family': 'JetBrains Mono, monospace',
          color: '#e2e8f0', 
          'text-valign': 'bottom', 
          'text-margin-y': 6, 
          width: 36, 
          height: 36, 
          'text-wrap': 'ellipsis', 
          'text-max-width': 150,
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

function updateIamBadge(status) {
  const b = $('iamBadge');
  const s = $('sIam');
  let text = 'IAM: none loaded';
  let cls = 'badge-iam-none';
  let statText = 'none loaded';
  if (status === 'demo') {
    text = 'IAM: demo data';
    cls = 'badge-iam-demo';
    statText = 'demo data';
  } else if (status === 'uploaded') {
    text = 'IAM: uploaded data';
    cls = 'badge-iam-uploaded';
    statText = 'uploaded export';
  }
  if (b) {
    b.textContent = text;
    b.className = 'badge-iam ' + cls;
  }
  if (s) {
    s.textContent = statText;
  }
}

function renderGraphElements() {
  if (!cy || !lastGraphData) return;
  const showAll = $('toggleShowAllNodes') ? $('toggleShowAllNodes').checked : false;

  let nodesToRender = lastGraphData.nodes || [];
  let edgesToRender = lastGraphData.edges || [];

  if (!showAll) {
    const relevantNodeIds = new Set();

    // 1. Nodes on attack paths
    (lastPaths || []).forEach(p => {
      (p.nodeIds || []).forEach(id => relevantNodeIds.add(id));
    });

    // 2. Nodes tied to rule findings
    (lastFindings || []).forEach(f => {
      if (f.targetId) relevantNodeIds.add(f.targetId);
      nodesToRender.forEach(n => {
        if (n.id === f.targetId || (f.targetName && n.name === f.targetName)) {
          relevantNodeIds.add(n.id);
        }
        if (f.file && (n.path === f.file || (n.id && n.id.endsWith(f.file)))) {
          relevantNodeIds.add(n.id);
        }
      });
    });

    if (relevantNodeIds.size > 0) {
      nodesToRender = nodesToRender.filter(n => relevantNodeIds.has(n.id));
      edgesToRender = edgesToRender.filter(e => relevantNodeIds.has(e.source) && relevantNodeIds.has(e.target));
    }
  }

  const els = [];
  nodesToRender.forEach(n => {
    els.push({
      data: {
        id: n.id,
        label: n.name,
        kind: n.label,
        sensitive: n.sensitive === true,
        untrusted: n.untrusted === true
      }
    });
  });

  edgesToRender.forEach(e => {
    els.push({
      data: {
        id: e.source + '|' + e.type + '|' + e.target,
        source: e.source,
        target: e.target,
        label: e.type
      }
    });
  });

  cy.elements().remove();
  cy.add(els);

  // Readable layout with larger spacing
  cy.layout({
    name: 'breadthfirst',
    directed: true,
    spacingFactor: 1.85,
    padding: 40,
    nodeDimensionsIncludeLabels: true,
    avoidOverlap: true
  }).run();
}

async function loadGraph() {
  const [g, p, f] = await Promise.all([
    api('/api/graph'),
    api('/api/paths').catch(() => []),
    api('/api/findings').catch(() => [])
  ]);
  lastGraphData = g || { nodes: [], edges: [] };
  paths = p || [];
  lastPaths = paths;
  lastFindings = f || [];

  updateIamBadge(g.iamStatus || 'none');
  renderGraphElements();

  if ($('sNodes')) $('sNodes').textContent = (g.nodes || []).length;
  if ($('sEdges')) $('sEdges').textContent = (g.edges || []).length;
  if ($('sPaths')) $('sPaths').textContent = paths.length;
  if ($('sAcc')) $('sAcc').textContent = paths.filter(x => x.accepted).length;
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

async function showPaths(fromCache = false) {
  if (!fromCache || !paths || !paths.length) {
    paths = await api('/api/paths').catch(() => []);
    lastPaths = paths;
  }
  highlight(paths.filter(p => !p.accepted).map(p => p.nodeIds));
  $('sim').innerHTML = '';

  if ($('sPaths')) {
    $('sPaths').textContent = paths.length;
    $('sAcc').textContent = paths.filter(p => p.accepted).length;
  }

  if (paths.length === 0) {
    const allNodes = (lastGraphData && lastGraphData.nodes) || [];
    const wfNodes = allNodes.filter(n => (n.label || n.kind) === 'Workflow');
    const numWorkflows = wfNodes.length;

    const untrustedTrgIds = new Set(allNodes.filter(n => (n.label || n.kind) === 'Trigger' && n.untrusted).map(n => n.id));
    const allEdges = (lastGraphData && lastGraphData.edges) || [];
    const untrustedEdges = allEdges.filter(e => untrustedTrgIds.has(e.source) && (e.type === 'FIRES' || !e.type));
    const wfWithUntrustedTrg = new Set(untrustedEdges.map(e => e.target)).size;

    let findingsList = lastFindings || [];
    if (!findingsList.length) {
      findingsList = await api('/api/findings').catch(() => []);
      lastFindings = findingsList;
    }

    const findingCards = findingsList.length > 0 ? findingsList.map(f => `
      <div class="rule-card">
        <div class="rule-card-header">
          <span class="rule-card-title">${esc(f.title)}</span>
          <span class="pill-badge ${f.severity === 'high' ? 'pill-red' : f.severity === 'medium' ? 'pill-purple' : 'pill-blue'}">${esc(f.ruleId)} &bull; ${esc(f.severity)}</span>
        </div>
        <div class="rule-card-meta">${esc(f.file || '')}${f.line ? ':' + f.line : ''} &bull; target: <code>${esc(f.targetName || f.targetId || '')}</code></div>
        <div class="rule-card-desc">${esc(f.description)}</div>
        <div class="rule-card-remed"><strong>Remediation:</strong> ${esc(f.remediation)}</div>
      </div>
    `).join('') : '<p class="good" style="margin-top:10px;">No static rule findings detected.</p>';

    $('detail').innerHTML = `
      <div class="zero-paths-banner">
        <h3>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
          No exploitable attack paths found
        </h3>
        <p>${numWorkflows} workflow${numWorkflows === 1 ? '' : 's'} scanned, ${wfWithUntrustedTrg} use untrusted triggers, and they don&#39;t run untrusted code.</p>
      </div>
      <div class="findings-section">
        <div class="findings-header">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          Static Rule Findings (${findingsList.length})
        </div>
        ${findingCards}
      </div>
    `;
    return;
  }

  $('detail').innerHTML = `<h2>${paths.length} attack path(s) from an untrusted trigger to a sensitive target</h2>` +
    paths.map(pathCard).join('');
}

async function showChoke() {
  const c = await api('/api/choke-points');
  const rows = (c.edges || []).map(e => `<tr><td>${esc(e.description)}</td><td class="bad">removes ${esc(e.paths)} of ${esc(c.activePaths)}</td>
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
  const groups = Object.entries(r.byLabel || {}).map(([k, v]) => `${esc(v)} ${esc(k)}`).join(', ') || 'nothing';
  const sens = (r.sensitiveReached && r.sensitiveReached.length) ? `<p class="bad">Sensitive targets reached: ${r.sensitiveReached.map(esc).join(', ')}</p>` : '<p class="good">No sensitive target reachable.</p>';
  const nodeRows = (r.nodes || []).map(n => {
    const via = Array.isArray(n.via) ? n.via : [];
    const viaHtml = via.length > 1 ? `<div class="via-path">${via.map(esc).map(v => `<span>${v}</span>`).join('')}</div>` : '';
    const hops = n.hops != null ? n.hops : '?';
    return `<li class="${n.sensitive ? 'sensitive' : ''}">${esc(n.name)} <em>(${esc(n.label)}, ${esc(hops)} hop${hops === 1 ? '' : 's'})</em>${viaHtml}</li>`;
  }).join('');
  $('detail').innerHTML = `<h2>${badge(r.outcome)} Blast radius of ${esc((cy.getElementById(id) && cy.getElementById(id).data('label')) || id)} (depth ${esc(depth)})</h2><p>If compromised it can reach ${esc(r.reachableCount)} node(s): ${groups}.</p>${sens}<ul class="node-list">${nodeRows}</ul>`;
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
    return `<li class="${markNew ? 'new' : ''} ${n.sensitive ? 'sensitive' : ''}">${esc(n.name)} <em>(${esc(n.label)}, ${esc(hops)} hop${hops === 1 ? '' : 's'})</em>${viaHtml}</li>`;
  }).join('');
  cy.elements().removeClass('hot blast dim');
  if (newAt4.length) {
    cy.elements().addClass('dim');
    newAt4.forEach(n => cy.getElementById(n.id).removeClass('dim').addClass('blast'));
  }
  $('depth-panel').innerHTML = `
    <h2>Depth contrast: "${esc(id)}"</h2>
    <p>At depth&nbsp;1: <b>${esc(r1.reachableCount)}</b> node(s) reachable &nbsp;|&nbsp; At depth&nbsp;4: <b>${esc(r4.reachableCount)}</b> node(s) reachable &nbsp;|&nbsp; <b class="${newAt4.length ? 'bad' : 'good'}">${esc(newAt4.length)} discovered only through graph traversal</b></p>
    <div class="depth-row">
      <div class="depth-col"><h3>Depth 1 &mdash; <b>${esc(r1.reachableCount)}</b> nodes</h3><ul class="node-list">${makeList(r1.nodes || [], false)}</ul></div>
      <div class="depth-col"><h3>Depth 4 &mdash; <b>${esc(r4.reachableCount)}</b> nodes &nbsp;<span style="color:var(--ok)">(+${esc(newAt4.length)} new)</span></h3><ul class="node-list">${makeList(r4.nodes || [], false)}${makeList(newAt4, true)}</ul></div>
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
  await loadGraph();
  await showPaths(true);
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

$('btnSample').onclick = guard(async () => {
  const s = await post('/api/ingest/sample');
  if (s && s.iamStatus) updateIamBadge(s.iamStatus);
  await loadGraph();
  await showPaths(true);
});
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
  const s = await post('/api/ingest/github', { owner, repo });
  if (s && s.iamStatus) updateIamBadge(s.iamStatus);
  await loadGraph();
  await showPaths(true);
});
$('btnPaths').onclick = guard(showPaths);
$('btnChoke').onclick = guard(showChoke);
$('btnDepth').onclick = guard(depthContrast);
$('btnLoad').onclick = guard(showLoadBearing);
$('btnReset').onclick = () => {
  cy.elements().removeClass('hot blast dim');
  $('sim').innerHTML = '';
  renderGraphElements();
};
$('btnAsk').onclick = guard(ask);
$('q').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnAsk').click(); });

const toggleEl = $('toggleShowAllNodes');
if (toggleEl) {
  toggleEl.addEventListener('change', () => {
    renderGraphElements();
    if (paths && paths.length) {
      highlight(paths.filter(p => !p.accepted).map(p => p.nodeIds));
    }
  });
}

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
const COLORS = { Trigger: '#e5484d', Workflow: '#3e63dd', Job: '#8e4ec6', Action: '#f5a524', Secret: '#d6409f', Role: '#30a46c', Resource: '#0090ff', Repo: '#889096' };
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
      { selector: 'node', style: { 'background-color': e => COLORS[e.data('kind')] || '#888', label: 'data(label)', 'font-size': 10, color: cssVar('--text'), 'text-valign': 'bottom', 'text-margin-y': 4, width: 28, height: 28, 'text-wrap': 'ellipsis', 'text-max-width': 120 } },
      { selector: 'node[?sensitive]', style: { shape: 'diamond', 'border-width': 3, 'border-color': '#e5484d', width: 34, height: 34 } },
      { selector: 'edge', style: { width: 1.5, 'line-color': cssVar('--edge'), 'target-arrow-color': cssVar('--edge'), 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', label: 'data(label)', 'font-size': 7, color: cssVar('--muted'), 'text-rotation': 'autorotate' } },
      { selector: '.dim', style: { opacity: 0.15 } },
      { selector: 'node.hot', style: { 'border-width': 4, 'border-color': '#e5484d' } },
      { selector: 'edge.hot', style: { 'line-color': '#e5484d', 'target-arrow-color': '#e5484d', width: 4 } },
      { selector: 'node.blast', style: { 'border-width': 4, 'border-color': '#f76b15' } }
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
  cy.layout({ name: 'breadthfirst', directed: true, spacingFactor: 1.15, padding: 20 }).run();
  $('stats').innerHTML = `<span><b>${g.nodes.length}</b> nodes</span><span><b>${g.edges.length}</b> edges</span><span><b id="sPaths">-</b> attack paths</span><span><b id="sAcc">-</b> accepted</span>`;
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

async function blast(id) {
  const r = await api('/api/blast-radius?node=' + encodeURIComponent(id));
  cy.elements().removeClass('hot blast dim');
  r.nodes.forEach(n => cy.getElementById(n.id).addClass('blast'));
  cy.getElementById(id).addClass('blast');
  const groups = Object.entries(r.byLabel).map(([k, v]) => `${v} ${esc(k)}`).join(', ') || 'nothing';
  const sens = r.sensitiveReached.length ? `<p class="bad">Sensitive targets reached: ${r.sensitiveReached.map(esc).join(', ')}</p>` : '<p class="good">No sensitive target reachable.</p>';
  $('detail').innerHTML = `<h2>Blast radius of ${esc(cy.getElementById(id).data('label') || id)}</h2><p>If compromised it can reach ${r.reachableCount} node(s): ${groups}.</p>${sens}`;
}

async function simulate(s, t, d) {
  const r = await post('/api/simulate-fix', { source: s, type: t, target: d });
  document.querySelectorAll('.card[data-key]').forEach(c => c.classList.toggle('removed', r.removedKeys.includes(c.dataset.key)));
  $('sim').innerHTML = `<h2>Simulated fix: ${esc(r.edge.type)}</h2>
    <p>Attack paths <b class="bad">${r.before}</b> &rarr; <b class="good">${r.after}</b> · newly created paths: <b>${r.newKeys.length}</b> · checked on a temporary graph in ${r.millis} ms · main graph untouched.</p>
    ${r.edgeExisted ? '' : '<p class="bad">That link was not found in the graph.</p>'}<p><b>Plan (not applied):</b> ${esc(r.proposal)}</p>`;
}

async function accept(key) {
  const owner = prompt('Risk owner:');
  if (!owner) return;
  const reason = prompt('Reason:') || '';
  const days = parseInt(prompt('Accepted for how many days?', '30'), 10) || 30;
  await post('/api/decisions', { pathKey: key, owner, reason, days });
  await showPaths();
}

async function ask() {
  const q = $('q').value.trim();
  if (!q) return;
  $('q').value = '';
  $('log').insertAdjacentHTML('beforeend', `<div class="msg user">${esc(q)}</div>`);
  const r = await post('/api/agent/ask', { question: q });
  const tools = r.toolCalls.map(c => c.name).join(', ') || 'none';
  $('log').insertAdjacentHTML('beforeend', `<div class="msg">${esc(r.answer)}<small>tools: ${esc(tools)} · ${esc(r.mode)}</small></div>`);
  $('log').scrollTop = $('log').scrollHeight;
  if (r.highlightPaths.length) highlight(r.highlightPaths);
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
  let slug = prompt('Public GitHub repo to scan (owner/repo or full GitHub URL):');
  if (!slug) return;
  slug = slug.trim().replace(/^https?:\/\/(www\.)?github\.com\//i, '').replace(/\.git$/i, '').replace(/\/$/, '');
  const parts = slug.split('/');
  if (parts.length < 2) {
    alert('Please enter in format "owner/repo" or paste a GitHub repository URL.');
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
$('btnReset').onclick = () => { cy.elements().removeClass('hot blast dim'); $('sim').innerHTML = ''; };
$('btnAsk').onclick = guard(ask);
$('q').addEventListener('keydown', e => { if (e.key === 'Enter') $('btnAsk').click(); });

initGraph();
guard(loadGraph)();
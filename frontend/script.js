/* ===================== STATE & HELPERS ===================== */

const S = {
  page: 'dashboard',
  incidents: [],
  selected: null,
  summary: {},
  hosts: [],
  iocs: [],
  policies: [],
  agents: [],
  approvals: [],
  ares: null
};

const $ = x => document.getElementById(x);

const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
}[m]));

async function api(u, o = {}) {
  let r = await fetch(u, o);
  if (!r.ok) throw Error(await r.text());
  return r.json();
}

function toast(t) {
  $('toast').textContent = t;
  $('toast').classList.remove('hidden');
  setTimeout(() => $('toast').classList.add('hidden'), 2400);
}

function page(p, el) {
  S.page = p;
  document.querySelectorAll('.nav button').forEach(x => x.classList.remove('active'));
  if (el) el.classList.add('active');
  render();
}

async function load() {
  try {
    [
      S.summary,
      S.incidents,
      S.hosts,
      S.iocs,
      S.policies,
      S.agents,
      S.approvals
    ] = await Promise.all([
      api('/api/summary'),
      api('/api/incidents'),
      api('/api/hosts'),
      api('/api/iocs'),
      api('/api/policies'),
      api('/api/agents'),
      api('/api/approvals')
    ]);

    if (S.selected?.id) {
      S.selected = S.incidents.find(x => x.id === S.selected.id) || S.selected;
    }
    render();
  } catch (e) {
    toast('Backend connection error');
  }
}

/* ===================== COMMON UI COMPONENTS ===================== */

function head(t, s) {
  return `<div class="page-head"><div><div class="crumb">AEGIS / JIIT CYBER RANGE</div><h1>${t}</h1><p>${s}</p></div><button class="btn" onclick="load()">↻ Refresh</button></div>`;
}

function kpis() {
  let s = S.summary;
  return `<div class="kpis">
    <div class="kpi"><div class="klabel">TOTAL INCIDENTS</div><div class="num">${s.incidents}</div><div class="trend">↑ Live</div></div>
    <div class="kpi"><div class="klabel">ACTIVE HOSTS</div><div class="num">${s.hosts}</div><div class="trend">↑ Fleet connected</div></div>
    <div class="kpi"><div class="klabel">AI AGENTS</div><div class="num">7</div><div class="trend">● All online</div></div>
    <div class="kpi"><div class="klabel">ACTIONS EXECUTED</div><div class="num">${s.actions}</div><div class="trend">↑ Bounded responses</div></div>
  </div>`;
}

function scenarios() {
  const list = [
    ['multi_stage', 'Run Multi-Stage Attack', 'Full attack simulation'],
    ['credential_abuse', 'Credential Abuse', 'Auth anomaly'],
    ['data_tampering', 'Data Tampering', 'File integrity'],
    ['network_anomaly', 'Network Anomaly', 'Suspicious traffic'],
    ['ambiguous', 'Ambiguous Event', 'Low confidence']
  ];

  return `<div class="scenario-bar">
    ${list.map((x, i) => `<button class="scenario ${i === 0 ? 'primary' : ''}" onclick="runScenario('${x[0]}')"><strong>${x[1]}</strong><span>${x[2]}</span></button>`).join('')}
    <button class="scenario" onclick="page('simulation')"><strong>ARES Evaluation</strong><span>Run 24 scenarios</span></button>
  </div>`;
}

function compact(i) {
  return `<div class="grid2">
    <div>
      ${(i.agents || []).slice(-8).map(a => `<div class="agentrow"><b>${esc(a.agent)}</b><span class="${a.status === 'DONE' ? 'done' : a.status === 'RUNNING' ? 'run' : 'wait'}">${a.status}</span><span>${esc(a.message)}</span></div>`).join('')}
    </div>
    <div>
      <span class="tiny muted">INCIDENT ID</span>
      <h2>${esc(i.id)}</h2>
      <p><b>Confidence:</b> ${Math.round(i.confidence * 100)}%</p>
      <p><b>Action:</b> ${esc(i.decision?.requested_action || '—')}</p>
      <p><b>Policy:</b> ${i.policy?.allowed ? '<span class="ok">AUTHORIZED</span>' : '<span class="warn">ESCALATED</span>'}</p>
      <button class="btn primary" onclick="openIncident('${i.id}')">Open Investigation →</button>
    </div>
  </div>`;
}

function confidence(i) {
  let p = Math.round(i.confidence * 100);
  return `<div class="grid2">
    <div class="bigconf">${p}%</div>
    <div><b>${i.severity} RISK</b><p class="muted">${esc(i.summary)}</p></div>
  </div>
  <div class="bar"><i style="width:${p}%;background:${p >= 85 ? '#e44b5d' : p >= 65 ? '#e89017' : '#1666d9'}"></i></div>
  <p class="tiny muted">Sources: ${i.confidence_trace?.independent_sources || 0} • Evidence: ${i.evidence?.length || 0} • Strength: ${i.confidence_trace?.evidence_strength || '—'}</p>`;
}

function table(a) {
  if (!a.length) return '<div class="empty">No incidents.</div>';

  return `<table class="table">
    <thead>
      <tr><th>ID</th><th>TYPE</th><th>HOST</th><th>SEVERITY</th><th>STATUS</th><th>CONF</th></tr>
    </thead>
    <tbody>
      ${a.map(i => `<tr onclick="openIncident('${i.id}')" style="cursor:pointer"><td><b>${i.id}</b></td><td>${esc(i.scenario)}</td><td>${i.host}</td><td><span class="badge ${i.severity.toLowerCase()}">${i.severity}</span></td><td>${i.status}</td><td>${Math.round(i.confidence * 100)}%</td></tr>`).join('')}
    </tbody>
  </table>`;
}

/* ===================== PAGES ===================== */

function dashboard() {
  let i = S.incidents[0];

  return head('Operations Dashboard', 'Autonomous security operations • source-grounded investigation • bounded response')
    + kpis()
    + scenarios()
    + `<div class="layout">
      <div>
        <div class="panel">
          <div class="panel-head"><h2>LIVE INVESTIGATION</h2><span class="badge ${i?.severity?.toLowerCase() || 'low'}">${i ? i.status : 'STANDBY'}</span></div>
          ${i ? compact(i) : '<div class="empty">Run a cyber-range scenario to activate the agent loop.</div>'}
        </div>
        <div class="panel">
          <div class="panel-head"><h2>RECENT INCIDENTS</h2><button class="btn" onclick="page('incidents')">View all →</button></div>
          ${table(S.incidents.slice(0, 8))}
        </div>
      </div>
      <div>
        <div class="panel">
          <h2>SYSTEM STATUS</h2>
          <div class="risk ok">OPERATIONAL</div>
          <p class="muted">PostgreSQL • Redis • WebSocket • Cyber Range</p>
          <div class="grid2">
            <div><span class="tiny muted">UPTIME</span><br><b>${S.summary.uptime}</b></div>
            <div><span class="tiny muted">EVENTS/SEC</span><br><b>${S.summary.events_per_sec}</b></div>
          </div>
        </div>
        <div class="panel">
          <h2>THREAT CONFIDENCE</h2>
          ${i ? confidence(i) : '<div class="empty">No incident</div>'}
        </div>
        <div class="panel">
          <h2>SAFETY ARCHITECTURE</h2>
          <p>LLM → Tool Registry → Evidence → Decision → <b>Policy Gate</b> → Response / Human Approval → Verification → Audit</p>
        </div>
      </div>
    </div>`;
}

function investigation() {
  let i = S.selected || S.incidents[0];

  return head('Live Investigation', 'Real-time planning, tool execution, evidence reasoning and bounded response')
    + scenarios()
    + `<div class="layout">
      <div class="panel">
        <div class="panel-head"><h2>AGENT EXECUTION STREAM</h2><span class="online">● LIVE</span></div>
        ${i ? stream(i) : '<div class="empty">Run an incident.</div>'}
      </div>
      <div>
        <div class="panel"><h2>DECISION TRACE</h2>${i ? decision(i) : '<div class="empty">Waiting.</div>'}</div>
        <div class="panel"><h2>CONFIDENCE EXPLANATION</h2>${i ? trace(i) : ''}</div>
      </div>
    </div>`;
}

function stream(i) {
  return (i.agents || []).map(a => `<div class="agentrow"><b>${esc(a.agent)}</b><span class="${a.status === 'DONE' ? 'done' : a.status === 'RUNNING' ? 'run' : 'wait'}">${a.status}</span><span>${esc(a.message)}</span></div>`).join('')

    + `<hr style="border:0;border-top:1px solid var(--line);margin:13px 0"><h2>INVESTIGATION PLAN</h2>`
    + (i.plan || []).map(x => `<div class="agentrow"><b>STEP ${x.step}</b><span>${esc(x.tool)}</span><span>${esc(x.purpose)}</span></div>`).join('')

    + `<h2>TOOL CALLS</h2>`
    + (i.tool_calls || []).map(x => `<div class="agentrow"><b>${esc(x.tool)}</b><span>${esc(x.risk)}</span><span>${esc(JSON.stringify(x.result))}</span></div>`).join('')

    + `<h2>ATTACK TIMELINE</h2>
       <div class="timeline">
         ${(i.timeline || []).map(e => `<div class="event"><span>${e.timestamp.split('T')[1]?.slice(0, 8)}</span><b>${esc(e.kind)}</b><span>${esc(JSON.stringify(e.detail))}</span><span class="badge ${e.severity.toLowerCase()}">${e.severity}</span></div>`).join('')}
       </div>`;
}

function decision(i) {
  let pending = i.approval?.status === 'PENDING';

  return `<div class="bigconf">${Math.round(i.confidence * 100)}%</div>
    <p><b>Recommendation:</b> ${i.decision?.requested_action}</p>
    <p><b>Policy:</b> ${i.policy?.allowed ? '<span class="ok">AUTHORIZED</span>' : '<span class="warn">HUMAN APPROVAL REQUIRED</span>'}</p>
    <p>${esc(i.policy?.reason || '')}</p>
    <p><b>Response:</b> ${esc(i.response?.message || '—')}</p>
    ${pending ? `<button class="btn primary" onclick="page('approvals')">Open Approval Queue →</button>` : ''}
    ${i.status === 'CLOSED' && i.response?.action === 'ISOLATE_HOST' ? `<button class="btn gold" onclick="rollback('${i.id}')">↩ Roll Back Containment</button>` : ''}
    <br><br>
    <button class="btn" onclick="openReport('${i.id}')">Generate Report</button>`;
}

function trace(i) {
  let t = i.confidence_trace || {};

  return `<div>
    ${(t.base_signals || []).map(x => `<div class="agentrow"><b>${esc(x.signal)}</b><span class="done">+${Math.round(x.impact * 100)}%</span><span>${esc(x.reason)}</span></div>`).join('')}
    <div class="agentrow"><b>Cross-source</b><span>${t.cross_source_correlation?.impact >= 0 ? '+' : ''}${Math.round((t.cross_source_correlation?.impact || 0) * 100)}%</span><span>${t.independent_sources || 0} independent sources</span></div>
    <div class="agentrow"><b>Missing telemetry</b><span>${Math.round((t.missing_telemetry_penalty || 0) * 100)}%</span><span>Uncertainty penalty</span></div>
    <hr>
    <b>Final: ${Math.round(i.confidence * 100)}%</b>
  </div>`;
}

function incidents() {
  return head('Incident Command', 'Investigate, contain, escalate and audit security events')
    + `<div class="panel">${table(S.incidents)}</div>`;
}

function hosts() {
  return head('Host Inventory', 'Synthetic endpoint fleet and reversible response controls')
    + `<div class="panel">
      <table class="table">
        <thead>
          <tr><th>HOST</th><th>IP</th><th>OS</th><th>OWNER</th><th>RISK</th><th>STATUS</th><th>ACTION</th></tr>
        </thead>
        <tbody>
          ${S.hosts.map(h => `<tr>
            <td><b>${h.name}</b><br><span class="muted">${h.id}</span></td>
            <td>${h.ip}</td>
            <td>${h.os}</td>
            <td>${h.owner}</td>
            <td>${Math.round(h.risk * 100)}%</td>
            <td>${h.status}</td>
            <td>${h.status === 'ISOLATED'
              ? `<button class="btn" onclick="host('${h.id}','restore')">Restore</button>`
              : `<button class="btn danger" onclick="host('${h.id}','isolate')">Isolate</button>`}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

function intel() {
  return head('Threat Intelligence', 'Synthetic IOC feed used by bounded investigation tools')
    + `<div class="grid3">
      ${S.iocs.map(x => `<div class="panel">
        <span class="badge ${x.severity.toLowerCase()}">${x.severity}</span>
        <h2 style="margin-top:10px">${x.value}</h2>
        <p class="muted">${x.type} • ${x.source}</p>
        <b>${Math.round(x.confidence * 100)}% confidence</b>
      </div>`).join('')}
    </div>`;
}

function simulation() {
  const scenarioList = {
    multi_stage: ['Multi-Stage Intrusion', 'high'],
    credential_abuse: ['Credential Abuse', 'high'],
    data_tampering: ['Data Tampering', 'critical'],
    network_anomaly: ['Network Anomaly', 'high'],
    ambiguous: ['Ambiguous Activity', 'medium']
  };

  return head('Attack Simulation & ARES', 'Controlled cyber-range plus autonomous regression evaluation')
    + `<div class="grid3">
      ${Object.entries(scenarioList).map(([k, v]) => `<div class="panel">
        <span class="badge ${v[1]}">${v[1].toUpperCase()}</span>
        <h2>${v[0]}</h2>
        <button class="btn primary" onclick="runScenario('${k}')">Run Scenario</button>
      </div>`).join('')}
      <div class="panel">
        <h2>ARES</h2>
        <p class="muted">24 automated synthetic security evaluations.</p>
        <button class="btn gold" onclick="runARES()">Run ARES Evaluation</button>
      </div>
    </div>`
    + (S.ares ? `<div class="panel">
      <h2>ARES RESULT</h2>
      <div class="grid3">
        <div><div class="bigconf">${Math.round(S.ares.detection_rate * 100)}%</div><span class="muted">Detection</span></div>
        <div><div class="bigconf">${Math.round(S.ares.investigation_rate * 100)}%</div><span class="muted">Investigation</span></div>
        <div><div class="bigconf">${Math.round(S.ares.safe_decision_rate * 100)}%</div><span class="muted">Safe Decisions</span></div>
      </div>
      <p>False containment: <b>${Math.round(S.ares.false_containment_rate * 100)}%</b> • Rollback: <b class="ok">${S.ares.rollback_test}</b> • Human escalation: <b class="ok">${S.ares.human_escalation_test}</b></p>
    </div>` : '')
    + `<div class="panel">
      <h2>SAFETY BOUNDARY</h2>
      <p>All scenarios are synthetic. AEGIS response tools modify only simulated host state.</p>
    </div>`;
}

function agents() {
  return head('Agent Control Center', 'Seven agents with explicit roles, bounded tools and measurable performance')
    + `<div class="grid3">
      ${S.agents.map(a => `<div class="panel">
        <div class="panel-head"><b>${a.name}</b><span class="badge low">ONLINE</span></div>
        <p class="muted">${a.role}</p>
        <div class="bigconf">${a.accuracy}%</div>
        <span class="tiny muted">${a.latency}</span>
        <div class="bar"><i style="width:${a.accuracy}%"></i></div>
      </div>`).join('')}
    </div>
    <div class="panel">
      <h2>TOOL REGISTRY</h2>
      <p class="muted">The LLM can only request registered tools. Write-capable tools are bounded and reversible.</p>
      <div id="tools">Loading...</div>
    </div>`;
}

function evidence() {
  let i = S.selected || S.incidents[0];

  return head('Evidence Graph', 'Source-grounded relationships and confidence contributions')
    + `<div class="panel">
      ${i
        ? `<div class="graph"><div class="nodes">${[...new Map(i.events.map(e => [e.source, e])).values()].map((e, n, a) => `<div class="node"><b>${e.source}</b><br>${e.kind}</div>${n < a.length - 1 ? '<div class="arrow">→</div>' : ''}`).join('')}</div></div>`
        : '<div class="empty">Run an incident first.</div>'}
      ${i
        ? (i.evidence || []).map(e => `<div class="agentrow"><b>${e.title}</b><span class="${e.contribution > 0 ? 'done' : 'warn'}">${Math.round(e.contribution * 100)}%</span><span>${esc(e.detail)}</span></div>`).join('')
        : ''}
    </div>`;
}

function approvals() {
  const pending = S.approvals.filter(x => x.status === 'PENDING');

  return head('Human Approval Queue', 'Actions blocked by policy until an operator explicitly approves them')
    + `<div class="panel">
      ${pending.length
        ? pending.map(a => `<div class="panel" style="border-color:#f0d28b">
            <div class="panel-head"><h2>${a.action} → ${a.target}</h2><span class="badge high">PENDING</span></div>
            <p>Confidence: <b>${Math.round(a.confidence * 100)}%</b></p>
            <p class="muted">${esc(a.reason)}</p>
            <button class="btn primary" onclick="approval('${a.approval_id}','approve')">Approve</button>
            <button class="btn danger" onclick="approval('${a.approval_id}','reject')">Reject</button>
          </div>`).join('')
        : '<div class="empty">No pending approvals.</div>'}
    </div>`;
}

function reports() {
  return head('Reports', 'Generated, source-grounded incident reports')
    + `<div class="panel">${table(S.incidents)}</div>`;
}

function policies() {
  return head('Policy Center', 'Deterministic authorization rules separate model reasoning from execution')
    + `<div class="panel">
      <table class="table">
        <thead>
          <tr><th>POLICY</th><th>ACTION</th><th>THRESHOLD</th><th>APPROVAL</th><th>STATUS</th><th></th></tr>
        </thead>
        <tbody>
          ${S.policies.map(p => `<tr>
            <td><b>${p.name}</b><br><span class="muted">${p.description}</span></td>
            <td>${p.action}</td>
            <td>${Math.round(p.threshold * 100)}%</td>
            <td>${p.approval}</td>
            <td>${p.enabled ? '<span class="ok">ENABLED</span>' : '<span class="warn">DISABLED</span>'}</td>
            <td><button class="btn" onclick="togglePolicy('${p.id}')">${p.enabled ? 'Disable' : 'Enable'}</button></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

async function settings() {
  let s = await api('/api/settings');
  let h = await api('/api/health');

  return head('Settings', 'Environment, model adapter and infrastructure status')
    + `<div class="grid2">
      <div class="panel">
        <h2>ENVIRONMENT</h2>
        <p>Database: <b>${h.database}</b></p>
        <p>Redis: <b>${h.redis ? 'CONNECTED' : 'FALLBACK'}</b></p>
        <p>LLM Adapter: <b>${h.llm ? 'ENABLED' : 'DETERMINISTIC FALLBACK'}</b></p>
        <p>Version: <b>${h.version}</b></p>
      </div>
      <div class="panel">
        <h2>ORGANIZATION</h2>
        <input id="org" value="${esc(s.org_name)}" style="width:100%;padding:10px;border:1px solid var(--line);border-radius:6px">
        <br><br>
        <button class="btn primary" onclick="saveSettings()">Save</button>
      </div>
    </div>`;
}

/* ===================== RENDER ===================== */

function render() {
  let fn = {
    dashboard,
    investigation,
    incidents,
    hosts,
    intel,
    simulation,
    agents,
    evidence,
    approvals,
    reports,
    policies,
    settings
  }[S.page];

  $('app').innerHTML = fn ? fn() : dashboard();

  if (S.page === 'agents') loadTools();
}

async function loadTools() {
  let t = await api('/api/tools');
  $('tools').innerHTML = t.map(x => `<div class="agentrow"><b>${x.name}</b><span>${x.risk}</span><span>${esc(x.description)}</span></div>`).join('');
}

/* ===================== ACTIONS ===================== */

async function runScenario(s) {
  try {
    let d = await api('/api/scenarios/' + s + '/run', { method: 'POST' });
    toast('Investigation started ' + d.incident_id);
    await load();
    S.selected = S.incidents.find(i => i.id === d.incident_id);
    page('investigation');
  } catch (e) {
    toast('Scenario failed');
  }
}

async function openIncident(id) {
  S.selected = S.incidents.find(i => i.id === id) || await api('/api/incidents/' + id);
  page('investigation');
}

async function host(id, a) {
  await api('/api/hosts/' + id + '/' + a, { method: 'POST' });
  toast(a === 'isolate' ? 'Host isolated' : 'Host restored');
  await load();
  page('hosts');
}

async function togglePolicy(id) {
  await api('/api/policies/' + id + '/toggle', { method: 'POST' });
  await load();
  page('policies');
}

async function approval(id, a) {
  await api('/api/approvals/' + id + '/' + a, { method: 'POST' });
  toast('Approval ' + a + 'd');
  await load();
  page('approvals');
}

async function rollback(id) {
  await api('/api/incidents/' + id + '/rollback', { method: 'POST' });
  toast('Containment rolled back');
  await load();
  openIncident(id);
}

async function runARES() {
  toast('ARES running 24 scenarios...');
  S.ares = await api('/api/ares/run', { method: 'POST' });
  render();
  toast('ARES evaluation complete');
}

/* ===================== REPORTS & MODAL ===================== */

async function openReport(id) {
  let r = await api('/api/reports/' + id);

  show(`<div class="modal-head"><h2>${id} — Incident Report</h2><button class="close" onclick="close()">×</button></div>
    <pre>${esc(r.content)}</pre>
    <button class="btn primary" onclick="download(${JSON.stringify(r.filename)},${JSON.stringify(r.content)})">Download</button>`);
}

function download(n, t) {
  let a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([t], { type: 'text/plain' }));
  a.download = n;
  a.click();
}

function show(x) {
  $('modalBody').innerHTML = x;
  $('modal').classList.remove('hidden');
}

function close() {
  $('modal').classList.add('hidden');
}

/* ===================== SEARCH & SETTINGS ===================== */

let timer;

async function search(q) {
  clearTimeout(timer);
  if (!q.trim()) return;

  timer = setTimeout(async () => {
    let r = await api('/api/search?q=' + encodeURIComponent(q));

    show(`<div class="modal-head"><h2>Search</h2><button class="close" onclick="close()">×</button></div>`
      + (r.length
        ? r.map(x => `<div class="agentrow"><b>${x.type}</b><span>${x.id}</span><span>${esc(x.title)}</span></div>`).join('')
        : '<div class="empty">No results.</div>'));
  }, 300);
}

async function saveSettings() {
  await api('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ org_name: $('org').value })
  });
  toast('Settings saved');
}

/* ===================== WEBSOCKET & INIT ===================== */

function connect() {
  let ws = new WebSocket(`ws://${location.host}/ws`);

  ws.onmessage = async e => {
    let d = JSON.parse(e.data);
    if (['agent', 'incident', 'audit', 'host', 'rollback', 'tool'].includes(d.type)) {
      await load();
    }
  };

  ws.onclose = () => setTimeout(connect, 1500);
}

connect();
load();

setInterval(() => {
  if (S.page === 'dashboard' || S.page === 'investigation' || S.page === 'approvals') {
    load();
  }
}, 3000);
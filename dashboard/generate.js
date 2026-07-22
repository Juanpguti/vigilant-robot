#!/usr/bin/env node
/**
 * Genera el dashboard de seguridad estático (site/) a partir de los
 * reportes JSON del pipeline: Semgrep, Trivy (fs + imagen), OWASP ZAP
 * y Gitleaks. Cada herramienta es expandible y muestra el detalle de
 * cada hallazgo con su remediación y enlace de referencia.
 *
 * Uso: node dashboard/generate.js
 * Entradas:  artifacts/** (reportes), history.json (histórico previo)
 * Salidas:   site/index.html, site/history.json, site/zap.html (si existe)
 */
const fs = require('fs');
const path = require('path');

const ART_DIR = process.env.ARTIFACTS_DIR || 'artifacts';
const OUT_DIR = 'site';
const MAX_FINDINGS = 25; // por herramienta

// ── Utilidades ────────────────────────────────────────────────────────────
function findFile(dir, name) {
  if (!fs.existsSync(dir)) return null;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = findFile(full, name);
      if (found) return found;
    } else if (entry.name === name) {
      return full;
    }
  }
  return null;
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function stripHtml(s) {
  return String(s || '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const zero = () => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

function addCounts(total, c) {
  for (const k of Object.keys(total)) total[k] += c[k] || 0;
}

// ── Parsers por herramienta ───────────────────────────────────────────────
// Cada parser devuelve { counts, found, findings: [{ sev, title, detail, fix, url }] }

function parseSemgrep(file) {
  const data = file && readJson(file);
  const c = zero();
  const findings = [];
  if (!data || !Array.isArray(data.results)) return { counts: c, found: !!data, findings };
  for (const r of data.results) {
    const sev = (r.extra && r.extra.severity) || '';
    let bucket = 'info';
    if (sev === 'ERROR') bucket = 'high';
    else if (sev === 'WARNING') bucket = 'medium';
    c[bucket] += 1;
    findings.push({
      sev: bucket,
      title: (r.check_id || '').split('.').pop(),
      detail: `${r.path}:${r.start ? r.start.line : '?'} — ${stripHtml(r.extra && r.extra.message).slice(0, 160)}`,
      fix: 'Corregir el patrón señalado en el código fuente.',
      url: r.extra && r.extra.metadata && (r.extra.metadata.source || (r.extra.metadata.references || [])[0]),
    });
  }
  return { counts: c, found: true, findings };
}

function parseTrivy(file) {
  const data = file && readJson(file);
  const c = zero();
  const findings = [];
  if (!data || !Array.isArray(data.Results)) return { counts: c, found: !!data, findings };
  for (const res of data.Results) {
    for (const v of res.Vulnerabilities || []) {
      const sev = (v.Severity || '').toUpperCase();
      let bucket = 'info';
      if (sev === 'CRITICAL') bucket = 'critical';
      else if (sev === 'HIGH') bucket = 'high';
      else if (sev === 'MEDIUM') bucket = 'medium';
      else if (sev === 'LOW') bucket = 'low';
      c[bucket] += 1;
      findings.push({
        sev: bucket,
        title: `${v.VulnerabilityID} · ${v.PkgName}`,
        detail: `${stripHtml(v.Title).slice(0, 140)} — instalado: ${v.InstalledVersion || '?'}`,
        fix: v.FixedVersion
          ? `Actualizar ${v.PkgName} a ${v.FixedVersion}`
          : 'Sin fix publicado aún: monitorear el aviso y evaluar mitigación.',
        url: v.PrimaryURL,
      });
    }
  }
  return { counts: c, found: true, findings };
}

function parseZap(file) {
  const data = file && readJson(file);
  const c = zero();
  const findings = [];
  if (!data || !Array.isArray(data.site)) return { counts: c, found: !!data, findings };
  for (const site of data.site) {
    for (const a of site.alerts || []) {
      const risk = String(a.riskcode);
      let bucket = 'info';
      if (risk === '3') bucket = 'high';
      else if (risk === '2') bucket = 'medium';
      else if (risk === '1') bucket = 'low';
      c[bucket] += 1;
      const n = (a.instances || []).length;
      findings.push({
        sev: bucket,
        title: stripHtml(a.name || a.alert),
        detail: `${stripHtml(a.desc).slice(0, 160)}${n ? ` (${n} instancia${n > 1 ? 's' : ''})` : ''}`,
        fix: stripHtml(a.solution).slice(0, 220) || 'Ver reporte ZAP completo.',
        url: a.reference ? stripHtml(a.reference).split(' ')[0] : null,
      });
    }
  }
  return { counts: c, found: true, findings };
}

function parseGitleaks(file) {
  const data = file && readJson(file);
  const c = zero();
  const findings = [];
  if (!Array.isArray(data)) return { counts: c, found: data !== null, findings };
  c.critical = data.length;
  for (const g of data) {
    findings.push({
      sev: 'critical',
      title: `Secreto expuesto · ${g.RuleID || 'regla'}`,
      detail: `${g.File || '?'}:${g.StartLine || '?'} — ${stripHtml(g.Description).slice(0, 140)}`,
      fix: 'Rotar el secreto de inmediato y purgarlo del historial (git filter-repo / BFG).',
      url: null,
    });
  }
  return { counts: c, found: true, findings };
}

// ── Recolección ───────────────────────────────────────────────────────────
const tools = [
  { id: 'semgrep', name: 'Semgrep', phase: 'SAST', ...parseSemgrep(findFile(ART_DIR, 'semgrep.json')) },
  { id: 'trivy-fs', name: 'Trivy fs', phase: 'SCA · dependencias', ...parseTrivy(findFile(ART_DIR, 'trivy-fs.json')) },
  { id: 'trivy-image', name: 'Trivy image', phase: 'Container scan', ...parseTrivy(findFile(ART_DIR, 'trivy-image.json')) },
  { id: 'zap', name: 'OWASP ZAP', phase: 'DAST', ...parseZap(findFile(ART_DIR, 'zap.json')) },
  { id: 'gitleaks', name: 'Gitleaks', phase: 'Secrets', ...parseGitleaks(findFile(ART_DIR, 'gitleaks.json')) },
];

const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
for (const t of tools) {
  t.findings.sort((a, b) => sevOrder[a.sev] - sevOrder[b.sev]);
  t.omitted = Math.max(0, t.findings.length - MAX_FINDINGS);
  t.findings = t.findings.slice(0, MAX_FINDINGS);
}

const totals = zero();
for (const t of tools) addCounts(totals, t.counts);

function toolStatus(t) {
  if (!t.found) return 'missing';
  if (t.counts.critical > 0 || t.counts.high > 0) return 'warn';
  return 'pass';
}

let jobResults = {};
try {
  jobResults = JSON.parse(process.env.JOB_RESULTS || '{}');
} catch {
  jobResults = {};
}
const pipelineFailed = Object.values(jobResults).some((r) => r === 'failure');
const gate = pipelineFailed ? 'fail' : totals.critical + totals.high > 0 ? 'warn' : 'pass';

// ── Histórico ─────────────────────────────────────────────────────────────
let history = [];
if (fs.existsSync('history.json')) {
  const prev = readJson('history.json');
  if (Array.isArray(prev)) history = prev;
}
history.push({
  run: Number(process.env.RUN_NUMBER || 0),
  date: new Date().toISOString(),
  sha: (process.env.COMMIT_SHA || '').slice(0, 7),
  gate,
  totals,
});
history = history.slice(-30);

// ── Render ────────────────────────────────────────────────────────────────
const repo = process.env.REPO_NAME || 'repo';
const runUrl = process.env.RUN_URL || '#';
const runNumber = process.env.RUN_NUMBER || '—';
const sha = (process.env.COMMIT_SHA || '').slice(0, 7) || '—';
const now = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
const hasZapHtml = !!findFile(ART_DIR, 'zap.html');

const GATE = {
  pass: { label: 'GATE: PASSED', desc: 'Sin hallazgos críticos ni altos. Todos los jobs en verde.', color: '#3FB68B' },
  warn: { label: 'GATE: WARN', desc: 'Hay hallazgos high tolerados o alertas WARN. Revisar antes de release.', color: '#EFA036' },
  fail: { label: 'GATE: FAILED', desc: 'Uno o más quality gates rompieron el pipeline.', color: '#E2544A' },
}[gate];

const SEV = {
  critical: { label: 'critical', color: '#E2544A' },
  high: { label: 'high', color: '#EFA036' },
  medium: { label: 'medium', color: '#4C9AE8' },
  low: { label: 'low', color: '#8B93A1' },
  info: { label: 'info', color: '#5F6673' },
};

const sevCards = ['critical', 'high', 'medium', 'low']
  .map(
    (k) =>
      `<div class="card"><span class="label">${SEV[k].label}</span><span class="value" style="color:${totals[k] > 0 ? SEV[k].color : 'var(--txt)'}">${totals[k]}</span></div>`
  )
  .join('\n    ');

const statusBadge = {
  pass: '<span class="badge pass">pass</span>',
  warn: '<span class="badge warn">findings</span>',
  missing: '<span class="badge miss">sin datos</span>',
};

function renderFinding(f) {
  const s = SEV[f.sev];
  const link = f.url ? ` <a class="ref" href="${esc(f.url)}" target="_blank" rel="noopener">aviso ↗</a>` : '';
  return `<li>
    <span class="fsev" style="color:${s.color};border-color:${s.color}55">${s.label}</span>
    <div class="fbody">
      <span class="ftitle">${esc(f.title)}${link}</span>
      <span class="fdetail">${esc(f.detail)}</span>
      <span class="ffix">➜ ${esc(f.fix)}</span>
    </div>
  </li>`;
}

const toolBlocks = tools
  .map((t) => {
    const c = t.counts;
    const total = c.critical + c.high + c.medium + c.low + c.info;
    const pills = ['critical', 'high', 'medium', 'low']
      .filter((k) => c[k] > 0)
      .map((k) => `<span class="pill" style="color:${SEV[k].color};border-color:${SEV[k].color}44">${c[k]} ${SEV[k].label}</span>`)
      .join(' ');
    const expandable = t.findings.length > 0;
    const summary = `<div class="trow${expandable ? '' : ' noexp'}">
      <span class="caret">${expandable ? '▸' : ''}</span>
      <span class="tid"><span class="tool">${t.name}</span><span class="phase">${t.phase}</span></span>
      <span class="num">${t.found ? total : '—'}</span>
      <span class="pills">${pills || '<span class="dim">limpio</span>'}</span>
      <span class="right">${statusBadge[toolStatus(t)]}</span>
    </div>`;
    if (!expandable) return `<div class="titem">${summary}</div>`;
    return `<details class="titem">
      <summary>${summary}</summary>
      <ul class="flist">
        ${t.findings.map(renderFinding).join('\n')}
        ${t.omitted ? `<li class="dim more">… y ${t.omitted} hallazgo(s) más en los artefactos del run.</li>` : ''}
      </ul>
    </details>`;
  })
  .join('\n');

const html = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security dashboard · ${esc(repo)}</title>
<style>
  :root {
    --bg: #0d1117; --panel: #151b24; --line: #232b37;
    --txt: #dde3ec; --dim: #8b93a1; --mono: ui-monospace, 'Cascadia Code', 'JetBrains Mono', Menlo, monospace;
  }
  * { box-sizing: border-box; margin: 0; }
  body { background: var(--bg); color: var(--txt); font-family: var(--mono); font-size: 14px; line-height: 1.6; padding: 40px 20px; }
  .wrap { max-width: 880px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; }
  h1 { font-size: 17px; font-weight: 600; letter-spacing: .3px; }
  .meta { color: var(--dim); font-size: 12px; }
  .meta a { color: var(--dim); }
  .gate { border: 1px solid ${GATE.color}55; background: ${GATE.color}14; border-left: 4px solid ${GATE.color}; padding: 14px 18px; margin: 22px 0; }
  .gate b { color: ${GATE.color}; font-size: 15px; letter-spacing: 1px; }
  .gate p { color: var(--dim); font-size: 12.5px; margin-top: 2px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 26px; }
  .card { background: var(--panel); border: 1px solid var(--line); padding: 14px 16px; }
  .card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--dim); }
  .card .value { font-size: 30px; font-weight: 600; margin-top: 2px; display: block; }
  h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 1.2px; color: var(--dim); margin: 28px 0 10px; }
  .tlist { background: var(--panel); border: 1px solid var(--line); }
  .titem { border-top: 1px solid var(--line); }
  .titem:first-child { border-top: none; }
  summary { list-style: none; cursor: pointer; }
  summary::-webkit-details-marker { display: none; }
  .trow { display: flex; align-items: center; gap: 12px; padding: 11px 14px; }
  .trow:hover { background: #1a212c; }
  .noexp:hover { background: transparent; }
  .caret { width: 14px; color: var(--dim); transition: transform .15s; flex-shrink: 0; }
  details[open] .caret { transform: rotate(90deg); }
  .tid { flex: 1 1 180px; }
  .tool { display: block; font-weight: 600; }
  .phase { display: block; font-size: 11.5px; color: var(--dim); }
  .num { font-size: 18px; width: 46px; text-align: center; flex-shrink: 0; }
  .pills { flex: 2 1 220px; font-size: 12px; }
  .pill { border: 1px solid; padding: 1px 8px; margin-right: 4px; white-space: nowrap; }
  .dim { color: var(--dim); }
  .right { width: 100px; text-align: right; flex-shrink: 0; }
  .badge { font-size: 11px; text-transform: uppercase; letter-spacing: .8px; padding: 2px 9px; border: 1px solid; }
  .badge.pass { color: #3FB68B; border-color: #3FB68B55; background: #3FB68B12; }
  .badge.warn { color: #EFA036; border-color: #EFA03655; background: #EFA03612; }
  .badge.miss { color: var(--dim); border-color: var(--line); }
  .flist { list-style: none; padding: 4px 14px 14px 40px; background: #10151d; }
  .flist li { display: flex; gap: 12px; padding: 10px 0; border-top: 1px dashed var(--line); }
  .flist li:first-child { border-top: none; }
  .fsev { font-size: 11px; text-transform: uppercase; letter-spacing: .8px; border: 1px solid; padding: 1px 8px; height: fit-content; flex-shrink: 0; margin-top: 2px; }
  .fbody { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .ftitle { font-weight: 600; font-size: 13px; }
  .fdetail { font-size: 12px; color: var(--dim); }
  .ffix { font-size: 12px; color: #3FB68B; }
  .ref { color: #4C9AE8; font-size: 12px; text-decoration: none; margin-left: 6px; }
  .ref:hover { text-decoration: underline; }
  .more { padding-left: 0; font-size: 12px; }
  .chart-box { background: var(--panel); border: 1px solid var(--line); padding: 18px; height: 240px; }
  footer { margin-top: 26px; color: var(--dim); font-size: 11.5px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px; }
  footer a { color: var(--dim); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>$ security-dashboard — ${esc(repo)}</h1>
    <span class="meta">run <a href="${esc(runUrl)}">#${esc(runNumber)}</a> · ${esc(sha)} · ${now}</span>
  </header>

  <div class="gate"><b>${GATE.label}</b><p>${GATE.desc}</p></div>

  <div class="cards">
    ${sevCards}
  </div>

  <h2>Resultados por herramienta · clic para expandir</h2>
  <div class="tlist">
${toolBlocks}
  </div>

  <h2>Tendencia · últimos ${history.length} runs</h2>
  <div class="chart-box"><canvas id="trend"></canvas></div>

  <footer>
    <span>SAST · SCA · Container · DAST · Secrets — generado por el pipeline</span>
    <span>${hasZapHtml ? '<a href="zap.html">reporte ZAP completo</a> · ' : ''}<a href="history.json">history.json</a></span>
  </footer>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script>
const history = ${JSON.stringify(history)};
new Chart(document.getElementById('trend'), {
  type: 'line',
  data: {
    labels: history.map(h => '#' + h.run),
    datasets: [
      { label: 'Critical', data: history.map(h => h.totals.critical), borderColor: '#E2544A', backgroundColor: '#E2544A', tension: .3, pointRadius: 3 },
      { label: 'High', data: history.map(h => h.totals.high), borderColor: '#EFA036', backgroundColor: '#EFA036', tension: .3, pointRadius: 3 },
      { label: 'Medium', data: history.map(h => h.totals.medium), borderColor: '#4C9AE8', backgroundColor: '#4C9AE8', tension: .3, pointRadius: 3 }
    ]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#8b93a1', font: { family: 'monospace', size: 11 }, boxWidth: 10 } } },
    scales: {
      x: { ticks: { color: '#8b93a1', font: { family: 'monospace', size: 10 } }, grid: { color: '#232b37' } },
      y: { beginAtZero: true, ticks: { color: '#8b93a1', font: { family: 'monospace', size: 10 }, precision: 0 }, grid: { color: '#232b37' } }
    }
  }
});
</script>
</body>
</html>`;

// ── Escritura ─────────────────────────────────────────────────────────────
fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(path.join(OUT_DIR, 'index.html'), html);
fs.writeFileSync(path.join(OUT_DIR, 'history.json'), JSON.stringify(history, null, 2));

const zapHtml = findFile(ART_DIR, 'zap.html');
if (zapHtml) fs.copyFileSync(zapHtml, path.join(OUT_DIR, 'zap.html'));

console.log('Dashboard generado en site/');
console.log('Totales:', JSON.stringify(totals));
console.log('Gate:', gate);
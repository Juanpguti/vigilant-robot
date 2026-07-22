#!/usr/bin/env node
/**
 * Genera el dashboard de seguridad estático (site/) a partir de los
 * reportes JSON producidos por el pipeline: Semgrep, Trivy (fs + imagen),
 * OWASP ZAP y Gitleaks. Mantiene un histórico entre ejecuciones.
 *
 * Uso: node dashboard/generate.js
 * Entradas:  artifacts/** (reportes), history.json (histórico previo)
 * Salidas:   site/index.html, site/history.json, site/zap.html (si existe)
 */
const fs = require('fs');
const path = require('path');

const ART_DIR = process.env.ARTIFACTS_DIR || 'artifacts';
const OUT_DIR = 'site';

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

const zero = () => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

function addCounts(total, c) {
  for (const k of Object.keys(total)) total[k] += c[k] || 0;
}

// ── Parsers por herramienta ───────────────────────────────────────────────
function parseSemgrep(file) {
  const data = file && readJson(file);
  const c = zero();
  if (!data || !Array.isArray(data.results)) return { counts: c, found: !!data };
  for (const r of data.results) {
    const sev = (r.extra && r.extra.severity) || '';
    if (sev === 'ERROR') c.high += 1;
    else if (sev === 'WARNING') c.medium += 1;
    else c.info += 1;
  }
  return { counts: c, found: true };
}

function parseTrivy(file) {
  const data = file && readJson(file);
  const c = zero();
  if (!data || !Array.isArray(data.Results)) return { counts: c, found: !!data };
  for (const res of data.Results) {
    for (const v of res.Vulnerabilities || []) {
      const sev = (v.Severity || '').toUpperCase();
      if (sev === 'CRITICAL') c.critical += 1;
      else if (sev === 'HIGH') c.high += 1;
      else if (sev === 'MEDIUM') c.medium += 1;
      else if (sev === 'LOW') c.low += 1;
      else c.info += 1;
    }
  }
  return { counts: c, found: true };
}

function parseZap(file) {
  const data = file && readJson(file);
  const c = zero();
  if (!data || !Array.isArray(data.site)) return { counts: c, found: !!data };
  for (const site of data.site) {
    for (const a of site.alerts || []) {
      const risk = String(a.riskcode);
      if (risk === '3') c.high += 1;
      else if (risk === '2') c.medium += 1;
      else if (risk === '1') c.low += 1;
      else c.info += 1;
    }
  }
  return { counts: c, found: true };
}

function parseGitleaks(file) {
  const data = file && readJson(file);
  const c = zero();
  if (!Array.isArray(data)) return { counts: c, found: data !== null };
  c.critical = data.length; // todo secreto expuesto es crítico
  return { counts: c, found: true };
}

// ── Recolección ───────────────────────────────────────────────────────────
const tools = [
  {
    id: 'semgrep',
    name: 'Semgrep',
    phase: 'SAST',
    icon: 'code',
    ...parseSemgrep(findFile(ART_DIR, 'semgrep.json')),
  },
  {
    id: 'trivy-fs',
    name: 'Trivy fs',
    phase: 'SCA · dependencias',
    icon: 'package',
    ...parseTrivy(findFile(ART_DIR, 'trivy-fs.json')),
  },
  {
    id: 'trivy-image',
    name: 'Trivy image',
    phase: 'Container scan',
    icon: 'box',
    ...parseTrivy(findFile(ART_DIR, 'trivy-image.json')),
  },
  {
    id: 'zap',
    name: 'OWASP ZAP',
    phase: 'DAST',
    icon: 'bug',
    ...parseZap(findFile(ART_DIR, 'zap.json')),
  },
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    phase: 'Secrets',
    icon: 'key',
    ...parseGitleaks(findFile(ART_DIR, 'gitleaks.json')),
  },
];

const totals = zero();
for (const t of tools) addCounts(totals, t.counts);

function toolStatus(t) {
  if (!t.found) return 'missing';
  if (t.counts.critical > 0 || t.counts.high > 0) return 'warn';
  return 'pass';
}

// Resultados de los jobs (pasados por el workflow)
let jobResults = {};
try {
  jobResults = JSON.parse(process.env.JOB_RESULTS || '{}');
} catch {
  jobResults = {};
}
const jobValues = Object.values(jobResults);
const pipelineFailed = jobValues.some((r) => r === 'failure');
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

const sevMeta = [
  ['critical', 'Critical', '#E2544A'],
  ['high', 'High', '#EFA036'],
  ['medium', 'Medium', '#4C9AE8'],
  ['low', 'Low', '#8B93A1'],
];

const statusBadge = {
  pass: '<span class="badge pass">pass</span>',
  warn: '<span class="badge warn">findings</span>',
  missing: '<span class="badge miss">sin datos</span>',
};

const rows = tools
  .map((t) => {
    const c = t.counts;
    const total = c.critical + c.high + c.medium + c.low + c.info;
    const detail = sevMeta
      .filter(([k]) => c[k] > 0)
      .map(([k, label, color]) => `<span class="pill" style="color:${color};border-color:${color}44">${c[k]} ${label.toLowerCase()}</span>`)
      .join(' ');
    return `<tr>
      <td><span class="tool">${t.name}</span><span class="phase">${t.phase}</span></td>
      <td class="num">${t.found ? total : '—'}</td>
      <td class="pills">${detail || '<span class="dim">limpio</span>'}</td>
      <td class="right">${statusBadge[toolStatus(t)]}</td>
    </tr>`;
  })
  .join('\n');

const html = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security dashboard · ${repo}</title>
<style>
  :root {
    --bg: #0d1117; --panel: #151b24; --line: #232b37;
    --txt: #dde3ec; --dim: #8b93a1; --mono: ui-monospace, 'Cascadia Code', 'JetBrains Mono', Menlo, monospace;
  }
  * { box-sizing: border-box; margin: 0; }
  body { background: var(--bg); color: var(--txt); font-family: var(--mono); font-size: 14px; line-height: 1.6; padding: 40px 20px; }
  .wrap { max-width: 860px; margin: 0 auto; }
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
  .card .value { font-size: 30px; font-weight: 600; margin-top: 2px; }
  h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 1.2px; color: var(--dim); margin: 28px 0 10px; }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); }
  td { padding: 11px 14px; border-top: 1px solid var(--line); vertical-align: middle; }
  tr:first-child td { border-top: none; }
  .tool { display: block; font-weight: 600; }
  .phase { display: block; font-size: 11.5px; color: var(--dim); }
  .num { font-size: 18px; width: 60px; text-align: center; }
  .pills { font-size: 12px; }
  .pill { border: 1px solid; padding: 1px 8px; margin-right: 4px; white-space: nowrap; }
  .dim { color: var(--dim); }
  .right { text-align: right; width: 100px; }
  .badge { font-size: 11px; text-transform: uppercase; letter-spacing: .8px; padding: 2px 9px; border: 1px solid; }
  .badge.pass { color: #3FB68B; border-color: #3FB68B55; background: #3FB68B12; }
  .badge.warn { color: #EFA036; border-color: #EFA03655; background: #EFA03612; }
  .badge.miss { color: var(--dim); border-color: var(--line); }
  .chart-box { background: var(--panel); border: 1px solid var(--line); padding: 18px; height: 240px; }
  footer { margin-top: 26px; color: var(--dim); font-size: 11.5px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px; }
  footer a { color: var(--dim); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>$ security-dashboard — ${repo}</h1>
    <span class="meta">run <a href="${runUrl}">#${runNumber}</a> · ${sha} · ${now}</span>
  </header>

  <div class="gate"><b>${GATE.label}</b><p>${GATE.desc}</p></div>

  <div class="cards">
    ${sevMeta
      .map(
        ([k, label, color]) =>
          `<div class="card"><span class="label">${label}</span><span class="value" style="color:${totals[k] > 0 ? color : 'var(--txt)'}">${totals[k]}</span></div>`
      )
      .join('\n    ')}
  </div>

  <h2>Resultados por herramienta</h2>
  <table>${rows}</table>

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

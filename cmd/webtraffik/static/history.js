// history.js — history/charts page logic for webTraffik
// Requires: Chart.js (global), chartjs-adapter-date-fns (global),
//           services.js (window.PORT_SERVICE_NAMES), common.js (setCookie/getCookie/fetchSelf)

/* ── Self info ── */
fetchSelf();

/* ── Port → service name lookup (from services.js) ── */
// Falls back to the raw port string if no name is known.
function portServiceName(port) {
  return (window.PORT_SERVICE_NAMES && window.PORT_SERVICE_NAMES[port]) || port;
}

/* ───────────────────────────────────────────────────────── helpers ── */
const PALETTE = [
  '#4fc3f7','#81c784','#ffb74d','#f06292','#ce93d8',
  '#80cbc4','#fff176','#ff8a65','#a5d6a7','#90caf9',
  '#ef9a9a','#b39ddb','#80deea','#e6ee9c','#ffcc02',
  '#f48fb1','#bcaaa4','#ffe082','#b0bec5','#69f0ae',
];

function color(i) { return PALETTE[i % PALETTE.length]; }

function topN(map, n) {
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n);
}

// Bucket events by time interval. Returns {label: ISO-string, count: n}[]
function bucketByTime(events, bucketMs) {
  const counts = {};
  for (const ev of events) {
    const t = Math.floor(new Date(ev.time).getTime() / bucketMs) * bucketMs;
    counts[t] = (counts[t] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => a[0] - b[0])
    .map(([t, c]) => ({ x: new Date(+t), y: c }));
}

// Bucket events by time, grouped by a key extractor. Returns { key: [{x,y}] }
function bucketByTimeGrouped(events, bucketMs, keyFn) {
  const groups = {};
  for (const ev of events) {
    const k = keyFn(ev);
    const t = Math.floor(new Date(ev.time).getTime() / bucketMs) * bucketMs;
    if (!groups[k]) groups[k] = {};
    groups[k][t] = (groups[k][t] || 0) + 1;
  }
  const result = {};
  for (const [k, times] of Object.entries(groups)) {
    result[k] = Object.entries(times)
      .sort((a, b) => a[0] - b[0])
      .map(([t, c]) => ({ x: new Date(+t), y: c }));
  }
  return result;
}

// Choose a sensible bucket size based on the time range
function chooseBucket(events) {
  if (events.length < 2) return 60 * 60 * 1000; // 1h
  const times = events.map(e => new Date(e.time).getTime()).filter(t => !isNaN(t));
  if (times.length < 2) return 60 * 60 * 1000;
  const range = Math.max(...times) - Math.min(...times);
  if (range <= 2 * 3600e3)       return 5 * 60e3;      // ≤2h → 5-min buckets
  if (range <= 24 * 3600e3)      return 30 * 60e3;     // ≤1d → 30-min buckets
  if (range <= 7 * 24 * 3600e3)  return 3 * 3600e3;    // ≤7d → 3-hour buckets
  if (range <= 30 * 24 * 3600e3) return 24 * 3600e3;   // ≤30d → daily buckets
  return 7 * 24 * 3600e3;                               // >30d → weekly buckets
}

/* ───────────────────────────────────────── Chart instances ── */
const charts = {};

function destroyAll() {
  for (const k of Object.keys(charts)) {
    if (charts[k]) { charts[k].destroy(); delete charts[k]; }
  }
}

const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 400 },
  plugins: {
    legend: {
      labels: {
        color: '#78909c',
        font: { family: "'JetBrains Mono', monospace", size: 11 },
        boxWidth: 12,
      }
    },
    tooltip: {
      backgroundColor: 'rgba(8,15,30,0.95)',
      titleColor: '#4fc3f7',
      bodyColor: '#c8d8f0',
      borderColor: '#1e3a5f',
      borderWidth: 1,
      titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
      bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
    }
  },
  scales: {
    x: {
      ticks: { color: '#546e7a', font: { family: "'JetBrains Mono', monospace", size: 10 } },
      grid: { color: 'rgba(30,58,95,0.3)' }
    },
    y: {
      ticks: { color: '#546e7a', font: { family: "'JetBrains Mono', monospace", size: 10 } },
      grid: { color: 'rgba(30,58,95,0.3)' }
    }
  }
};

function timelineDefaults(unit, minTime, maxTime) {
  return {
    ...CHART_DEFAULTS,
    scales: {
      x: {
        type: 'time',
        time: { unit },
        min: minTime,
        max: maxTime,
        ticks: { color: '#546e7a', font: { family: "'JetBrains Mono', monospace", size: 10 }, maxRotation: 0 },
        grid: { color: 'rgba(30,58,95,0.3)' }
      },
      y: {
        beginAtZero: true,
        ticks: { color: '#546e7a', font: { family: "'JetBrains Mono', monospace", size: 10 } },
        grid: { color: 'rgba(30,58,95,0.3)' }
      }
    }
  };
}

function barDefaults(horizontal) {
  const base = JSON.parse(JSON.stringify(CHART_DEFAULTS));
  if (horizontal) {
    base.indexAxis = 'y';
  }
  return base;
}

/* ─────────────────────────────────────── Render all charts ── */
function renderCharts(metrics, events) {
  destroyAll();
  if (!metrics && (!events || events.length === 0)) return;

  // ── 1. Timeline from pre-aggregated hourly buckets ──
  //    Connections as bars (left axis), Unique IPs as line (right axis),
  //    Bans as small bars (left axis, stacked visual cue).
  const tb = metrics.time_buckets || [];
  if (tb.length > 0) {
    const timelineConns = tb.map(b => ({ x: new Date(b.bucket), y: b.value }));
    const timelineIPs   = tb.map(b => ({ x: new Date(b.bucket), y: b.unique_ips || 0 }));
    const timelineBans  = tb.map(b => ({ x: new Date(b.bucket), y: b.bans || 0 }));
    const hasBans = timelineBans.some(d => d.y > 0);
    const hasIPs  = timelineIPs.some(d => d.y > 0);

    const datasets = [{
      label: 'Connections',
      data: timelineConns,
      backgroundColor: 'rgba(79,195,247,0.5)',
      borderColor: '#4fc3f7',
      borderWidth: 1,
      borderRadius: 2,
      yAxisID: 'y',
      order: 2,
    }];

    if (hasBans) {
      datasets.push({
        label: 'Bans',
        data: timelineBans,
        backgroundColor: 'rgba(239,83,80,0.6)',
        borderColor: '#ef5350',
        borderWidth: 1,
        borderRadius: 2,
        yAxisID: 'y',
        order: 1,
      });
    }

    if (hasIPs) {
      datasets.push({
        label: 'Unique IPs',
        data: timelineIPs,
        type: 'line',
        borderColor: '#81c784',
        backgroundColor: 'rgba(129,199,132,0.15)',
        borderWidth: 2,
        pointRadius: tb.length <= 24 ? 3 : 0,
        pointHoverRadius: 5,
        tension: 0.3,
        fill: false,
        yAxisID: 'y1',
        order: 0,
      });
    }

    const tlOpts = timelineDefaults('hour',
      new Date(tb[0].bucket),
      new Date(tb[tb.length - 1].bucket));

    // Add right Y-axis for unique IPs
    if (hasIPs) {
      tlOpts.scales.y1 = {
        position: 'right',
        beginAtZero: true,
        grid: { drawOnChartArea: false },
        ticks: { color: '#81c784', font: { family: "'JetBrains Mono', monospace", size: 10 } },
        title: { display: true, text: 'Unique IPs', color: '#81c784', font: { family: "'JetBrains Mono', monospace", size: 10 } },
      };
      tlOpts.scales.y.title = {
        display: true, text: 'Connections', color: '#4fc3f7',
        font: { family: "'JetBrains Mono', monospace", size: 10 },
      };
    }

    charts.timeline = new Chart(document.getElementById('chart-timeline'), {
      type: 'bar',
      data: { datasets },
      options: tlOpts,
    });
  }

  // ── 2. Top Ports (from metrics connections aggregated by port) ──
  const portMap = {};
  for (const c of (metrics.connections || [])) {
    const p = c.labels.port || 'unknown';
    portMap[p] = (portMap[p] || 0) + c.value;
  }
  const topPorts = topN(portMap, 15);
  if (topPorts.length > 0) {
    charts.ports = new Chart(document.getElementById('chart-ports'), {
      type: 'bar',
      data: {
        labels: topPorts.map(([p]) => `${p} (${portServiceName(p)})`),
        datasets: [{
          label: 'Hits',
          data: topPorts.map(([, c]) => c),
          backgroundColor: topPorts.map((_, i) => color(i) + 'aa'),
          borderColor: topPorts.map((_, i) => color(i)),
          borderWidth: 1,
          borderRadius: 2,
        }]
      },
      options: barDefaults(true),
    });
  }

  // ── 3. Top Countries (from metrics connections aggregated by cc) ──
  const ccMap = {};
  for (const c of (metrics.connections || [])) {
    const k = c.labels.cc || 'XX';
    ccMap[k] = (ccMap[k] || 0) + c.value;
  }
  const topCC = topN(ccMap, 15);
  if (topCC.length > 0) {
    charts.countries = new Chart(document.getElementById('chart-countries'), {
      type: 'bar',
      data: {
        labels: topCC.map(([cc]) => cc),
        datasets: [{
          label: 'Connections',
          data: topCC.map(([, c]) => c),
          backgroundColor: topCC.map((_, i) => color(i + 3) + 'aa'),
          borderColor: topCC.map((_, i) => color(i + 3)),
          borderWidth: 1,
          borderRadius: 2,
        }]
      },
      options: barDefaults(true),
    });
  }

  // ── 4. Top Services (from metrics connections aggregated by service) ──
  const svcMap = {};
  for (const c of (metrics.connections || [])) {
    const k = c.labels.service || portServiceName(c.labels.port || '');
    svcMap[k] = (svcMap[k] || 0) + c.value;
  }
  const topSvc = topN(svcMap, 12);
  if (topSvc.length > 0) {
    charts.services = new Chart(document.getElementById('chart-services'), {
      type: 'doughnut',
      data: {
        labels: topSvc.map(([s]) => s),
        datasets: [{
          data: topSvc.map(([, c]) => c),
          backgroundColor: topSvc.map((_, i) => color(i + 6) + 'cc'),
          borderColor: 'rgba(10,14,26,0.5)',
          borderWidth: 2,
        }]
      },
      options: {
        ...CHART_DEFAULTS,
        scales: {},
        cutout: '60%',
      },
    });
  }

  // ── 5. Top Source IPs (from raw events — IPs not in metrics) ──
  if (events && events.length > 0) {
    const ipMap = {};
    for (const ev of events) ipMap[ev.src_ip] = (ipMap[ev.src_ip] || 0) + 1;
    const topIPs = topN(ipMap, 15);
    charts.ips = new Chart(document.getElementById('chart-ips'), {
      type: 'bar',
      data: {
        labels: topIPs.map(([ip]) => ip),
        datasets: [{
          label: 'Hits',
          data: topIPs.map(([, c]) => c),
          backgroundColor: topIPs.map((_, i) => color(i + 9) + 'aa'),
          borderColor: topIPs.map((_, i) => color(i + 9)),
          borderWidth: 1,
          borderRadius: 2,
        }]
      },
      options: barDefaults(true),
    });
  }

  // ── 6. Per-port timeline (from metrics port_timeline) ──
  const portTimeline = metrics.port_timeline || {};
  const portTimelineRow = document.getElementById('port-timeline-row');
  const ptPorts = Object.keys(portTimeline);
  if (ptPorts.length > 1) {
    // Show top 8 ports by total volume
    const ptTotals = {};
    for (const [p, buckets] of Object.entries(portTimeline)) {
      ptTotals[p] = buckets.reduce((s, b) => s + b.value, 0);
    }
    const topPTports = topN(ptTotals, 8).map(([p]) => p);

    portTimelineRow.style.display = '';
    charts.portTimeline = new Chart(document.getElementById('chart-port-timeline'), {
      type: 'line',
      data: {
        datasets: topPTports.map((p, i) => ({
          label: `${p} (${portServiceName(p)})`,
          data: (portTimeline[p] || []).map(b => ({ x: new Date(b.bucket), y: b.value })),
          borderColor: color(i),
          backgroundColor: color(i) + '22',
          borderWidth: 2,
          pointRadius: (portTimeline[p] || []).length <= 3 ? 4 : 0,
          pointHoverRadius: 5,
          tension: 0.3,
          fill: false,
        }))
      },
      options: {
        ...timelineDefaults('hour',
          tb.length > 0 ? new Date(tb[0].bucket) : undefined,
          tb.length > 0 ? new Date(tb[tb.length - 1].bucket) : undefined),
        plugins: { ...CHART_DEFAULTS.plugins }
      },
    });
  } else {
    portTimelineRow.style.display = 'none';
  }

  // ── 7. Per-country timeline (from metrics country_timeline) ──
  const ccTimeline = metrics.country_timeline || {};
  const ccTimelineRow = document.getElementById('country-timeline-row');
  const ctCountries = Object.keys(ccTimeline);
  if (ctCountries.length > 1) {
    const ctTotals = {};
    for (const [cc, buckets] of Object.entries(ccTimeline)) {
      ctTotals[cc] = buckets.reduce((s, b) => s + b.value, 0);
    }
    const topCTcc = topN(ctTotals, 8).map(([cc]) => cc);

    ccTimelineRow.style.display = '';
    charts.countryTimeline = new Chart(document.getElementById('chart-country-timeline'), {
      type: 'line',
      data: {
        datasets: topCTcc.map((cc, i) => ({
          label: cc,
          data: (ccTimeline[cc] || []).map(b => ({ x: new Date(b.bucket), y: b.value })),
          borderColor: color(i),
          backgroundColor: color(i) + '22',
          borderWidth: 2,
          pointRadius: (ccTimeline[cc] || []).length <= 3 ? 4 : 0,
          pointHoverRadius: 5,
          tension: 0.3,
          fill: false,
        }))
      },
      options: {
        ...timelineDefaults('hour',
          tb.length > 0 ? new Date(tb[0].bucket) : undefined,
          tb.length > 0 ? new Date(tb[tb.length - 1].bucket) : undefined),
        plugins: { ...CHART_DEFAULTS.plugins }
      },
    });
  } else {
    ccTimelineRow.style.display = 'none';
  }
}

/* ─────────────────────────────────────────── Result table ── */
function renderTable(events) {
  const tbody = document.getElementById('result-tbody');
  tbody.innerHTML = '';
  const slice = events.slice(-200);
  const frag = document.createDocumentFragment();
  for (const ev of slice) {
    const tr = document.createElement('tr');
    const d = ev.time ? new Date(ev.time) : null;
    const t = d ? d.toLocaleString('en-US', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).replace(',', '') : '';
    tr.innerHTML = `
      <td>${t}</td>
      <td class="highlight">${ev.src_ip}</td>
      <td>${ev.src_city || ''}</td>
      <td>${ev.src_cc || ''}</td>
      <td class="highlight">${ev.dst_port}</td>
      <td>${portServiceName(ev.dst_port)}</td>
      <td>${ev.protocol || 'tcp'}</td>`;
    frag.appendChild(tr);
  }
  tbody.appendChild(frag);
}

/* ─────────────────────────────────────── Populate service dropdown ── */
async function loadServices() {
  try {
    const resp = await fetch('/api/services');
    const svcs = await resp.json();
    const sel = document.getElementById('f-service');
    svcs.forEach(s => {
      const opt = document.createElement('option');
      opt.value = s.name;
      opt.textContent = s.name + ' (' + s.ports.sort((a, b) => a - b).join(', ') + ')';
      sel.appendChild(opt);
    });
  } catch(e) { /* ignore */ }
}

/* ─────────────────────────────────────────────── Main query ── */
async function runQuery() {
  const btn = document.getElementById('btn-query');
  btn.disabled = true;
  document.getElementById('loading-indicator').classList.add('visible');
  document.getElementById('result-summary').textContent = '';

  const country = document.getElementById('f-country').value.trim();
  const ip      = document.getElementById('f-ip').value.trim();
  const port    = document.getElementById('f-port').value.trim();
  const service = document.getElementById('f-service').value;
  const from    = document.getElementById('f-date-from').value;
  const to      = document.getElementById('f-date-to').value;

  // Build params for /api/history (raw events — used for Top IPs + result table)
  const histParams = new URLSearchParams();
  if (country) histParams.set('country', country);
  if (ip)      histParams.set('ip', ip);
  if (port)    histParams.set('port', port);
  if (service) histParams.set('service', service);
  if (from)    histParams.set('date_from', localDateTimeToUTC(from));
  if (to)      histParams.set('date_to',   localDateTimeToUTC(to));

  // Build params for /api/metrics (aggregated — used for all other charts)
  const metricParams = new URLSearchParams();
  if (from) metricParams.set('from', localDateTimeToUTC(from));
  if (to)   metricParams.set('to',   localDateTimeToUTC(to));

  try {
    // Fetch both endpoints in parallel
    const [histResp, metricResp] = await Promise.all([
      fetch('/api/history?' + histParams.toString()),
      fetch('/api/metrics?' + metricParams.toString()),
    ]);

    if (!histResp.ok) throw new Error('History HTTP ' + histResp.status);
    if (!metricResp.ok) throw new Error('Metrics HTTP ' + metricResp.status);

    const events  = await histResp.json();
    const metrics = await metricResp.json();

    // Compute total connections from metrics
    const totalConns = (metrics.connections || []).reduce((s, c) => s + c.value, 0);

    // Compute ban totals from metrics
    const bans = metrics.bans || [];
    const totalBans   = bans.reduce((s, b) => s + b.value, 0);
    const autoBans    = bans.filter(b => b.labels.type === 'auto').reduce((s, b) => s + b.value, 0);
    const manualBans  = bans.filter(b => b.labels.type === 'manual').reduce((s, b) => s + b.value, 0);

    // Update status
    const summary = document.getElementById('result-summary');
    summary.innerHTML =
      `<span class="stat">${totalConns.toLocaleString()}</span> connections` +
      ` &nbsp;|&nbsp; <span class="stat">~${(metrics.unique_ips || 0).toLocaleString()}</span> unique IPs (approx)` +
      ` &nbsp;|&nbsp; <span class="stat">${totalBans.toLocaleString()}</span> bans` +
      (totalBans > 0 ? ` (${autoBans} auto, ${manualBans} manual)` : '') +
      ` &nbsp;|&nbsp; <span class="stat">${events.length.toLocaleString()}</span> raw events`;

    if (totalConns === 0 && events.length === 0) {
      document.getElementById('charts-grid').classList.remove('visible');
      document.getElementById('summary-section').classList.remove('visible');
      document.getElementById('empty-state').style.display = 'flex';
      document.getElementById('empty-state').querySelector('div:last-child').textContent =
        'No events matched the selected filters.';
      destroyAll();
    } else {
      document.getElementById('empty-state').style.display = 'none';
      document.getElementById('charts-grid').classList.add('visible');
      document.getElementById('summary-section').classList.add('visible');
      renderCharts(metrics, events);
      renderTable(events);
    }
  } catch(err) {
    document.getElementById('result-summary').textContent = 'Error: ' + err.message;
  } finally {
    btn.disabled = false;
    document.getElementById('loading-indicator').classList.remove('visible');
  }
}

function clearFilters() {
  document.getElementById('f-country').value = '';
  document.getElementById('f-ip').value = '';
  document.getElementById('f-port').value = '';
  document.getElementById('f-service').value = '';
  setDefaultDates();
  destroyAll();
  document.getElementById('charts-grid').classList.remove('visible');
  document.getElementById('summary-section').classList.remove('visible');
  document.getElementById('empty-state').style.display = 'flex';
  document.getElementById('empty-state').querySelector('div:last-child').textContent =
    'Set filters above and click Query to explore connection history';
  document.getElementById('result-summary').textContent = '';
}

/* ─────────────────────────────────────────────── Boot ── */
document.getElementById('btn-query').addEventListener('click', runQuery);
document.getElementById('btn-clear').addEventListener('click', clearFilters);

// Also run on Enter in any filter input
document.querySelectorAll('#filter-panel input').forEach(el => {
  el.addEventListener('keydown', e => { if (e.key === 'Enter') runQuery(); });
});

// Format a Date as YYYY-MM-DDTHH:MM:SS for datetime-local input
function localDateTimeStr(d) {
  const y   = d.getFullYear();
  const mo  = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  const h   = String(d.getHours()).padStart(2, '0');
  const mi  = String(d.getMinutes()).padStart(2, '0');
  const s   = String(d.getSeconds()).padStart(2, '0');
  return `${y}-${mo}-${day}T${h}:${mi}:${s}`;
}

// Convert a datetime-local value (YYYY-MM-DDTHH:MM or YYYY-MM-DDTHH:MM:SS) to UTC ISO string
function localDateTimeToUTC(dtStr) {
  return new Date(dtStr).toISOString();
}

// Persist time range to cookie whenever inputs change
document.getElementById('f-date-from').addEventListener('change', function() {
  setCookie('wt_hist_from', this.value, 365);
});
document.getElementById('f-date-to').addEventListener('change', function() {
  setCookie('wt_hist_to', this.value, 365);
});

// Set date inputs — restore from cookie or default to last 1 hour
function setDefaultDates() {
  const savedFrom = getCookie('wt_hist_from');
  const savedTo   = getCookie('wt_hist_to');
  if (savedFrom && savedTo) {
    document.getElementById('f-date-from').value = savedFrom;
    document.getElementById('f-date-to').value   = savedTo;
  } else {
    const now  = new Date();
    const from = new Date(now.getTime() - 3600000); // 1 hour ago
    document.getElementById('f-date-to').value   = localDateTimeStr(now);
    document.getElementById('f-date-from').value = localDateTimeStr(from);
  }
}
setDefaultDates();

loadServices();

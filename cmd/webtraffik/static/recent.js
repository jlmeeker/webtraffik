// recent.js — recent events page logic for webTraffik
// Requires: services.js (window.PORT_SERVICE_NAMES), common.js (hexPreview)
(() => {
  // ── Self info (uses fetchSelf from common.js) ──
  fetchSelf();

  // PORT_SERVICE_NAMES is defined in /services.js (single source of truth).
  const PORT_SERVICE_NAMES = window.PORT_SERVICE_NAMES;

  const listEl       = document.getElementById('event-list');
  const loadingEl    = document.getElementById('loading');
  const emptyEl      = document.getElementById('empty-state');
  const countEl      = document.getElementById('event-count');
  const totalEl      = document.getElementById('total-count');
  const refreshBtn   = document.getElementById('refresh-btn');
  const expandAllBtn = document.getElementById('expand-all-btn');
  const serviceSel   = document.getElementById('filter-service');
  const limitSel     = document.getElementById('filter-limit');

  let allExpanded = false;
  let rawEvents = []; // full snapshot from /api/recent
  let servicePortMap = {}; // service name -> Set of port strings

  function buildRow(ev) {
    const t = new Date(ev.time);
    const ts   = t.toLocaleTimeString('en-US', { hour12: false });
    const date = t.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const srcLabel  = [ev.src_ip, ev.src_city, ev.src_cc].filter(Boolean).join(' / ');
    const portNum   = ev.dst_port && ev.dst_port !== 'unknown' ? ev.dst_port : '';
    const svcName   = portNum ? (PORT_SERVICE_NAMES[portNum] || '') : '';
    const portLabel = portNum ? (':' + portNum + (svcName ? ' ' + svcName : '')) : '';
    const protoLabel = ev.protocol ? ev.protocol.toUpperCase() : '';

    const row = document.createElement('div');
    row.className = 'log-entry';

    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.textContent = date + ' ' + ts;
    row.appendChild(timeSpan);

    const srcSpan = document.createElement('span');
    srcSpan.className = 'log-src';
    srcSpan.textContent = srcLabel;
    row.appendChild(srcSpan);

    if (portLabel) {
      const arrowSpan = document.createElement('span');
      arrowSpan.className = 'log-arrow';
      arrowSpan.textContent = '\u2192';
      row.appendChild(arrowSpan);
      const portSpan = document.createElement('span');
      portSpan.className = 'log-port';
      portSpan.textContent = portLabel;
      row.appendChild(portSpan);
    }

    if (protoLabel) {
      const protoSpan = document.createElement('span');
      protoSpan.className = 'log-proto';
      protoSpan.textContent = protoLabel;
      row.appendChild(protoSpan);
    }

    if (ev.client_data) {
      const hint = document.createElement('span');
      hint.className = 'log-data-hint';
      hint.textContent = '[data]';
      hint.addEventListener('click', e => {
        e.stopPropagation();
        row.classList.toggle('expanded');
      });
      row.appendChild(hint);

      const dataBlock = document.createElement('pre');
      dataBlock.className = 'log-client-data';
      dataBlock.textContent = hexPreview(ev.client_data);
      row.appendChild(dataBlock);

      if (allExpanded) row.classList.add('expanded');
    }

    return row;
  }

  function applyFilters() {
    let filtered = rawEvents.filter(ev => ev.client_data);
    const svc = serviceSel.value;
    if (svc && servicePortMap[svc]) {
      const ports = servicePortMap[svc];
      filtered = filtered.filter(ev => ports.has(ev.dst_port));
    }
    const limit = parseInt(limitSel.value, 10) || 1000;
    // Take the most recent N (events are oldest-first from API)
    if (filtered.length > limit) {
      filtered = filtered.slice(filtered.length - limit);
    }
    render(filtered);
  }

  function render(events) {
    listEl.textContent = '';
    countEl.textContent = events.length;
    totalEl.textContent = rawEvents.length;

    if (events.length === 0) {
      emptyEl.style.display = 'block';
      emptyEl.textContent = rawEvents.length === 0
        ? 'No events in the ring buffer yet.'
        : 'No events match the current filter.';
      return;
    }
    emptyEl.style.display = 'none';

    // Newest first
    const frag = document.createDocumentFragment();
    for (let i = events.length - 1; i >= 0; i--) {
      frag.appendChild(buildRow(events[i]));
    }
    listEl.appendChild(frag);
  }

  async function fetchRecent() {
    loadingEl.style.display = 'flex';
    emptyEl.style.display = 'none';
    listEl.textContent = '';
    refreshBtn.disabled = true;
    try {
      const resp = await fetch('/api/recent');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      rawEvents = await resp.json();
      applyFilters();
    } catch (err) {
      rawEvents = [];
      listEl.textContent = '';
      emptyEl.textContent = 'Failed to load events: ' + err.message;
      emptyEl.style.display = 'block';
    } finally {
      loadingEl.style.display = 'none';
      refreshBtn.disabled = false;
    }
  }

  // Populate service dropdown from /api/services
  async function loadServices() {
    try {
      const resp = await fetch('/api/services');
      const svcs = await resp.json();
      svcs.forEach(s => {
        servicePortMap[s.name] = new Set(s.ports.map(String));
        const opt = document.createElement('option');
        opt.value = s.name;
        opt.textContent = s.name;
        serviceSel.appendChild(opt);
      });
    } catch (e) {
      // dropdown stays with just "All"
    }
  }

  refreshBtn.addEventListener('click', fetchRecent);
  serviceSel.addEventListener('change', applyFilters);
  limitSel.addEventListener('change', applyFilters);

  expandAllBtn.addEventListener('click', () => {
    allExpanded = !allExpanded;
    expandAllBtn.textContent = allExpanded ? 'Collapse All Data' : 'Expand All Data';
    const entries = listEl.querySelectorAll('.log-entry');
    entries.forEach(row => {
      if (row.querySelector('.log-client-data')) {
        row.classList.toggle('expanded', allExpanded);
      }
    });
  });

  // Load services then fetch events
  loadServices().then(fetchRecent);
})();

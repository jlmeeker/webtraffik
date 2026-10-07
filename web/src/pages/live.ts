import '../styles/theme.css';
import '../styles/live.css';

import { initChrome } from '../lib/chrome';
import { otherColor, SERIES_SLOTS, seriesColors } from '../lib/palette';
import { ServiceRegistry } from '../lib/services';
import { createLiveState, recordEvent, resetLiveState, updateLastSeen } from '../lib/store';
import { cssVar, onThemeChange } from '../lib/theme';
import type { ConnectionEvent, LonLat } from '../lib/types';
import { $, prefersReducedMotion } from '../lib/utils/dom';
import { ensureInt } from '../lib/utils/format';
import { getPref, setPref } from '../lib/utils/prefs';
import { LiveStream, type StreamStatus } from '../lib/ws';
import { LogPanel } from '../log';
import { ArcLayer } from '../map/arcs';
import { AudioEngine } from '../map/audio';
import { Magnifier } from '../map/magnifier';
import { DotTooltip } from '../map/tooltip';
import { MapView } from '../map/view';
import { loadWorld } from '../map/world';
import { BannedPanel } from '../panels/banned';
import { EBPFPanel } from '../panels/ebpf';
import { LastSeenPanel } from '../panels/lastseen';
import { ScannersPanel } from '../panels/scanners';
import { PanelScheduler } from '../panels/scheduler';
import { ServicesPanel } from '../panels/services';
import { TraceLayer } from '../traceroute/animate';

const HOURS_PREF = 'wt_live_hours';
const PAUSE_BUFFER_MAX = 5000;

function main(): void {
  const self = initChrome();
  const services = new ServiceRegistry();
  const state = createLiveState(ensureInt(getPref(HOURS_PREF), 1, 24, 1));
  const reduced = prefersReducedMotion();

  // ── Colours follow the theme ──────────────────────────────────────────────
  let series = seriesColors();
  let other = otherColor();
  const colorForPort = (port: string): string => {
    const ps = state.portStats.get(port);
    const slot = ps ? ps.slot : SERIES_SLOTS;
    return slot < SERIES_SLOTS ? (series[slot] ?? other) : other;
  };

  // ── Map ───────────────────────────────────────────────────────────────────
  const view = new MapView($<SVGSVGElement>('#map'));
  const zoomLevelEl = $('#zoom-level');
  let zoomTimer: ReturnType<typeof setTimeout> | null = null;
  view.onZoom((k) => {
    zoomLevelEl.textContent = `${k.toFixed(1)}x`;
    zoomLevelEl.classList.add('visible');
    if (zoomTimer) clearTimeout(zoomTimer);
    zoomTimer = setTimeout(() => zoomLevelEl.classList.remove('visible'), k === 1 ? 600 : 1500);
  });

  const banned = new BannedPanel($('#banned-rows'), $('#banned-count'), () => arcs.syncBanned());
  const scanners = new ScannersPanel($('#scanner-rows'), $('#scanner-count'));

  const trace = new TraceLayer(view, {
    indicator: $('#trace-indicator'),
    reducedMotion: () => reduced,
    getSelf: () => {
      const s = self.value;
      return s ? { lat: s.lat, lon: s.lon, city: s.city, cc: s.cc, ip: s.ip } : null;
    },
  });
  const startTrace = (ev: ConnectionEvent | { src_ip: string; src_lat: number; src_lon: number; src_city?: string; src_cc?: string }) => {
    if (!ev.src_ip) return;
    trace.start(ev.src_ip, { lat: ev.src_lat, lon: ev.src_lon, city: ev.src_city ?? '', cc: ev.src_cc ?? '' });
  };

  const tooltip = new DotTooltip('#dot-tooltip', {
    isBanned: (ip, port) => banned.isBanned(ip, port),
    onToggleBan: (ev) => void banned.toggle(ev.src_ip, ev.dst_port),
    onTrace: startTrace,
  });

  const audio = new AudioEngine();
  const magnifier = new Magnifier($('#magnifier'), $<SVGSVGElement>('#mag-svg'), view, () => cssVar('--self-dot'), () => reduced);

  const arcs = new ArcLayer({
    view,
    tooltip,
    colorForPort,
    arcEndColor: () => cssVar('--arc-end', '#fff'),
    bannedColor: () => cssVar('--critical', '#e66767'),
    isBanned: (ip, port) => banned.isBanned(ip, port),
    suppressArcs: () => trace.active,
    reducedMotion: () => reduced,
    onArc: (ev, src, dst, c1, hits) => {
      if (magnifier.shouldShow(src, dst)) magnifier.showArcThrottled(ev, src, dst, c1, hits);
    },
    onTone: (src: LonLat, dst: LonLat) => audio.play(src, dst),
  });

  self.subscribe((s) => {
    if (s && (s.lat || s.lon)) arcs.setSelf([s.lon, s.lat]);
  });

  loadWorld()
    .then((w) => view.setWorld(w))
    .catch((e: unknown) => console.warn('world map failed to load', e));

  onThemeChange(() => {
    series = seriesColors();
    other = otherColor();
    arcs.recolor();
    servicesPanel.dirty = true;
  });

  // ── Panels ────────────────────────────────────────────────────────────────
  const servicesPanel = new ServicesPanel($('#service-rows'), state, services, colorForPort);
  const lastSeen = new LastSeenPanel($('#lastseen-rows'), state, (e) =>
    startTrace({ src_ip: e.ip, src_lat: e.lat, src_lon: e.lon, src_city: e.city, src_cc: e.cc }),
  );
  const ebpf = new EBPFPanel($('#ebpf-rows'));
  const scheduler = new PanelScheduler(2000);
  scheduler.add(servicesPanel);
  scheduler.add(lastSeen);
  scheduler.start();
  void services.ready.then(() => {
    servicesPanel.dirty = true;
  });

  const log = new LogPanel($('#log-panel'), services, startTrace);

  // ── Header controls ───────────────────────────────────────────────────────
  const connCountEl = $('#conn-count');
  const wsStatusEl = $('#ws-status');
  const notice = $('#stream-notice');
  const pauseBtn = $<HTMLButtonElement>('#pause-btn');
  const audioBtn = $<HTMLButtonElement>('#audio-toggle');
  const slider = $<HTMLInputElement>('#time-slider');
  const sliderLabel = $('#slider-label');

  slider.value = String(state.hours);
  sliderLabel.textContent = `${state.hours}h`;
  slider.setAttribute('aria-valuetext', `${state.hours} hour${state.hours === 1 ? '' : 's'}`);

  audioBtn.setAttribute('aria-pressed', String(audio.enabled));
  audio.armUnlock();
  audioBtn.addEventListener('click', () => {
    audio.setEnabled(!audio.enabled);
    audioBtn.setAttribute('aria-pressed', String(audio.enabled));
  });

  let paused = false;
  const pauseBuffer: ConnectionEvent[] = [];
  let replayDone = false;
  let liveStatus: StreamStatus = 'connecting';

  function showNotice(text: string | null, cls = ''): void {
    notice.hidden = text === null;
    notice.textContent = text ?? '';
    notice.className = `stream-notice ${cls}`.trim();
  }

  function renderStatus(): void {
    const s = paused ? 'paused' : liveStatus;
    wsStatusEl.dataset.status = s;
    const label: Record<string, string> = {
      open: 'Live',
      connecting: 'Connecting',
      reconnecting: 'Reconnecting',
      closed: 'Disconnected',
      paused: 'Paused',
    };
    wsStatusEl.setAttribute('aria-label', label[s] ?? s);
    wsStatusEl.title = label[s] ?? s;
  }

  function setPaused(p: boolean): void {
    paused = p;
    pauseBtn.setAttribute('aria-pressed', String(p));
    pauseBtn.setAttribute('aria-label', p ? 'Resume live updates' : 'Pause live updates');
    if (p) showNotice('Paused — events are buffered', 'paused');
    else {
      showNotice(null);
      const buffered = pauseBuffer.splice(0);
      for (const ev of buffered) process(ev, true);
      servicesPanel.dirty = true;
      lastSeen.dirty = true;
      scheduler.renderAll();
    }
    renderStatus();
  }
  pauseBtn.addEventListener('click', () => setPaused(!paused));
  document.addEventListener('keydown', (e) => {
    if (e.key === ' ' && e.target === document.body) {
      e.preventDefault();
      setPaused(!paused);
    }
  });

  // ── Event pipeline ────────────────────────────────────────────────────────
  function process(ev: ConnectionEvent, asReplay: boolean): void {
    recordEvent(state, ev);
    connCountEl.textContent = String(state.events.length);
    servicesPanel.dirty = true;

    const isScanner = scanners.ips.has(ev.src_ip);
    if (!isScanner) {
      if (updateLastSeen(state, ev)) lastSeen.dirty = true;
      log.add(ev);
    }
    if (ev.replay || asReplay) {
      if (!isScanner) arcs.drawHistoryDot(ev);
      if (state.events.length % 200 === 0) log.flush();
      return;
    }
    if (!replayDone) {
      replayDone = true;
      scheduler.renderAll();
      log.flush();
    }
    if (!isScanner) arcs.handleLive(ev);
  }

  function resetAll(): void {
    trace.cancel();
    view.zoomToWorld(0);
    resetLiveState(state);
    connCountEl.textContent = '0';
    replayDone = false;
    servicesPanel.reset();
    lastSeen.reset();
    arcs.reset();
    magnifier.reset();
    log.reset();
    pauseBuffer.length = 0;
  }

  const stream = new LiveStream({
    hours: state.hours,
    onReset: resetAll,
    onEvent: (ev) => {
      if (paused) {
        pauseBuffer.push(ev);
        if (pauseBuffer.length > PAUSE_BUFFER_MAX) pauseBuffer.splice(0, pauseBuffer.length - PAUSE_BUFFER_MAX);
        return;
      }
      process(ev, false);
    },
    onStatus: (s, info) => {
      liveStatus = s;
      renderStatus();
      if (s === 'reconnecting' && info.delayMs > 0) {
        showNotice(`Connection lost — retrying in ${Math.round(info.delayMs / 1000)}s (attempt ${info.attempt})`);
      } else if (s === 'open' && !paused) {
        showNotice(null);
      }
    },
  });

  let sliderTimer: ReturnType<typeof setTimeout> | null = null;
  slider.addEventListener('input', () => {
    const val = ensureInt(slider.value, 1, 24, 1);
    sliderLabel.textContent = `${val}h`;
    slider.setAttribute('aria-valuetext', `${val} hour${val === 1 ? '' : 's'}`);
    if (sliderTimer) clearTimeout(sliderTimer);
    sliderTimer = setTimeout(() => {
      sliderTimer = null;
      if (val === state.hours) return;
      state.hours = val;
      setPref(HOURS_PREF, String(val));
      stream.setHours(val);
    }, 700);
  });

  // ── Mobile drawers ────────────────────────────────────────────────────────
  for (const btn of document.querySelectorAll<HTMLButtonElement>('.panel-toggle')) {
    const side = btn.dataset.drawer;
    const panel = side === 'left' ? $('#left-panels') : $('#right-panels');
    btn.addEventListener('click', () => {
      const open = !panel.classList.contains('open');
      for (const p of document.querySelectorAll('.panel-stack')) p.classList.remove('open');
      for (const b of document.querySelectorAll('.panel-toggle')) b.setAttribute('aria-expanded', 'false');
      panel.classList.toggle('open', open);
      btn.setAttribute('aria-expanded', String(open));
    });
  }

  // ── Go ────────────────────────────────────────────────────────────────────
  banned.start();
  scanners.start();
  ebpf.start();
  renderStatus();
  stream.start();
}

main();

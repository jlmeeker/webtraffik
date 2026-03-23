// index.js — live map page logic for webTraffik
// Requires: d3 (global), topojson (global), services.js (window.PORT_SERVICE_NAMES), common.js
(() => {
  // ── State ────────────────────────────────────────────────────────────────
  let selfPos = null;    // { lat, lon, ip, city, cc }
  let connCount = 0;
  let replayDone = false; // becomes true after first non-replay event

  // ── Event storage (no cap — controlled by server-side time window) ────
  const eventRing = []; // oldest-first; all events from the replay + live

  function evictEvent(ev) {
    const port = ev.dst_port || 'unknown';
    if (portStats[port]) {
      portStats[port].count--;
      if (portStats[port].count <= 0) delete portStats[port];
    }
    if (port) {
      serviceStats[port] = (serviceStats[port] || 1) - 1;
      if (serviceStats[port] <= 0) delete serviceStats[port];
      serviceDirty = true;
    }
  }

  function recordEvent(ev) {
    eventRing.push(ev);
    // Evict events that have fallen outside the current time window.
    const cutoff = Date.now() - currentHours * 3600_000;
    while (eventRing.length > 0 && new Date(eventRing[0].time).getTime() < cutoff) {
      evictEvent(eventRing.shift());
    }
  }

  // Port stats: { portStr -> { count, color } }
  const portStats = {};
  let portColorIdx = 0;

  // Palette for port swatches (distinct from arc palette)
  const PORT_COLORS = [
    '#4fc3f7', '#ffb74d', '#81c784', '#f06292',
    '#ce93d8', '#80cbc4', '#fff176', '#ff8a65',
    '#90caf9', '#a5d6a7', '#ef9a9a', '#b39ddb',
  ];

  // Assigns a stable color to each port and tracks its hit count.
  // Called on every event so colors are available to arc drawing and panels.
  function ensurePortColor(port) {
    if (!port) return;
    if (!portStats[port]) {
      portStats[port] = { count: 0, color: PORT_COLORS[portColorIdx % PORT_COLORS.length] };
      portColorIdx++;
    }
    portStats[port].count++;
  }

  // ── Map setup ────────────────────────────────────────────────────────────
  const svg = d3.select('#map');
  const mapEl = document.getElementById('map');
  function dims() {
    return { w: mapEl.clientWidth, h: mapEl.clientHeight };
  }

  let { w, h } = dims();

  // Base projection scale/translate (viewport-derived); zoom modifies these.
  let baseScale = w / 6.3;
  let baseTranslate = [w / 2, h / 2];

  const projection = d3.geoNaturalEarth1()
    .scale(baseScale)
    .translate(baseTranslate);

  const path = d3.geoPath().projection(projection);

  // ── Projection-based zoom ──────────────────────────────────────────────
  // Instead of applying an SVG transform (which would scale strokes and dots),
  // we update the projection's scale and translate on every zoom event, then
  // reproject all geo paths, dots, and arcs.  This keeps strokes crisp at all
  // zoom levels and reuses the same reprojection logic as resize().

  let currentTransform = d3.zoomIdentity; // track for resize integration

  function reproject() {
    // Apply zoom transform to the base projection parameters
    projection
      .scale(baseScale * currentTransform.k)
      .translate([
        currentTransform.x + currentTransform.k * baseTranslate[0],
        currentTransform.y + currentTransform.k * baseTranslate[1],
      ]);

    // Reproject all geo paths (sphere, graticule, land/borders/lakes/rivers)
    sphereGroup.select('path').attr('d', path);
    graticuleGroup.select('path').attr('d', path);
    landGroup.selectAll('path').attr('d', path);

    // Reproject all source dots from their stored [lon, lat] datum
    dotGroup.selectAll('.src-dot').each(function(d) {
      if (!d) return;
      const pt = projection(d);
      if (!pt) return;
      d3.select(this).attr('cx', pt[0]).attr('cy', pt[1]);
    });

    // Reproject persistent arcs in the registry
    arcRegistry.forEach((entry) => {
      const p0 = projection(entry.srcPt);
      const p1 = projection(entry.dstPt);
      if (!p0 || !p1) return;
      const [x0, y0] = p0;
      const [x1, y1] = p1;
      const mx = (x0 + x1) / 2;
      const my = (y0 + y1) / 2;
      const chord = Math.sqrt((x1 - x0) ** 2 + (y1 - y0) ** 2);
      const bulge = Math.min(chord * 0.35, h * 0.25);
      const cx = mx;
      const cy = my - bulge;
      const fullD = `M${x0},${y0} Q${cx},${cy} ${x1},${y1}`;
      const N = 20;
      entry.lineData = [];
      for (let i = 0; i <= N; i++) {
        const t = i / N;
        const u = 1 - t;
        entry.lineData.push([
          u * u * x0 + 2 * u * t * cx + t * t * x1,
          u * u * y0 + 2 * u * t * cy + t * t * y1,
        ]);
      }
      entry.arcPath.attr('d', fullD);
      let totalLen = 0;
      for (let i = 1; i < entry.lineData.length; i++) {
        const dx = entry.lineData[i][0] - entry.lineData[i - 1][0];
        const dy = entry.lineData[i][1] - entry.lineData[i - 1][1];
        totalLen += Math.sqrt(dx * dx + dy * dy);
      }
      entry.totalLen = totalLen;
      entry.arcPath.attr('stroke-dasharray', totalLen).attr('stroke-dashoffset', 0);
      entry.gradEntry.el.attr('x1', x0).attr('y1', y0).attr('x2', x1).attr('y2', y1);
    });

    // Reproject self dot
    drawSelfDot();
  }

  const zoomLevelEl = document.getElementById('zoom-level');
  let zoomLevelTimer = null;

  const zoom = d3.zoom()
    .scaleExtent([1, 20])       // 1x to 20x zoom
    .filter((event) => {
      // Allow wheel events everywhere (for zoom), but block drag-start on
      // interactive dots so their hover/tooltip events are not swallowed.
      if (event.type === 'wheel') return true;
      if (event.target.classList && event.target.classList.contains('src-dot')) return false;
      return !event.button; // default: ignore right-click
    })
    .on('zoom', (event) => {
      currentTransform = event.transform;
      reproject();
      // Show zoom level indicator briefly
      const k = currentTransform.k;
      zoomLevelEl.textContent = k.toFixed(1) + 'x';
      zoomLevelEl.classList.add('visible');
      if (zoomLevelTimer) clearTimeout(zoomLevelTimer);
      zoomLevelTimer = setTimeout(() => {
        zoomLevelEl.classList.remove('visible');
      }, k === 1 ? 600 : 1500);
    });

  svg.call(zoom);

  // Double-click resets to default view with a smooth transition
  svg.on('dblclick.zoom', null); // remove d3's default dblclick-zoom
  svg.on('dblclick', () => {
    svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
  });

  // Defs: glow filters
  const defs = svg.append('defs');

  function makeGlow(id, color) {
    const f = defs.append('filter').attr('id', id).attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    f.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', 3).attr('result', 'blur');
    const merge = f.append('feMerge');
    merge.append('feMergeNode').attr('in', 'blur');
    merge.append('feMergeNode').attr('in', 'blur');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');
  }

  makeGlow('glow-blue',   '#4fc3f7');
  // glow-orange and glow-green removed — only self-dot uses glow-blue

  // Gradient pool for arcs — reuse gradients by color pair instead of
  // creating a new <linearGradient> per arc.  Each key is "c1|c2".
  const gradientPool = new Map(); // key -> { el, refCount }

  function acquireGradient(c1, c2, x0, y0, x1, y1) {
    const key = c1 + '|' + c2;
    let entry = gradientPool.get(key);
    if (!entry) {
      const id = `arc-grad-${gradientPool.size}`;
      const g = defs.append('linearGradient').attr('id', id)
        .attr('gradientUnits', 'userSpaceOnUse');
      g.append('stop').attr('offset', '0%').attr('stop-color', c1).attr('stop-opacity', 0.9);
      g.append('stop').attr('offset', '100%').attr('stop-color', c2).attr('stop-opacity', 0.9);
      entry = { el: g, id, refCount: 0 };
      gradientPool.set(key, entry);
    }
    entry.refCount++;
    // Update coordinates to latest arc (good enough — gradients are similar angles)
    entry.el.attr('x1', x0).attr('y1', y0).attr('x2', x1).attr('y2', y1);
    return entry;
  }

  function releaseGradient(c1, c2) {
    const key = c1 + '|' + c2;
    const entry = gradientPool.get(key);
    if (entry) {
      entry.refCount--;
      // Keep gradient in DOM even at refCount 0 — it will be reused
    }
  }

  const sphereGroup = svg.append('g');
  const graticuleGroup = svg.append('g');
  const landGroup = svg.append('g');
  const arcGroup = svg.append('g');
  const pulseGroup = svg.append('g');  // pulse particles render above arcs
  const dotGroup = svg.append('g');

  const graticule = d3.geoGraticule()();

  // Draw sphere + graticule
  sphereGroup.append('path')
    .datum({ type: 'Sphere' })
    .attr('class', 'sphere')
    .attr('d', path);

  graticuleGroup.append('path')
    .datum(graticule)
    .attr('class', 'graticule')
    .attr('d', path);

  // Load world TopoJSON (sane-topojson includes lakes + rivers layers)
  const WORLD_URL = 'https://cdn.jsdelivr.net/npm/sane-topojson@4/dist/world_110m.json';
  let worldLandGeo = null;   // cached for magnifier
  let worldBorderGeo = null; // cached for magnifier
  let worldLakesGeo = null;  // cached for magnifier
  let worldRiversGeo = null; // cached for magnifier

  d3.json(WORLD_URL).then(world => {
    worldLandGeo = topojson.feature(world, world.objects.land);
    worldBorderGeo = topojson.mesh(world, world.objects.countries, (a, b) => a !== b);
    worldLakesGeo = topojson.feature(world, world.objects.lakes);
    worldRiversGeo = topojson.feature(world, world.objects.rivers);

    landGroup.append('path')
      .datum(worldLandGeo)
      .attr('class', 'land')
      .attr('d', path);

    landGroup.append('path')
      .datum(worldBorderGeo)
      .attr('class', 'border')
      .attr('d', path);

    landGroup.append('path')
      .datum(worldLakesGeo)
      .attr('class', 'lake')
      .attr('d', path);

    landGroup.append('path')
      .datum(worldRiversGeo)
      .attr('class', 'river')
      .attr('d', path);

    // Initialize magnifier now that geo data is available
    magInit();
  });

  // ── Magnifier inset ─────────────────────────────────────────────────────
  const MAG_IDLE_MS = 5000;       // fade out after 5s of no events
  const MAG_PAD_DEG = 8;          // padding around bbox in degrees
  const MAG_MIN_SPAN = 15;        // minimum bbox span in degrees (prevents over-zoom)
  const MAG_W = 420;
  const MAG_H = 300;

  const magEl = document.getElementById('magnifier');
  const magSvg = d3.select('#mag-svg');
  let magIdleTimer = null;
  let magVisible = false;
  let magInitialized = false;

  // Magnifier has its own projection, path generator, and SVG groups
  // Use Mercator for the magnifier — it zooms cleanly to any region
  // (geoNaturalEarth1 is designed for world-scale views and fitSize
  // doesn't produce tight zoom on small bounding boxes)
  const magProjection = d3.geoMercator();
  const magPath = d3.geoPath().projection(magProjection);
  let magSphereGroup, magLandGroup, magArcGroup, magDotGroup;

  function magInit() {
    if (magInitialized) return;
    magInitialized = true;

    // Magnifier needs its own glow filter (can't reference #map's defs)
    const magDefs = magSvg.append('defs');
    const mf = magDefs.append('filter').attr('id', 'mag-glow-blue')
      .attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    mf.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', 3).attr('result', 'blur');
    const mm = mf.append('feMerge');
    mm.append('feMergeNode').attr('in', 'blur');
    mm.append('feMergeNode').attr('in', 'blur');
    mm.append('feMergeNode').attr('in', 'SourceGraphic');

    magSphereGroup = magSvg.append('g');
    magLandGroup = magSvg.append('g');
    magArcGroup = magSvg.append('g');
    magDotGroup = magSvg.append('g');

    magSphereGroup.append('path')
      .datum({ type: 'Sphere' })
      .attr('class', 'mag-sphere')
      .attr('d', magPath);

    if (worldLandGeo) {
      magLandGroup.append('path')
        .datum(worldLandGeo)
        .attr('class', 'mag-land')
        .attr('d', magPath);
    }
    if (worldBorderGeo) {
      magLandGroup.append('path')
        .datum(worldBorderGeo)
        .attr('class', 'mag-border')
        .attr('d', magPath);
    }
    if (worldLakesGeo) {
      magLandGroup.append('path')
        .datum(worldLakesGeo)
        .attr('class', 'mag-lake')
        .attr('d', magPath);
    }
    if (worldRiversGeo) {
      magLandGroup.append('path')
        .datum(worldRiversGeo)
        .attr('class', 'mag-river')
        .attr('d', magPath);
    }
  }

  // Fit the magnifier projection to a bounding box around src and dst
  function magFitBbox(srcPt, dstPt) {
    let lonMin = Math.min(srcPt[0], dstPt[0]) - MAG_PAD_DEG;
    let lonMax = Math.max(srcPt[0], dstPt[0]) + MAG_PAD_DEG;
    let latMin = Math.min(srcPt[1], dstPt[1]) - MAG_PAD_DEG;
    let latMax = Math.max(srcPt[1], dstPt[1]) + MAG_PAD_DEG;

    // Enforce minimum span to prevent over-zoom on short arcs
    const lonSpan = lonMax - lonMin;
    const latSpan = latMax - latMin;
    if (lonSpan < MAG_MIN_SPAN) {
      const pad = (MAG_MIN_SPAN - lonSpan) / 2;
      lonMin -= pad; lonMax += pad;
    }
    if (latSpan < MAG_MIN_SPAN) {
      const pad = (MAG_MIN_SPAN - latSpan) / 2;
      latMin -= pad; latMax += pad;
    }

    // Clamp to valid ranges
    lonMin = Math.max(-180, lonMin);
    lonMax = Math.min(180, lonMax);
    latMin = Math.max(-85, latMin);
    latMax = Math.min(85, latMax);

    // Manually compute center, scale, and translate for Mercator.
    // This avoids fitSize issues where D3's internal bbox computation
    // doesn't produce meaningful zoom on small regions.
    const centerLon = (lonMin + lonMax) / 2;
    const centerLat = (latMin + latMax) / 2;

    // Project corner points at scale=1, center=[0,0] to measure span
    magProjection
      .scale(1)
      .center([0, 0])
      .translate([0, 0]);

    let topLeft = magProjection([lonMin, latMax]);
    let bottomRight = magProjection([lonMax, latMin]);

    let projW = Math.abs(bottomRight[0] - topLeft[0]);
    let projH = Math.abs(bottomRight[1] - topLeft[1]);

    // Mercator inflates high-latitude regions vertically. If the projected
    // aspect ratio is far from the magnifier's aspect ratio, the arc gets
    // squished into a narrow band and appears vertical when it should be
    // horizontal (or vice versa). Fix by expanding the bbox in the
    // deficient dimension so the projected shape roughly matches the
    // magnifier's aspect ratio.
    const magAspect = MAG_W / MAG_H; // ~1.4
    const projAspect = projH > 0 ? projW / projH : magAspect;
    let bboxAdjusted = false;
    if (projAspect < magAspect * 0.5) {
      // Too tall/narrow — widen the longitude bbox
      const targetProjW = projH * magAspect;
      const lonCenter = (lonMin + lonMax) / 2;
      // Mercator x is linear in lon, so ratio works directly
      const factor = targetProjW / projW;
      const halfSpan = ((lonMax - lonMin) * factor) / 2;
      lonMin = Math.max(-180, lonCenter - halfSpan);
      lonMax = Math.min(180, lonCenter + halfSpan);
      bboxAdjusted = true;
    } else if (projAspect > magAspect * 2) {
      // Too wide/short — heighten the latitude bbox
      const targetProjH = projW / magAspect;
      const latCenter = (latMin + latMax) / 2;
      // Mercator y is non-linear in lat, so use iterative widening
      const factor = targetProjH / projH;
      const halfSpan = ((latMax - latMin) * factor) / 2;
      latMin = Math.max(-85, latCenter - halfSpan);
      latMax = Math.min(85, latCenter + halfSpan);
      bboxAdjusted = true;
    }
    if (bboxAdjusted) {
      // Re-project with adjusted bbox
      topLeft = magProjection([lonMin, latMax]);
      bottomRight = magProjection([lonMax, latMin]);
      projW = Math.abs(bottomRight[0] - topLeft[0]);
      projH = Math.abs(bottomRight[1] - topLeft[1]);
    }

    // Scale to fit the inset with some margin
    const margin = 0.85; // use 85% of inset area
    const scale = margin * Math.min(MAG_W / projW, MAG_H / projH);

    magProjection
      .scale(scale)
      .center([centerLon, centerLat])
      .translate([MAG_W / 2, MAG_H / 2]);
  }

  // Redraw the magnifier's static map layers after projection change
  function magRedrawMap() {
    magSphereGroup.select('path').attr('d', magPath);
    magLandGroup.selectAll('path').attr('d', magPath);
  }

  // Show the magnifier for a given arc event
  function magShowArc(ev, srcPt, dstPt, c1, c2, hitCount) {
    if (!magInitialized || !worldLandGeo) return;

    // Fit projection to the arc's bounding box
    magFitBbox(srcPt, dstPt);
    magRedrawMap();

    // Clear previous arc/dots in magnifier
    magArcGroup.selectAll('*').remove();
    magDotGroup.selectAll('*').remove();

    // Project points in magnifier space
    const [mx0, my0] = magProjection(srcPt);
    const [mx1, my1] = magProjection(dstPt);

    // Draw great-circle arc in magnifier
    const interp = d3.geoInterpolate(srcPt, dstPt);
    const N = 30; // higher fidelity for zoomed view
    const lineData = [];
    for (let i = 0; i <= N; i++) lineData.push(magProjection(interp(i / N)));
    const lineGen = d3.line().x(d => d[0]).y(d => d[1]).curve(d3.curveNatural);
    const fullD = lineGen(lineData);

    // Approximate path length
    let totalLen = 0;
    for (let i = 1; i < lineData.length; i++) {
      const dx = lineData[i][0] - lineData[i - 1][0];
      const dy = lineData[i][1] - lineData[i - 1][1];
      totalLen += Math.sqrt(dx * dx + dy * dy);
    }

    const sw = Math.min(8, 2 + (hitCount - 1) * 0.5);
    const magArc = magArcGroup.append('path')
      .attr('class', 'mag-arc')
      .attr('d', fullD)
      .attr('stroke', c1)
      .attr('stroke-width', sw)
      .attr('stroke-dasharray', totalLen)
      .attr('stroke-dashoffset', totalLen)
      .attr('opacity', 1);

    magArc.transition()
      .duration(800)
      .ease(d3.easeQuadInOut)
      .attr('stroke-dashoffset', 0);

    // Source dot
    const dotR = Math.min(8, 4 + Math.log2(hitCount));
    magDotGroup.append('circle')
      .attr('class', 'mag-dot')
      .attr('cx', mx0).attr('cy', my0)
      .attr('r', 0)
      .attr('fill', c1)
      .attr('opacity', 1)
      .transition().duration(300).attr('r', dotR);

    // Destination dot (self)
    if (selfPos) {
      magDotGroup.append('circle')
        .attr('class', 'mag-self-dot')
        .attr('cx', mx1).attr('cy', my1)
        .attr('r', 5);
    }

    // Source label
    const label = ev.src_city && ev.src_cc
      ? `${ev.src_city}, ${ev.src_cc}`
      : ev.src_city || ev.src_cc || ev.src_ip || '';
    if (label) {
      magDotGroup.append('text')
        .attr('x', mx0 + 8).attr('y', my0 - 6)
        .attr('fill', '#c8d8f0')
        .attr('font-size', '11px')
        .attr('font-family', 'inherit')
        .text(label);
    }

    // Show the magnifier
    magShow();
  }

  // Determine whether to show the magnifier for a given arc.
  // Returns true if:
  //   (a) the arc is short on screen AND the main map isn't already zoomed
  //       enough to make it clearly visible, OR
  //   (b) the main map is zoomed in far enough that the arc can't be seen
  //       in its entirety (one or both endpoints are outside the viewport).
  const MAG_SHORT_THRESHOLD = 0.25; // fraction of viewport width
  const MAG_ZOOMED_THRESHOLD = 0.12; // arc considered "large enough" when zoomed

  function shouldShowMagnifier(srcPt, dstPt) {
    const [x0, y0] = projection(srcPt);
    const [x1, y1] = projection(dstPt);
    const arcPixelDist = Math.sqrt((x1 - x0) ** 2 + (y1 - y0) ** 2);
    const isShort = arcPixelDist < w * MAG_SHORT_THRESHOLD;

    // Check if either endpoint falls outside the visible viewport
    const offScreen = x0 < 0 || x0 > w || y0 < 0 || y0 > h ||
                      x1 < 0 || x1 > w || y1 < 0 || y1 > h;

    const isZoomed = currentTransform.k > 1.5;

    // Case 1: Arc is short on screen but the map is zoomed in enough that
    // the arc is already reasonably sized — suppress the magnifier.
    if (isShort && isZoomed && arcPixelDist >= w * MAG_ZOOMED_THRESHOLD) {
      return false;
    }

    // Case 2: Map is zoomed in and the arc extends beyond the viewport —
    // show the magnifier so the user can see the full arc.
    if (isZoomed && offScreen) {
      return true;
    }

    // Case 3: Original behavior — show for short arcs at default zoom.
    return isShort;
  }

  function magShow() {
    if (!magVisible) {
      magVisible = true;
      magEl.classList.add('visible');
    }
    // Reset idle timer
    if (magIdleTimer) clearTimeout(magIdleTimer);
    magIdleTimer = setTimeout(magHide, MAG_IDLE_MS);
  }

  function magHide() {
    magVisible = false;
    magEl.classList.remove('visible');
    magIdleTimer = null;
  }

  // ── Self dot ─────────────────────────────────────────────────────────────
  let selfDotEl = null;

  function drawSelfDot() {
    if (!selfPos) return;
    const [sx, sy] = projection([selfPos.lon, selfPos.lat]);
    if (selfDotEl) selfDotEl.remove();
    selfDotEl = dotGroup.append('circle')
      .attr('class', 'self-dot')
      .attr('cx', sx)
      .attr('cy', sy)
      .attr('r', 5)
      .attr('filter', 'url(#glow-blue)');
  }

  // ── Resize ───────────────────────────────────────────────────────────────
  function resize() {
    const d = dims();
    w = d.w; h = d.h;

    // Update base projection parameters for the new viewport size.
    // reproject() will apply the current zoom transform on top.
    baseScale = w / 6.3;
    baseTranslate = [w / 2, h / 2];

    reproject();
  }

  window.addEventListener('resize', () => resize());

  // ── Self info ────────────────────────────────────────────────────────────
  fetch('/api/self')
    .then(r => r.json())
    .then(data => {
      selfPos = { lat: data.lat, lon: data.lon, ip: data.ip, city: data.city, cc: data.cc };
      document.getElementById('my-ip').textContent = data.ip || '—';
      document.getElementById('my-loc').textContent =
        [data.city, data.cc].filter(Boolean).join(', ') || '—';
      drawSelfDot();
    })
    .catch(e => console.warn('Self info fetch failed:', e));

  // Dirty flags — set true when data changes; cleared after each render
  let serviceDirty = false;
  let logDirty = false;
  let logRafScheduled = false;

  // ── Sidebar renders on a 2-second interval (decoupled from events) ──
  // Uses requestIdleCallback to avoid competing with arc animations.
  // Falls back to setTimeout for browsers without rIC support.
  const scheduleIdle = window.requestIdleCallback
    ? (fn) => requestIdleCallback(fn, { timeout: 3000 })
    : (fn) => setTimeout(fn, 100);

  function sidebarLoop() {
    scheduleIdle(() => {
      renderSidebar();
      setTimeout(sidebarLoop, 2000);
    });
  }
  setTimeout(sidebarLoop, 2000);

  function renderSidebar() {
    renderServiceStats();
  }

  // ── Banned IPs panel ─────────────────────────────────────────────────────
  const bannedRowsEl = document.getElementById('banned-rows');

  function formatTimeRemaining(expiresAt) {
    const ms = new Date(expiresAt) - Date.now();
    if (ms <= 0) return 'expiring';
    const totalSec = Math.floor(ms / 1000);
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    const s = totalSec % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function renderBannedPanel(bans) {
    bannedRowsEl.innerHTML = '';
    if (!bans || bans.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'ban-empty';
      empty.textContent = 'none';
      bannedRowsEl.appendChild(empty);
      return;
    }
    bans.forEach(b => {
      const row = document.createElement('div');
      row.className = 'ban-row';
      const remaining = formatTimeRemaining(b.expires_at);
      row.innerHTML =
        `<div class="ban-ip">${b.ip}</div>` +
        `<div class="ban-meta">port ${b.port} &mdash; ${b.service || 'unknown'}</div>` +
        `<div class="ban-expire">expires in ${remaining}</div>`;
      bannedRowsEl.appendChild(row);
    });
  }

  function fetchBanned() {
    fetch('/api/banned')
      .then(r => r.json())
      .then(bans => { renderBannedPanel(bans); syncBannedSet(bans); })
      .catch(() => {});
  }

  // Poll every 10 seconds to refresh ban list and countdown labels.
  fetchBanned();
  setInterval(fetchBanned, 10000);

  // ── Port Scanners panel ───────────────────────────────────────────────────
  const scannerRowsEl = document.getElementById('scanner-rows');

  function renderScannerPanel(scanners) {
    scannerRowsEl.innerHTML = '';
    if (!scanners || scanners.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'scan-empty';
      empty.textContent = 'none';
      scannerRowsEl.appendChild(empty);
      return;
    }
    scanners.forEach(s => {
      const row = document.createElement('div');
      row.className = 'scan-row';
      const remaining = formatTimeRemaining(s.expires_at);
      const ago = formatTimeAgo(s.detected_at);
      row.innerHTML =
        `<div class="scan-ip">${s.ip}</div>` +
        `<div class="scan-meta">${s.port_count} ports &mdash; detected ${ago}</div>` +
        `<div class="scan-expire">clears in ${remaining}</div>`;
      scannerRowsEl.appendChild(row);
    });
  }

  function formatTimeAgo(isoStr) {
    const ms = Date.now() - new Date(isoStr);
    if (ms < 0) return 'just now';
    const totalSec = Math.floor(ms / 1000);
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    const s = totalSec % 60;
    if (h > 0) return `${h}h ${m}m ago`;
    if (m > 0) return `${m}m ${s}s ago`;
    return `${s}s ago`;
  }

  function fetchScanners() {
    fetch('/api/scanners')
      .then(r => r.json())
      .then(scanners => renderScannerPanel(scanners))
      .catch(() => {});
  }

  // Poll every 10 seconds, same cadence as banned panel.
  fetchScanners();
  setInterval(fetchScanners, 10000);

  // ── Log/arc rendering stays on rAF for low-latency display ──
  function scheduleLogRender() {
    if (logRafScheduled) return;
    logRafScheduled = true;
    requestAnimationFrame(() => { logRafScheduled = false; flushLog(); });
  }

  // ── Service stats ─────────────────────────────────────────────────────────
  // PORT_SERVICE_NAMES is defined in /services.js (single source of truth).
  const PORT_SERVICE_NAMES = window.PORT_SERVICE_NAMES;

  const serviceStats = {}; // { port -> count }
  const serviceRowsEl = document.getElementById('service-rows');
  const serviceRowMap = new Map(); // port -> { row, countEl, barEl }

  function updateServiceStats(port) {
    if (!port) return;
    serviceStats[port] = (serviceStats[port] || 0) + 1;
    serviceDirty = true;
  }

  function renderServiceStats() {
    if (!serviceDirty) return;
    serviceDirty = false;
    const top = Object.entries(serviceStats).sort((a, b) => b[1] - a[1]).slice(0, 20);
    const topSet = new Set(top.map(([p]) => p));
    const maxCount = top.length > 0 ? top[0][1] : 1;

    // Remove rows no longer in top 20
    for (const [p, entry] of serviceRowMap) {
      if (!topSet.has(p)) { entry.row.remove(); serviceRowMap.delete(p); }
    }

    // Create or update rows
    top.forEach(([p, count]) => {
      const svcName = PORT_SERVICE_NAMES[p] || `port ${p}`;
      const portColor = portStats[p]?.color || '#546e7a';
      const pct = Math.max(4, Math.round((count / maxCount) * 100));
      let entry = serviceRowMap.get(p);
      if (!entry) {
        const row = document.createElement('div');
        row.className = 'stat-row';
        row.style.flexDirection = 'column';
        row.style.alignItems = 'stretch';
        row.style.gap = '2px';
        row.innerHTML =
          `<div style="display:flex;align-items:center;gap:6px;">` +
            `<span class="stat-label" style="color:${portColor}">:${p} <span style="color:#78909c;font-weight:400">${svcName}</span></span>` +
            `<span class="stat-count"></span>` +
          `</div>` +
          `<div style="height:3px;border-radius:2px;background:rgba(255,255,255,0.07);overflow:hidden;">` +
            `<div style="height:100%;width:0%;background:${portColor};opacity:0.7;border-radius:2px;"></div>` +
          `</div>`;
        const countEl = row.querySelector('.stat-count');
        const barEl = row.querySelector('div > div:last-child > div');
        entry = { row, countEl, barEl };
        serviceRowsEl.appendChild(row);
        serviceRowMap.set(p, entry);
      }
      const countStr = String(count);
      if (entry.countEl.textContent !== countStr) entry.countEl.textContent = countStr;
      const pctStr = pct + '%';
      if (entry.barEl.style.width !== pctStr) entry.barEl.style.width = pctStr;
    });

    // Reorder only if current DOM order differs from sorted order
    const currentKeys = [...serviceRowsEl.children].map(r => {
      const label = r.querySelector('.stat-label');
      return label ? label.textContent.split(' ')[0].replace(':', '') : '';
    });
    const sortedKeys = top.map(([p]) => p);
    const orderChanged = sortedKeys.length !== currentKeys.length || sortedKeys.some((k, i) => k !== currentKeys[i]);
    if (orderChanged) {
      top.forEach(([p]) => serviceRowsEl.appendChild(serviceRowMap.get(p).row));
    }
  }

  // ── Arc drawing ──────────────────────────────────────────────────────────
  let arcSeq = 0;

  // Colour palette cycling for distinct arcs
  const PALETTE = [
    ['#ff9800', '#4fc3f7'],
    ['#ef5350', '#80cbc4'],
    ['#ab47bc', '#fff176'],
    ['#26c6da', '#ff8a65'],
    ['#66bb6a', '#f48fb1'],
  ];

  // ── Arc registry — persistent arcs with pulse reuse ─────────────────────
  // Key: src_ip (string)
  // Value: { arcPath, gradEntry, c1, c2, srcPt, dstPt, lineData,
  //          totalLen, hitCount, expireTimer, dotEl, ev }
  const arcRegistry = new Map();
  const ARC_TTL = 12000;         // ms — idle timeout before arc fades out
  const ARC_REST_OPACITY = 0.18; // resting opacity of persistent arcs
  const PULSE_DURATION = 1200;   // ms — pulse travel time src→dst
  const MAX_PULSES = 80;         // cap concurrent pulse particles
  let activePulses = 0;

  // ── Audio engine — Web Audio API tones per event ──────────────────────
  // Plays a short sine-wave tone for each live event. Duration is
  // proportional to the great-circle arc length. Toggle persisted in cookie.
  const _audioCookie = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('audioEnabled='));
  let audioEnabled = _audioCookie ? _audioCookie.split('=')[1] === 'true' : false;
  let audioCtx = null;

  const AUDIO_MIN_DURATION = 0.06;  // seconds — shortest tone (nearby)
  const AUDIO_MAX_DURATION = 0.50;  // seconds — longest tone (antipodal)
  const AUDIO_BASE_FREQ    = 220;   // Hz — lowest pitch (long arcs)
  const AUDIO_TOP_FREQ     = 1320;  // Hz — highest pitch (short arcs)
  const AUDIO_GAIN         = 0.07;  // master volume (gentle)
  const MAX_CONCURRENT_TONES = 12;  // prevent audio pile-up under floods
  let activeTones = 0;

  function ensureAudioCtx() {
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (audioCtx.state === 'suspended') audioCtx.resume();
    return audioCtx;
  }

  // Great-circle distance in km between two [lon, lat] points.
  function geoDistKm(a, b) {
    const R = 6371;
    const toRad = Math.PI / 180;
    const dLat = (b[1] - a[1]) * toRad;
    const dLon = (b[0] - a[0]) * toRad;
    const sinLat = Math.sin(dLat / 2);
    const sinLon = Math.sin(dLon / 2);
    const h = sinLat * sinLat +
              Math.cos(a[1] * toRad) * Math.cos(b[1] * toRad) * sinLon * sinLon;
    return R * 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
  }

  const MAX_GEO_DIST = 20015; // half Earth circumference in km

  // Play a tone for a single event.
  // srcPt/dstPt are [lon, lat].
  function playEventTone(srcPt, dstPt) {
    if (!audioEnabled || activeTones >= MAX_CONCURRENT_TONES) return;
    const ctx = ensureAudioCtx();

    const dist = geoDistKm(srcPt, dstPt);
    const t = Math.min(dist / MAX_GEO_DIST, 1); // 0 = nearby, 1 = antipodal

    // Duration: longer arcs get longer tones
    const duration = AUDIO_MIN_DURATION + t * (AUDIO_MAX_DURATION - AUDIO_MIN_DURATION);
    // Frequency: shorter arcs get higher pitch, longer arcs get lower pitch
    const freq = AUDIO_TOP_FREQ - t * (AUDIO_TOP_FREQ - AUDIO_BASE_FREQ);

    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(freq, now);
    // Gentle pitch glide down over the tone duration
    osc.frequency.exponentialRampToValueAtTime(freq * 0.85, now + duration);

    gain.gain.setValueAtTime(0, now);
    // Fast attack
    gain.gain.linearRampToValueAtTime(AUDIO_GAIN, now + 0.008);
    // Sustain then smooth release
    gain.gain.setValueAtTime(AUDIO_GAIN, now + duration * 0.5);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);

    osc.connect(gain);
    gain.connect(ctx.destination);

    activeTones++;
    osc.start(now);
    osc.stop(now + duration);
    osc.onended = () => { activeTones--; osc.disconnect(); gain.disconnect(); };
  }

  // Toggle button wiring
  const audioToggleBtn = document.getElementById('audio-toggle');
  audioToggleBtn.classList.toggle('active', audioEnabled); // reflect cookie state on load
  audioToggleBtn.addEventListener('click', () => {
    audioEnabled = !audioEnabled;
    audioToggleBtn.classList.toggle('active', audioEnabled);
    document.cookie = `audioEnabled=${audioEnabled};path=/;max-age=31536000`;
    if (audioEnabled) ensureAudioCtx();
  });

  // Browsers block AudioContext creation until a user gesture has occurred.
  // If the cookie restored audioEnabled=true, we need the first interaction
  // anywhere on the page to unlock the AudioContext — otherwise no sound
  // plays even though the button shows as active.
  if (audioEnabled) {
    const unlockAudio = () => {
      ensureAudioCtx();
      document.removeEventListener('pointerdown', unlockAudio);
      document.removeEventListener('keydown', unlockAudio);
    };
    document.addEventListener('pointerdown', unlockAudio);
    document.addEventListener('keydown', unlockAudio);
  }

  // ── Adaptive arc rate control ────────────────────────────────────────────
  // Track event timestamps in a 1-second sliding window to measure rate.
  const FLOOD_THRESHOLD = 10;  // events/sec — above this we batch
  const arcTimestamps = [];    // recent event arrival times (ms)

  function currentRate() {
    const now = performance.now();
    // Evict timestamps older than 1 second
    while (arcTimestamps.length > 0 && now - arcTimestamps[0] > 1000) {
      arcTimestamps.shift();
    }
    return arcTimestamps.length;
  }

  // Flood buffer — only used when rate >= FLOOD_THRESHOLD
  // Key: src_ip  Value: { ev, count } — deduplicates floods from same IP
  const arcBuffer = new Map();
  let floodFlushTimer = null;

  function handleArc(ev) {
    if (!ev.src_lon && !ev.src_lat) return;
    arcTimestamps.push(performance.now());

    if (currentRate() < FLOOD_THRESHOLD) {
      // Normal traffic — draw immediately, no latency
      dispatchArc(ev, 1);
    } else {
      // Flood — buffer and deduplicate by source IP
      const key = ev.src_ip || `${ev.src_lon},${ev.src_lat}`;
      if (arcBuffer.has(key)) {
        arcBuffer.get(key).count++;
      } else {
        arcBuffer.set(key, { ev, count: 1 });
      }
      // Ensure a flush is scheduled (only one timer at a time)
      if (!floodFlushTimer) {
        floodFlushTimer = setTimeout(flushArcs, 1000);
      }
    }
  }

  // stroke-width scales with hit count: 1 hit → 1.5px, 10+ hits → 6px
  function arcWidth(count) {
    return Math.min(6, 1.5 + (count - 1) * 0.5);
  }

  function flushArcs() {
    floodFlushTimer = null;
    if (arcBuffer.size === 0) return;
    const entries = [...arcBuffer.values()];
    arcBuffer.clear();
    entries.forEach(({ ev, count }) => dispatchArc(ev, count));
  }

  // ── Dispatch: reuse existing arc or create new one ──────────────────────
  function dispatchArc(ev, hitCount) {
    const key = ev.src_ip || `${ev.src_lon},${ev.src_lat}`;
    const existing = arcRegistry.get(key);

    if (existing) {
      // Reuse — reset TTL, pulse, flash arc brighter
      existing.hitCount += hitCount;
      resetArcTTL(key, existing);
      flashArc(existing);
      sendPulse(existing, hitCount);
      pulseDot(existing, hitCount);
      // Update tooltip with new hit count (pass ev so ban button stays correct)
      attachTooltip(existing.dotEl, tooltipLabel(existing.ev, existing.hitCount), existing.ev);
      // Trigger magnifier for short arcs or arcs clipped by zoom
      if (shouldShowMagnifier(existing.srcPt, existing.dstPt)) {
        magShowArc(ev, existing.srcPt, existing.dstPt, existing.c1, existing.c2, existing.hitCount);
      }
    } else {
      drawArc(ev, hitCount);
    }

    // Audio: play a tone for this event (src/dst coords always available)
    playEventTone([ev.src_lon, ev.src_lat], [ev.dst_lon, ev.dst_lat]);
  }

  // ── Draw a new persistent arc ───────────────────────────────────────────
  function drawArc(ev, hitCount = 1) {
    const srcPt = [ev.src_lon, ev.src_lat];
    const dstPt = [ev.dst_lon, ev.dst_lat];

    if (!srcPt[0] && !srcPt[1]) return; // no geo data

    // Use the port's assigned color as c1 if available, else cycle palette
    const portColor = portStats[ev.dst_port]?.color;
    const [c1, c2] = portColor
      ? [portColor, '#ffffff']
      : PALETTE[arcSeq % PALETTE.length];
    arcSeq++;

    const [x0, y0] = projection(srcPt);
    const [x1, y1] = projection(dstPt);

    // Reuse pooled gradient by color pair
    const gradEntry = acquireGradient(c1, c2, x0, y0, x1, y1);

    // Build arc as a simple screen-space quadratic bezier.
    // Control point sits above the midpoint; the bulge height scales with the
    // chord distance so short arcs get a gentle curve, long arcs get a taller bow.
    const mx = (x0 + x1) / 2;
    const my = (y0 + y1) / 2;
    const chord = Math.sqrt((x1 - x0) ** 2 + (y1 - y0) ** 2);
    const bulge = Math.min(chord * 0.35, h * 0.25);
    const cx = mx;
    const cy = my - bulge;
    const fullD = `M${x0},${y0} Q${cx},${cy} ${x1},${y1}`;

    // Sample points along the bezier for pulse animation & length estimation
    const N = 20;
    const lineData = [];
    for (let i = 0; i <= N; i++) {
      const t = i / N;
      const u = 1 - t;
      lineData.push([
        u * u * x0 + 2 * u * t * cx + t * t * x1,
        u * u * y0 + 2 * u * t * cy + t * t * y1,
      ]);
    }

    const sw = arcWidth(hitCount);
    const arcPath = arcGroup.append('path')
      .attr('class', 'arc-path')
      .attr('d', fullD)
      .attr('stroke', `url(#${gradEntry.id})`)
      .attr('stroke-width', sw)
      .attr('opacity', 0);

    // Approximate path length from segment distances
    let totalLen = 0;
    for (let i = 1; i < lineData.length; i++) {
      const dx = lineData[i][0] - lineData[i - 1][0];
      const dy = lineData[i][1] - lineData[i - 1][1];
      totalLen += Math.sqrt(dx * dx + dy * dy);
    }

    // Arc appears immediately at resting opacity — no draw-in flash.
    // The pulse particle traveling along the arc is the primary visual cue.
    arcPath
      .attr('stroke-dasharray', 'none')
      .attr('opacity', ARC_REST_OPACITY)
      .classed('resting', true);

    // Source dot — animates in bright, then settles as a persistent faded dot
    const dotR = Math.min(6, 3 + Math.log2(hitCount));
    const srcDot = dotGroup.append('circle')
      .attr('class', 'src-dot')
      .attr('cx', x0)
      .attr('cy', y0)
      .attr('r', 0)
      .attr('fill', c1)
      .attr('opacity', 1)
      .style('cursor', 'crosshair')
      .datum(srcPt); // store [lon, lat] for reprojection on resize

    attachTooltip(srcDot, tooltipLabel(ev, hitCount), ev);
    tagDotWithEvent(srcDot, ev);

    // Apply banned styling immediately if this IP is already in the ban set.
    if (bannedSet.has(banKey(ev.src_ip, ev.dst_port))) {
      srcDot.classed('banned', true).attr('fill', '#ef5350').attr('opacity', 0.9);
    }

    srcDot.transition().duration(300).attr('r', dotR + 1)
      .transition().delay(2500).duration(600)
        .attr('r', dotR)
        .attr('opacity', 0.35);

    trackDot(srcDot.node());

    // Register this arc for pulse reuse
    const key = ev.src_ip || `${ev.src_lon},${ev.src_lat}`;
    const entry = {
      arcPath, gradEntry, c1, c2, srcPt, dstPt,
      lineData, totalLen,
      hitCount, expireTimer: null, dotEl: srcDot, ev,
    };
    arcRegistry.set(key, entry);
    resetArcTTL(key, entry);
    trackArc(key); // track by registry key, not DOM node

    // Send initial pulse particle along the new arc
    sendPulse(entry, hitCount);

    // Trigger magnifier for short arcs or arcs clipped by zoom
    if (shouldShowMagnifier(srcPt, dstPt)) {
      magShowArc(ev, srcPt, dstPt, c1, c2, hitCount);
    }
  }

  // ── Arc TTL management ──────────────────────────────────────────────────
  function resetArcTTL(key, entry) {
    if (entry.expireTimer) clearTimeout(entry.expireTimer);
    entry.expireTimer = setTimeout(() => expireArc(key), ARC_TTL);
  }

  function expireArc(key) {
    const entry = arcRegistry.get(key);
    if (!entry) return;
    arcRegistry.delete(key);
    // Fade out and remove the arc path
    entry.arcPath
      .interrupt() // cancel any in-progress transition
      .transition()
        .duration(800)
        .attr('opacity', 0)
      .on('end', function() {
        d3.select(this).remove();
      });
    releaseGradient(entry.c1, entry.c2);
    // Remove from arcRing
    const idx = arcRing.indexOf(key);
    if (idx !== -1) arcRing.splice(idx, 1);
  }

  // ── Update arc on repeat hit (no flash — pulse particle is the cue) ────
  function flashArc(entry) {
    // Thicken stroke based on cumulative hits (no opacity flash)
    const sw = arcWidth(Math.min(entry.hitCount, 20));
    entry.arcPath.attr('stroke-width', sw);
  }

  // ── Pulse particle — travels along cached path points ───────────────────
  function sendPulse(entry, hitCount) {
    if (activePulses >= MAX_PULSES) return; // cap to avoid DOM overload
    activePulses++;

    const pts = entry.lineData;
    if (!pts || pts.length < 2) { activePulses--; return; }

    const pulseR = Math.min(8, 4 + Math.log2(hitCount) * 0.8);
    const pulse = pulseGroup.append('circle')
      .attr('class', 'arc-pulse')
      .attr('cx', pts[0][0])
      .attr('cy', pts[0][1])
      .attr('r', pulseR)
      .attr('fill', entry.c1)
      .attr('opacity', 0.95)
      .attr('stroke', entry.c1)
      .attr('stroke-width', pulseR * 0.8)
      .attr('stroke-opacity', 0.5);

    const duration = PULSE_DURATION;
    const lastIdx = pts.length - 1;

    d3.timer(function(elapsed) {
      const t = Math.min(1, elapsed / duration);
      // Ease for smooth acceleration/deceleration
      const et = d3.easeQuadInOut(t);
      // Interpolate along the pre-computed point array
      const rawIdx = et * lastIdx;
      const i = Math.floor(rawIdx);
      const f = rawIdx - i;
      const i2 = Math.min(i + 1, lastIdx);
      const x = pts[i][0] + (pts[i2][0] - pts[i][0]) * f;
      const y = pts[i][1] + (pts[i2][1] - pts[i][1]) * f;

      pulse.attr('cx', x).attr('cy', y);
      // Fade out over the last 20% of travel
      if (t > 0.8) {
        pulse.attr('opacity', 0.95 * (1 - (t - 0.8) / 0.2));
      }

      if (t >= 1) {
        pulse.remove();
        activePulses--;
        return true; // stop timer
      }
    });
  }

  // ── Pulse the existing dot on repeat hit ────────────────────────────────
  function pulseDot(entry, hitCount) {
    if (!entry.dotEl) return;
    const dotR = Math.min(6, 3 + Math.log2(entry.hitCount));
    entry.dotEl
      .interrupt()
      .attr('opacity', 1)
      .attr('r', dotR + 2)
      .transition().duration(400)
        .attr('r', dotR)
        .attr('opacity', 0.50);
  }

  // ── Dot lifecycle cap ───────────────────────────────────────────────────
  const MAX_DOTS = 1000;
  const dotRing = []; // circular buffer of DOM nodes

  function trackDot(node) {
    dotRing.push(node);
    while (dotRing.length > MAX_DOTS) {
      const old = dotRing.shift();
      if (old.parentNode) old.parentNode.removeChild(old);
    }
  }

  // ── Arc lifecycle cap ─────────────────────────────────────────────────
  const MAX_ARCS = 150;
  const arcRing = []; // circular buffer of registry keys

  function trackArc(key) {
    arcRing.push(key);
    while (arcRing.length > MAX_ARCS) {
      const oldKey = arcRing.shift();
      // Force-expire the oldest arc
      const entry = arcRegistry.get(oldKey);
      if (entry) {
        if (entry.expireTimer) clearTimeout(entry.expireTimer);
        arcRegistry.delete(oldKey);
        entry.arcPath.remove();
        releaseGradient(entry.c1, entry.c2);
      }
    }
  }

  // ── Log panel ─────────────────────────────────────────────────────────────
  const logPanel = document.getElementById('log-panel');
  const logBuffer = []; // pending entries, flushed on next rAF

  function addLog(ev) {
    logBuffer.push(ev);
    logDirty = true;
    scheduleLogRender();
  }

  function flushLog() {
    if (!logDirty) return;
    logDirty = false;
    if (logBuffer.length === 0) return;
    const entries = logBuffer.splice(0); // drain buffer atomically
    // Build a fragment so we touch the DOM once per frame
    const frag = document.createDocumentFragment();
    entries.forEach(ev => {
      const t = new Date(ev.time);
      const ts = t.toLocaleTimeString('en-US', { hour12: false });
      const srcLabel = [ev.src_ip, ev.src_city, ev.src_cc].filter(Boolean).join(' / ');
      const portNum = ev.dst_port && ev.dst_port !== 'unknown' ? ev.dst_port : '';
      const svcName = portNum ? (PORT_SERVICE_NAMES[portNum] || '') : '';
      const portLabel = portNum ? `:${portNum}${svcName ? ' ' + svcName : ''}` : '';
      const protoLabel = ev.protocol ? ev.protocol.toUpperCase() : '';
      const row = document.createElement('div');
      row.className = 'log-entry';

      // Build the main line using textContent (safe from XSS)
      const timeSpan = document.createElement('span');
      timeSpan.className = 'log-time';
      timeSpan.textContent = ts;
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

      if (ev.src_lat && ev.src_lon) {
        row.addEventListener('click', () => {
          dispatchArc(ev, 1);
          row.classList.add('arc-flash');
          setTimeout(() => row.classList.remove('arc-flash'), 400);
        });
      } else {
        row.style.cursor = 'default';
      }
      frag.prepend ? frag.prepend(row) : frag.insertBefore(row, frag.firstChild);
    });
    logPanel.prepend(frag);
    // Trim to 200 entries in one pass
    while (logPanel.children.length > 200) {
      logPanel.removeChild(logPanel.lastChild);
    }
  }

  // ── WebSocket ─────────────────────────────────────────────────────────────
  const wsStatus = document.getElementById('ws-status');
  const connCountEl = document.getElementById('conn-count');

  // ── Time slider state ──
  const timeSlider = document.getElementById('time-slider');
  const sliderLabel = document.getElementById('slider-label');
  let currentHours = 1;

  // Restore from cookie or default to 1h
  const savedHours = getCookie('wt_live_hours');
  if (savedHours) {
    const n = parseInt(savedHours, 10);
    if (n >= 1 && n <= 24) currentHours = n;
  }
  timeSlider.value = currentHours;
  sliderLabel.textContent = currentHours + 'h';

  // ── Reset all visual state for reconnect ──
  function resetState() {
    // Reset zoom to default view
    currentTransform = d3.zoomIdentity;
    svg.call(zoom.transform, d3.zoomIdentity);

    // Clear event ring + stats
    eventRing.length = 0;
    connCount = 0;
    connCountEl.textContent = '0';
    replayDone = false;

    // Clear port stats
    for (const k in portStats) delete portStats[k];
    portColorIdx = 0;

    // Clear service stats + DOM rows
    for (const k in serviceStats) delete serviceStats[k];
    for (const [, entry] of serviceRowMap) entry.row.remove();
    serviceRowMap.clear();
    serviceDirty = true;

    // Clear dots
    dotRing.length = 0;
    dotGroup.selectAll('.src-dot').remove();

    // Clear arcs
    arcRegistry.forEach((entry, key) => {
      if (entry.expireTimer) clearTimeout(entry.expireTimer);
      entry.arcPath.remove();
      releaseGradient(entry.c1, entry.c2);
    });
    arcRegistry.clear();
    arcRing.length = 0;
    arcGroup.selectAll('path').remove();
    activePulses = 0;

    // Clear arc flood buffer
    arcBuffer.clear();
    if (floodFlushTimer) { clearTimeout(floodFlushTimer); floodFlushTimer = null; }

    // Clear log
    logBuffer.length = 0;
    logPanel.innerHTML = '';
    logDirty = false;
  }

  // ── Ban toggle / hover card state ────────────────────────────────────────
  // bannedSet: tracks IPs currently banned, keyed by "ip|port".
  // Populated on load from /api/banned and kept in sync after each ban/unban.
  const bannedSet = new Set();

  function banKey(ip, port) { return `${ip}|${port}`; }

  // Sync bannedSet from the latest /api/banned response and update all dots.
  function syncBannedSet(bans) {
    bannedSet.clear();
    (bans || []).forEach(b => bannedSet.add(banKey(b.ip, b.port)));
    // Reflect ban state on every live dot that has ev data attached.
    dotGroup.selectAll('.src-dot').each(function() {
      const d3el = d3.select(this);
      const ev = this.__wtEv;
      if (!ev) return;
      const isBanned = bannedSet.has(banKey(ev.src_ip, ev.dst_port));
      d3el.classed('banned', isBanned);
      if (isBanned) d3el.attr('fill', '#ef5350').attr('opacity', 0.9);
    });
  }

  // Attach ev to the DOM node so the hover card can read it later.
  function tagDotWithEvent(dotEl, ev) {
    dotEl.node().__wtEv = ev;
  }

  function tooltipLabel(ev, hitCount = 1) {
    const city = ev.src_city || '';
    const cc   = ev.src_cc   || '';
    const loc  = (city && cc) ? `${city}, ${cc}` : city || cc || ev.src_ip || '';
    return hitCount > 1 ? `${loc} \u00d7${hitCount}` : loc;
  }

  // ── Hover card wiring ─────────────────────────────────────────────────────
  const dotTooltip  = document.getElementById('dot-tooltip');
  const tipLabelEl  = document.getElementById('tip-label-text');
  const tipBanBtn   = document.getElementById('tip-ban-btn');
  let tipHideTimer  = null;
  let tipCurrentEv  = null;

  function showTip(event, label, ev) {
    clearTimeout(tipHideTimer);
    tipCurrentEv = ev;
    tipLabelEl.textContent = label || ev.src_ip;

    const isBanned = ev && bannedSet.has(banKey(ev.src_ip, ev.dst_port));
    tipBanBtn.textContent = isBanned ? 'Unban' : 'Ban';
    tipBanBtn.className   = 'tip-ban' + (isBanned ? ' tip-unban' : '');
    tipBanBtn.style.display = ev ? 'block' : 'none';

    positionTip(event.clientX, event.clientY);
    dotTooltip.style.display = 'block';
  }

  function moveTip(x, y) {
    positionTip(x, y);
  }

  function positionTip(cx, cy) {
    const w = dotTooltip.offsetWidth  || 140;
    const h = dotTooltip.offsetHeight || 56;
    const x = Math.min(cx + 14, window.innerWidth  - w - 6);
    const y = Math.min(cy - 10, window.innerHeight - h - 6);
    dotTooltip.style.left = x + 'px';
    dotTooltip.style.top  = y + 'px';
  }

  function scheduleTipHide() {
    tipHideTimer = setTimeout(() => {
      dotTooltip.style.display = 'none';
      tipCurrentEv = null;
    }, 120);  // short delay — enough to move cursor from dot onto card
  }

  // Hovering on the card itself cancels the hide timer.
  dotTooltip.addEventListener('mouseenter', () => clearTimeout(tipHideTimer));
  dotTooltip.addEventListener('mouseleave', () => scheduleTipHide());

  tipBanBtn.addEventListener('click', () => {
    const ev = tipCurrentEv;
    dotTooltip.style.display = 'none';
    tipCurrentEv = null;
    if (!ev) return;
    const isBanned = bannedSet.has(banKey(ev.src_ip, ev.dst_port));
    const url = isBanned ? '/api/unban' : '/api/ban';
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ev.src_ip, port: ev.dst_port }),
    })
      .then(r => r.json())
      .then(() => fetchBanned())
      .catch(() => {});
  });

  function attachTooltip(sel, label, ev) {
    sel
      .on('mouseover', function(event) { showTip(event, label, ev); })
      .on('mousemove', function(event) { moveTip(event.clientX, event.clientY); })
      .on('mouseout',  function()      { scheduleTipHide(); });
  }

  // Draw a faded static dot for historical events (no arc animation)
  function drawHistoryDot(ev) {
    if (!ev.src_lon && !ev.src_lat) return;
    const srcPt = [ev.src_lon, ev.src_lat];
    const [x, y] = projection(srcPt);
    const portColor = portStats[ev.dst_port]?.color || '#546e7a';
    const dot = dotGroup.append('circle')
      .attr('class', 'src-dot')
      .attr('cx', x).attr('cy', y).attr('r', 3)
      .attr('fill', portColor)
      .attr('opacity', 0.35)
      .style('cursor', 'crosshair')
      .datum(srcPt); // store [lon, lat] for reprojection on resize
    attachTooltip(dot, tooltipLabel(ev), ev);
    tagDotWithEvent(dot, ev);
    if (bannedSet.has(banKey(ev.src_ip, ev.dst_port))) {
      dot.classed('banned', true).attr('fill', '#ef5350').attr('opacity', 0.9);
    }
    trackDot(dot.node());
  }

  let currentWs = null;

  function connect() {
    resetState();
    const ws = new WebSocket(`ws://${location.host}/ws?hours=${currentHours}`);
    currentWs = ws;

    ws.onopen = () => {
      wsStatus.className = 'connected';
    };

    ws.onmessage = (msg) => {
      if (ws !== currentWs) return; // stale connection, ignore
      let ev;
      try { ev = JSON.parse(msg.data); } catch { return; }

      recordEvent(ev);
      connCount = eventRing.length;
      connCountEl.textContent = connCount;

      ensurePortColor(ev.dst_port || 'unknown');
      updateServiceStats(ev.dst_port || 'unknown');
      addLog(ev);

      if (ev.replay) {
        drawHistoryDot(ev);
        // Flush log every 200 replay events so the log panel
        // populates progressively instead of staying empty.
        if (connCount % 200 === 0) flushLog();
      } else {
        // First live event after replay — flush sidebar once immediately
        // so panels are populated without waiting for the 2s timer.
        if (!replayDone) {
          replayDone = true;
          renderSidebar();
          flushLog();
        }
        handleArc(ev);  // instant at low rate, batched during floods
      }
    };

    ws.onclose = () => {
      // Only auto-reconnect if this is still the active connection
      // (slider changes replace currentWs before the old one closes)
      if (ws !== currentWs) return;
      wsStatus.className = 'disconnected';
      currentWs = null;
      setTimeout(connect, 2000);
    };

    ws.onerror = () => ws.close();
  }

  // Slider: update label instantly, debounce reconnect until user stops dragging
  let sliderTimer = null;
  timeSlider.addEventListener('input', () => {
    const val = parseInt(timeSlider.value, 10);
    sliderLabel.textContent = val + 'h';
    if (sliderTimer) clearTimeout(sliderTimer);
    sliderTimer = setTimeout(() => {
      sliderTimer = null;
      if (val === currentHours) return;
      currentHours = val;
      setCookie('wt_live_hours', val, 365);
      if (currentWs) currentWs.close();
      connect();
    }, 1000);
  });

  connect();

})();

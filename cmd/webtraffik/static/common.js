// common.js — shared utilities for all webTraffik pages
// Loaded as a plain global script (no ES modules).

// ── Cookie helpers ──────────────────────────────────────────────────────────
function setCookie(name, value, days) {
  const d = new Date();
  d.setTime(d.getTime() + days * 86400000);
  document.cookie = name + '=' + encodeURIComponent(value) + ';expires=' + d.toUTCString() + ';path=/;SameSite=Lax';
}

function getCookie(name) {
  const prefix = name + '=';
  const parts = document.cookie.split(';');
  for (let i = 0; i < parts.length; i++) {
    const c = parts[i].trim();
    if (c.indexOf(prefix) === 0) return decodeURIComponent(c.substring(prefix.length));
  }
  return '';
}

// ── Self-info fetch ─────────────────────────────────────────────────────────
// Populates #my-ip and #my-loc on any page that has those elements.
function fetchSelf() {
  fetch('/api/self')
    .then(r => r.json())
    .then(data => {
      const ipEl  = document.getElementById('my-ip');
      const locEl = document.getElementById('my-loc');
      if (ipEl)  ipEl.textContent  = data.ip || '\u2014';
      if (locEl) locEl.textContent = [data.city, data.cc].filter(Boolean).join(', ') || '\u2014';
    })
    .catch(() => {});
}

// ── Hex dump preview ────────────────────────────────────────────────────────
// Decodes a hex string into a hex+ASCII dump (plain text, safe for textContent).
function hexPreview(hexStr) {
  if (!hexStr) return '';
  const bytes = [];
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes.push(parseInt(hexStr.substr(i, 2), 16));
  }
  const lines = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk  = bytes.slice(off, off + 16);
    const hexPart = chunk.map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascPart = chunk.map(b => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.').join('');
    const addr    = off.toString(16).padStart(4, '0');
    lines.push(addr + '  ' + hexPart.padEnd(48) + '  ' + ascPart);
  }
  return lines.join('\n');
}

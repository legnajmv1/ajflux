/* ═══════════════════════════════════════════════
   AJFLUX — JavaScript Global
   ═══════════════════════════════════════════════ */

'use strict';

// Adjunta automáticamente X-CSRFToken a toda petición de escritura hecha con
// fetch() desde el panel web (sesión). La app móvil usa Authorization: Token
// y el middleware la exime de CSRF, así que esto no le afecta.
(function () {
  function getCookie(name) {
    const m = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return m ? decodeURIComponent(m[2]) : null;
  }
  const originalFetch = window.fetch;
  window.fetch = function (input, init) {
    init = init || {};
    const method = (init.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const token = getCookie('csrftoken');
      if (token) {
        init.headers = new Headers(init.headers || {});
        if (!init.headers.has('X-CSRFToken')) {
          init.headers.set('X-CSRFToken', token);
        }
      }
    }
    return originalFetch(input, init);
  };
})();

window.AJFLUX = {
  devices:   [],
  alerts:    [],
  topology:  { nodes: [], edges: [] },
  reports:   [],
  metrics:   {},
  scanRunning: false,
};

// ── Helpers de formato ─────────────────────────
function fLat(v)  { return v != null ? v.toFixed(0) + ' ms' : '—'; }
function fJit(v)  { return v != null ? v.toFixed(1) + ' ms' : '—'; }
function fLoss(v) { return v != null ? v.toFixed(1) + '%'   : '—'; }
function fQos(v)  { return v != null ? v.toFixed(0) + '%'   : '—'; }
function fTs(iso) {
  return new Date(iso).toLocaleString('es', { dateStyle: 'short', timeStyle: 'short' });
}

// ── Colores ────────────────────────────────────
function latClass(v) {
  if (!v)      return 'muted';
  if (v < 50)  return 'lat-good';
  if (v < 150) return 'lat-warn';
  return 'lat-bad';
}
function qosClass(v) {
  if (v == null) return 'muted';
  if (v >= 80)   return 'qos-good';
  if (v >= 60)   return 'qos-warn';
  return 'qos-bad';
}
function lossClass(v) { return (v && v > 1) ? 'lat-bad' : 'muted'; }

// ── Iconos ─────────────────────────────────────
const DEVICE_ICONS = {
  router:'router', switch:'device_hub', wifi:'wifi_tethering',
  server:'dns', desktop:'computer', laptop:'laptop',
  phone:'smartphone', tablet:'tablet_android', tv:'tv',
  camera:'videocam', printer:'print', iot:'memory',
};
function dIcon(type) { return DEVICE_ICONS[type] || 'devices_other'; }

const DEVICE_TYPES_ES = {
  router:'Router', switch:'Switch', wifi:'Punto de Acceso WiFi',
  server:'Servidor', desktop:'PC de escritorio', laptop:'Laptop',
  phone:'Teléfono', tablet:'Tablet', tv:'Televisor',
  camera:'Cámara IP', printer:'Impresora', iot:'Dispositivo IoT',
  unknown:'Desconocido',
};
function dTypeEs(type) { return DEVICE_TYPES_ES[type] || 'Desconocido'; }

// ── Chip de estado ─────────────────────────────
function statusChip(status) {
  const map = {
    online:  ['chip-online',  'En línea'],
    offline: ['chip-offline', 'Desconectado'],
    warning: ['chip-warning', 'Alerta'],
  };
  const [cls, label] = map[status] || ['chip-offline', 'Desconocido'];
  return `<span class="chip ${cls}">${label}</span>`;
}

// ── Polling central ────────────────────────────
function startPolling() {
  setConnStatus('online');
  pollLive();
  setInterval(pollLive, 8000);
}

function pollLive() {
  fetch('/api/live/')
    .then(r => r.json())
    .then(data => {
      setConnStatus('online');
      if (data.devices) {
        window.AJFLUX.devices = data.devices;
        document.dispatchEvent(new CustomEvent('ajflux:devices', { detail: data.devices }));
      }
      if (data.alerts) {
        window.AJFLUX.alerts = data.alerts;
        document.dispatchEvent(new CustomEvent('ajflux:alerts', { detail: data.alerts }));
      }
      if (data.scan) {
        const overlay = document.getElementById('scan-overlay');
        if (overlay) {
          if (data.scan.running) {
            overlay.classList.add('active');
            const bar = document.getElementById('scan-bar');
            const msg = document.getElementById('scan-status');
            if (bar) bar.style.width = data.scan.progress + '%';
            if (msg) msg.textContent = data.scan.message || 'Escaneando...';
          } else if (overlay.classList.contains('active')) {
            const bar = document.getElementById('scan-bar');
            const msg = document.getElementById('scan-status');
            if (bar) bar.style.width = '100%';
            if (msg) msg.textContent = 'Escaneo completado ✓';
            setTimeout(() => {
              overlay.classList.remove('active');
              if (bar) bar.style.width = '0%';
              document.dispatchEvent(new CustomEvent('ajflux:scan_complete'));
            }, 1200);
          }
        }
      }
    })
    .catch(() => setConnStatus('offline'));
}

function setConnStatus(state) {
  const dot   = document.getElementById('conn-dot');
  const txt   = document.getElementById('conn-text');
  const lDot  = document.getElementById('live-dot');
  const lLbl  = document.getElementById('live-label');

  if (state === 'online') {
    if (dot)  { dot.style.background = 'var(--primary)'; dot.style.boxShadow = '0 0 6px var(--primary)'; dot.classList.add('pulse-anim'); }
    if (txt)  { txt.textContent = 'En línea'; txt.style.color = 'var(--primary)'; }
    if (lDot) { lDot.style.background = 'var(--primary)'; lDot.style.boxShadow = '0 0 8px var(--primary)'; }
    if (lLbl) lLbl.textContent = 'En vivo';
  } else {
    if (dot)  { dot.style.background = 'var(--red)'; dot.style.boxShadow = '0 0 6px var(--red)'; dot.classList.remove('pulse-anim'); }
    if (txt)  { txt.textContent = 'Sin conexión'; txt.style.color = 'var(--red)'; }
    if (lDot) { lDot.style.background = 'var(--red)'; lDot.style.boxShadow = 'none'; }
    if (lLbl) lLbl.textContent = 'Desconectado';
  }
}

// ── Escaneo ────────────────────────────────────
function triggerScan() {
  const overlay = document.getElementById('scan-overlay');
  if (overlay) overlay.classList.add('active');
  const bar = document.getElementById('scan-bar');
  const msg = document.getElementById('scan-status');
  if (bar) bar.style.width = '2%';
  if (msg) msg.textContent = 'Iniciando escaneo ARP...';
  fetch('/api/scan/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  }).catch(() => { if (overlay) overlay.classList.remove('active'); });
}

// ── Sidebar ────────────────────────────────────
function toggleSidebar() {
  const sidebar  = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  sidebar.classList.toggle('open');
  if (backdrop) backdrop.classList.toggle('active', sidebar.classList.contains('open'));
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  const backdrop = document.getElementById('sidebar-backdrop');
  if (backdrop) backdrop.classList.remove('active');
}

// ── Reloj ──────────────────────────────────────
function startClock() {
  const el = document.getElementById('live-clock');
  if (!el) return;
  const tick = () => el.textContent =
    new Date().toLocaleTimeString('es', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
  tick();
  setInterval(tick, 1000);
}

// ── Exportar PDF ───────────────────────────────
function exportPDF(reportId) {
  const url = reportId ? `/reportes/exportar-pdf/${reportId}/` : '/reportes/exportar-pdf/';
  window.open(url, '_blank');
}

// ── Tema claro/oscuro ──────────────────────────
// Chart.js dibuja en canvas y no entiende var(--x), así que los colores de
// los gráficos se leen del CSS y se cambian a mano al alternar el tema.
const THEME_LIGHT_SWAP = {
  '#00d4ff': '#0077a8', '#00e676': '#0a8f4a', '#ffab00': '#b36b00', '#ff3366': '#d61f4f',
};

function isLightTheme() {
  return document.documentElement.getAttribute('data-theme') === 'light';
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function themeColor(color) {
  return isLightTheme() ? (THEME_LIGHT_SWAP[String(color).toLowerCase()] || color) : color;
}

function applyChartTheme() {
  if (typeof Chart === 'undefined') return;
  Object.values(Chart.instances).forEach(chart => {
    const o = chart.options;
    if (o.plugins && o.plugins.legend && o.plugins.legend.labels) o.plugins.legend.labels.color = cssVar('--chart-legend');
    if (o.scales && o.scales.y) {
      o.scales.y.grid.color = cssVar('--chart-grid');
      o.scales.y.ticks.color = cssVar('--chart-tick');
      if (o.scales.y.border) o.scales.y.border.color = cssVar('--chart-grid');
    }
    chart.data.datasets.forEach(ds => {
      if (!ds._baseColor) return;
      ds.borderColor = themeColor(ds._baseColor);
      ds.backgroundColor = themeColor(ds._baseColor) + '14';
    });
    chart.update('none');
  });
}

function toggleTheme() {
  const light = !isLightTheme();
  if (light) document.documentElement.setAttribute('data-theme', 'light');
  else document.documentElement.removeAttribute('data-theme');
  try { localStorage.setItem('ajflux.theme', light ? 'light' : 'dark'); } catch (e) {}
  applyChartTheme();
  document.dispatchEvent(new CustomEvent('ajflux:theme', { detail: { light } }));
}

// ── Gráfico de línea ───────────────────────────
function makeLineChart(canvasId, labels, datasets, yLabel = '') {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  const key = '_chart_' + canvasId;
  if (window[key]) window[key].destroy();
  window[key] = new Chart(ctx.getContext('2d'), {
    type: 'line',
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          display: datasets.length > 1,
          labels: { color: cssVar('--chart-legend'), font: { size: 12, family: "'JetBrains Mono', monospace" } },
        },
      },
      scales: {
        x: { display: false },
        y: {
          min: 0,
          grid: { color: cssVar('--chart-grid') },
          ticks: {
            color: cssVar('--chart-tick'),
            font: { size: 12, family: "'JetBrains Mono', monospace" },
            callback: v => v + yLabel,
          },
          border: { color: cssVar('--chart-grid') },
        },
      },
    },
  });
  return window[key];
}

function chartDataset(data, color, label = '') {
  return {
    label,
    data,
    _baseColor: color,
    borderColor: themeColor(color),
    backgroundColor: themeColor(color) + '14',
    borderWidth: 1.5,
    pointRadius: 0,
    tension: 0.4,
    fill: true,
  };
}

// ── Eliminar blur en móvil vía JS (respaldo al CSS) ────────────
function removeMobileBlur() {
  if (window.innerWidth > 768) return;
  const canvas = document.getElementById('net-canvas');
  if (canvas) canvas.style.display = 'none';
  document.querySelectorAll('*').forEach(el => {
    el.style.backdropFilter = 'none';
    el.style.webkitBackdropFilter = 'none';
  });
}

// ── Init ───────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  removeMobileBlur();
  startClock();
  startPolling();
  const path = window.location.pathname;
  document.querySelectorAll('.nav-item[data-url]').forEach(el => {
    if (path === el.dataset.url || (el.dataset.url !== '/' && path.startsWith(el.dataset.url))) {
      el.classList.add('active');
    }
    el.addEventListener('click', () => {
      if (window.innerWidth <= 768) closeSidebar();
    });
  });
  // Marcar ítem activo en barra inferior
  document.querySelectorAll('.bn-item[data-url]').forEach(el => {
    if (path === el.dataset.url || (el.dataset.url !== '/' && path.startsWith(el.dataset.url))) {
      el.classList.add('active');
    }
  });
});

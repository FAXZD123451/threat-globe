// Threat Globe — globo 3D de ataques.
// Los eventos llegan del backend por WebSocket (/ws). Si no hay backend
// (por ejemplo, en GitHub Pages), se usa una simulación local.
// handleAttack() es el único punto de entrada de eventos.

const ARC_FLIGHT_MS = 1800;   // lo que tarda un arco en llegar al sensor
const ARC_LIFETIME_MS = 3200; // cuánto permanece el arco en el globo
const FEED_SIZE = 7;

const IMG = "https://unpkg.com/three-globe@2.41.12/example/img";
const COUNTRIES_URL = "https://unpkg.com/globe.gl@2.33.1/example/datasets/ne_110m_admin_0_countries.geojson";

// ---------- Utilidades ----------
function weightedPick(items) {
  const total = items.reduce((s, i) => s + i.w, 0);
  let r = Math.random() * total;
  for (const item of items) {
    if ((r -= item.w) <= 0) return item;
  }
  return items[items.length - 1];
}

const jitter = (v, amount) => v + (Math.random() - 0.5) * amount;
const typeById = Object.fromEntries(ATTACK_TYPES.map(t => [t.id, t]));
const UNKNOWN_TYPE = { label: "Otro", color: "#8899aa" };
const typeOf = id => typeById[id] || UNKNOWN_TYPE;
const sensorById = Object.fromEntries(SENSORS.map(s => [s.id, s]));
const sensorOf = id => sensorById[id] || SENSORS[0];

// Escapa texto que viene de atacantes (comandos, credenciales) antes de meterlo en el HTML.
const esc = s => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Nombres de países en español a partir del código ISO (lo hace el propio navegador).
const regionNames = new Intl.DisplayNames(["es"], { type: "region" });
// En Natural Earth algunos países no traen ISO_A2 ("-99").
const MISSING_ISO = { France: "FR", Norway: "NO", Kosovo: "XK" };
const isoOf = props => (props.ISO_A2 !== "-99" ? props.ISO_A2 : MISSING_ISO[props.NAME]);
function countryName(props) {
  const code = isoOf(props);
  if (code) {
    try { return regionNames.of(code); } catch { /* código raro: usamos el nombre en inglés */ }
  }
  return props.NAME;
}

// ---------- Globo ----------
const globe = Globe()(document.getElementById("globe"))
  .globeImageUrl(`${IMG}/earth-blue-marble.jpg`)
  .bumpImageUrl(`${IMG}/earth-topology.png`)
  .backgroundImageUrl(`${IMG}/night-sky.png`)
  .atmosphereColor("#7fd8ff")
  .atmosphereAltitude(0.2)
  // Arcos de ataque
  .arcColor(d => [`${d.color}00`, d.color])
  .arcStroke(0.9)
  .arcAltitudeAutoScale(0.45)
  .arcDashLength(0.6)
  .arcDashGap(2)
  .arcDashInitialGap(1)
  .arcDashAnimateTime(ARC_FLIGHT_MS)
  // Ondas de impacto
  .ringColor(d => t => `${d.color}${Math.round((1 - t) * 255).toString(16).padStart(2, "0")}`)
  .ringMaxRadius(d => d.radius)
  .ringPropagationSpeed(3)
  .ringRepeatPeriod(ARC_FLIGHT_MS)
  // Sensores (honeypots)
  .pointsData(SENSORS)
  .pointColor(() => "#36e6c1")
  .pointAltitude(0.015)
  .pointRadius(0.55)
  .pointLabel(s => `<div class="tip"><b>${esc(s.city)}</b><br>Sensor ${esc(s.id)} · ${stats.bySensor[s.id] || 0} ataques</div>`)
  // Fronteras de países
  .polygonAltitude(d => (d === hovered ? 0.012 : 0.006))
  .polygonCapColor(d => (d === hovered ? "rgba(54,230,193,0.22)" : "rgba(0,0,0,0)"))
  .polygonSideColor(() => "rgba(0,0,0,0)")
  .polygonStrokeColor(() => "rgba(255,255,255,0.35)")
  .polygonLabel(d => {
    const n = stats.byCode[isoOf(d.properties)] || 0;
    return `<div class="tip"><b>${esc(d.__name)}</b><br>${n} ataque${n === 1 ? "" : "s"} originados</div>`;
  })
  .onPolygonHover(d => {
    hovered = d;
    globe.polygonAltitude(globe.polygonAltitude()).polygonCapColor(globe.polygonCapColor());
  })
  .polygonsTransitionDuration(150)
  // Nombres de países como HTML: admiten tildes y ñ y tienen tamaño fijo en pantalla.
  .htmlLat(d => d.lat)
  .htmlLng(d => d.lng)
  .htmlAltitude(0.01)
  .htmlElement(d => d.el)
  .htmlTransitionDuration(0);

let hovered = null;

globe.pointOfView({ lat: 25, lng: 20, altitude: 2.3 }, 0);
globe.controls().autoRotate = true;
globe.controls().autoRotateSpeed = 0.35;

window.addEventListener("resize", () => {
  globe.width(window.innerWidth).height(window.innerHeight);
});

// ---------- Países: fronteras y etiquetas por nivel de zoom ----------
let countryLabels = [];
let labelTier = null;

// Centro aproximado del polígono más grande del país (evita poner "Francia" en la Guayana).
function labelPoint(geometry) {
  const polygons = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  const ring = polygons
    .map(p => p[0])
    .reduce((a, b) => (b.length > a.length ? b : a));
  const [lng, lat] = ring.reduce(([x, y], [px, py]) => [x + px, y + py], [0, 0]);
  return { lat: lat / ring.length, lng: lng / ring.length };
}

// Según la altura de la cámara: lejos no hay nombres, a media distancia solo
// los países grandes y de cerca todos.
function updateLabels(altitude) {
  const tier = altitude > 1.5 ? 0 : altitude > 0.8 ? 1 : 2;
  if (tier === labelTier) return;
  labelTier = tier;
  const visible = tier === 0 ? []
    : tier === 1 ? countryLabels.filter(l => l.rank <= 2 && l.pop >= 25e6)
    : countryLabels;
  globe.htmlElementsData(visible);
  updateLabelVisibility();
}

// Oculta los nombres que quedan detrás del globo (a más de ~75° del centro de la vista).
const RAD = Math.PI / 180;
function updateLabelVisibility() {
  const { lat, lng } = globe.pointOfView();
  for (const label of globe.htmlElementsData()) {
    const cos = Math.sin(lat * RAD) * Math.sin(label.lat * RAD)
      + Math.cos(lat * RAD) * Math.cos(label.lat * RAD) * Math.cos((label.lng - lng) * RAD);
    label.el.style.opacity = cos > 0.26 ? "1" : "0";
  }
}

fetch(COUNTRIES_URL)
  .then(r => r.json())
  .then(({ features }) => {
    const countries = features.filter(f => f.properties.ISO_A2 !== "AQ"); // sin Antártida
    countries.forEach(f => { f.__name = countryName(f.properties); });
    countryLabels = countries.map(f => {
      const el = document.createElement("div");
      el.className = "country-label";
      el.textContent = f.__name;
      return {
        el,
        rank: f.properties.LABELRANK,
        pop: f.properties.POP_EST,
        ...labelPoint(f.geometry),
      };
    });
    globe.polygonsData(countries);
    updateLabels(globe.pointOfView().altitude);
  })
  .catch(err => console.warn("No se pudieron cargar las fronteras:", err));

globe.onZoom(pov => {
  updateLabels(pov.altitude);
  updateLabelVisibility();
});

// ---------- Arcos y ondas ----------
let arcs = [];
let rings = [];

function addArc(attack) {
  const sensor = sensorOf(attack.sensor);
  const arc = {
    startLat: attack.lat, startLng: attack.lng,
    endLat: sensor.lat, endLng: sensor.lng,
    color: attack.color,
  };
  arcs = [...arcs, arc];
  globe.arcsData(arcs);
  setTimeout(() => {
    arcs = arcs.filter(a => a !== arc);
    globe.arcsData(arcs);
  }, ARC_LIFETIME_MS);

  // Onda en el origen al salir y en el sensor al llegar
  addRing({ lat: attack.lat, lng: attack.lng, color: attack.color, radius: 2.5 });
  setTimeout(() => addRing({ lat: sensor.lat, lng: sensor.lng, color: attack.color, radius: 4 }), ARC_FLIGHT_MS);
}

function addRing(ring) {
  rings = [...rings, ring];
  globe.ringsData(rings);
  setTimeout(() => {
    rings = rings.filter(r => r !== ring);
    globe.ringsData(rings);
  }, ARC_FLIGHT_MS);
}

// ---------- Estadísticas ----------
const stats = {};
function resetStats() {
  Object.assign(stats, {
    total: 0, times: [], byType: {}, byCountry: {}, byCode: {}, byCred: {}, bySensor: {},
  });
  const feed = document.getElementById("feed");
  if (feed) feed.innerHTML = "";
}
resetStats();

const $ = id => document.getElementById(id);

function bump(map, key) { map[key] = (map[key] || 0) + 1; }

function topN(map, n) {
  return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, n);
}

function renderBars(el, entries, colorFor) {
  const max = entries.length ? Math.max(entries[0][1], 1) : 1;
  el.innerHTML = entries.map(([key, count]) => `
    <li>
      <div class="row"><span>${esc(key)}</span><span>${count}</span></div>
      <div class="track"><div class="fill" style="width:${(count / max) * 100}%;background:${colorFor(key)}"></div></div>
    </li>`).join("");
}

function renderStats() {
  const now = Date.now();
  stats.times = stats.times.filter(t => now - t < 60_000);

  $("total").textContent = stats.total.toLocaleString("es");
  $("rate").textContent = stats.times.length;

  renderBars($("types"),
    ATTACK_TYPES.map(t => [t.label, stats.byType[t.id] || 0]).sort((a, b) => b[1] - a[1]),
    label => ATTACK_TYPES.find(t => t.label === label).color);

  renderBars($("countries"), topN(stats.byCountry, 6), () => "#36e6c1");

  renderBars($("sensors"),
    topN(stats.bySensor, 4).map(([id, n]) => [sensorOf(id).city, n]), () => "#7fd8ff");

  $("creds").innerHTML = topN(stats.byCred, 5)
    .map(([cred, n]) => `<li><span>${esc(cred)}</span><span>×${n}</span></li>`).join("");
}

function pushFeed(attack) {
  const time = new Date(attack.timestamp).toLocaleTimeString("es", { hour12: false });
  const detail = attack.command ? ` <span class="t">$ ${esc(attack.command)}</span>`
    : attack.credential ? ` <span class="t">${esc(attack.credential)}</span>` : "";
  const li = document.createElement("li");
  li.innerHTML = `
    <span class="dot" style="background:${attack.color};box-shadow:0 0 8px ${attack.color}"></span>
    <span class="t">${time}</span>
    <span>${esc(attack.ip)} · ${esc(attack.country)} → ${esc(sensorOf(attack.sensor).city)} · ${typeOf(attack.type).label}${detail}</span>`;
  const feed = $("feed");
  feed.prepend(li);
  while (feed.children.length > FEED_SIZE) feed.lastChild.remove();
}

// ---------- Punto de entrada de eventos ----------
// Formato: { timestamp, ip, country, country_code, lat, lng, type, sensor, credential?, command? }
// live=false se usa al cargar el historial: cuenta en estadísticas pero no dibuja arcos.
function handleAttack(event, live = true) {
  const attack = { ...event, color: typeOf(event.type).color };
  const sensor = sensorOf(attack.sensor).id;

  stats.total++;
  if (Date.now() - attack.timestamp < 60_000) stats.times.push(attack.timestamp);
  bump(stats.byType, attack.type);
  bump(stats.byCountry, attack.country);
  if (attack.country_code) bump(stats.byCode, attack.country_code);
  bump(stats.bySensor, sensor);
  if (attack.credential) bump(stats.byCred, attack.credential);

  // Sin coordenadas (IP sin geolocalizar) no hay arco, pero sí aparece en el feed.
  if (live && attack.lat != null && attack.lng != null) addArc(attack);
  pushFeed(attack);
  if (live) renderStats();
}

// ---------- Simulación local (solo sin backend) ----------
function fakeIp() {
  // Rango de documentación (TEST-NET), enmascarado igual que lo hace el backend.
  const nets = ["192.0.2", "198.51.100", "203.0.113"];
  return `${nets[Math.floor(Math.random() * nets.length)]}.x`;
}

function simulateAttack() {
  const src = weightedPick(SOURCES);
  const type = weightedPick(ATTACK_TYPES);
  handleAttack({
    timestamp: Date.now(),
    ip: fakeIp(),
    country: src.country,
    country_code: src.code,
    lat: jitter(src.lat, 8),
    lng: jitter(src.lng, 8),
    type: type.id,
    sensor: SENSORS[Math.floor(Math.random() * SENSORS.length)].id,
    credential: type.id === "ssh-brute" || type.id === "intrusion"
      ? CREDENTIALS[Math.floor(Math.random() * CREDENTIALS.length)]
      : null,
  });
}

let localTimer = null;

function startLocalSimulation() {
  if (localTimer) return;
  (function loop() {
    simulateAttack();
    // Ráfagas irregulares: a veces llueven ataques, a veces hay calma
    const burst = Math.random() < 0.15;
    localTimer = setTimeout(loop, burst ? 120 : 350 + Math.random() * 900);
  })();
}

function stopLocalSimulation() {
  clearTimeout(localTimer);
  localTimer = null;
}

// ---------- Conexión con el backend ----------
const MODE_LABELS = {
  connecting: "CONECTANDO…",
  simulator: "BACKEND · DATOS SIMULADOS",
  cowrie: "EN VIVO · HONEYPOT COWRIE",
  local: "SIN BACKEND · SIMULACIÓN LOCAL",
};

function setMode(mode) {
  const el = $("mode");
  el.textContent = `MODO: ${MODE_LABELS[mode] || mode}`;
  el.dataset.mode = mode;
}

function connect() {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  let ws;
  try {
    ws = new WebSocket(`${scheme}://${location.host}/ws`);
  } catch {
    return onDown();
  }

  ws.onmessage = ({ data }) => {
    const msg = JSON.parse(data);
    if (msg.kind === "snapshot") {
      stopLocalSimulation();
      resetStats();
      setMode(msg.source);
      msg.events.forEach(e => handleAttack(e, false));
      renderStats();
    } else if (msg.kind === "attack") {
      handleAttack(msg.event);
    }
  };

  ws.onclose = onDown;

  function onDown() {
    // Sin backend mostramos la simulación local mientras seguimos reintentando.
    setMode("local");
    startLocalSimulation();
    setTimeout(connect, 3000);
  }
}

setMode("connecting");
connect();

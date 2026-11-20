// Carte du dashboard Nœud (deploiement.packaging § Liste des partenaires et
// carte). Fond Natural Earth embarqué, points issus de /api/map, regroupés en
// bulles quand ils sont proches à l'écran. Aucune ressource extérieure.
"use strict";

const token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
history.replaceState(null, "", location.pathname);

const KINDS = [
  { key: "partenaire", label: "Nœuds partenaires", css: "--partenaire" },
  { key: "candidat", label: "Nœuds non partenaires", css: "--candidat" },
  { key: "liste noire", label: "Nœuds en liste noire", css: "--noire" },
  { key: "utilisateur", label: "Utilisateurs", css: "--utilisateur" },
];
const CELL = 46; // taille de la grille de regroupement (px)

const canvas = document.getElementById("map");
const ctx = canvas.getContext("2d");
const visible = Object.fromEntries(KINDS.map((k) => [k.key, true]));
let world = [];
let data = { points: [], non_localises: {}, attribution: "" };
let view = { zoom: 1, x: 0, y: 0 }; // translation en px écran
let clusters = [];

function css(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function size() {
  const r = window.devicePixelRatio || 1;
  canvas.width = innerWidth * r;
  canvas.height = innerHeight * r;
  ctx.setTransform(r, 0, 0, r, 0, 0);
}

// Projection équirectangulaire : largeur du monde = 360 unités à zoom 1.
function base() {
  return Math.min(innerWidth / 360, innerHeight / 180);
}
function project(lon, lat) {
  const s = base() * view.zoom;
  const ox = innerWidth / 2 - 180 * s + view.x;
  const oy = innerHeight / 2 - 90 * s + view.y;
  return [ox + (lon + 180) * s, oy + (90 - lat) * s];
}

function drawWorld() {
  ctx.fillStyle = css("--sea");
  ctx.fillRect(0, 0, innerWidth, innerHeight);
  ctx.fillStyle = css("--land");
  ctx.strokeStyle = css("--border");
  ctx.lineWidth = 0.7;
  for (const poly of world) {
    ctx.beginPath();
    for (const ringPts of poly) {
      ringPts.forEach(([lon, lat], i) => {
        const [x, y] = project(lon, lat);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.closePath();
    }
    ctx.fill();
    ctx.stroke();
  }
}

function buildClusters() {
  clusters = [];
  KINDS.forEach((k, ki) => {
    if (!visible[k.key]) return;
    const cells = new Map();
    for (const p of data.points) {
      if (p.kind !== k.key) continue;
      const [x, y] = project(p.lon, p.lat);
      if (x < -CELL || y < -CELL || x > innerWidth + CELL || y > innerHeight + CELL) continue;
      const id = Math.floor(x / CELL) + ":" + Math.floor(y / CELL);
      const c = cells.get(id) || { kind: k, ki, sx: 0, sy: 0, points: [] };
      c.sx += x;
      c.sy += y;
      c.points.push(p);
      cells.set(id, c);
    }
    for (const c of cells.values()) {
      const n = c.points.length;
      // Léger décalage par type : les bulles de types différents ne se masquent pas.
      const off = (ki - 1.5) * 5;
      clusters.push({ ...c, x: c.sx / n + off, y: c.sy / n + off, r: n === 1 ? 6 : Math.min(26, 9 + 4 * Math.log2(n)) });
    }
  });
}

function drawClusters() {
  for (const c of clusters) {
    ctx.beginPath();
    ctx.arc(c.x, c.y, c.r, 0, 2 * Math.PI);
    ctx.fillStyle = css(c.kind.css);
    ctx.globalAlpha = c.points.length === 1 ? 0.95 : 0.85;
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = css("--land");
    ctx.stroke();
    if (c.points.length > 1) {
      ctx.fillStyle = "#fff";
      ctx.font = "bold 11px system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(String(c.points.length), c.x, c.y + 0.5);
    }
  }
}

function draw() {
  drawWorld();
  buildClusters();
  drawClusters();
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function renderToggles() {
  const box = document.getElementById("toggles");
  box.replaceChildren();
  for (const k of KINDS) {
    const l = el("label");
    const i = el("input");
    i.type = "checkbox";
    i.checked = visible[k.key];
    i.addEventListener("change", () => {
      visible[k.key] = i.checked;
      draw();
    });
    const dot = el("span", undefined, "dot");
    dot.style.background = css(k.css);
    l.append(i, dot, el("span", k.label), el("span", String(data.points.filter((p) => p.kind === k.key).length), "count"));
    box.appendChild(l);
  }
  const un = Object.entries(data.non_localises || {}).filter(([, n]) => n > 0);
  const u = document.getElementById("unlocated");
  u.replaceChildren();
  if (!data.geoip) u.append(el("div", "Base de géolocalisation absente : écran Réseau, « Mettre à jour la base de géolocalisation »"));
  if (un.length) u.append(el("div", "Non localisés : " + un.map(([k, n]) => `${k} ${n}`).join(", ")));
  document.getElementById("foot").textContent = [data.attribution, world.length ? "Fond : Natural Earth" : ""].filter(Boolean).join(" · ");
}

function showDetail(c) {
  const body = document.getElementById("detail-body");
  body.replaceChildren();
  body.append(el("h2", `${c.kind.label} — ${c.points.length}`));
  const ul = el("ul");
  for (const p of c.points.slice(0, 200)) {
    const li = el("li");
    li.append(el("strong", p.label));
    if (p.detail) li.append(el("div", p.detail));
    ul.appendChild(li);
  }
  if (c.points.length > 200) ul.appendChild(el("li", `… ${c.points.length - 200} de plus`));
  body.append(ul);
  document.getElementById("detail").style.display = "block";
}

document.getElementById("close").addEventListener("click", () => {
  document.getElementById("detail").style.display = "none";
});

// Zoom autour du curseur, déplacement à la souris.
canvas.addEventListener("wheel", (e) => {
  e.preventDefault();
  const f = e.deltaY < 0 ? 1.25 : 0.8;
  const z = Math.max(1, Math.min(64, view.zoom * f));
  const k = z / view.zoom;
  const cx = e.clientX - innerWidth / 2;
  const cy = e.clientY - innerHeight / 2;
  view.x = cx - (cx - view.x) * k;
  view.y = cy - (cy - view.y) * k;
  view.zoom = z;
  draw();
}, { passive: false });

let drag = null;
canvas.addEventListener("mousedown", (e) => {
  drag = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false };
  canvas.classList.add("dragging");
});
addEventListener("mousemove", (e) => {
  if (!drag) return;
  const dx = e.clientX - drag.x;
  const dy = e.clientY - drag.y;
  if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
  view.x = drag.vx + dx;
  view.y = drag.vy + dy;
  draw();
});
addEventListener("mouseup", (e) => {
  canvas.classList.remove("dragging");
  if (drag && !drag.moved) {
    const hit = clusters.filter((c) => Math.hypot(c.x - e.clientX, c.y - e.clientY) <= c.r + 3);
    if (hit.length) showDetail(hit[hit.length - 1]);
  }
  drag = null;
});
addEventListener("resize", () => {
  size();
  draw();
});

async function load() {
  const r = await fetch("/api/map", { headers: { Authorization: "Bearer " + token } });
  if (!r.ok) {
    document.getElementById("unlocated").replaceChildren(el("div", "accès refusé : rouvrez la carte depuis le dashboard", "error"));
    return;
  }
  data = await r.json();
  renderToggles();
  draw();
}

(async () => {
  size();
  try {
    world = (await (await fetch("world.json")).json()).polygons;
  } catch (_) {
    world = [];
  }
  await load();
  setInterval(load, 30000);
})();

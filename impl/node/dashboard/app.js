// Dashboard local P2P-Storage (Nœud et Connecteur, même fichier).
// Jeton remis par le fragment d'URL (#token=…), gardé en mémoire et retiré
// de la barre d'adresse (docs/07-deploiement/packaging.md § API locale).
"use strict";

const token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
history.replaceState(null, "", location.pathname);

const main = document.getElementById("main");
const live = document.getElementById("live");

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function cell(v) {
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function render(value) {
  if (Array.isArray(value)) {
    if (value.length === 0) return el("p", "aucun", "empty");
    if (typeof value[0] !== "object" || value[0] === null) {
      const ul = el("ul");
      value.forEach((v) => ul.appendChild(el("li", cell(v))));
      return ul;
    }
    const cols = [...new Set(value.flatMap((o) => Object.keys(o)))];
    const t = el("table");
    const head = t.createTHead().insertRow();
    const body = t.createTBody();
    let sortCol = null;
    let asc = true;
    const fill = () => {
      body.replaceChildren();
      const rows = sortCol === null ? value : [...value].sort((a, b) => {
        const x = a[sortCol], y = b[sortCol];
        const r = typeof x === "number" && typeof y === "number" ? x - y : cell(x).localeCompare(cell(y), "fr", { numeric: true });
        return asc ? r : -r;
      });
      rows.forEach((o) => {
        const r = body.insertRow();
        cols.forEach((c) => r.appendChild(el("td", cell(o[c]))));
      });
    };
    cols.forEach((c) => {
      const th = el("th", c);
      th.title = "trier";
      th.style.cursor = "pointer";
      th.addEventListener("click", () => {
        asc = sortCol === c ? !asc : true;
        sortCol = c;
        head.querySelectorAll("th").forEach((h) => (h.textContent = h.dataset.col));
        th.textContent = c + (asc ? " ▲" : " ▼");
        fill();
      });
      th.dataset.col = c;
      head.appendChild(th);
    });
    fill();
    return t;
  }
  if (value !== null && typeof value === "object") {
    const t = el("table");
    Object.entries(value).forEach(([k, v]) => {
      const r = t.insertRow();
      r.appendChild(el("th", k));
      r.appendChild(el("td", cell(v)));
    });
    return t;
  }
  return el("p", cell(value));
}

function actionForm(a) {
  const f = el("form");
  const inputs = (a["champs"] || []).map((name) => {
    const l = el("label", name);
    const i = el("input");
    i.name = name;
    i.autocomplete = "off";
    l.appendChild(i);
    f.appendChild(l);
    return i;
  });
  const b = el("button", a["libellé"]);
  b.type = "submit";
  f.appendChild(b);
  const msg = el("span");
  f.appendChild(msg);
  f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = {};
    inputs.forEach((i) => (body[i.name] = i.value.trim()));
    const r = await fetch("/api/action/" + encodeURIComponent(a["nom"]), {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    msg.className = r.ok ? "" : "error";
    msg.textContent = r.ok ? "fait" : await r.text();
    if (r.ok) refresh();
  });
  return f;
}

let actionsShown = false;

function show(status) {
  document.getElementById("title").textContent = status["titre"] || "P2P-Storage";
  document.title = status["titre"] || "P2P-Storage";
  const keep = actionsShown ? document.getElementById("actions") : null;
  main.replaceChildren();
  if (status["carte"]) {
    const s = el("section");
    const b = el("button", "Ouvrir la carte du monde");
    b.addEventListener("click", () => window.open("map.html#token=" + encodeURIComponent(token), "_blank", "noopener"));
    s.appendChild(b);
    main.appendChild(s);
  }
  Object.entries(status).forEach(([k, v]) => {
    if (k === "titre" || k === "actions" || k === "carte") return;
    const s = el("section");
    s.appendChild(el("h2", k));
    s.appendChild(render(v));
    main.appendChild(s);
  });
  if (keep) {
    main.appendChild(keep);
  } else if ((status["actions"] || []).length) {
    const s = el("section");
    s.id = "actions";
    s.appendChild(el("h2", "actions"));
    status["actions"].forEach((a) => s.appendChild(actionForm(a)));
    main.appendChild(s);
    actionsShown = true;
  }
}

async function refresh() {
  const r = await fetch("/api/status", { headers: { Authorization: "Bearer " + token } });
  if (!r.ok) {
    live.textContent = "accès refusé (rouvrez l'URL affichée au démarrage)";
    live.className = "error";
    return;
  }
  show(await r.json());
}

function connect() {
  const ws = new WebSocket("ws://" + location.host + "/api/ws");
  ws.onopen = () => {
    ws.send(token);
    live.textContent = "en direct";
    live.className = "";
  };
  ws.onmessage = (m) => show(JSON.parse(m.data));
  ws.onclose = () => {
    live.textContent = "déconnecté — nouvelle tentative…";
    setTimeout(connect, 3000);
  };
}

refresh().then(connect);

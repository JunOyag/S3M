// Dashboard local S3m (Nœud et Connecteur, même fichier).
// Jeton remis par le fragment d'URL (#token=…), gardé en mémoire et retiré
// de la barre d'adresse (docs/07-deploiement/packaging.md § API locale).
//
// Le serveur décrit tout en JSON : sections (objets, listes, tableaux),
// actions (formulaires) et, dans les tableaux, boutons par ligne (`_actions`).
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

// ---------------------------------------------------------------- messages

function toast(message, kind = "ok") {
  let box = document.getElementById("toasts");
  if (!box) {
    box = el("div");
    box.id = "toasts";
    box.setAttribute("role", "status");
    box.setAttribute("aria-live", "polite");
    document.body.appendChild(box);
  }
  const t = el("div", message, "toast " + kind);
  box.appendChild(t);
  requestAnimationFrame(() => t.classList.add("show"));
  setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => t.remove(), 300);
  }, kind === "error" ? 7000 : 3500);
}

// ---------------------------------------------------------------- actions

async function runAction(nom, body, button, label) {
  if (button) button.disabled = true;
  try {
    const r = await fetch("/api/action/" + encodeURIComponent(nom), {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (r.ok) {
      const res = await r.json().catch(() => ({}));
      toast(res.message || (label ? `${label} : c'est fait` : "C'est fait"));
      refresh();
    } else {
      toast(await r.text(), "error");
    }
  } catch (e) {
    toast("Connexion au moteur impossible", "error");
  } finally {
    if (button) button.disabled = false;
  }
}

function cell(v) {
  if (v === null || v === undefined) return "—";
  if (v === true) return "oui";
  if (v === false) return "non";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function rowActions(list) {
  const td = el("td", undefined, "row-actions");
  for (const a of list || []) {
    const b = el("button", a["libellé"], "small");
    b.addEventListener("click", () => runAction(a["nom"], a["valeurs"] || {}, b, a["libellé"]));
    td.appendChild(b);
  }
  return td;
}

function render(value) {
  if (Array.isArray(value)) {
    if (value.length === 0) return el("p", "aucun", "empty");
    if (typeof value[0] !== "object" || value[0] === null) {
      const ul = el("ul");
      value.forEach((v) => ul.appendChild(el("li", cell(v))));
      return ul;
    }
    const cols = [...new Set(value.flatMap((o) => Object.keys(o)))].filter((c) => c !== "_actions");
    const withActions = value.some((o) => o["_actions"]);
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
        if (withActions) r.appendChild(rowActions(o["_actions"]));
      });
    };
    cols.forEach((c) => {
      const th = el("th", c);
      th.title = "trier";
      th.style.cursor = "pointer";
      th.dataset.col = c;
      th.addEventListener("click", () => {
        asc = sortCol === c ? !asc : true;
        sortCol = c;
        head.querySelectorAll("th[data-col]").forEach((h) => (h.textContent = h.dataset.col));
        th.textContent = c + (asc ? " ▲" : " ▼");
        fill();
      });
      head.appendChild(th);
    });
    if (withActions) head.appendChild(el("th", ""));
    fill();
    return t;
  }
  if (value !== null && typeof value === "object") {
    const t = el("table", undefined, "kv");
    Object.entries(value).forEach(([k, v]) => {
      const r = t.insertRow();
      r.appendChild(el("th", k));
      r.appendChild(el("td", cell(v)));
    });
    return t;
  }
  return el("p", cell(value));
}

// Formulaire : champs texte, nombre ou case à cocher, valeurs pré-remplies.
function actionForm(a) {
  const f = el("form", undefined, (a["champs"] || []).length > 3 ? "form grid" : "form");
  const values = a["valeurs"] || {};
  const types = a["types"] || {};
  const help = a["aide"] || {};
  if (a["titre"]) f.appendChild(el("h3", a["titre"]));
  const inputs = (a["champs"] || []).map((name) => {
    const l = el("label");
    const i = el("input");
    i.name = name;
    i.autocomplete = "off";
    if (types[name] === "bool") {
      i.type = "checkbox";
      i.checked = values[name] === true;
      l.classList.add("check");
      l.append(i, el("span", name));
    } else {
      if (types[name] === "number") i.type = "number";
      if (values[name] !== undefined && values[name] !== null) i.value = String(values[name]);
      l.append(el("span", name), i);
    }
    if (help[name]) l.title = help[name];
    f.appendChild(l);
    return i;
  });
  const b = el("button", a["libellé"]);
  b.type = "submit";
  f.appendChild(b);
  f.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const body = {};
    inputs.forEach((i) => (body[i.name] = i.type === "checkbox" ? i.checked : i.value.trim()));
    runAction(a["nom"], body, b, a["libellé"]);
  });
  return f;
}

// --------------------------------------------------------------- affichage

let actionsKey = "";

function show(status) {
  document.getElementById("title").textContent = status["titre"] || "S3m";
  document.title = status["titre"] || "S3m";
  const actions = status["actions"] || [];
  // Les formulaires ne sont reconstruits que s'ils changent, et restent dans
  // la page entre deux rafraîchissements : saisie et focus préservés.
  const key = JSON.stringify(actions);
  let keep = document.getElementById("actions");
  if (keep && key !== actionsKey) {
    keep.remove();
    keep = null;
  }
  [...main.children].forEach((c) => c !== keep && c.remove());
  const frag = document.createDocumentFragment();
  if (status["carte"]) {
    const s = el("section");
    const b = el("button", "Ouvrir la carte du monde");
    b.addEventListener("click", () => window.open("map.html#token=" + encodeURIComponent(token), "_blank", "noopener"));
    s.appendChild(b);
    frag.appendChild(s);
  }
  Object.entries(status).forEach(([k, v]) => {
    if (k === "titre" || k === "actions" || k === "carte") return;
    const s = el("section");
    s.appendChild(el("h2", k));
    s.appendChild(render(v));
    frag.appendChild(s);
  });
  main.insertBefore(frag, keep);
  if (!keep && actions.length) {
    const s = el("section");
    s.id = "actions";
    s.appendChild(el("h2", "actions"));
    actions.forEach((a) => s.appendChild(actionForm(a)));
    main.appendChild(s);
    actionsKey = key;
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

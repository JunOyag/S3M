// Dashboard local S3m (Nœud et Connecteur, même fichier).
// Jeton remis par le fragment d'URL (#token=…), gardé en mémoire et retiré
// de la barre d'adresse (docs/07-deploiement/packaging.md § API locale).
//
// Le serveur décrit tout en JSON : sections (objets, listes, tableaux),
// actions (formulaires) et, dans les tableaux, boutons par ligne (`_actions`).
"use strict";

const hashParams = new URLSearchParams(location.hash.slice(1));
const token = hashParams.get("token") || "";
// `#token=…&page=<id>` ouvre directement un écran.
const linkedPage = hashParams.get("page");
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

function toast(message, kind = "ok", href) {
  let box = document.getElementById("toasts");
  if (!box) {
    box = el("div");
    box.id = "toasts";
    box.setAttribute("role", "status");
    box.setAttribute("aria-live", "polite");
    document.body.appendChild(box);
  }
  const t = el("div", message, "toast " + kind);
  if (href) {
    const a = el("a", " Ouvrir");
    a.href = href;
    a.target = "_blank";
    a.rel = "noopener";
    t.appendChild(a);
  }
  box.appendChild(t);
  requestAnimationFrame(() => t.classList.add("show"));
  setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => t.remove(), 300);
  }, kind === "error" || href ? 7000 : 3500);
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
      // `ouvrir` : page à ouvrir (dashboard d'un Nœud administré à distance).
      const w = res.ouvrir ? window.open(res.ouvrir, "_blank", "noopener") : true;
      toast(res.message || (label ? `${label} : c'est fait` : "C'est fait"), "ok", w ? undefined : res.ouvrir);
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
  if (Array.isArray(v) && v.every((x) => x === null || typeof x !== "object")) return v.length ? v.join("\n") : "aucun";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

// Valeur lisible selon son libellé : tailles en octets, instants Unix.
function bytes(n) {
  const u = ["o", "Ko", "Mo", "Go", "To", "Po"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return (i ? n.toFixed(n < 10 ? 1 : 0).replace(".", ",") : String(n)) + " " + u[i];
}

const DATE_KEY = /(dernier|dernière|expire|publiée le|prochaine|contact|heure|le$)/i;

function fmt(k, v) {
  if (typeof v === "number" && k) {
    if (/octets/i.test(k)) return bytes(v);
    if (v > 1.4e9 && v < 4.2e9 && DATE_KEY.test(k)) return new Date(v * 1000).toLocaleString("fr-FR");
  }
  return cell(v);
}

// QR code : SVG fourni par le moteur, affiché comme image (jamais inséré).
// Objet imbriqué : sous-tableau.
function valueNode(v, k) {
  if (v !== null && typeof v === "object" && !(Array.isArray(v) && v.every((x) => x === null || typeof x !== "object"))) {
    return render(v);
  }
  if (typeof v === "string" && /^\s*(<\?xml[^>]*>\s*)?<svg[\s>]/.test(v)) {
    const i = el("img", undefined, "qr");
    i.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(v);
    i.alt = "QR code";
    return i;
  }
  return document.createTextNode(fmt(k, v));
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
        cols.forEach((c) => r.appendChild(el("td", fmt(c, o[c]))));
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
      const td = el("td");
      td.appendChild(valueNode(v, k));
      r.appendChild(td);
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
  // `libellés` : texte affiché d'un champ (le nom envoyé reste `champs`).
  const labels = a["libellés"] || {};
  if (a["titre"]) f.appendChild(el("h3", a["titre"]));
  const inputs = (a["champs"] || []).map((name) => {
    const l = el("label");
    const i = el("input");
    i.name = name;
    i.autocomplete = "off";
    const text = labels[name] || name;
    if (types[name] === "bool") {
      i.type = "checkbox";
      i.checked = values[name] === true;
      l.classList.add("check");
      l.append(i, el("span", text));
    } else {
      if (types[name] === "number") i.type = "number";
      if (values[name] !== undefined && values[name] !== null) i.value = String(values[name]);
      l.append(el("span", text), i);
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

// Écrans : le moteur décrit `pages` (sections et actions de chacune) et
// `résumé` (indicateurs de la vue d'ensemble). Sans `pages`, un seul écran.
const RESERVED = new Set(["titre", "actions", "carte", "pages", "résumé"]);
let actionsKey = "";
let lastStatus = null;
let page = null;

function pagesOf(status) {
  const all = Object.keys(status).filter((k) => !RESERVED.has(k));
  const pages = status["pages"];
  if (!Array.isArray(pages) || pages.length === 0) {
    return [{ id: "_", titre: "", sections: all, actions: null, carte: true }];
  }
  // La carte n'existe que sur le Nœud lui-même (pas à distance).
  const out = pages
    .filter((p) => p["cadre"] !== "map.html" || status["carte"])
    .map((p) => ({ ...p, sections: [...(p.sections || [])] }));
  // Ce qu'aucun écran ne cite va dans l'écran « autres » (rien ne se perd).
  const used = new Set(out.flatMap((p) => p.sections));
  const other = out.find((p) => p["autres"]) || out[out.length - 1];
  all.filter((k) => !used.has(k)).forEach((k) => other.sections.push(k));
  const named = new Set(out.flatMap((p) => p.actions || []));
  other.extra = (status["actions"] || []).filter((a) => !named.has(a["nom"])).map((a) => a["nom"]);
  return out;
}

function go(id) {
  page = id;
  try {
    sessionStorage.setItem("s3m-page", id);
  } catch (e) {
    /* stockage indisponible : sans effet */
  }
  window.scrollTo(0, 0);
  if (lastStatus) show(lastStatus);
}

function menu(pages) {
  let nav = document.getElementById("menu");
  if (pages.length < 2) {
    if (nav) nav.remove();
    document.body.classList.remove("with-menu");
    return;
  }
  document.body.classList.add("with-menu");
  if (!nav) {
    nav = el("nav");
    nav.id = "menu";
    nav.setAttribute("aria-label", "Écrans");
    document.body.insertBefore(nav, main);
  }
  const key = pages.map((p) => p.id + ":" + p.titre).join("|") + "#" + page;
  if (nav.dataset.key === key) return;
  nav.dataset.key = key;
  nav.replaceChildren();
  pages.forEach((p) => {
    const b = el("button", p.titre, p.id === page ? "active" : undefined);
    b.type = "button";
    if (p.id === page) b.setAttribute("aria-current", "page");
    b.addEventListener("click", () => go(p.id));
    nav.appendChild(b);
  });
}

function cards(list) {
  const box = el("div", undefined, "cards");
  list.forEach((c) => {
    const d = el(c["page"] ? "button" : "div", undefined, "card " + (c["état"] || "neutre"));
    if (c["page"]) {
      d.type = "button";
      d.addEventListener("click", () => go(c["page"]));
    }
    d.appendChild(el("span", c["libellé"], "card-label"));
    d.appendChild(el("span", c["unité"] === "octets" ? bytes(c["valeur"] || 0) : cell(c["valeur"]), "card-value"));
    if (c["détail"]) d.appendChild(el("span", c["détail"], "card-detail"));
    box.appendChild(d);
  });
  return box;
}

function show(status) {
  lastStatus = status;
  document.getElementById("title").textContent = status["titre"] || "S3m";
  document.title = status["titre"] || "S3m";
  const pages = pagesOf(status);
  if (!page || !pages.some((p) => p.id === page)) {
    let saved = null;
    try {
      saved = sessionStorage.getItem("s3m-page");
    } catch (e) {
      /* stockage indisponible */
    }
    const want = linkedPage || saved;
    page = pages.some((p) => p.id === want) ? want : pages[0].id;
  }
  menu(pages);
  const p = pages.find((x) => x.id === page);
  const wanted = p.actions === null ? null : [...(p.actions || []), ...(p.extra || [])];
  const actions = (status["actions"] || []).filter((a) => wanted === null || wanted.includes(a["nom"]));
  // Les formulaires ne sont reconstruits que s'ils changent, et restent dans
  // la page entre deux rafraîchissements : saisie et focus préservés.
  const key = page + JSON.stringify(actions);
  let keep = document.getElementById("actions");
  if (keep && key !== actionsKey) {
    keep.remove();
    keep = null;
  }
  // Écran intégré (`cadre`, ex. la carte) : gardé entre deux rafraîchissements
  // (zoom et position conservés).
  let frame = document.getElementById("frame");
  if (frame && frame.dataset.page !== page) {
    frame.remove();
    frame = null;
  }
  [...main.children].forEach((c) => c !== keep && c !== frame && c.remove());
  const frag = document.createDocumentFragment();
  if (pages.length > 1) frag.appendChild(el("h2", p.titre, "page-title"));
  if (p["résumé"] && Array.isArray(status["résumé"])) frag.appendChild(cards(status["résumé"]));
  const mapPage = pages.find((x) => x["cadre"] === "map.html");
  if (status["carte"] && p.carte) {
    const s = el("section");
    const b = el("button", "Ouvrir la carte du monde");
    b.addEventListener("click", () =>
      mapPage ? go(mapPage.id) : window.open("map.html#token=" + encodeURIComponent(token), "_blank", "noopener"),
    );
    s.appendChild(b);
    frag.appendChild(s);
  }
  if (p["cadre"] && !frame) {
    frame = el("iframe", undefined, "frame");
    frame.id = "frame";
    frame.dataset.page = page;
    frame.title = p.titre;
    frame.src = p["cadre"] + "#token=" + encodeURIComponent(token);
    main.appendChild(frame);
  }
  if (p["cadre"]) {
    const full = el("a", "Ouvrir en plein écran", "frame-link");
    full.href = p["cadre"] + "#token=" + encodeURIComponent(token);
    full.target = "_blank";
    full.rel = "noopener";
    frag.appendChild(full);
  }
  p.sections.forEach((k) => {
    if (!(k in status)) return;
    const s = el("section");
    s.appendChild(el("h2", k));
    s.appendChild(render(status[k]));
    frag.appendChild(s);
  });
  main.insertBefore(frag, frame || keep);
  if (!keep && actions.length) {
    const s = el("section");
    s.id = "actions";
    s.appendChild(el("h2", "Actions"));
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

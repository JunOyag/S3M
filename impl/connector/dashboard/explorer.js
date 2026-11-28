"use strict";
// Explorateur de l'espace S3m (dashboard Connecteur) : navigation, dossiers,
// envoi par glisser-déposer, sélection multiple, déplacement, téléchargement,
// partage, suppression, « garder sur cet appareil », couleurs de dossier.

const token = (() => {
  const t = new URLSearchParams(location.hash.slice(1)).get("token");
  try {
    if (t) localStorage.setItem("s3m-token", t);
    return t || localStorage.getItem("s3m-token") || "";
  } catch (_) {
    return t || "";
  }
})();

// Thème choisi dans le dashboard (clair / foncé / système).
function applyTheme() {
  let t = "systeme";
  try {
    t = localStorage.getItem("s3m-theme") || "systeme";
  } catch (_) {}
  if (t === "clair") document.documentElement.dataset.theme = "light";
  else if (t === "fonce") document.documentElement.dataset.theme = "dark";
  else delete document.documentElement.dataset.theme;
}
applyTheme();
addEventListener("storage", (ev) => ev.key === "s3m-theme" && applyTheme());

// Morceau envoyé ou lu (octets), comme `explorer::CHUNK`.
const CHUNK = 512 * 1024;
const SHARED = "/Partagés avec moi";
const PRESETS = ["#e05a4f", "#f08c2e", "#e0b100", "#3fa34d", "#2a9d8f", "#3b7dd8", "#8a5cd0", "#d0549a"];

let cwd = "/";
let folderMode = false;
let readOnly = false;
let busy = 0;
let contacts = [];
let entries = [];
// Sélection : chemins choisis et ancre du shift+clic.
let selected = new Set();
let anchor = null;
// Pagination : lignes par page (mémorisé) et page affichée.
let pageSize = 50;
try {
  pageSize = Number(localStorage.getItem("s3m-explorer-lignes")) || 50;
} catch (_) {}
let pageNo = 0;
const pageCount = () => Math.max(1, Math.ceil(entries.length / pageSize));
const shown = () => entries.slice(pageNo * pageSize, (pageNo + 1) * pageSize);
// Identité changée : « Rechiffrer avec la nouvelle clé » proposé.
let reencryptable = false;
// Version passée parcourue (`protocols.historique-versions`) : hash de sa
// racine et libellé ; null : version actuelle.
let version = null;
let versionLabel = "";
const when = (t) => (t > 1.4e9 ? new Date(t * 1000).toLocaleString() : "date inconnue");

const $ = (id) => document.getElementById(id);
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
const join = (dir, name) => (dir === "/" ? "/" + name : dir + "/" + name);
const parent = (p) => (p.lastIndexOf("/") <= 0 ? "/" : p.slice(0, p.lastIndexOf("/")));
const base = (p) => p.slice(p.lastIndexOf("/") + 1);
const inShared = (p) => p === SHARED || p.startsWith(SHARED + "/");

async function call(nom, body) {
  const r = await fetch("/api/action/" + encodeURIComponent(nom), {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!r.ok) throw new Error((await r.text()) || r.statusText);
  return r.json().catch(() => ({}));
}

function status(text, err) {
  const s = $("status");
  s.textContent = text || "";
  s.classList.toggle("err", !!err);
}

function size(n) {
  const u = ["o", "Ko", "Mo", "Go", "To"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return (i ? n.toFixed(n < 10 ? 1 : 0).replace(".", ",") : String(n)) + " " + u[i];
}

// Icônes (SVG : un dossier prend sa couleur).
const SVG = "http://www.w3.org/2000/svg";
function icon(kind, color) {
  const s = document.createElementNS(SVG, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("class", "ico");
  s.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(SVG, "path");
  const d = {
    folder: "M3 6.5A1.5 1.5 0 0 1 4.5 5h4.6l2 2h8.4A1.5 1.5 0 0 1 21 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z",
    file: "M6 3h8l5 5v12a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zm8 0v5h5",
    up: "M12 5l-6 6h4v8h4v-8h4z",
    share: "M16 5a3 3 0 1 1 0 .01zM6 12a3 3 0 1 1 0 .01zM16 19a3 3 0 1 1 0 .01zM8.6 10.7l4.8-2.9M8.6 13.3l4.8 2.9",
    people: "M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zm-6 9c0-3.3 2.7-6 6-6s6 2.7 6 6M16 11a3 3 0 1 0 0-6M18 14c2 .6 3.5 2.6 3.5 5",
    down: "M12 4v11m-5-5 5 5 5-5M5 20h14",
    edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4",
    star: "M12 3.5l2.6 5.4 5.9.8-4.3 4.1 1 5.8-5.2-2.8-5.2 2.8 1-5.8-4.3-4.1 5.9-.8z",
  }[kind];
  p.setAttribute("d", d);
  if (kind === "folder" || kind === "up") {
    p.setAttribute("fill", color || "var(--folder)");
  } else if (kind === "star" && color) {
    p.setAttribute("fill", color);
    p.setAttribute("stroke", color);
  } else {
    p.setAttribute("fill", "none");
    p.setAttribute("stroke", "currentColor");
    p.setAttribute("stroke-width", "1.7");
    p.setAttribute("stroke-linejoin", "round");
    p.setAttribute("stroke-linecap", "round");
  }
  s.appendChild(p);
  return s;
}

// ------------------------------------------------------------ hexadécimal

function toHex(bytes) {
  const h = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) h[i] = (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
  return h.join("");
}
function fromHex(s) {
  const b = new Uint8Array(s.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
  return b;
}

// ------------------------------------------------------------ fenêtres

// Fenêtre générique : `build(form)` remplit le contenu ; `buttons` =
// [{ label, value, cls }] — le dernier est le bouton par défaut (Entrée).
// `check(value)` (async) peut refuser la validation en rendant un message,
// affiché dans la fenêtre qui reste ouverte. Rend la valeur du bouton, ou
// null (Échap, Annuler).
function modal(title, build, buttons, check) {
  return new Promise((resolve) => {
    const d = $("dlg");
    const f = $("dlgform");
    f.replaceChildren(el("h3", title));
    build(f);
    const err = el("p", "", "dlg-err");
    err.hidden = true;
    f.appendChild(err);
    const row = el("div", undefined, "row-btns");
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      d.close();
      resolve(v);
    };
    buttons.forEach((b, i) => {
      const last = i === buttons.length - 1;
      const x = el("button", b.label, "act" + (b.cls ? " " + b.cls : last ? "" : " secondary"));
      x.type = last ? "submit" : "button";
      if (!last) x.addEventListener("click", () => finish(b.value));
      row.appendChild(x);
    });
    f.appendChild(row);
    f.onsubmit = async (ev) => {
      ev.preventDefault();
      const v = buttons[buttons.length - 1].value;
      if (check) {
        const sub = row.lastChild;
        sub.disabled = true;
        let msg = null;
        try {
          msg = await check(v);
        } catch (e) {
          msg = e.message;
        }
        sub.disabled = false;
        if (msg) {
          err.textContent = msg;
          err.hidden = false;
          return;
        }
      }
      finish(v);
    };
    d.oncancel = (ev) => {
      ev.preventDefault();
      finish(null);
    };
    d.onclose = null;
    d.showModal();
    const first = f.querySelector("input, textarea, select") || row.lastChild;
    first.focus();
    if (first.select && first.dataset.sel) first.setSelectionRange(0, Number(first.dataset.sel));
    else if (first.select) first.select();
  });
}

function uiConfirm(title, text, okLabel, danger) {
  return modal(title, (f) => f.appendChild(el("p", text)), [
    { label: "Annuler", value: null },
    { label: okLabel || "Confirmer", value: true, cls: danger ? "danger" : "" },
  ]).then((v) => v === true);
}

function uiAlert(title, text) {
  return modal(title, (f) => f.appendChild(el("p", text)), [{ label: "OK", value: true }]);
}

// Champs texte : [[libellé, valeur, aide, suggestions]] ; rend les valeurs.
function dialog(title, fields, okLabel, check) {
  const inputs = [];
  return modal(
    title,
    (f) => {
      for (const [label, value, help, suggestions, sel] of fields) {
        const l = el("label", label);
        const i = el("input");
        i.value = value || "";
        if (help) i.placeholder = help;
        if (sel !== undefined) i.dataset.sel = String(sel);
        if (suggestions && suggestions.length) {
          const list = el("datalist");
          list.id = "dl-" + Math.random().toString(36).slice(2);
          suggestions.forEach((s) => {
            const o = el("option");
            o.value = s;
            list.appendChild(o);
          });
          i.setAttribute("list", list.id);
          l.appendChild(list);
        }
        l.appendChild(i);
        f.appendChild(l);
        inputs.push(i);
      }
    },
    [
      { label: "Annuler", value: null },
      { label: okLabel || "OK", value: true },
    ],
    check ? () => check(inputs.map((i) => i.value.trim())) : undefined,
  ).then((v) => (v ? inputs.map((i) => i.value.trim()) : null));
}

function copyButton(text) {
  const b = el("button", "", "copy");
  b.type = "button";
  b.title = "Copier";
  b.setAttribute("aria-label", "Copier");
  b.textContent = "⧉";
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const t = el("textarea");
      t.value = text;
      document.body.appendChild(t);
      t.select();
      document.execCommand("copy");
      t.remove();
    }
    b.title = "Copié !";
    setTimeout(() => (b.title = "Copier"), 1500);
    status("Copié dans le presse-papiers");
  });
  return b;
}

function reveal(title, text) {
  return modal(
    title,
    (f) => {
      const box = el("div", undefined, "copyrow");
      const t = el("textarea");
      t.rows = 4;
      t.readOnly = true;
      t.value = text;
      box.append(t, copyButton(text));
      f.appendChild(box);
      f.appendChild(el("p", "Le destinataire l'ajoute dans S3m, page Partages, « Ajouter un partage reçu ».", "muted"));
    },
    [{ label: "Fermer", value: true }],
  );
}

// ------------------------------------------------------------ affichage

async function load(path) {
  try {
    const r = await call("explorer_list", version ? { chemin: path, version } : { chemin: path });
    if (r["chemin"] !== cwd) {
      selected.clear();
      anchor = null;
      pageNo = 0;
    }
    cwd = r["chemin"];
    if (!version) {
      folderMode = !!r["mode dossier"];
      contacts = r["contacts"] || [];
      reencryptable = !!r["rechiffrer"];
      document.title = "Explorateur S3m" + (r["pseudo"] ? " — " + r["pseudo"] : "");
    }
    readOnly = !!version || !!r["lecture seule"] || inShared(cwd);
    $("banner").hidden = !version;
    const old = version ? 0 : r["éléments à l'ancienne clé"] || 0;
    $("oldkey").hidden = !old;
    $("oldkeytext").textContent = old
      ? old + " élément(s) de ce dossier sont encore protégés par votre ancienne clé, compromise (marqués 🔓). Rechiffrez-les pour qu'elle ne permette plus de les lire."
      : "";
    $("bannertext").textContent = version ? "Version du " + versionLabel + " — lecture seule" : "";
    $("restoredir").hidden = !version || cwd === "/";
    try {
      sessionStorage.setItem("s3m-explorer", cwd);
    } catch (_) {}
    crumbs();
    entries = (r["entrées"] || []).map((e) => Object.assign({ path: join(cwd, e["nom"]) }, e));
    const exist = new Set(entries.map((e) => e.path));
    selected = new Set([...selected].filter((p) => exist.has(p)));
    rows();
    for (const id of ["mkdir", "upfiles", "upfolder"]) $(id).disabled = readOnly;
    $("hint").hidden = readOnly;
    if (!busy) status("");
  } catch (e) {
    status(e.message, true);
  }
}

function crumbs() {
  const nav = $("crumbs");
  nav.replaceChildren();
  const parts = cwd.split("/").filter(Boolean);
  const add = (label, path) => {
    const b = el("button", label);
    b.type = "button";
    b.addEventListener("click", () => load(path));
    dropTarget(b, path);
    nav.appendChild(b);
  };
  add("Mon espace", "/");
  let acc = "";
  for (const p of parts) {
    acc += "/" + p;
    nav.appendChild(el("span", "›"));
    add(p, acc);
  }
}

const byPath = (p) => entries.find((e) => e.path === p);
const writableEntry = (e) => !version && !e["lecture seule"];

function open(e) {
  if (e["dossier"]) return load(e.path);
  if (e["indisponible"]) return status("Fichier indisponible hors ligne : votre Nœud et ses partenaires sont injoignables, et ce fichier n'est pas sur cet appareil.", true);
  download(e.path, e["taille"]);
}

function selectClick(ev, e) {
  const idx = entries.indexOf(e);
  if (ev.shiftKey && anchor !== null && byPath(anchor)) {
    const a = entries.indexOf(byPath(anchor));
    const [lo, hi] = a < idx ? [a, idx] : [idx, a];
    if (!(ev.ctrlKey || ev.metaKey)) selected.clear();
    for (let i = lo; i <= hi; i++) selected.add(entries[i].path);
  } else if (ev.ctrlKey || ev.metaKey) {
    if (selected.has(e.path)) selected.delete(e.path);
    else selected.add(e.path);
    anchor = e.path;
  } else if (selected.size === 1 && selected.has(e.path) && ev.detail === 1) {
    // Reclic simple sur la seule ligne sélectionnée : désélection (pas le
    // second clic d'un double-clic).
    selected.clear();
    anchor = null;
  } else {
    selected = new Set([e.path]);
    anchor = e.path;
  }
  paintSelection();
}

function paintSelection() {
  for (const tr of $("rows").querySelectorAll("tr.row[data-path]")) {
    const on = selected.has(tr.dataset.path);
    tr.classList.toggle("sel", on);
    const c = tr.querySelector("input.check");
    if (c) c.checked = on;
  }
  // Case d'en-tête : la page affichée.
  const page = shown();
  const onPage = page.filter((e) => selected.has(e.path)).length;
  const all = $("checkall");
  all.checked = page.length > 0 && onPage === page.length;
  all.indeterminate = onPage > 0 && onPage < page.length;
  const bar = $("selbar");
  bar.hidden = selected.size === 0;
  document.body.classList.toggle("has-sel", selected.size > 0);
  $("selall").hidden = selected.size >= entries.length;
  $("selall").textContent = "Tout sélectionner (" + entries.length + " éléments, toutes pages)";
  if (selected.size) {
    const list = [...selected].map(byPath).filter(Boolean);
    const files = list.filter((e) => !e["dossier"]);
    const dirs = list.length - files.length;
    const vol = files.reduce((s, e) => s + (e["taille"] || 0), 0);
    $("seltext").textContent =
      list.length + " élément(s) sélectionné(s) — " + size(vol) + (dirs ? " (hors contenu de " + dirs + " dossier(s))" : "");
    const w = list.every(writableEntry);
    for (const id of ["selmove", "seldelete", "selkeep", "selfree"]) $(id).hidden = !w;
    $("seldownload").hidden = !files.length;
  }
}

function quick(label, kind, fn, color) {
  const b = el("button", "", "qa");
  b.type = "button";
  b.title = label;
  b.setAttribute("aria-label", label);
  b.appendChild(icon(kind, color));
  b.addEventListener("click", (ev) => {
    ev.stopPropagation();
    fn();
  });
  return b;
}

function rows() {
  const tb = $("rows");
  tb.replaceChildren();
  // « Dossier parent » : toujours en tête, sauf à la racine.
  if (cwd !== "/") {
    const tr = el("tr", undefined, "row up");
    tr.appendChild(el("td"));
    const td = el("td", undefined, "name");
    td.appendChild(icon("up"));
    td.appendChild(document.createTextNode("Dossier parent"));
    td.colSpan = 4;
    tr.appendChild(td);
    tr.title = "Remonter dans " + (parent(cwd) === "/" ? "Mon espace" : base(parent(cwd)));
    tr.addEventListener("dblclick", () => load(parent(cwd)));
    tr.addEventListener("click", () => {
      selected.clear();
      paintSelection();
    });
    dropTarget(tr, parent(cwd));
    tb.appendChild(tr);
  }
  if (!entries.length) {
    const tr = el("tr");
    const td = el("td", readOnly ? "Dossier vide." : "Dossier vide : glissez des fichiers ici.", "muted");
    td.colSpan = 5;
    tr.appendChild(td);
    tb.appendChild(tr);
    pageNo = 0;
    pager();
    paintSelection();
    return;
  }
  pageNo = Math.min(pageNo, pageCount() - 1);
  pager();
  for (const e of shown()) {
    const path = e.path;
    const tr = el("tr", undefined, "row");
    tr.dataset.path = path;
    tr.tabIndex = 0;
    const ck = el("td", undefined, "ck");
    const c = el("input", undefined, "check");
    c.type = "checkbox";
    c.setAttribute("aria-label", "Sélectionner " + e["nom"]);
    c.addEventListener("click", (ev) => {
      ev.stopPropagation();
      if (c.checked) selected.add(path);
      else selected.delete(path);
      anchor = path;
      paintSelection();
    });
    ck.appendChild(c);
    tr.appendChild(ck);
    const name = el("td", undefined, "name");
    if (e["partages"]) {
      const s = el("button", "", "shared");
      s.type = "button";
      s.title = "Partagé (" + e["partages"] + ") : modifier le partage";
      s.appendChild(icon("people"));
      s.addEventListener("click", (ev) => {
        ev.stopPropagation();
        editShares(path);
      });
      name.appendChild(s);
    }
    name.appendChild(icon(e["dossier"] ? "folder" : "file", e["couleur"]));
    name.appendChild(el("span", e["nom"], "label"));
    if (e["favori"]) name.appendChild(el("span", "★", "fav"));
    if (e["gardé"]) name.appendChild(el("span", "sur cet appareil", "tag"));
    if (e["indisponible"]) {
      const t = el("span", "indisponible hors ligne", "tag");
      t.title = "Votre Nœud et ses partenaires sont injoignables, et ce fichier n'est pas sur cet appareil : il sera lisible à leur retour.";
      name.appendChild(t);
      tr.classList.add("dim");
    }
    if (e["ancienne clé"]) {
      const t = el("span", "🔓 ancienne clé", "tag old");
      t.title = "Encore protégé par votre ancienne clé, compromise : rechiffrez-le (menu ⋯)";
      name.appendChild(t);
    }
    tr.title = e["dossier"] ? "Double-clic : ouvrir" : "Double-clic : télécharger";
    tr.addEventListener("click", (ev) => selectClick(ev, e));
    tr.addEventListener("dblclick", () => open(e));
    tr.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") open(e);
      else if (ev.key === "F2" && writableEntry(e)) rename(path);
      else if (ev.key === "Delete" && writableEntry(e)) removeMany(selected.has(path) ? [...selected] : [path]);
    });
    tr.appendChild(name);
    tr.appendChild(el("td", e["dossier"] ? "" : size(e["taille"] || 0), "num"));
    const t = e["modifié"];
    tr.appendChild(el("td", t > 1.4e9 ? new Date(t * 1000).toLocaleString() : "", "num date"));
    const acts = el("td", undefined, "acts");
    // Actions rapides (ligne survolée ou sélectionnée).
    const qa = el("span", undefined, "quick");
    if (writableEntry(e)) qa.appendChild(quick("Partager", "share", () => share(path)));
    if (!e["dossier"]) qa.appendChild(quick("Télécharger", "down", () => open(e)));
    if (writableEntry(e)) qa.appendChild(quick("Renommer", "edit", () => rename(path)));
    if (!version)
      qa.appendChild(quick(e["favori"] ? "Retirer des favoris" : "Ajouter aux favoris", "star", () => favorite(e), e["favori"] ? "#e0a800" : undefined));
    acts.appendChild(qa);
    const items = menuItems(e);
    if (writableEntry(e)) {
      // Glisser l'élément (ou la sélection) sur un dossier : déplacement.
      tr.draggable = true;
      tr.addEventListener("dragstart", (ev) => {
        const list = selected.has(path) ? [...selected] : [path];
        ev.dataTransfer.setData("application/x-s3m-path", JSON.stringify(list));
        ev.dataTransfer.effectAllowed = "move";
      });
    }
    if (e["dossier"]) dropTarget(tr, path);
    if (items.length) {
      const more = el("button", "⋯", "more");
      more.type = "button";
      more.title = "Actions";
      more.setAttribute("aria-label", "Actions sur " + e["nom"]);
      more.setAttribute("aria-haspopup", "menu");
      more.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const r = more.getBoundingClientRect();
        openMenu(menuItems(e), r.right, r.bottom, more);
      });
      tr.addEventListener("contextmenu", (ev) => {
        ev.preventDefault();
        // Clic droit hors sélection : la ligne seule devient la sélection.
        if (!selected.has(path)) {
          selected = new Set([path]);
          anchor = path;
          paintSelection();
        }
        openMenu(selected.size > 1 ? selectionItems() : menuItems(e), ev.clientX, ev.clientY, more);
      });
      acts.appendChild(more);
    }
    tr.appendChild(acts);
    tb.appendChild(tr);
  }
  paintSelection();
}

// Pied de liste : lignes par page (10, 50, 100, autre) et numéro de page.
function pager() {
  const box = $("pager");
  box.replaceChildren();
  if (!entries.length) return;
  const n = pageCount();
  const l = el("label", "Lignes par page ");
  const s = el("select");
  const sizes = [10, 50, 100];
  for (const v of sizes) {
    const o = el("option", String(v));
    o.value = String(v);
    s.appendChild(o);
  }
  if (!sizes.includes(pageSize)) {
    const o = el("option", String(pageSize));
    o.value = String(pageSize);
    s.appendChild(o);
  }
  const other = el("option", "Autre…");
  other.value = "autre";
  s.appendChild(other);
  s.value = String(pageSize);
  s.addEventListener("change", async () => {
    let v = Number(s.value);
    if (s.value === "autre") {
      const r = await dialog("Lignes par page", [["Nombre de lignes", String(pageSize)]], "Appliquer", async ([x]) =>
        Number.isInteger(Number(x)) && Number(x) >= 1 && Number(x) <= 10000 ? null : "Saisissez un nombre entier entre 1 et 10 000.",
      );
      v = r ? Number(r[0]) : pageSize;
    }
    const first = pageNo * pageSize;
    pageSize = v;
    pageNo = Math.floor(first / pageSize);
    try {
      localStorage.setItem("s3m-explorer-lignes", String(pageSize));
    } catch (_) {}
    rows();
  });
  l.appendChild(s);
  box.appendChild(l);
  const nav = el("span", undefined, "pages");
  const btn = (label, to, disabled) => {
    const b = el("button", label, "small");
    b.type = "button";
    b.disabled = disabled;
    b.addEventListener("click", () => {
      pageNo = to;
      rows();
    });
    nav.appendChild(b);
  };
  btn("‹ Précédente", pageNo - 1, pageNo === 0);
  const lp = el("label", " Page ");
  const num = el("input", undefined, "pageno");
  num.type = "number";
  num.min = "1";
  num.max = String(n);
  num.value = String(pageNo + 1);
  num.addEventListener("change", () => {
    const v = Math.min(n, Math.max(1, Math.round(Number(num.value)) || 1));
    pageNo = v - 1;
    rows();
  });
  lp.append(num, document.createTextNode(" / " + n + " "));
  nav.appendChild(lp);
  btn("Suivante ›", pageNo + 1, pageNo >= n - 1);
  box.appendChild(nav);
  box.appendChild(el("span", entries.length + " élément(s)", "muted"));
}

function menuItems(e) {
  const path = e.path;
  const items = [];
  const btn = (label, fn, cls) => items.push({ label, fn, cls });
  if (e["dossier"]) btn("Ouvrir", () => load(path));
  else btn("Télécharger", () => open(e));
  if (version) {
    btn("Restaurer cette version", () => restore(path, version, versionLabel));
    return items;
  }
  if (!inShared(cwd)) btn("Historique des versions…", () => versionsOf(path, e["dossier"]));
  if (!e["lecture seule"]) {
    btn("Partager", () => share(path));
    if (e["partages"]) btn("Modifier le partage…", () => editShares(path));
    btn("Renommer", () => rename(path));
    const org = [
      { label: "Déplacer…", fn: () => moveMany([path]) },
      { label: e["favori"] ? "Retirer des favoris" : "Ajouter aux favoris", fn: () => favorite(e) },
    ];
    if (e["dossier"]) org.push({ label: "Couleur de dossier…", fn: () => pickColor(e) });
    items.push({ label: "Organiser", sub: org });
    if (e["ancienne clé"]) btn("Rechiffrer avec la nouvelle clé", () => run("Rechiffrement de " + e["nom"], () => call("explorer_reencrypt", { chemin: path })));
    btn(e["gardé"] ? "Ne plus garder hors connexion" : "Rendre disponible hors connexion", () => keep([path], !e["gardé"]));
    if (!e["gardé"]) btn("Libérer l'espace", () => freeSpace([path]));
    btn("Supprimer", () => removeMany([path]), "danger");
  } else {
    btn(e["favori"] ? "Retirer des favoris" : "Ajouter aux favoris", () => favorite(e));
  }
  return items;
}

function selectionItems() {
  const list = [...selected];
  const items = [];
  const w = list.map(byPath).filter(Boolean).every(writableEntry);
  if (list.some((p) => byPath(p) && !byPath(p)["dossier"])) items.push({ label: "Télécharger", fn: downloadMany });
  if (w) {
    items.push({ label: "Déplacer…", fn: () => moveMany(list) });
    items.push({ label: "Rendre disponible hors connexion", fn: () => keep(list, true) });
    items.push({ label: "Libérer l'espace", fn: () => freeSpace(list) });
    items.push({ label: "Supprimer", fn: () => removeMany(list), cls: "danger" });
  }
  return items;
}

// Menu contextuel : `items` = [{ label, fn, cls, sub }], aligné à droite
// sur (x, y) et gardé dans la fenêtre ; un sous-menu (`sub`) s'ouvre à
// droite, ou à gauche faute de place. Fermé par un clic ailleurs, Échap,
// le défilement ou un choix. Flèches entre les entrées.
let menuEl = null;
let subEl = null;
function closeMenu(refocus) {
  if (subEl) {
    subEl.remove();
    subEl = null;
  }
  if (!menuEl) return;
  const back = menuEl._opener;
  menuEl.remove();
  menuEl = null;
  if (refocus && back) back.focus();
}
function buildMenu(items, isSub) {
  const m = el("div", undefined, "menu");
  m.setAttribute("role", "menu");
  for (const it of items) {
    const b = el("button", it.label + (it.sub ? "" : ""), (it.cls || "") + (it.sub ? " has-sub" : ""));
    b.type = "button";
    b.setAttribute("role", "menuitem");
    if (it.sub) {
      b.setAttribute("aria-haspopup", "menu");
      const show = () => openSub(it.sub, b);
      b.addEventListener("mouseenter", show);
      b.addEventListener("click", (ev) => {
        ev.stopPropagation();
        show();
        subEl.querySelector("button").focus();
      });
      b.addEventListener("keydown", (ev) => {
        if (ev.key === "ArrowRight") {
          ev.preventDefault();
          show();
          subEl.querySelector("button").focus();
        }
      });
    } else {
      if (!isSub) b.addEventListener("mouseenter", () => subEl && (subEl.remove(), (subEl = null)));
      b.addEventListener("click", (ev) => {
        ev.stopPropagation();
        closeMenu();
        it.fn();
      });
    }
    m.appendChild(b);
  }
  m.addEventListener("keydown", (ev) => {
    const list = [...m.querySelectorAll("button")];
    const i = list.indexOf(document.activeElement);
    if (ev.key === "Escape") {
      ev.preventDefault();
      ev.stopPropagation();
      if (isSub) {
        const opener = m._opener;
        m.remove();
        subEl = null;
        opener.focus();
      } else closeMenu(true);
    } else if (ev.key === "ArrowLeft" && isSub) {
      ev.preventDefault();
      const opener = m._opener;
      m.remove();
      subEl = null;
      opener.focus();
    } else if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
      ev.preventDefault();
      const n = list.length;
      list[(i + (ev.key === "ArrowDown" ? 1 : n - 1)) % n].focus();
    } else if (ev.key === "Tab") {
      closeMenu();
    }
  });
  m.addEventListener("click", (ev) => ev.stopPropagation());
  return m;
}
function openSub(items, opener) {
  if (subEl && subEl._opener === opener) return;
  if (subEl) subEl.remove();
  const m = buildMenu(items, true);
  m._opener = opener;
  document.body.appendChild(m);
  subEl = m;
  const r = opener.getBoundingClientRect();
  const w = m.offsetWidth;
  const h = m.offsetHeight;
  const left = r.right + w + 4 > innerWidth ? r.left - w : r.right;
  m.style.left = Math.max(4, left) + "px";
  m.style.top = Math.max(4, Math.min(r.top - 4, innerHeight - h - 4)) + "px";
}
function openMenu(items, x, y, opener) {
  closeMenu();
  if (!items.length) return;
  const m = buildMenu(items, false);
  m._opener = opener;
  document.body.appendChild(m);
  menuEl = m;
  const w = m.offsetWidth;
  const h = m.offsetHeight;
  m.style.left = Math.max(4, Math.min(x - w, innerWidth - w - 4)) + "px";
  m.style.top = Math.max(4, y + h > innerHeight - 4 ? y - h : y) + "px";
  m.querySelector("button").focus();
}
document.addEventListener("click", () => closeMenu());
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") closeMenu(true);
});
addEventListener("scroll", () => closeMenu(), true);
addEventListener("resize", () => closeMenu());

// Cible de dépôt : éléments déplacés dedans, ou fichiers envoyés dedans.
function dropTarget(node, dir) {
  if (inShared(dir)) return;
  node.addEventListener("dragover", (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    node.classList.add("drop-target");
  });
  node.addEventListener("dragleave", () => node.classList.remove("drop-target"));
  node.addEventListener("drop", (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    node.classList.remove("drop-target");
    $("zone").classList.remove("dragover");
    const raw = ev.dataTransfer.getData("application/x-s3m-path");
    if (raw) {
      const list = JSON.parse(raw).filter((p) => p !== dir && parent(p) !== dir);
      if (list.length) moveTo(list, dir);
      return;
    }
    dropFiles(ev.dataTransfer, dir);
  });
}

// ------------------------------------------------------------ actions

async function run(label, fn) {
  busy++;
  status(label + "…");
  try {
    const r = await fn();
    status((r && r.message) || "");
    return true;
  } catch (e) {
    status(e.message, true);
    uiAlert("Échec", label + " : " + e.message);
    return false;
  } finally {
    busy--;
    load(cwd);
  }
}

async function mkdir() {
  const v = await dialog("Nouveau dossier", [["Nom", "", "Nouveau dossier"]], "Créer", async ([n]) => {
    if (!n) return "Saisissez un nom.";
    await call("explorer_mkdir", { chemin: n.startsWith("/") ? n : join(cwd, n) });
    return null;
  });
  if (v) load(cwd);
}

// Renommer : nouveau nom, ou chemin (relatif au dossier, ou absolu) ; une
// destination inexistante est signalée dans la fenêtre.
async function rename(path) {
  const n = base(path);
  const dot = n.lastIndexOf(".");
  const e = byPath(path);
  const sel = e && !e["dossier"] && dot > 0 ? dot : n.length;
  const v = await dialog("Renommer « " + n + " »", [["Nouveau nom (ou chemin)", n, "", null, sel]], "Renommer", async ([x]) => {
    if (!x) return "Saisissez un nom.";
    if (x === n) return null;
    const to = x.startsWith("/") ? x : join(parent(path), x);
    await call("explorer_move", { de: path, vers: to });
    return null;
  });
  if (v) {
    selected.clear();
    load(cwd);
  }
}

// Déplacer : fenêtre de navigation dans les dossiers de l'espace.
async function moveMany(list) {
  if (!list.length) return;
  let at = parent(list[0]);
  let dirs = [];
  const title = list.length > 1 ? "Déplacer " + list.length + " éléments" : "Déplacer « " + base(list[0]) + " »";
  const picked = await modal(
    title,
    (f) => {
      const where = el("div", "", "pick-where");
      const box = el("div", undefined, "pick");
      f.append(where, box);
      const show = async (dir) => {
        at = dir;
        where.replaceChildren();
        const parts = dir.split("/").filter(Boolean);
        const add = (label, p) => {
          const b = el("button", label, "crumb");
          b.type = "button";
          b.addEventListener("click", () => show(p));
          where.appendChild(b);
        };
        add("Mon espace", "/");
        let acc = "";
        for (const p of parts) {
          acc += "/" + p;
          where.appendChild(el("span", "›", "muted"));
          add(p, acc);
        }
        box.replaceChildren(el("p", "Chargement…", "muted"));
        try {
          const r = await call("explorer_list", { chemin: dir });
          dirs = (r["entrées"] || []).filter((e) => e["dossier"]).map((e) => join(dir, e["nom"]));
        } catch (e) {
          box.replaceChildren(el("p", e.message, "dlg-err"));
          return;
        }
        box.replaceChildren();
        if (dir !== "/") {
          const up = el("button", "", "pick-row");
          up.type = "button";
          up.append(icon("up"), document.createTextNode("Dossier parent"));
          up.addEventListener("click", () => show(parent(dir)));
          box.appendChild(up);
        }
        const usable = dirs.filter((d) => !inShared(d) && !list.some((p) => d === p || d.startsWith(p + "/")));
        if (!usable.length) box.appendChild(el("p", "Aucun sous-dossier.", "muted"));
        for (const d of usable) {
          const b = el("button", "", "pick-row");
          b.type = "button";
          b.append(icon("folder"), document.createTextNode(base(d)));
          b.addEventListener("click", () => show(d));
          box.appendChild(b);
        }
      };
      show(at);
    },
    [
      { label: "Annuler", value: null },
      { label: "Déplacer ici", value: true },
    ],
    async () => {
      if (inShared(at)) return "Impossible de déplacer dans « Partagés avec moi ».";
      if (list.every((p) => parent(p) === at)) return "Les éléments sont déjà dans ce dossier.";
      return null;
    },
  );
  if (picked) moveTo(list, at);
}

async function moveTo(list, dir) {
  busy++;
  const errs = [];
  let n = 0;
  for (const p of list) {
    if (parent(p) === dir) continue;
    status("Déplacement de " + base(p) + "…");
    try {
      await call("explorer_move", { de: p, vers: join(dir, base(p)) });
      n++;
    } catch (e) {
      errs.push(base(p) + " : " + e.message);
    }
  }
  busy--;
  selected.clear();
  status(n + " élément(s) déplacé(s)", errs.length > 0);
  if (errs.length) uiAlert("Déplacement incomplet", errs.join("\n"));
  load(cwd);
}

async function removeMany(list) {
  if (!list.length) return;
  const one = list.length === 1 ? byPath(list[0]) : null;
  const what = one
    ? one["dossier"]
      ? "le dossier « " + one["nom"] + " » et tout son contenu"
      : "« " + one["nom"] + " »"
    : list.length + " éléments (dossiers compris avec leur contenu)";
  if (!(await uiConfirm("Supprimer", "Supprimer " + what + " ? Il reste récupérable dans l'historique des versions.", "Supprimer", true))) return;
  busy++;
  const errs = [];
  for (const p of list) {
    status("Suppression de " + base(p) + "…");
    try {
      await call("explorer_delete", { chemin: p });
    } catch (e) {
      errs.push(base(p) + " : " + e.message);
    }
  }
  busy--;
  selected.clear();
  status(errs.length ? "Suppression incomplète" : list.length + " élément(s) supprimé(s)", errs.length > 0);
  if (errs.length) uiAlert("Suppression incomplète", errs.join("\n"));
  load(cwd);
}

async function each(label, list, fn) {
  busy++;
  const errs = [];
  for (const p of list) {
    status(label + " : " + base(p) + "…");
    try {
      await fn(p);
    } catch (e) {
      errs.push(base(p) + " : " + e.message);
    }
  }
  busy--;
  status(errs.length ? label + " incomplète" : label + " : " + list.length + " élément(s)", errs.length > 0);
  if (errs.length) uiAlert(label + " incomplète", errs.join("\n"));
  load(cwd);
}

function keep(list, on) {
  each(on ? "Mise hors connexion" : "Retrait du hors connexion", list, (p) => call(on ? "keep_offline" : "unkeep_offline", { "élément": p }));
}

// Retire de ce disque le contenu déjà envoyé au Nœud (reste visible,
// revient à l'ouverture).
function freeSpace(list) {
  each("Libération de l'espace", list, (p) => call("free_space", { "élément": p }));
}

function favorite(e) {
  run(e["favori"] ? "Retrait du favori" : "Ajout aux favoris", () => call("explorer_favorite", { chemin: e.path }));
}

function recentColors() {
  try {
    return JSON.parse(localStorage.getItem("s3m-couleurs") || "[]").slice(0, 8);
  } catch (_) {
    return [];
  }
}

async function pickColor(e) {
  let chosen = e["couleur"] || "";
  const v = await modal(
    "Couleur du dossier « " + e["nom"] + " »",
    (f) => {
      const swatches = (label, list) => {
        if (!list.length) return;
        f.appendChild(el("p", label, "muted"));
        const row = el("div", undefined, "swatches");
        for (const c of list) {
          const b = el("button", "", "swatch" + (c === chosen ? " on" : ""));
          b.type = "button";
          b.style.background = c;
          b.title = c;
          b.setAttribute("aria-label", "Couleur " + c);
          b.addEventListener("click", () => {
            chosen = c;
            f.querySelectorAll(".swatch").forEach((x) => x.classList.toggle("on", x.title === c));
            custom.value = c;
          });
          row.appendChild(b);
        }
        f.appendChild(row);
      };
      const custom = el("input");
      custom.type = "color";
      custom.value = chosen || "#3b7dd8";
      swatches("Couleurs récentes", recentColors());
      swatches("Couleurs prédéfinies", PRESETS);
      const l = el("label", "Autre couleur ");
      l.className = "inline";
      custom.addEventListener("input", () => {
        chosen = custom.value;
        f.querySelectorAll(".swatch").forEach((x) => x.classList.remove("on"));
      });
      l.appendChild(custom);
      f.appendChild(l);
    },
    [
      { label: "Annuler", value: null },
      { label: "Couleur par défaut", value: "aucune" },
      { label: "Appliquer", value: "ok" },
    ],
  );
  if (!v) return;
  const c = v === "aucune" ? "" : chosen;
  if (c) {
    try {
      const r = [c, ...recentColors().filter((x) => x !== c)].slice(0, 8);
      localStorage.setItem("s3m-couleurs", JSON.stringify(r));
    } catch (_) {}
  }
  run("Couleur du dossier", () => call("explorer_color", { chemin: e.path, couleur: c }));
}

async function share(path) {
  const v = await dialog(
    "Partager « " + base(path) + " »",
    [
      ["Destinataire (pseudo d'un contact ou identifiant S3m ; vide : lien public)", "", "pseudo ou identifiant", contacts],
      ["Expiration (jours, vide : jamais)", "", "0"],
    ],
    "Partager",
  );
  if (!v) return;
  busy++;
  status("Création du partage…");
  try {
    const r = await call("create_share", { "élément": path, destinataire: v[0], "expiration (jours)": v[1] || "0" });
    status(r.message || "");
    const rv = r["révéler"];
    if (rv && rv["à copier"]) await reveal(rv["titre"] || "Partage", rv["à copier"]);
  } catch (e) {
    status(e.message, true);
    uiAlert("Partage refusé", e.message);
  } finally {
    busy--;
    load(cwd);
  }
}

// Partages actifs d'un élément : afficher le lien / l'invitation, retirer,
// ou en créer un nouveau.
async function editShares(path) {
  let r;
  try {
    r = await call("explorer_shares", { chemin: path });
  } catch (e) {
    return uiAlert("Partages", e.message);
  }
  let action = null;
  const v = await modal(
    "Partages de « " + base(path) + " »",
    (f) => {
      const list = r["partages"] || [];
      if (!list.length) f.appendChild(el("p", "Aucun partage actif.", "muted"));
      const t = el("table");
      for (const s of list) {
        const tr = el("tr");
        tr.appendChild(el("td", s["pour"]));
        tr.appendChild(el("td", s["expire le"] ? "expire le " + when(s["expire le"]) : "sans expiration", "muted"));
        tr.appendChild(el("td", s["état"], "muted"));
        const td = el("td", undefined, "acts");
        const b1 = el("button", s["lien public"] ? "Lien" : "Invitation", "small");
        b1.type = "button";
        b1.addEventListener("click", () => {
          action = { kind: "show", id: s["id"] };
          $("dlgform").requestSubmit();
        });
        const b2 = el("button", "Retirer", "small danger");
        b2.type = "button";
        b2.addEventListener("click", () => {
          action = { kind: "revoke", id: s["id"], pour: s["pour"] };
          $("dlgform").requestSubmit();
        });
        td.append(b1, b2);
        tr.appendChild(td);
        t.appendChild(tr);
      }
      if (list.length) f.appendChild(t);
    },
    [
      { label: "Fermer", value: null },
      { label: "Nouveau partage", value: "new" },
    ],
  );
  if (!v) return;
  if (!action) return share(path);
  if (action.kind === "show") {
    try {
      const x = await call("show_share", { id: action.id });
      const rv = x["révéler"];
      if (rv) await reveal(rv["titre"] || "Partage", rv["à copier"]);
    } catch (e) {
      uiAlert("Partage", e.message);
    }
    return editShares(path);
  }
  if (await uiConfirm("Retirer le partage", "Retirer le partage avec " + action.pour + " ? Il ne pourra plus rien lire ; ce qu'il a déjà téléchargé ne peut pas lui être repris.", "Retirer", true)) {
    await run("Retrait du partage", () => call("revoke_share", { id: action.id }));
  }
}

async function download(path, total) {
  busy++;
  const parts = [];
  let off = 0;
  try {
    for (;;) {
      status("Téléchargement de " + base(path) + (total ? " : " + Math.round((100 * off) / total) + " %" : "…"));
      const r = await call("explorer_read", version ? { chemin: path, offset: off, version } : { chemin: path, offset: off });
      const b = fromHex(r["données"] || "");
      parts.push(b);
      off += b.length;
      if (r["fin"] || !b.length) break;
    }
    const a = el("a");
    a.href = URL.createObjectURL(new Blob(parts));
    a.download = base(path);
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 1000);
    status(base(path) + " téléchargé");
    return true;
  } catch (e) {
    status(e.message, true);
    return false;
  } finally {
    busy--;
  }
}

// Téléchargement de tous les fichiers sélectionnés (un par un).
async function downloadMany() {
  const files = [...selected].map(byPath).filter((e) => e && !e["dossier"] && !e["indisponible"]);
  let ok = 0;
  for (const e of files) if (await download(e.path, e["taille"])) ok++;
  status(ok + " / " + files.length + " fichier(s) téléchargé(s)", ok < files.length);
}

// ------------------------------------------------------------ envoi

async function upload(file, dir) {
  const path = join(dir, file.name);
  let off = 0;
  do {
    const slice = new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer());
    const last = off + slice.length >= file.size;
    status("Envoi de " + file.name + (file.size ? " : " + Math.round((100 * off) / file.size) + " %" : ""));
    await call("explorer_write", { chemin: path, offset: off, "données": toHex(slice), fin: last });
    off += slice.length;
  } while (off < file.size);
}

// Dossiers intermédiaires créés au besoin (envoi d'une arborescence).
async function ensureDir(path, made) {
  if (path === "/" || made.has(path)) return;
  await ensureDir(parent(path), made);
  try {
    await call("explorer_mkdir", { chemin: path });
  } catch (_) {
    // Déjà présent.
  }
  made.add(path);
}

// `items` : [{ file, rel }] où `rel` est le chemin relatif (« a/b/c.txt »).
async function sendAll(items, dir) {
  if (!items.length) return;
  busy++;
  const made = new Set();
  let done = 0;
  try {
    for (const { file, rel } of items) {
      const sub = rel.includes("/") ? join(dir, rel.slice(0, rel.lastIndexOf("/"))) : dir;
      await ensureDir(sub, made);
      await upload(file, sub);
      done++;
    }
    status(done + " fichier(s) importé(s) ; synchronisation avec votre Nœud en cours");
  } catch (e) {
    status("Import interrompu après " + done + " fichier(s) : " + e.message, true);
  } finally {
    busy--;
    load(cwd);
  }
}

// Fichiers et dossiers déposés (arborescences comprises).
async function dropFiles(dt, dir) {
  const items0 = [...(dt.items || [])]
    .map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null))
    .filter(Boolean);
  if (!items0.length) {
    return sendAll([...(dt.files || [])].map((f) => ({ file: f, rel: f.name })), dir);
  }
  const items = [];
  const walk = async (entry, prefix) => {
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej));
      items.push({ file, rel: prefix + file.name });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      for (;;) {
        const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        if (!batch.length) break;
        for (const c of batch) await walk(c, prefix + entry.name + "/");
      }
    }
  };
  for (const e of items0) await walk(e, "");
  sendAll(items, dir);
}

// ------------------------------------------------------------ démarrage

$("mkdir").addEventListener("click", mkdir);
$("upfiles").addEventListener("click", () => $("pickfiles").click());
$("upfolder").addEventListener("click", () => $("pickfolder").click());
$("pickfiles").addEventListener("change", (ev) => {
  sendAll([...ev.target.files].map((f) => ({ file: f, rel: f.name })), cwd);
  ev.target.value = "";
});
$("pickfolder").addEventListener("change", (ev) => {
  sendAll([...ev.target.files].map((f) => ({ file: f, rel: f.webkitRelativePath || f.name })), cwd);
  ev.target.value = "";
});
// Case d'en-tête : toute la page affichée (ajoutée à la sélection, ou retirée).
$("checkall").addEventListener("change", (ev) => {
  for (const e of shown()) {
    if (ev.target.checked) selected.add(e.path);
    else selected.delete(e.path);
  }
  paintSelection();
});
$("selall").addEventListener("click", () => {
  selected = new Set(entries.map((e) => e.path));
  paintSelection();
});
$("selnone").addEventListener("click", () => {
  selected.clear();
  paintSelection();
});
$("selmove").addEventListener("click", () => moveMany([...selected]));
$("seldelete").addEventListener("click", () => removeMany([...selected]));
$("selkeep").addEventListener("click", () => keep([...selected], true));
$("selfree").addEventListener("click", () => freeSpace([...selected]));
$("seldownload").addEventListener("click", downloadMany);
document.addEventListener("keydown", (ev) => {
  if ($("dlg").open || ev.target.closest("input, textarea")) return;
  if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "a") {
    ev.preventDefault();
    selected = new Set(entries.map((e) => e.path));
    paintSelection();
  } else if (ev.key === "Escape" && selected.size && !menuEl) {
    selected.clear();
    paintSelection();
  } else if (ev.key === "Backspace" && cwd !== "/") {
    load(parent(cwd));
  }
});

// ------------------------------------------------------------ versions

function browse(v, label, path) {
  version = v;
  versionLabel = label;
  load(path);
}

async function restore(path, v, label) {
  if (!(await uiConfirm("Restaurer", "Restaurer « " + path + " » tel qu'il était le " + label + " ? La version actuelle reste dans l'historique.", "Restaurer"))) return;
  const keepVersion = version;
  version = null;
  run("Restauration de " + base(path), () => call("explorer_restore", { chemin: path, version: v })).then(() => {
    version = keepVersion;
    load(cwd);
  });
}

// Fenêtre listant les versions d'un élément (ou de tout l'espace),
// regroupées par jour ; pour un dossier, ce que chaque version a ajouté,
// supprimé et modifié par rapport à la précédente.
async function versionsOf(path, isDir) {
  let r;
  try {
    status("Lecture de l'historique…");
    r = await call("explorer_versions", { chemin: path });
    status("");
  } catch (e) {
    status(e.message, true);
    return;
  }
  let then = null;
  await modal(
    path === "/" ? "Historique des versions : mon espace" : "Historique des versions de « " + base(path) + " »",
    (f) => {
      f.appendChild(el("p", "Versions gardées " + (r["conservation (jours)"] || 0) + " jours, comptées dans votre quota (Mon compte pour les purger).", "muted"));
      const list = r["versions"] || [];
      if (!list.length) f.appendChild(el("p", "Aucune version passée."));
      const days = [];
      for (const v of list) {
        const t = v["du"] > 1.4e9 ? new Date(v["du"] * 1000) : null;
        const day = t ? t.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long", year: "numeric" }) : "date inconnue";
        let g = days.find((x) => x.day === day);
        if (!g) days.push((g = { day, rows: [] }));
        g.rows.push(v);
      }
      const num = (x) => (x === null || x === undefined ? "—" : String(x));
      days.forEach((g, gi) => {
        const det = el("details", undefined, "day");
        det.open = gi === 0;
        det.appendChild(el("summary", g.day.charAt(0).toUpperCase() + g.day.slice(1) + " — " + g.rows.length + " version(s)"));
        const t = el("table");
        const head = el("tr");
        const cols = isDir ? ["Heure", "Ajouts", "Suppressions", "Modifications", ""] : ["Heure", "Taille", ""];
        for (const h of cols) head.appendChild(el("th", h));
        t.appendChild(head);
        for (const v of g.rows) {
          const tr = el("tr");
          const hour = v["du"] > 1.4e9 ? new Date(v["du"] * 1000).toLocaleTimeString() : "—";
          tr.appendChild(el("td", v["actuelle"] ? "Version actuelle" : hour));
          if (isDir) {
            tr.appendChild(el("td", num(v["ajouts"]), "num"));
            tr.appendChild(el("td", num(v["suppressions"]), "num"));
            tr.appendChild(el("td", num(v["modifications"]), "num"));
          } else {
            tr.appendChild(el("td", size(v["taille"] || 0), "num"));
          }
          const td = el("td", undefined, "acts");
          const add = (txt, fn) => {
            const b = el("button", txt, "small");
            b.type = "button";
            b.addEventListener("click", () => {
              then = fn;
              $("dlgform").requestSubmit();
            });
            td.appendChild(b);
          };
          const label = when(v["du"]);
          if (!v["actuelle"]) {
            if (isDir) add("Parcourir", () => browse(v["version"], label, path));
            else
              add("Télécharger", () => {
                const keepVersion = version;
                version = v["version"];
                download(path, v["taille"]).finally(() => (version = keepVersion));
              });
            if (path !== "/") add("Restaurer", () => restore(path, v["version"], label));
          }
          tr.appendChild(td);
          t.appendChild(tr);
        }
        det.appendChild(t);
        f.appendChild(det);
      });
    },
    [{ label: "Fermer", value: true }],
  );
  if (then) then();
}

$("versions").addEventListener("click", () => versionsOf("/", true));
$("reencryptall").addEventListener("click", () =>
  run("Rechiffrement de ce dossier", () => call("explorer_reencrypt", { chemin: cwd })));
$("current").addEventListener("click", () => browse(null, "", cwd));
$("restoredir").addEventListener("click", () => restore(cwd, version, versionLabel));
$("restoreall").addEventListener("click", async () => {
  if (!(await uiConfirm("Restaurer tout l'espace", "Remettre TOUT votre espace dans l'état du " + versionLabel + " ? (après un rançongiciel par exemple) La version actuelle reste dans l'historique.", "Tout restaurer", true))) return;
  const v = version;
  version = null;
  run("Retour de tout l'espace au " + versionLabel, () => call("explorer_restore_all", { version: v }));
});

const zone = $("zone");
zone.addEventListener("dragover", (ev) => {
  if (readOnly) return;
  ev.preventDefault();
  zone.classList.add("dragover");
});
zone.addEventListener("dragleave", (ev) => {
  if (!zone.contains(ev.relatedTarget)) zone.classList.remove("dragover");
});
zone.addEventListener("drop", (ev) => {
  ev.preventDefault();
  zone.classList.remove("dragover");
  if (readOnly) return;
  if (ev.dataTransfer.getData("application/x-s3m-path")) return;
  dropFiles(ev.dataTransfer, cwd);
});

let start = "/";
try {
  start = sessionStorage.getItem("s3m-explorer") || "/";
} catch (_) {}
load(start);
// Changements faits ailleurs (autre appareil, dossier synchronisé).
setInterval(() => {
  if (!busy && !document.hidden && !$("dlg").open && !menuEl) load(cwd);
}, 15000);

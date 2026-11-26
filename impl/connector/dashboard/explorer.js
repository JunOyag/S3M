"use strict";
// Explorateur de l'espace S3m (dashboard Connecteur) : navigation, dossiers,
// envoi par glisser-déposer, déplacement, téléchargement, partage,
// suppression, « garder sur cet appareil ».

const token = (() => {
  const t = new URLSearchParams(location.hash.slice(1)).get("token");
  try {
    if (t) localStorage.setItem("s3m-token", t);
    return t || localStorage.getItem("s3m-token") || "";
  } catch (_) {
    return t || "";
  }
})();

// Morceau envoyé ou lu (octets), comme `explorer::CHUNK`.
const CHUNK = 512 * 1024;
const SHARED = "/Partagés avec moi";

let cwd = "/";
let folderMode = false;
let readOnly = false;
let busy = 0;
let contacts = [];
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

// ------------------------------------------------------------ affichage

async function load(path) {
  try {
    const r = await call("explorer_list", version ? { chemin: path, version } : { chemin: path });
    cwd = r["chemin"];
    if (!version) {
      folderMode = !!r["mode dossier"];
      contacts = r["contacts"] || [];
      reencryptable = !!r["rechiffrer"];
    }
    readOnly = !!version || !!r["lecture seule"] || cwd === SHARED || cwd.startsWith(SHARED + "/");
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
    rows(r["entrées"] || []);
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

function rows(entries) {
  const tb = $("rows");
  tb.replaceChildren();
  if (!entries.length) {
    const tr = el("tr");
    const td = el("td", readOnly ? "Dossier vide." : "Dossier vide : glissez des fichiers ici.", "muted");
    td.colSpan = 4;
    tr.appendChild(td);
    tb.appendChild(tr);
    return;
  }
  for (const e of entries) {
    const path = join(cwd, e["nom"]);
    const tr = el("tr", undefined, "row");
    const name = el("td", undefined, "name");
    if (!version) {
      // Favori en un clic (affiché sur l'accueil).
      const star = el("button", e["favori"] ? "★" : "☆", "star" + (e["favori"] ? " on" : ""));
      star.type = "button";
      star.title = e["favori"] ? "Retirer des favoris" : "Ajouter aux favoris (affiché sur l'accueil)";
      star.addEventListener("click", (ev) => {
        ev.stopPropagation();
        run(e["favori"] ? "Retrait du favori" : "Ajout aux favoris", () => call("explorer_favorite", { chemin: path }));
      });
      name.appendChild(star);
    }
    name.appendChild(el("span", e["dossier"] ? "📁" : "📄", "ico"));
    name.appendChild(document.createTextNode(e["nom"]));
    if (e["gardé"]) name.appendChild(el("span", "sur cet appareil", "tag"));
    if (e["ancienne clé"]) {
      const t = el("span", "🔓 ancienne clé", "tag old");
      t.title = "Encore protégé par votre ancienne clé, compromise : rechiffrez-le (menu ⋯)";
      name.appendChild(t);
    }
    name.title = e["dossier"] ? "Ouvrir" : "Télécharger";
    name.addEventListener("click", () => (e["dossier"] ? load(path) : download(path, e["taille"])));
    tr.appendChild(name);
    tr.appendChild(el("td", e["dossier"] ? "" : size(e["taille"] || 0), "num"));
    const t = e["modifié"];
    tr.appendChild(el("td", t > 1.4e9 ? new Date(t * 1000).toLocaleString() : "", "num date"));
    const acts = el("td", undefined, "acts");
    // Actions de la ligne : menu « ⋯ » (et clic droit sur la ligne).
    const items = [];
    const btn = (label, fn, cls) => items.push({ label, fn, cls });
    if (!e["dossier"]) btn("Télécharger", () => download(path, e["taille"]));
    if (version) {
      btn("Restaurer cette version", () => restore(path, version, versionLabel));
    } else if (cwd !== SHARED && !cwd.startsWith(SHARED + "/")) {
      btn("Versions…", () => versionsOf(path, e["dossier"]));
    }
    if (!e["lecture seule"]) {
      btn("Partager", () => share(path));
      btn("Renommer / déplacer", () => move(path));
      if (e["ancienne clé"]) btn("Rechiffrer avec la nouvelle clé", () => run("Rechiffrement de " + e["nom"], () => call("explorer_reencrypt", { chemin: path })));
      if (folderMode) {
        btn(e["gardé"] ? "Ne plus garder" : "Garder hors ligne", () => keep(path, !e["gardé"]));
        if (!e["gardé"]) btn("Libérer l'espace", () => freeSpace(path));
      }
      btn("Supprimer", () => remove(path, e["dossier"]), "danger");
      // Glisser l'élément sur un dossier : déplacement.
      tr.draggable = true;
      tr.addEventListener("dragstart", (ev) => {
        ev.dataTransfer.setData("application/x-s3m-path", path);
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
        openMenu(items, r.right, r.bottom, more);
      });
      tr.addEventListener("contextmenu", (ev) => {
        ev.preventDefault();
        openMenu(items, ev.clientX, ev.clientY, more);
      });
      acts.appendChild(more);
    }
    tr.appendChild(acts);
    tb.appendChild(tr);
  }
}

// Menu contextuel unique : `items` = [{ label, fn, cls }], aligné à
// droite sur (x, y) et gardé dans la fenêtre ; fermé par un clic ailleurs,
// Échap, le défilement ou un choix. Flèches haut / bas entre les entrées.
let menuEl = null;
function closeMenu(refocus) {
  if (!menuEl) return;
  const back = menuEl._opener;
  menuEl.remove();
  menuEl = null;
  if (refocus && back) back.focus();
}
function openMenu(items, x, y, opener) {
  closeMenu();
  const m = el("div", undefined, "menu");
  m.setAttribute("role", "menu");
  m._opener = opener;
  for (const it of items) {
    const b = el("button", it.label, it.cls || "");
    b.type = "button";
    b.setAttribute("role", "menuitem");
    b.addEventListener("click", (ev) => {
      ev.stopPropagation();
      closeMenu();
      it.fn();
    });
    m.appendChild(b);
  }
  m.addEventListener("keydown", (ev) => {
    const list = [...m.querySelectorAll("button")];
    const i = list.indexOf(document.activeElement);
    if (ev.key === "Escape") {
      ev.preventDefault();
      closeMenu(true);
    } else if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
      ev.preventDefault();
      const n = list.length;
      list[(i + (ev.key === "ArrowDown" ? 1 : n - 1)) % n].focus();
    } else if (ev.key === "Tab") {
      closeMenu();
    }
  });
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

// Cible de dépôt : élément déplacé dedans, ou fichiers envoyés dedans.
function dropTarget(node, dir) {
  if (dir === SHARED || dir.startsWith(SHARED + "/")) return;
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
    const from = ev.dataTransfer.getData("application/x-s3m-path");
    if (from) {
      if (from !== dir && parent(from) !== dir) doMove(from, join(dir, base(from)));
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
    return false;
  } finally {
    busy--;
    load(cwd);
  }
}

function dialog(title, fields, okLabel) {
  return new Promise((resolve) => {
    const d = $("dlg");
    const f = $("dlgform");
    f.replaceChildren(el("h3", title));
    const inputs = fields.map(([label, value, help, suggestions]) => {
      const l = el("label", label);
      const i = el("input");
      i.value = value || "";
      if (help) i.placeholder = help;
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
      return i;
    });
    const row = el("div", undefined, "row-btns");
    const cancel = el("button", "Annuler", "act secondary");
    cancel.value = "cancel";
    const ok = el("button", okLabel || "OK", "act");
    ok.value = "ok";
    row.append(cancel, ok);
    f.appendChild(row);
    d.onclose = () => resolve(d.returnValue === "ok" ? inputs.map((i) => i.value.trim()) : null);
    d.returnValue = "";
    d.showModal();
    if (inputs[0]) inputs[0].focus();
  });
}

function reveal(title, text) {
  const d = $("dlg");
  const f = $("dlgform");
  f.replaceChildren(el("h3", title));
  const t = el("textarea");
  t.rows = 4;
  t.readOnly = true;
  t.value = text;
  f.appendChild(t);
  f.appendChild(el("p", "Le destinataire l'ajoute dans S3m, page Partages, « Ajouter un partage reçu ».", "muted"));
  const row = el("div", undefined, "row-btns");
  const copy = el("button", "Copier", "act secondary");
  copy.type = "button";
  copy.addEventListener("click", async () => {
    t.select();
    try {
      await navigator.clipboard.writeText(t.value);
    } catch (_) {
      document.execCommand("copy");
    }
    status("Copié dans le presse-papiers");
  });
  const close = el("button", "Fermer", "act");
  close.value = "ok";
  row.append(copy, close);
  f.appendChild(row);
  d.onclose = null;
  d.showModal();
}

async function mkdir() {
  const v = await dialog("Nouveau dossier", [["Nom", "", "Nouveau dossier"]], "Créer");
  if (!v || !v[0]) return;
  run("Création", () => call("explorer_mkdir", { chemin: join(cwd, v[0]) }));
}

async function move(path) {
  const v = await dialog("Renommer ou déplacer", [["Nouveau chemin", path]], "Valider");
  if (!v || !v[0] || v[0] === path) return;
  doMove(path, v[0].startsWith("/") ? v[0] : join(parent(path), v[0]));
}

function doMove(from, to) {
  run("Déplacement", () => call("explorer_move", { de: from, vers: to }));
}

function remove(path, isDir) {
  const what = isDir ? "le dossier « " + base(path) + " » et tout son contenu" : "« " + base(path) + " »";
  if (!window.confirm("Supprimer " + what + " ?")) return;
  run("Suppression", () => call("explorer_delete", { chemin: path }));
}

function keep(path, on) {
  run(on ? "Mise hors ligne" : "Retrait", () =>
    call(on ? "keep_offline" : "unkeep_offline", { "élément": path }));
}

// Retire de ce disque le contenu déjà envoyé au Nœud (reste visible,
// revient à l'ouverture).
function freeSpace(path) {
  run("Libération de l'espace", () => call("free_space", { "élément": path }));
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
    if (rv && rv["à copier"]) reveal(rv["titre"] || "Partage", rv["à copier"]);
  } catch (e) {
    status(e.message, true);
  } finally {
    busy--;
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
  } catch (e) {
    status(e.message, true);
  } finally {
    busy--;
  }
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
    status(done + " fichier(s) envoyé(s) ; synchronisation avec votre Nœud en cours");
  } catch (e) {
    status("Envoi interrompu après " + done + " fichier(s) : " + e.message, true);
  } finally {
    busy--;
    load(cwd);
  }
}

// Fichiers et dossiers déposés (arborescences comprises).
async function dropFiles(dt, dir) {
  const entries = [...(dt.items || [])]
    .map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null))
    .filter(Boolean);
  if (!entries.length) {
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
  for (const e of entries) await walk(e, "");
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
// ------------------------------------------------------------ versions

function browse(v, label, path) {
  version = v;
  versionLabel = label;
  load(path);
}

function restore(path, v, label) {
  if (!window.confirm("Restaurer « " + path + " » tel qu'il était le " + label + " ? La version actuelle reste dans l'historique.")) return;
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
  const d = $("dlg");
  const f = $("dlgform");
  f.replaceChildren(el("h3", path === "/" ? "Revenir en arrière : mon espace" : "Versions de « " + base(path) + " »"));
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
          d.close();
          fn();
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
  const row = el("div", undefined, "row-btns");
  const close = el("button", "Fermer", "act");
  close.value = "ok";
  row.appendChild(close);
  f.appendChild(row);
  d.onclose = null;
  d.showModal();
}

$("versions").addEventListener("click", () => versionsOf("/", true));
$("reencryptall").addEventListener("click", () =>
  run("Rechiffrement de ce dossier", () => call("explorer_reencrypt", { chemin: cwd })));
$("current").addEventListener("click", () => browse(null, "", cwd));
$("restoredir").addEventListener("click", () => restore(cwd, version, versionLabel));
$("restoreall").addEventListener("click", () => {
  if (!window.confirm("Remettre TOUT votre espace dans l'état du " + versionLabel + " ? (après un rançongiciel par exemple) La version actuelle reste dans l'historique.")) return;
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
  const from = ev.dataTransfer.getData("application/x-s3m-path");
  if (from) return;
  dropFiles(ev.dataTransfer, cwd);
});

let start = "/";
try {
  start = sessionStorage.getItem("s3m-explorer") || "/";
} catch (_) {}
load(start);
// Changements faits ailleurs (autre appareil, dossier synchronisé).
setInterval(() => {
  if (!busy && !document.hidden && !$("dlg").open) load(cwd);
}, 15000);

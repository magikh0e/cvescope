"use strict";
// cvescope local page. Every string from feeds is untrusted: DOM is built with textContent only.

const $ = (s) => document.querySelector(s);
const state = { item: null, host: null, current: null, items: [], rows: [], shown: [], sel: new Map(), readOnly: false, acked: 0 };
const selKey = (m) => `${m.cve_id}|${m.item_id}`;

// view choices remembered per browser; storage can be missing (private window), so never rely on it
const PREFS = ["invGroup", "invSort", "fSort"];
function loadPrefs() {
  for (const k of PREFS) {
    try { const v = localStorage.getItem("cvescope." + k); if (v && $("#" + k).querySelector(`option[value="${v}"]`)) $("#" + k).value = v; } catch { /* ignore */ }
  }
}
function savePref(k) { try { localStorage.setItem("cvescope." + k, $("#" + k).value); } catch { /* ignore */ } }
const TIER = { act: "Act now", watch: "Watch", info: "Info" };
const TIER_RANK = { act: 0, watch: 1, info: 2 };
const SIG = { kev: "KEV", msf: "Metasploit", nuclei: "Nuclei", edb: "Exploit-DB", poc: "GitHub PoC", local: "archive" };

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(String(c)));
  return el;
}
function safeUrl(u) {
  try { const x = new URL(u); return x.protocol === "https:" || x.protocol === "http:" ? x.href : null; } catch { return null; }
}
function link(u, text) {
  const s = safeUrl(u);
  return s ? h("a", { href: s, target: "_blank", rel: "noopener noreferrer", text: text || s }) : h("span", { text: text || u || "" });
}
async function api(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(path + " " + r.status);
  return r.json();
}
async function post(path, obj) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(obj) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || path + " " + r.status);
  return d;
}
const pct = (p) => (p == null ? "" : (p * 100).toFixed(p >= 0.995 ? 1 : 0) + "%");
const day = (s) => (s ? String(s).slice(0, 10) : "");
const empty = (msg) => h("div", { class: "empty", text: msg });

// ---------- inventory + totals ----------
async function loadSummary() {
  const s = await api("/api/summary");
  state.items = s.items;
  state.readOnly = !!s.read_only;
  state.acked = s.totals.acked || 0;
  $("#ackCount").textContent = `(${state.acked})`;
  $("#ackFilter").hidden = !state.acked && !$("#fAcked").checked;
  const t = $("#totals");
  t.replaceChildren(
    h("button", { class: "total act", type: "button", title: "Exploited or point-and-shoot", onclick: () => showTiers(false) }, `${s.totals.act} act now`),
    h("button", { class: "total watch", type: "button", title: "Public exploit or likely", onclick: () => showTiers(false) }, `${s.totals.watch} watch`),
    h("button", { class: "total info", type: "button", title: "Matches with no known exploit", onclick: () => showTiers(true) }, `${s.totals.info} info`),
  );
  renderHealth(s.health);
  renderInventory();
  const hosts = [...new Set(s.items.map((it) => it.host))].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  $("#fHost").replaceChildren(h("option", { value: "", text: "all hosts" }), ...hosts.map((x) => h("option", { value: x, text: x })));
  $("#fHost").value = state.host || "";
  const f = $("#feeds");
  f.replaceChildren(h("h3", { text: "Feeds" }), ...s.sources.map((x) =>
    h("div", { title: x.last_error || "" }, h("span", { text: x.name }),
      h("span", { class: x.last_error ? "err" : "muted", text: x.last_error ? "error" : day(x.last_ok) }))),
    h("div", {}, h("span", { class: "muted", text: `${s.cves.toLocaleString()} CVEs` }), h("span", { class: "muted", text: s.epss_date ? "EPSS " + s.epss_date : "" })));
}

const byName = (a, b) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true });
const byRisk = (a, b) => b.act - a.act || b.watch - a.watch || b.info - a.info;
const sumCounts = (its) => its.reduce((t, it) => ({ act: t.act + it.counts.act, watch: t.watch + it.counts.watch, info: t.info + it.counts.info }),
  { act: 0, watch: 0, info: 0 });

function riskBadges(c, okTitle) {
  return h("span", { class: "badges" },
    c.act ? h("span", { class: "badge act", title: "act now", text: c.act }) : null,
    c.watch ? h("span", { class: "badge watch", title: "watch", text: c.watch }) : null,
    !c.act && !c.watch && okTitle ? h("span", { class: "badge ok", title: okTitle, text: "✓" }) : null);
}

function itemRow(it) {
  const hint = it.extra && (it.extra.hint || it.extra.note);
  const li = h("li", { "data-id": it.id, title: it.error || hint || `${it.ruled_out} CVEs ruled out by version`, onclick: () => selectItem(it.id) },
    h("span", { class: "name", text: it.name }), riskBadges(it.counts, `${it.ruled_out} CVEs ruled out by version`),
    h("span", { class: "ver", text: it.version || "version unknown" }),
    it.error ? h("span", { class: "err", text: "collector failed: last known version" }) : null,
    !it.error && hint ? h("span", { class: "hint", text: hint }) : null);
  if (state.item === it.id) li.classList.add("on");
  return li;
}

function renderInventory() {
  const ul = $("#items");
  const f = $("#invFilter").value.trim().toLowerCase();
  const group = $("#invGroup").value, sort = $("#invSort").value;
  const items = state.items.filter((it) => !f || [it.name, it.host, it.version, it.collector]
    .some((x) => x && String(x).toLowerCase().includes(f)));
  const order = sort === "risk" ? (a, b) => byRisk(a.counts, b.counts) || byName(a.name, b.name) : (a, b) => byName(a.name, b.name);
  const keyOf = group === "host" ? (it) => it.host : group === "source" ? (it) => it.collector.split(":")[0] : () => "";
  const groups = new Map();
  for (const it of items) {
    const k = keyOf(it);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(it);
  }
  const keys = [...groups.keys()].sort(sort === "risk"
    ? (a, b) => byRisk(sumCounts(groups.get(a)), sumCounts(groups.get(b))) || byName(a, b) : byName);
  const out = [];
  for (const k of keys) {
    const its = groups.get(k).sort(order);
    if (group === "host") {
      out.push(h("li", { class: `group pick${state.host === k ? " on" : ""}`, "data-host": k, title: `Show only ${k}`, onclick: () => selectHost(k) },
        h("span", { class: "gname", text: k }), riskBadges(sumCounts(its)), h("span", { class: "gcount", text: `${its.length} item${its.length === 1 ? "" : "s"}` })));
    } else if (group === "source") {
      out.push(h("li", { class: "group", text: k }));
    }
    out.push(...its.map(itemRow));
  }
  if (!items.length) out.push(h("li", { class: "group", text: `nothing matches “${f}”` }));
  ul.replaceChildren(...out);
}

// ---------- sync health ----------
function ago(hours) {
  if (hours == null) return "";
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))} min ago`;
  if (hours < 48) return `${Math.round(hours)} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}

function renderHealth(hl) {
  const chip = $("#health"), banner = $("#healthBanner");
  if (!hl) { chip.textContent = ""; banner.hidden = true; return; }
  chip.className = `health ${hl.level}`;
  chip.textContent = hl.finished ? `${hl.level === "ok" ? "" : "⚠ "}synced ${ago(hl.age_hours)}` : "⚠ never synced";
  chip.title = hl.problems.length ? hl.problems.join("\n") : `last full sync ${hl.finished}`;
  if (hl.level === "ok") { banner.hidden = true; return; }
  banner.className = `banner ${hl.level}`;
  banner.replaceChildren(...hl.problems.map((p) => h("p", { text: p })));
  banner.hidden = false;
}

function markSelection() {
  for (const li of document.querySelectorAll("#items li[data-id]")) li.classList.toggle("on", li.dataset.id === state.item);
  for (const li of document.querySelectorAll("#items li[data-host]")) li.classList.toggle("on", !state.item && li.dataset.host === state.host);
  $("#fHost").value = state.item ? "" : state.host || "";
}

function selectItem(id) {
  state.item = state.item === id ? null : id;
  state.host = null;
  markSelection();
  tab("exposure");
  loadMatches();
}

function selectHost(host) {
  state.host = state.host === host ? null : host || null;
  state.item = null;
  markSelection();
  tab("exposure");
  loadMatches();
}

// ---------- exposure ----------
function showTiers(info) { $("#fInfo").checked = info; state.item = null; state.host = null; selectItem(null); }

const sigKeys = (s) => Object.keys(SIG).filter((k) => s && s[k]);  // fixed order: KEV first

function matchRow(m) {
  const sig = sigKeys(m.signals);
  const a = m.ack, acked = a && a.state === "active";
  const why = m.why && m.why.length ? TIER[m.tier] + ": " + m.why.join(" · ") : null;
  const pick = state.readOnly ? null : h("input", { type: "checkbox", class: "pick", "aria-label": `Select ${m.cve_id} on ${m.item_name}`,
    onclick: (e) => { e.stopPropagation(); toggleSel(m, e.target.checked); } });
  if (pick) pick.checked = state.sel.has(selKey(m));
  return h("div", { class: `row ${m.tier}${acked ? " acked" : ""}`, "data-cve": m.cve_id, onclick: () => openCve(m.cve_id) },
    h("span", { class: "bar" }),
    h("span", { class: "id" }, pick, m.cve_id),
    h("span", { class: "title", text: m.title || m.description || "" }),
    h("span", { class: "nums" },
      m.cvss != null ? h("span", { title: "CVSS base score", text: "CVSS " + m.cvss }) : null,
      m.epss_pct != null ? h("span", { title: "EPSS percentile", text: "EPSS " + pct(m.epss_pct) }) : null),
    h("span", { class: "meta" },
      h("span", { class: `pill ${m.status}`, text: m.status }),
      acked ? h("span", { class: "pill acked", title: ackLine(a), text: "acknowledged" }) : null,
      h("span", { text: `${m.item_name}${m.item_version ? " " + m.item_version : ""}` }),
      m.host && !m.item_name.includes(m.host) ? h("span", { class: "host", text: "on " + m.host }) : null,
      ...sig.map((k) => h("span", { class: `chip ${k}`, text: SIG[k] + (m.signals[k] > 1 ? " ×" + m.signals[k] : "") })),
      h("span", { text: "published " + day(m.published) })),
    why || (a && !acked) ? h("span", { class: "why" }, why, a && !acked ? h("span", { class: "ackwarn", text: ackLine(a) }) : null) : null);
}

async function loadMatches() {
  const tiers = $("#fInfo").checked ? "act,watch,info" : "act,watch";
  const q = new URLSearchParams({ tiers, keyword: $("#fKeyword").checked ? "1" : "0", acked: $("#fAcked").checked ? "1" : "0" });
  if (state.item) q.set("item", state.item);
  state.rows = await api("/api/matches?" + q);
  renderMatches();
}

const num = (v) => (v == null ? -1 : Number(v));
const SORTS = {
  tier: null,  // the server's order: tier, then evidence
  new: (a, b) => String(b.published || "").localeCompare(String(a.published || "")),
  cvss: (a, b) => num(b.cvss) - num(a.cvss),
  epss: (a, b) => num(b.epss_pct) - num(a.epss_pct),
};

// report links follow the view: the picked host (or the picked item's host) and the tiers shown
function updateReportLinks() {
  const it = state.items.find((x) => x.id === state.item);
  const q = new URLSearchParams({ tier: $("#fInfo").checked ? "info" : "watch", days: "7" });
  const host = it ? it.host : state.host;
  if (host) q.set("host", host);
  if ($("#fKeyword").checked) q.set("keyword", "1");
  for (const [id, fmt] of [["repHtml", "html"], ["repMd", "md"], ["repCsv", "csv"], ["repJson", "json"]]) {
    q.set("format", fmt);
    $("#" + id).href = "/api/report?" + q;
  }
}

// host, text and sort apply to the rows already loaded: no round trip while typing
function renderMatches() {
  updateReportLinks();
  const it = state.items.find((x) => x.id === state.item);
  const text = $("#fText").value.trim().toLowerCase();
  let rows = state.rows;
  if (!it && state.host) rows = rows.filter((m) => m.host === state.host);
  if (text) rows = rows.filter((m) => [m.cve_id, m.title, m.description, m.item_name, m.host, m.status]
    .some((x) => x && String(x).toLowerCase().includes(text)));
  const sort = SORTS[$("#fSort").value];
  if (sort) rows = [...rows].sort((a, b) => sort(a, b) || (TIER_RANK[a.tier] - TIER_RANK[b.tier]));
  const scope = it ? it.name : state.host;
  const note = $("#filterNote");
  note.replaceChildren();
  if (scope || text) {
    note.append(`showing ${rows.length} of ${state.rows.length}${scope ? " for " + scope : ""}${text ? ` matching “${text}”` : ""} `,
      h("button", { class: "linkish", type: "button", text: "clear", onclick: clearFilters }));
  }
  // only what's on screen can stay selected: a filter change never acknowledges hidden rows
  state.shown = rows;
  const visible = new Set(rows.map(selKey));
  for (const k of [...state.sel.keys()]) if (!visible.has(k)) state.sel.delete(k);
  updateBulk();
  const list = $("#matchList");
  if (rows.length) { list.replaceChildren(...rows.map(matchRow)); return; }
  if (text && state.rows.length) { list.replaceChildren(empty(`Nothing here matches “${text}”.`)); return; }
  const info = $("#fInfo").checked;
  list.replaceChildren(empty(it ? `Nothing ${info ? "" : "exploited or likely "}matches ${it.name} ${it.version || ""}. ${it.ruled_out} CVEs were ruled out by version.`
    : state.host ? `Nothing ${info ? "" : "exploited or likely "}matches anything on ${state.host}.${info ? "" : " Tick “include info” to see the rest."}`
      : "No exploited or likely CVEs match your inventory right now. Tick “include info” to see the rest."
        + (state.acked && !$("#fAcked").checked ? ` ${state.acked} acknowledged ${state.acked === 1 ? "one is" : "ones are"} hidden.` : "")));
}

// ---------- acknowledging many at once ----------
function toggleSel(m, on) {
  if (on) state.sel.set(selKey(m), m); else state.sel.delete(selKey(m));
  updateBulk();
}

function updateBulk() {
  const bar = $("#bulkBar"), n = state.sel.size, shown = state.shown.length;
  bar.hidden = state.readOnly || !shown;
  if (bar.hidden) return;
  const all = $("#selAll");
  all.checked = n > 0 && n === shown;
  all.indeterminate = n > 0 && n < shown;
  $("#selCount").textContent = n ? `${n} selected` : `select all ${shown} shown`;
  $("#bulkActions").hidden = !n;
  const acked = [...state.sel.values()].filter((m) => m.ack).length;
  $("#bulkAck").textContent = `Acknowledge ${n}`;
  $("#bulkUnack").hidden = !acked;
  $("#bulkUnack").textContent = `Remove acknowledgement (${acked})`;
}

function bulkMessage(text, undo) {
  const box = $("#bulkMsg");
  box.className = "bulkmsg";
  box.replaceChildren(text, undo ? " " : "", undo ? h("button", { class: "linkish", type: "button", text: "undo", onclick: undo }) : "");
}

async function bulkRun(path, pairs, extra, done) {
  const box = $("#bulkMsg");
  for (const b of document.querySelectorAll("#bulkActions button")) b.disabled = true;
  try {
    const r = await post(path, { pairs, ...extra });
    state.sel.clear();
    await loadSummary();
    await loadMatches();
    done(r.count);
  } catch (e) {
    box.className = "bulkmsg err";
    box.textContent = e.message;
  } finally {
    for (const b of document.querySelectorAll("#bulkActions button")) b.disabled = false;
  }
}

function bulkAck() {
  const pairs = [...state.sel.values()].map((m) => ({ cve: m.cve_id, item: m.item_id }));
  const days = $("#bulkDays").value;
  bulkRun("/api/ack/bulk", pairs, { note: $("#bulkNote").value, days: days ? Number(days) : null }, (n) => {
    $("#bulkNote").value = "";
    bulkMessage(`Acknowledged ${n}.${$("#fAcked").checked ? "" : " They're hidden now; “show acknowledged” lists them."}`,
      () => bulkRun("/api/unack/bulk", pairs, {}, (k) => bulkMessage(`Took back ${k}.`)));
  });
}

function bulkUnack() {
  const pairs = [...state.sel.values()].filter((m) => m.ack).map((m) => ({ cve: m.cve_id, item: m.item_id }));
  bulkRun("/api/unack/bulk", pairs, {}, (n) => bulkMessage(`Removed ${n} acknowledgement${n === 1 ? "" : "s"}.`));
}

function clearFilters() {
  $("#fText").value = "";
  if (state.item || state.host) { state.item = null; state.host = null; markSelection(); loadMatches(); } else renderMatches();
}

// ---------- detail ----------
function kv(pairs) {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of pairs) if (v != null && v !== "") dl.append(h("dt", { text: k }), h("dd", {}, v));
  return dl;
}

async function openCve(id, keepScroll) {
  state.current = id;
  for (const r of document.querySelectorAll(".row")) r.classList.toggle("on", r.dataset.cve === id);
  history.replaceState(null, "", "#" + id);
  const d = await api("/api/cve/" + encodeURIComponent(id));
  const body = $("#detailBody");
  const s = d.signals || {};
  const parts = [
    h("h1", { text: d.id }),
    h("div", { class: "muted", text: [d.assigner, "published " + day(d.published), d.state !== "PUBLISHED" ? d.state : ""].filter(Boolean).join(" · ") }),
    d.title ? h("p", { text: d.title }) : null,
    h("div", { class: `tierbox ${d.tier}` }, h("strong", { text: TIER[d.tier] }), d.why.length ? " · " + d.why.join(" · ") : " · no known exploitation"),
    h("p", { class: "desc", text: d.description || "" }),
    kv([["CVSS", d.cvss != null ? `${d.cvss} ${d.severity || ""} (v${d.cvss_version})` : "not scored"],
        ["vector", d.cvss_vector], ["CWE", d.cwe],
        ["EPSS", d.epss ? `${(d.epss.score * 100).toFixed(2)}% chance in 30 days · percentile ${pct(d.epss.pct)}` : "none"],
        ["SSVC", d.ssvc_exploitation ? `exploitation ${d.ssvc_exploitation} · automatable ${d.ssvc_automatable || "?"} · impact ${d.ssvc_impact || "?"}` : null]]),
  ];
  if (d.matches.length) {
    parts.push(h("h3", { text: "Your inventory" }), h("ul", { class: "ev" }, d.matches.map((m) =>
      h("li", {}, h("span", { class: `pill ${m.status}`, text: m.status }), " ", `${m.item_name} ${m.item_version || ""}`, h("div", { class: "muted", text: m.detail }),
        m.live || m.ack ? ackBlock(d.id, m) : null))));
  }
  if (s.kev) {
    const k = s.kev[0];
    parts.push(h("h3", { text: "CISA KEV" }), kv([["added", k.added], ["due", k.due], ["product", `${k.vendor} ${k.product}`],
      ["ransomware", k.ransomware], ["action", k.action]]));
  }
  const exploitList = (key, label, fn) => { if (s[key]) parts.push(h("h3", { text: `${label} (${s[key].length})` }), h("ul", { class: "ev" }, s[key].map(fn))); };
  exploitList("msf", "Metasploit", (m) => h("li", {}, link(m.url, m.key), h("div", { class: "muted", text: [m.name, m.type, m.rank && "rank " + m.rank, m.check ? "has check" : ""].filter(Boolean).join(" · ") })));
  exploitList("nuclei", "Nuclei", (m) => h("li", {}, link(m.url, m.name || m.key), h("div", { class: "muted", text: m.severity || "" })));
  exploitList("edb", "Exploit-DB", (m) => h("li", {}, link(m.url, m.title || "EDB-" + m.key), h("div", { class: "muted", text: [m.date, m.type, m.platform, m.verified ? "verified" : "unverified"].filter(Boolean).join(" · ") })));
  exploitList("local", "Your archive", (m) => h("li", {}, m.url ? link(m.url, m.file) : h("span", { class: "mono", text: m.file })));
  if (s.poc) {
    parts.push(h("h3", { text: `GitHub PoCs (${s.poc.length})` }),
      h("div", { class: "note", text: "Repos are listed, never fetched. Fake PoCs that drop malware on researchers are common: read the code first and only run it in a throwaway VM." }),
      h("ul", { class: "ev" }, s.poc.slice(0, 40).map((p) => h("li", {}, link(p.url, p.key),
        h("div", { class: "muted", text: `★ ${p.stars || 0} · forks ${p.forks || 0} · created ${day(p.created)}${p.description ? " · " + p.description : ""}` }),
        p.flags && p.flags.length ? h("div", { class: "warn", text: "⚠ " + p.flags.join(" · ") }) : null))));
  }
  if (d.events.length) {
    parts.push(h("h3", { text: "History" }), h("ul", { class: "ev" }, d.events.map((e) =>
      h("li", {}, h("span", { class: "mono muted", text: e.ts.slice(0, 16).replace("T", " ") + "  " }), e.summary || e.kind))));
  }
  if (d.affected.length) {
    parts.push(h("h3", { text: "Affected (from the CVE record)" }),
      h("pre", { class: "aff", text: d.affected.map((a) => `${a.v || "?"} / ${a.p || "?"} [${a.src}] default=${a.ds || "-"}\n` +
        (a.vs || []).map((v) => `   ${v.status || "?"}: ${v.version || ""}${v.lessThan ? " < " + v.lessThan : ""}${v.lessThanOrEqual ? " <= " + v.lessThanOrEqual : ""}`).join("\n")).join("\n") }));
  }
  // a CVE links to cve.org and NVD; an advisory without a CVE (GHSA-, PSA-, ...) to its own page,
  // which its source put first in refs
  const own = d.id.startsWith("CVE-")
    ? [h("li", {}, link(`https://www.cve.org/CVERecord?id=${d.id}`, "cve.org record")),
      h("li", {}, link(`https://nvd.nist.gov/vuln/detail/${d.id}`, "NVD"))]
    : [h("li", { class: "muted", text: `No CVE ID: this is ${d.assigner || "the vendor"}'s advisory, listed under its own ID.` })];
  parts.push(h("h3", { text: "References" }), h("ul", { class: "ev" }, ...own,
    ...(d.refs || []).map((u) => h("li", {}, link(u)))));
  body.replaceChildren(...parts.filter(Boolean));
  const top = $("#detail").scrollTop;
  $("#detail").hidden = false;
  document.querySelector(".layout").classList.add("with-detail");
  $("#detail").scrollTop = keepScroll ? top : 0;
}

// ---------- acknowledgements ----------
function ackLine(a) {
  const when = `Acknowledged ${day(a.created)}`;
  if (a.state === "active") return `${when}${a.until ? ", until " + a.until : ""}${a.note ? ": " + a.note : ""}`;
  if (a.state === "expired") return `${when}, ${a.reason}, so it's back`;
  return `${when}, back because: ${a.reason}`;
}

async function afterAck(cve) {
  await loadSummary();
  await loadMatches();
  await openCve(cve, true);
}

function ackBlock(cve, m) {
  const box = h("div", { class: "ack" });
  const a = m.ack;
  const fail = (e) => box.append(h("div", { class: "err", text: e.message }));
  const undo = () => post("/api/unack", { cve, item: m.item_id }).then(() => afterAck(cve), fail);
  const form = () => {
    const note = h("input", { type: "text", maxlength: "500", "aria-label": "Note",
      placeholder: "What did you do? e.g. applied the opt-in fix, blocked at the firewall" });
    const days = h("select", { "aria-label": "How long" }, ...[["", "no end date"], ["7", "for 7 days"], ["30", "for 30 days"],
      ["90", "for 90 days"], ["365", "for a year"]].map(([v, t]) => h("option", { value: v, text: t })));
    const err = h("div", { class: "err" });
    const submit = (e) => {
      e.preventDefault();
      post("/api/ack", { cve, item: m.item_id, note: note.value, days: days.value ? Number(days.value) : null })
        .then(() => afterAck(cve), (x) => { err.textContent = x.message; });
    };
    box.replaceChildren(
      h("div", { class: "muted", text: "Hides it from act now, watch, the counts and alerts. It comes back if it gets worse: a higher tier, a new kind of exploit evidence, or a check that turns out affected." }),
      h("form", { class: "ackform", onsubmit: submit }, note, days,
        h("button", { type: "submit", class: "btn primary", text: "Acknowledge" }),
        h("button", { type: "button", class: "btn", onclick: show, text: "Cancel" }), err));
    note.focus();
  };
  function show() {
    const btns = state.readOnly ? null : h("div", { class: "ackbtns" },
      !a || a.state !== "active" ? h("button", { type: "button", class: "btn", onclick: form, text: a ? "Acknowledge again" : "Acknowledge" }) : null,
      a ? h("button", { type: "button", class: "btn", onclick: undo, text: "Remove acknowledgement" }) : null);
    box.replaceChildren(...[a ? h("div", { class: a.state === "active" ? "acknote" : "warn", text: ackLine(a) }) : null, btns].filter(Boolean));
  }
  show();
  return box;
}

function closeDetail() {
  $("#detail").hidden = true;
  document.querySelector(".layout").classList.remove("with-detail");
  history.replaceState(null, "", location.pathname);
  for (const r of document.querySelectorAll(".row")) r.classList.remove("on");
}

// ---------- changes / hot / search ----------
async function loadEvents() {
  const q = new URLSearchParams({ days: $("#days").value, all: $("#fAllEvents").checked ? "1" : "0" });
  const ev = await api("/api/events?" + q);
  $("#eventList").replaceChildren(...(ev.length ? ev.map((e) =>
    h("div", { class: "row info", onclick: () => openCve(e.cve_id) }, h("span", { class: "bar" }),
      h("span", { class: "id", text: e.cve_id }), h("span", { class: "title", text: e.summary }),
      h("span", { class: "nums", text: e.ts.slice(0, 16).replace("T", " ") }),
      e.title ? h("span", { class: "meta", text: e.title }) : null))
    : [empty($("#fAllEvents").checked ? "No changes in this window." : "Nothing changed for the CVEs that hit your inventory in this window. Changes appear after the first sync, which loads history quietly.")]));
}

async function loadHot() {
  const d = await api("/api/hot");
  const sect = (title, rows, fn, none) => [h("h2", { text: title }), rows.length ? h("div", { class: "list" }, rows.map(fn)) : empty(none)];
  $("#hotBody").replaceChildren(h("div", { class: "hot" },
    ...sect("Added to CISA KEV, last 30 days", d.kev, (k) => h("div", { class: "row act", onclick: () => openCve(k.cve_id) },
      h("span", { class: "bar" }), h("span", { class: "id", text: k.cve_id }), h("span", { class: "title", text: k.name || "" }),
      h("span", { class: "nums", text: day(k.added) }),
      h("span", { class: "meta" }, h("span", { text: `${k.vendor} ${k.product}` }), k.ransomware === "Known" ? h("span", { class: "chip kev", text: "ransomware" }) : null,
        k.epss_pct != null ? h("span", { text: "EPSS " + pct(k.epss_pct) }) : null)), "None in the last 30 days."),
    ...sect("Newly weaponized (since your first sync)", d.weaponized, (w) => h("div", { class: "row watch", onclick: () => openCve(w.cve_id) },
      h("span", { class: "bar" }), h("span", { class: "id", text: w.cve_id }), h("span", { class: "title", text: w.summary }),
      h("span", { class: "nums", text: w.ts.slice(0, 10) }), w.title ? h("span", { class: "meta", text: w.title }) : null), "Nothing new yet: exploits published after your first sync show up here."),
    ...sect("Highest EPSS among CVEs from the last 30 days", d.epss_new, (e) => h("div", { class: "row info", onclick: () => openCve(e.cve_id) },
      h("span", { class: "bar" }), h("span", { class: "id", text: e.cve_id }), h("span", { class: "title", text: e.title || "" }),
      h("span", { class: "nums", text: `EPSS ${(e.score * 100).toFixed(1)}%` })), "No EPSS data yet.")));
}

async function doSearch(q) {
  const t = $("#searchTab");
  t.hidden = false;
  tab("search");
  const rows = await api("/api/search?q=" + encodeURIComponent(q));
  if (rows.length === 1 && rows[0].id.toUpperCase() === q.toUpperCase()) openCve(rows[0].id);
  $("#searchList").replaceChildren(...(rows.length ? rows.map((r) => {
    const sig = sigKeys(r.signals);
    return h("div", { class: "row info", onclick: () => openCve(r.id) }, h("span", { class: "bar" }),
      h("span", { class: "id", text: r.id }), h("span", { class: "title", text: r.title || r.description }),
      h("span", { class: "nums" }, r.cvss != null ? "CVSS " + r.cvss : "", r.epss_pct != null ? " · EPSS " + pct(r.epss_pct) : ""),
      h("span", { class: "meta" }, ...sig.map((k) => h("span", { class: `chip ${k}`, text: SIG[k] })), h("span", { text: day(r.published) })));
  }) : [empty("No matches.")]));
}

// ---------- wiring ----------
function tab(name) {
  for (const b of document.querySelectorAll(".tabs button")) b.classList.toggle("on", b.dataset.tab === name);
  for (const p of document.querySelectorAll(".pane")) p.classList.toggle("on", p.id === name);
  if (name === "changes") loadEvents();
  if (name === "hot") loadHot();
}
for (const b of document.querySelectorAll(".tabs button")) b.addEventListener("click", () => tab(b.dataset.tab));
$("#fInfo").addEventListener("change", loadMatches);
$("#fKeyword").addEventListener("change", loadMatches);
$("#fAcked").addEventListener("change", loadMatches);
$("#days").addEventListener("change", loadEvents);
$("#fAllEvents").addEventListener("change", loadEvents);
$("#allItems").addEventListener("click", () => { state.item = null; state.host = null; selectItem(null); });
$("#invFilter").addEventListener("input", renderInventory);
for (const k of ["invGroup", "invSort"]) $("#" + k).addEventListener("change", () => { savePref(k); renderInventory(); });
$("#fHost").addEventListener("change", (e) => { state.host = null; selectHost(e.target.value || null); });
$("#fText").addEventListener("input", renderMatches);
$("#selAll").addEventListener("change", (e) => {
  state.sel.clear();
  if (e.target.checked) for (const m of state.shown) state.sel.set(selKey(m), m);
  renderMatches();
});
$("#bulkAck").addEventListener("click", bulkAck);
$("#bulkUnack").addEventListener("click", bulkUnack);
$("#bulkClear").addEventListener("click", () => { state.sel.clear(); renderMatches(); });
$("#fSort").addEventListener("change", () => { savePref("fSort"); renderMatches(); });
$("#closeDetail").addEventListener("click", closeDetail);
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !e.target.closest(".ackform")) closeDetail(); });
$("#searchForm").addEventListener("submit", (e) => { e.preventDefault(); const q = $("#q").value.trim(); if (q.length >= 3) doSearch(q); });

(async () => {
  try {
    loadPrefs();
    await loadSummary();
    await loadMatches();
    const m = /^#((?:CVE|GHSA|PSA|PYSEC|GO|RUSTSEC|MAL|OSV)-[\w.:-]{3,60})$/i.exec(location.hash);
    if (m) openCve(/^ghsa-/i.test(m[1]) ? "GHSA-" + m[1].slice(5).toLowerCase() : m[1].toUpperCase());
  } catch (err) {
    $("#matchList").replaceChildren(empty("Couldn't reach the cvescope API: " + err.message));
  }
})();

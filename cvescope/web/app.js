"use strict";
// cvescope local page. Every string from feeds is untrusted: DOM is built with textContent only.

const $ = (s) => document.querySelector(s);
const state = { item: null, current: null, items: [] };
const TIER = { act: "Act now", watch: "Watch", info: "Info" };
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
const pct = (p) => (p == null ? "" : (p * 100).toFixed(p >= 0.995 ? 1 : 0) + "%");
const day = (s) => (s ? String(s).slice(0, 10) : "");
const empty = (msg) => h("div", { class: "empty", text: msg });

// ---------- inventory + totals ----------
async function loadSummary() {
  const s = await api("/api/summary");
  state.items = s.items;
  const t = $("#totals");
  t.replaceChildren(
    h("button", { class: "total act", type: "button", title: "Exploited or point-and-shoot", onclick: () => showTiers(false) }, `${s.totals.act} act now`),
    h("button", { class: "total watch", type: "button", title: "Public exploit or likely", onclick: () => showTiers(false) }, `${s.totals.watch} watch`),
    h("button", { class: "total info", type: "button", title: "Matches with no known exploit", onclick: () => showTiers(true) }, `${s.totals.info} info`),
  );
  renderHealth(s.health);
  const ul = $("#items");
  ul.replaceChildren();
  let group = null;
  for (const it of s.items) {
    const g = it.collector.split(":")[0];
    if (g !== group) { group = g; ul.append(h("li", { class: "group", text: g })); }
    const c = it.counts;
    const badges = h("span", { class: "badges" },
      c.act ? h("span", { class: "badge act", title: "act now", text: c.act }) : null,
      c.watch ? h("span", { class: "badge watch", title: "watch", text: c.watch }) : null,
      !c.act && !c.watch ? h("span", { class: "badge ok", title: `${it.ruled_out} CVEs ruled out by version`, text: "✓" }) : null);
    const hint = it.extra && (it.extra.hint || it.extra.note);
    const li = h("li", { "data-id": it.id, title: it.error || hint || `${it.ruled_out} CVEs ruled out by version`, onclick: () => selectItem(it.id) },
      h("span", { class: "name", text: it.name }), badges,
      h("span", { class: "ver", text: it.version || "version unknown" }),
      it.error ? h("span", { class: "err", text: "collector failed: last known version" }) : null,
      !it.error && hint ? h("span", { class: "hint", text: hint }) : null);
    if (state.item === it.id) li.classList.add("on");
    ul.append(li);
  }
  const f = $("#feeds");
  f.replaceChildren(h("h3", { text: "Feeds" }), ...s.sources.map((x) =>
    h("div", { title: x.last_error || "" }, h("span", { text: x.name }),
      h("span", { class: x.last_error ? "err" : "muted", text: x.last_error ? "error" : day(x.last_ok) }))),
    h("div", {}, h("span", { class: "muted", text: `${s.cves.toLocaleString()} CVEs` }), h("span", { class: "muted", text: s.epss_date ? "EPSS " + s.epss_date : "" })));
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

function selectItem(id) {
  state.item = state.item === id ? null : id;
  for (const li of document.querySelectorAll("#items li[data-id]")) li.classList.toggle("on", li.dataset.id === state.item);
  tab("exposure");
  loadMatches();
}

// ---------- exposure ----------
function showTiers(info) { $("#fInfo").checked = info; state.item = null; selectItem(null); }

const sigKeys = (s) => Object.keys(SIG).filter((k) => s && s[k]);  // fixed order: KEV first

function matchRow(m) {
  const sig = sigKeys(m.signals);
  return h("div", { class: `row ${m.tier}`, "data-cve": m.cve_id, onclick: () => openCve(m.cve_id) },
    h("span", { class: "bar" }),
    h("span", { class: "id", text: m.cve_id }),
    h("span", { class: "title", text: m.title || m.description || "" }),
    h("span", { class: "nums" },
      m.cvss != null ? h("span", { title: "CVSS base score", text: "CVSS " + m.cvss }) : null,
      m.epss_pct != null ? h("span", { title: "EPSS percentile", text: "EPSS " + pct(m.epss_pct) }) : null),
    h("span", { class: "meta" },
      h("span", { class: `pill ${m.status}`, text: m.status }),
      h("span", { text: `${m.item_name}${m.item_version ? " " + m.item_version : ""}` }),
      ...sig.map((k) => h("span", { class: `chip ${k}`, text: SIG[k] + (m.signals[k] > 1 ? " ×" + m.signals[k] : "") })),
      h("span", { text: "published " + day(m.published) })),
    m.why && m.why.length ? h("span", { class: "why", text: TIER[m.tier] + ": " + m.why.join(" · ") }) : null);
}

async function loadMatches() {
  const tiers = $("#fInfo").checked ? "act,watch,info" : "act,watch";
  const q = new URLSearchParams({ tiers, keyword: $("#fKeyword").checked ? "1" : "0" });
  if (state.item) q.set("item", state.item);
  const rows = await api("/api/matches?" + q);
  const it = state.items.find((x) => x.id === state.item);
  $("#filterNote").textContent = it ? `showing ${it.name} only` : "";
  const list = $("#matchList");
  if (!rows.length) {
    list.replaceChildren(empty(it ? `Nothing ${$("#fInfo").checked ? "" : "exploited or likely "}matches ${it.name} ${it.version || ""}. ${it.ruled_out} CVEs were ruled out by version.`
      : "No exploited or likely CVEs match your inventory right now. Tick “include info” to see the rest."));
    return;
  }
  list.replaceChildren(...rows.map(matchRow));
}

// ---------- detail ----------
function kv(pairs) {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of pairs) if (v != null && v !== "") dl.append(h("dt", { text: k }), h("dd", {}, v));
  return dl;
}

async function openCve(id) {
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
      h("li", {}, h("span", { class: `pill ${m.status}`, text: m.status }), " ", `${m.item_name} ${m.item_version || ""}`, h("div", { class: "muted", text: m.detail })))));
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
  parts.push(h("h3", { text: "References" }), h("ul", { class: "ev" },
    h("li", {}, link(`https://www.cve.org/CVERecord?id=${d.id}`, "cve.org record")),
    h("li", {}, link(`https://nvd.nist.gov/vuln/detail/${d.id}`, "NVD")),
    ...(d.refs || []).map((u) => h("li", {}, link(u)))));
  body.replaceChildren(...parts.filter(Boolean));
  $("#detail").hidden = false;
  document.querySelector(".layout").classList.add("with-detail");
  $("#detail").scrollTop = 0;
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
$("#days").addEventListener("change", loadEvents);
$("#fAllEvents").addEventListener("change", loadEvents);
$("#allItems").addEventListener("click", () => { state.item = null; selectItem(null); });
$("#closeDetail").addEventListener("click", closeDetail);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetail(); });
$("#searchForm").addEventListener("submit", (e) => { e.preventDefault(); const q = $("#q").value.trim(); if (q.length >= 3) doSearch(q); });

(async () => {
  try {
    await loadSummary();
    await loadMatches();
    const m = /^#(CVE-\d{4}-\d{4,7})$/i.exec(location.hash);
    if (m) openCve(m[1].toUpperCase());
  } catch (err) {
    $("#matchList").replaceChildren(empty("Couldn't reach the cvescope API: " + err.message));
  }
})();

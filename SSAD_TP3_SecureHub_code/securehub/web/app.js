"use strict";
/* SecureHub front end: plain JavaScript, no libraries, no CDN. Every call goes to the local gateway. */
const $ = (s, r = document) => r.querySelector(s);
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, "");
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat(Infinity)) { if (c == null || c === false) continue; e.append(c.nodeType ? c : document.createTextNode(String(c))); }
  return e;
}
const S = { token: null, user: null, info: {}, tab: "home", zone: "127.0.0.1", expires: 0 };
try { const t = sessionStorage.getItem("sh_token"); if (t) { S.token = t; S.user = JSON.parse(sessionStorage.getItem("sh_user")); S.expires = +sessionStorage.getItem("sh_exp") || 0; } } catch (e) {}

async function api(method, path, body, o = {}) {
  const headers = { "Content-Type": "application/json" };
  const tok = o.token === undefined ? S.token : o.token;
  if (tok) headers.Authorization = "Bearer " + tok;
  if (o.ip) headers["X-Sim-IP"] = o.ip;
  const t0 = performance.now();
  let r, j = {};
  try {
    r = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    try { j = await r.json(); } catch (e) { j = {}; }
  } catch (e) { logReq(method, path, 0, "cannot reach the server"); return { status: 0, json: { error: "network" }, ms: 0 }; }
  const ms = Math.round(performance.now() - t0);
  logReq(method, path, r.status, j.reason || j.error || "", ms);
  return { status: r.status, json: j, ms };
}
function logReq(method, path, status, why, ms) {
  const box = $("#reqlog"); if (!box) return;
  const cls = "s" + String(status)[0];
  const d = h("div", {}, new Date().toLocaleTimeString() + "  ", method + " " + path.split("?")[0] + "  ", h("b", { class: cls }, status || "ERR"), "  " + (why || "") + (ms != null ? "  " + ms + " ms" : ""));
  box.prepend(d); while (box.children.length > 60) box.lastChild.remove();
}
function badge(t, c) { return h("span", { class: "badge " + (c || "") }, t); }
function statusChip(r) { return h("span", { class: "s" + String(r.status)[0] }, "HTTP " + r.status + (r.json && (r.json.reason || r.json.error) ? " · " + (r.json.reason || r.json.error) : "")); }
function pre(x) { return h("pre", {}, typeof x === "string" ? x : JSON.stringify(x, null, 2)); }
function table(cols, rows, fmt) {
  return h("table", {}, h("thead", {}, h("tr", {}, cols.map(c => h("th", {}, c)))),
    h("tbody", {}, rows.map(r => h("tr", {}, r.map((v, i) => h("td", {}, fmt ? fmt(v, i) : (v === null ? "∅" : String(v))))))));
}
const b64u = s => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/"))));
const role = () => S.user && S.user.role;
const isAdmin = () => role() === "administrator";

/* ------------------------------------------------------------ navigation */
const TABS = [["home", "Home"], ["token", "Token"], ["docs", "Documents"], ["lake", "Data lake"], ["dash", "Dashboard"], ["lab", "Attack lab"], ["rsa", "RSA lab"]];
const RENDER = {};
function buildNav() {
  const nav = $("#nav"); nav.replaceChildren();
  for (const [id, label] of TABS) {
    const need = (id === "dash" || id === "lab") ? isAdmin() : (id === "token" || id === "docs" || id === "lake") ? !!S.token : true;
    nav.append(h("button", { class: S.tab === id ? "on" : "", disabled: !need, title: need ? "" : (id === "dash" || id === "lab" ? "administrator only" : "sign in first"), onclick: () => show(id) }, label));
  }
  $("#whoText").textContent = S.user ? S.user.username + " (" + S.user.role + ")" : "not signed in";
  $("#loginBtn").hidden = !!S.token; $("#logoutBtn").hidden = !S.token;
}
function show(id) {
  S.tab = id;
  for (const [t] of TABS) $("#tab-" + t).hidden = t !== id;
  buildNav();
  if (id !== "dash") stopStream();
  RENDER[id] && RENDER[id]();
}

/* ------------------------------------------------------------ login */
async function openLogin() {
  $("#modal").hidden = false; $("#loginMsg").textContent = "";
  if (!S.info.name) { const r = await api("GET", "/api/info", undefined, { token: null }); S.info = r.json; }
  const box = $("#demoUsers"); box.replaceChildren();
  for (const u of S.info.demo_users || []) box.append(h("button", { class: "chip", onclick: () => { $("#lu").value = u.username; $("#lp").value = u.password; } }, u.username + " · " + u.role));
  $("#lu").focus();
}
async function doLogin() {
  const r = await api("POST", "/auth/login", { username: $("#lu").value, password: $("#lp").value }, { token: null });
  if (r.status !== 200) { const m = $("#loginMsg"); m.className = "msg bad"; m.textContent = r.status === 429 ? "Too many attempts. Try again in " + r.json.retry_after + " s." : "Wrong username or password."; return; }
  S.token = r.json.token; S.user = r.json.user; S.expires = r.json.expires_at;
  try { sessionStorage.setItem("sh_token", S.token); sessionStorage.setItem("sh_user", JSON.stringify(S.user)); sessionStorage.setItem("sh_exp", S.expires); } catch (e) {}
  $("#modal").hidden = true; $("#lp").value = "";
  show(S.tab === "home" ? (isAdmin() ? "dash" : S.user.role === "doctor" || S.user.role === "analyst" ? "lake" : "docs") : S.tab);
}
async function doLogout() {
  if (S.token) await api("POST", "/auth/logout");
  S.token = S.user = null;
  try { sessionStorage.clear(); } catch (e) {}
  show("home");
}

/* ------------------------------------------------------------ home */
RENDER.home = () => {
  const el = $("#tab-home"); el.replaceChildren(
    h("h1", {}, "SecureHub: one platform, three questions of access control"),
    h("p", { class: "muted" }, "A student, a teacher, an administrator, a doctor and an analyst use the same system. Three questions decide what each may do: who are you (authenticate), what may you do (authorize), what did you do (account)."),
    h("div", { class: "grid g3" },
      card("1 · Authenticate", "Password check against a salted PBKDF2 hash. The auth server answers with a token signed with RSA (RS256). The gateway verifies the signature before anything else.", "Token tab · RSA lab"),
      card("2 · Authorize", "RBAC (student, teacher, administrator) decides the action; object rules decide which document. On the data lake, ABAC decides per column and per row, with deny-overrides, masking, hashing and query rewriting on Spark.", "Documents tab · Data lake tab"),
      card("3 · Account", "Every request, allowed or refused, enters a hash-chained log. Eight rules watch it and a live dashboard shows alerts. Window rules also run on Spark.", "Dashboard · Attack lab")),
    h("h2", {}, "Path of one request"),
    h("div", { class: "flow" },
      box("Browser", "sends Authorization: Bearer <token>"), h("div", { class: "arrow" }, "→"),
      box("Gateway (reference monitor)", "verifies RSA signature, expiry, audience; applies RBAC; default deny"), h("div", { class: "arrow" }, "→"),
      box("Document service / Data lake", "re-checks the object rule; ABAC plan; Spark or Python engine"), h("div", { class: "arrow" }, "→"),
      box("Audit log + detection", "hash chain, 8 rules, live dashboard")),
    h("h2", {}, "A 5-minute demonstration"),
    h("ol", {},
      h("li", {}, "Sign in as ", h("b", {}, "alice"), ". Token tab: decode it, change role to administrator, send it: the signature check refuses it."),
      h("li", {}, "Documents tab: open document 4 (hers), then document 5 (bob's): 403, because the object rule says not the owner."),
      h("li", {}, "Sign in as ", h("b", {}, "dr_amine"), ". Data lake tab: run the doctor preset, then ask for treatment_cost: deny-overrides blocks it. Read the SQL the platform wrote instead of yours."),
      h("li", {}, "Sign in as ", h("b", {}, "lina"), " (analyst): raw rows are refused, aggregates work with pseudonymous ids and groups of fewer than 5 are hidden."),
      h("li", {}, "Sign in as ", h("b", {}, "root"), ": Attack lab → Run all attacks, then watch Dashboard alerts and press Verify chain.")),
    h("p", { class: "muted small" }, "Educational platform on 127.0.0.1. Its RSA is a teaching implementation, not for real security. The 'X-Sim-IP' header that simulates source addresses exists only for the lab."));
  if (!S.token) el.append(h("p", {}, h("button", { onclick: openLogin }, "Sign in to start")));
};
const card = (t, p, where) => h("div", { class: "card" }, h("h3", {}, t), h("p", {}, p), h("div", { class: "muted small" }, where));
const box = (t, p) => h("div", { class: "box" }, h("b", {}, t), h("div", { class: "small muted" }, p));

/* ------------------------------------------------------------ token */
let lastTamper = null;
RENDER.token = async () => {
  const el = $("#tab-token"); el.replaceChildren(h("h1", {}, "Your access token"));
  if (!S.token) { el.append(h("p", {}, "Sign in first.")); return; }
  const [hd, pl, sg] = S.token.split(".");
  let header = {}, payload = {};
  try { header = JSON.parse(unb64u(hd)); payload = JSON.parse(unb64u(pl)); } catch (e) {}
  const left = Math.max(0, payload.exp - Math.floor(Date.now() / 1000));
  el.append(
    h("div", { class: "card tok" }, h("span", { class: "h" }, hd), ".", h("span", { class: "p" }, pl), ".", h("span", { class: "s" }, sg.slice(0, 60) + "… (" + Math.round(sg.length * 0.75) + " signature bytes)")),
    h("div", { class: "grid g2" },
      h("div", { class: "card" }, h("h3", {}, "Header"), pre(header), h("h3", {}, "Payload (encoded, NOT encrypted: anyone can read it)"), pre(payload), h("p", { class: "small muted" }, "Expires in " + Math.floor(left / 60) + " min " + (left % 60) + " s. Claims: sub = who, role = RBAC role, aud = which service, iat/exp = validity, jti = unique id (used for logout/revocation), kid = which RSA key signed it.")),
      h("div", { class: "card" }, h("h3", {}, "Signature"), h("p", {}, "signature = (padded SHA-256 of header.payload) ^ d mod n. Only the auth server knows d. Anyone with the public key (n, e) can check it."),
        h("div", { class: "row" }, h("button", { onclick: askVerify }, "Ask the server to verify this token"), h("button", { class: "ghost", onclick: showKeys }, "Show public keys")),
        h("div", { id: "tokOut" })))
    , h("h2", {}, "Tamper lab"),
    h("p", { class: "muted" }, "Edit the payload yourself, keep the old signature, and send it to an administrator endpoint. The gateway recomputes the check and refuses. (This also raises a token_tampering alert for the administrator.)"),
    h("div", { class: "card" }, h("textarea", { id: "tamperBox", rows: 9 }, JSON.stringify(payload, null, 2)),
      h("div", { class: "row" },
        h("button", { class: "ghost small", onclick: () => { const p = JSON.parse($("#tamperBox").value); p.role = "administrator"; $("#tamperBox").value = JSON.stringify(p, null, 2); } }, "set role = administrator"),
        h("button", { onclick: () => sendTampered(false) }, "Send edited token → /admin/stats"),
        h("button", { class: "ghost", onclick: () => sendTampered(true) }, "Same, with alg = none")),
      h("div", { id: "tamperOut" })));
};
async function askVerify() {
  const r = await api("POST", "/lab/inspect", { token: S.token });
  $("#tokOut").replaceChildren(h("p", {}, r.json.valid ? h("span", { class: "ok" }, "Server: token is VALID") : h("span", { class: "bad" }, "Server: refused (" + r.json.reason + ")")));
}
async function showKeys() {
  const r = await api("GET", "/auth/public-key", undefined, { token: null });
  $("#tokOut").replaceChildren(table(["kid", "status", "bits", "e", "n (first 40 digits)"], r.json.keys.map(k => [k.kid, k.status, k.bits, k.e, k.n.slice(0, 40) + "…"])));
}
async function sendTampered(none) {
  let p; try { p = JSON.parse($("#tamperBox").value); } catch (e) { $("#tamperOut").textContent = "Payload is not valid JSON."; return; }
  const [hd, , sg] = S.token.split(".");
  const header = none ? b64u(JSON.stringify({ alg: "none", typ: "SHT", kid: JSON.parse(unb64u(hd)).kid })) : hd;
  const forged = header + "." + b64u(JSON.stringify(p)) + "." + (none ? "" : sg);
  const ins = await api("POST", "/lab/inspect", { token: forged });
  const r = await api("GET", "/admin/stats", undefined, { token: forged });
  $("#tamperOut").replaceChildren(h("p", {}, "Endpoint answer: ", statusChip(r)), h("p", {}, "Why: ", h("b", {}, ins.json.reason), " - ", ins.json.message || ""));
}

/* ------------------------------------------------------------ documents */
RENDER.docs = async () => {
  const el = $("#tab-docs"); el.replaceChildren(h("h1", {}, "Documents"), h("p", { class: "muted" }, "The API filters the list for your role and checks the object again when you open one. Role: ", h("b", {}, role())));
  if (!S.token) { el.append(h("p", {}, "Sign in first.")); return; }
  const r = await api("GET", "/api/documents");
  const out = h("div", { id: "docView", class: "card" }, "Select a document, or type an id below.");
  el.append(h("div", { class: "grid g2" },
    h("div", { class: "card" }, h("h3", {}, "Visible to you (" + (r.json.documents ? r.json.documents.length : 0) + ")"),
      r.status !== 200 ? h("p", { class: "bad" }, "Refused: ", statusChip(r), h("br"), h("span", { class: "muted" }, "your role has no document permission; the data lake tab is for your role.")) :
        table(["id", "title", "course", "kind", ""], r.json.documents.map(d => [d.id, d.title, d.course, d.kind, d.id]), (v, i) => i === 4 ? h("button", { class: "small ghost", onclick: () => openDoc(v) }, "open") : String(v))),
    h("div", {}, out,
      h("div", { class: "card" }, h("h3", {}, "Open by id (try someone else's)"), h("div", { class: "row" }, h("input", { id: "docId", type: "number", value: 5, style: "width:90px" }), h("button", { onclick: () => openDoc($("#docId").value) }, "GET /api/documents/<id>")),
        h("p", { class: "small muted" }, "Student: 5 is bob's grades → 403 not_owner. Teacher: other course → 403 not_your_course. Administrator: exams and grades → 403 separation_of_duties. 99 → 404.")),
      role() === "teacher" ? h("div", { class: "card" }, h("h3", {}, "Create a document"), h("label", {}, "Title", h("input", { id: "nt", value: "Lecture notes" })), h("label", {}, "Course", h("input", { id: "nc", value: (S.user.courses || [])[0] || "" })), h("div", { class: "row" }, h("button", { onclick: createDoc }, "POST /api/documents")), h("div", { id: "createOut" })) : null,
      isAdmin() ? h("div", { class: "card" }, h("h3", {}, "Delete"), h("div", { class: "row" }, h("input", { id: "delId", type: "number", value: 12, style: "width:90px" }), h("button", { onclick: delDoc }, "DELETE /api/documents/<id>")), h("div", { id: "delOut" })) : null)));
};
async function openDoc(id) {
  const r = await api("GET", "/api/documents/" + encodeURIComponent(id));
  $("#docView").replaceChildren(h("h3", {}, "Document " + id), h("p", {}, statusChip(r)), r.status === 200 ? h("div", {}, h("b", {}, r.json.title), h("div", { class: "muted small" }, r.json.course + " · " + r.json.kind + " · owner " + r.json.owner), h("p", {}, r.json.body)) : pre(r.json));
}
async function createDoc() { const r = await api("POST", "/api/documents", { title: $("#nt").value, course: $("#nc").value, kind: "lecture", body: "created from the portal" }); $("#createOut").replaceChildren(statusChip(r)); if (r.status === 201) RENDER.docs(); }
async function delDoc() { const r = await api("DELETE", "/api/documents/" + $("#delId").value); $("#delOut").replaceChildren(statusChip(r)); }

/* ------------------------------------------------------------ data lake (ABAC) */
const PRESETS = [
  ["My patients (all columns)", { columns: "*", limit: 10 }],
  ["Diagnosis filter", { columns: ["record_id", "full_name", "diagnosis_label"], where: [{ col: "diagnosis_code", op: "=", value: "I10" }], limit: 10 }],
  ["Ask for billing", { columns: ["record_id", "treatment_cost"], limit: 5 }],
  ["Restricted column", { columns: ["record_id", "national_id"], limit: 3 }],
  ["Statistics by diagnosis", { group_by: ["diagnosis_code"], metrics: [{ fn: "count" }, { fn: "avg", col: "treatment_cost" }, { fn: "count_distinct", col: "patient_id" }], order_by: [{ col: "diagnosis_code" }] }],
  ["Visits per pseudonym", { group_by: ["patient_id"], metrics: [{ fn: "count" }], order_by: [{ col: "n", dir: "desc" }], limit: 5 }],
  ["Count per service", { group_by: ["service"], metrics: [{ fn: "count" }], order_by: [{ col: "service" }] }],
  ["Filter on hashed id", { group_by: ["city"], metrics: [{ fn: "count" }], where: [{ col: "patient_id", op: "=", value: "P0000001" }] }],
  ["Injection attempt", { group_by: ["city"], metrics: [{ fn: "count" }], where: [{ col: "city", op: "=", value: "x' OR '1'='1" }] }],
];
RENDER.lake = async () => {
  const el = $("#tab-lake"); el.replaceChildren(h("h1", {}, "Data lake: fine-grained access (ABAC) on PySpark"));
  if (!S.token) { el.append(h("p", {}, "Sign in first.")); return; }
  const r = await api("GET", "/lake/info", undefined, { ip: S.zone });
  if (r.status !== 200) { el.append(h("div", { class: "card" }, h("p", {}, "Your role (", h("b", {}, role()), ") has no permission on the data lake: ", statusChip(r)), h("p", { class: "muted" }, "RBAC is the coarse gate. Sign in as dr_amine, lina or root to use the lake."))); return; }
  const info = r.json, me = info.subject;
  const purposes = ["care", "research", "statistics", "maintenance"];
  el.append(
    h("p", { class: "muted" }, "One table of hospital records. The platform decides per column (clear, masked, hashed or denied) and per row, from the user's attributes, the declared purpose and the network zone. Conflicts: deny-overrides."),
    h("div", { class: "card" }, h("div", { class: "row" },
      h("span", {}, "You: ", h("b", {}, me.username), " · ", me.role, me.service ? " · service " + me.service : ""),
      h("label", {}, "Purpose ", h("select", { id: "lkPurpose" }, purposes.map(p => h("option", { value: p, selected: me.purposes[0] === p }, p)))),
      h("label", {}, "Network ", h("select", { id: "lkZone", onchange: e => { S.zone = e.target.value; } },
        h("option", { value: "127.0.0.1", selected: S.zone === "127.0.0.1" }, "hospital network (internal)"), h("option", { value: "203.0.113.9", selected: S.zone !== "127.0.0.1" }, "outside (external)"))),
      h("label", {}, "Engine ", h("select", { id: "lkEngine" }, h("option", { value: "python" }, "pure Python"), h("option", { value: "spark", disabled: !info.engines.spark }, info.engines.spark ? "PySpark (first run starts Spark)" : "PySpark (not installed)")))),
      h("div", { class: "chips" }, PRESETS.map(([n, q]) => h("button", { class: "chip", onclick: () => { $("#lkQuery").value = JSON.stringify(q, null, 1); } }, n))),
      h("textarea", { id: "lkQuery", rows: 7 }, JSON.stringify(PRESETS[0][1], null, 1)),
      h("div", { class: "row" }, h("button", { onclick: () => lakeGo(false) }, "Explain (no data)"), h("button", { onclick: () => lakeGo(true) }, "Run query"),
        isAdmin() ? h("button", { class: "ghost", onclick: lakeViews }, "Same query as doctor, analyst, administrator") : null)),
    h("div", { id: "lkOut" }),
    h("details", {}, h("summary", {}, "Column catalog and policy rules (" + info.rules.length + " rules)"),
      table(["column", "type", "sensitivity", "tags", "masked as"], info.columns.map(c => [c.name, c.type, c.sensitivity + " " + c.sensitivity_name, c.tags.join(", "), c.mask])),
      table(["rule", "effect", "who", "purpose", "zone", "columns", "then", "description"], info.rules.map(x => [x.id, x.effect, (x.role || ["anyone"]).join("/"), x.purpose ? x.purpose.join("/") : x.purpose_not ? "not " + x.purpose_not.join("/") : "any", (x.zone || ["any"]).join("/"), JSON.stringify(x.columns), x.obligation || "deny", x.desc]))));
};
function readLake() {
  let q; try { q = JSON.parse($("#lkQuery").value); } catch (e) { $("#lkOut").replaceChildren(h("p", { class: "bad" }, "Query is not valid JSON: " + e.message)); return null; }
  return { purpose: $("#lkPurpose").value, query: q, engine: $("#lkEngine").value };
}
async function lakeGo(run) {
  const b = readLake(); if (!b) return;
  const out = $("#lkOut"); out.replaceChildren(h("p", { class: "muted" }, run && b.engine === "spark" ? "Running on Spark (the first query starts the engine, about 10 s)…" : "…"));
  const r = await api("POST", run ? "/lake/query" : "/lake/explain", b, { ip: S.zone });
  const plan = r.json.plan || r.json;
  const parts = [];
  if (r.status === 400) { parts.push(h("div", { class: "card" }, h("p", { class: "bad" }, "Rejected before planning: ", statusChip(r), " - ", r.json.message || ""))); out.replaceChildren(...parts); return; }
  const refused = r.status === 403 || plan.allowed === false;
  parts.push(h("div", { class: "card" }, h("h3", {}, refused ? h("span", { class: "bad" }, "Refused: " + plan.reason + (plan.columns_denied && plan.columns_denied.length ? " (" + plan.columns_denied.join(", ") + ")" : "")) : h("span", { class: "ok" }, run ? "Allowed" : "Would be allowed")),
    h("p", { class: "small muted" }, "role " + plan.role + " · purpose " + plan.purpose + " · zone " + plan.zone + (plan.row_filter ? " · row filter: " + plan.row_filter.col + " = " + plan.row_filter.value : " · no row filter") +
      " · constraints: " + (plan.constraints.aggregate_only ? "aggregate only, " : "") + "groups ≥ " + plan.constraints.k_min + ", max " + plan.constraints.max_rows + " rows"),
    h("h3", {}, "Decision per column"),
    table(["column", "used as", "sensitivity", "outcome", "permits", "denies", "why"], plan.explain.map(x => [x.column, x.role_in_query, x.sensitivity, x.outcome, x.permits.join(",") || "-", x.denies.join(",") || "-", x.why]), (v, i) => i === 3 ? badge(v, "b-" + v) : String(v))));
  if (plan.sql) parts.push(h("div", { class: "grid g2" }, h("div", { class: "card" }, h("h3", {}, "You asked"), pre(plan.original_sql || "")), h("div", { class: "card" }, h("h3", {}, "The platform ran (rewritten)"), pre(plan.sql))));
  if (run && r.json.result) { const res = r.json.result; parts.push(h("div", { class: "card" }, h("h3", {}, res.row_count + " row(s) · engine " + res.engine + " · " + res.ms + " ms"), h("div", { class: "scroll" }, table(res.columns, res.rows)))); }
  out.replaceChildren(...parts);
}
async function lakeViews() {
  const b = readLake(); const out = $("#lkOut"); out.replaceChildren(h("p", { class: "muted" }, "Running the same query as three identities…"));
  const r = await api("POST", "/lab/lake-views", { query: b ? b.query : undefined });
  const cols = r.json.views.map(v => {
    const ok = v.attempt_status === 200;
    const blk = (j, st, label) => st === 200 ? h("div", {}, h("div", { class: "small muted" }, label), h("div", { class: "scroll" }, table(j.result.columns, j.result.rows))) :
      h("div", {}, h("div", { class: "small muted" }, label), h("p", { class: "bad" }, "Refused: " + (j.reason || j.error), j.plan && j.plan.columns_denied && j.plan.columns_denied.length ? " (" + j.plan.columns_denied.join(", ") + ")" : ""));
    return h("div", { class: "card" }, h("h3", {}, v.role), h("div", { class: "small muted" }, v.user + " · purpose " + v.purpose),
      blk(v.attempt, v.attempt_status, "same query"), v.fallback ? blk(v.fallback, v.fallback_status, "role-appropriate query: " + JSON.stringify(v.fallback_query).slice(0, 90) + "…") : null);
  });
  out.replaceChildren(h("h2", {}, "Same table, three views"), h("div", { class: "grid g3" }, cols));
}

/* ------------------------------------------------------------ dashboard */
const DASH = { entries: [], ctl: null, last: 0, timer: null };
function stopStream() { if (DASH.ctl) { DASH.ctl.abort(); DASH.ctl = null; } clearTimeout(DASH.timer); }
RENDER.dash = async () => {
  const el = $("#tab-dash"); el.replaceChildren(
    h("h1", {}, "Audit dashboard (administrator)"),
    h("div", { class: "grid g4", id: "stats" }),
    h("div", { class: "row" },
      h("label", {}, h("input", { type: "checkbox", id: "fAlerts", onchange: drawDash }), " alerts only"),
      h("label", {}, h("input", { type: "checkbox", id: "fSelf", checked: true, onchange: drawDash }), " hide the dashboard's own reads"),
      h("button", { onclick: verifyChain }, "Verify hash chain"), h("button", { class: "ghost", onclick: tamperLog }, "Simulate log tampering"),
      h("button", { class: "ghost", onclick: rotateKey }, "Rotate RSA key"), h("span", { id: "liveState", class: "muted small" }, "connecting…")),
    h("div", { id: "chainOut" }),
    h("h2", {}, "Alerts"), h("div", { id: "alerts" }, h("span", { class: "muted" }, "none yet")),
    h("h2", {}, "Every request (newest first)"), h("div", { class: "scroll", style: "max-height:420px", id: "feed" }));
  DASH.entries = []; DASH.last = 0; stopStream(); startStream();
};
async function startStream() {
  DASH.ctl = new AbortController();
  try {
    const resp = await fetch("/admin/stream?since=" + DASH.last, { headers: { Authorization: "Bearer " + S.token }, signal: DASH.ctl.signal });
    if (!resp.ok) throw new Error("status " + resp.status);
    $("#liveState").textContent = "● live (server-sent events)";
    const rd = resp.body.getReader(), dec = new TextDecoder(); let buf = "";
    for (;;) {
      const { done, value } = await rd.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let i; while ((i = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
        if (chunk.startsWith("data: ")) { const e = JSON.parse(chunk.slice(6)); DASH.entries.push(e); DASH.last = Math.max(DASH.last, e.id); schedDraw(); }
      }
    }
  } catch (e) {
    if (e.name === "AbortError") return;
    $("#liveState").textContent = "stream lost, polling every 2 s";
    DASH.timer = setTimeout(poll, 2000);
  }
}
async function poll() {
  if (S.tab !== "dash") return;
  const r = await api("GET", "/admin/audit?since=" + DASH.last + "&limit=500");
  for (const e of r.json.entries || []) { DASH.entries.push(e); DASH.last = Math.max(DASH.last, e.id); }
  schedDraw(); DASH.timer = setTimeout(poll, 2000);
}
let drawT = null;
function schedDraw() { if (!drawT) drawT = setTimeout(() => { drawT = null; drawDash(); }, 250); }
function drawDash() {
  if (!$("#feed")) return;
  const es = DASH.entries, req = es.filter(e => e.type === "request"), al = es.filter(e => e.type === "alert");
  $("#stats").replaceChildren(...[["requests", req.length], ["allowed", req.filter(e => e.status < 400).length], ["refused", req.filter(e => e.status >= 400).length], ["alerts", al.length]].map(([k, v]) => h("div", { class: "card stat" }, h("b", {}, v), k)));
  $("#alerts").replaceChildren(...(al.length ? al.slice(-15).reverse().map(a => h("div", { class: "alert " + a.severity }, h("b", {}, a.rule), " · " + a.severity + " · " + a.subject + " · measured " + a.measured + " · " + a.message + " · evidence #" + (a.evidence || []).join(", #"))) : [h("span", { class: "muted" }, "none yet")]));
  let list = es.slice(); if ($("#fAlerts").checked) list = list.filter(e => e.type === "alert");
  if ($("#fSelf").checked) list = list.filter(e => !(e.type === "request" && e.user === (S.user && S.user.username) && /^\/admin\/(audit|stats|stream|verify)/.test(e.path)));
  list = list.slice(-120).reverse();
  $("#feed").replaceChildren(table(["#", "time", "ip", "user", "request", "status", "decision", "reason", "details"], list.map(e => e.type === "alert" ?
    [e.id, new Date(e.ts * 1000).toLocaleTimeString(), "", "", "ALERT " + e.rule, "", e.severity, e.message, ""] :
    [e.id, new Date(e.ts * 1000).toLocaleTimeString(), e.ip, (e.user || "-") + (e.role ? " (" + e.role + ")" : ""), e.method + " " + e.path, e.status, e.decision, e.reason, [e.lab ? "lab" : "", e.rows != null ? e.rows + " rows" : "", e.purpose ? "purpose " + e.purpose : ""].filter(Boolean).join(" · ")]),
    (v, i) => (i === 5 ? h("b", { class: "s" + String(v)[0] }, v) : String(v))));
}
async function verifyChain() {
  const r = await api("GET", "/admin/verify-chain");
  $("#chainOut").replaceChildren(h("div", { class: "card" }, r.json.ok ? h("span", { class: "ok" }, "Chain valid: " + r.json.checked + " entries checked. ") : h("span", { class: "bad" }, "CHAIN BROKEN at entry #" + r.json.first_bad + " (" + r.json.reason + "). "), h("span", { class: "muted small" }, "head " + r.json.head.hash.slice(0, 24) + "… (write it down: it also reveals deleted last entries)")));
}
async function tamperLog() { const r = await api("POST", "/lab/tamper-log", {}); $("#chainOut").replaceChildren(h("div", { class: "card" }, "Entry #" + r.json.id + " was edited in storage (user → nobody). ", r.json.verify.ok ? h("span", { class: "ok" }, "chain still valid?!") : h("span", { class: "bad" }, "Verification now fails at entry #" + r.json.verify.first_bad + "."))); }
async function rotateKey() { const r = await api("POST", "/admin/rotate-key"); $("#chainOut").replaceChildren(h("div", { class: "card" }, "New active key: ", h("b", {}, r.json.active), ". Tokens signed with older keys are now refused (retired_key); users sign in again.")); }

/* ------------------------------------------------------------ attack lab */
RENDER.lab = async () => {
  const el = $("#tab-lab"); el.replaceChildren(h("h1", {}, "Attack lab (administrator)"),
    h("p", { class: "muted" }, "Each attack is sent through the real gateway as ordinary requests from a simulated address. The expected detection rule must fire; the normal-traffic run must raise nothing."));
  const r = await api("GET", "/lab/attacks");
  el.append(h("div", { class: "row" }, h("button", { onclick: runAll }, "Run all " + r.json.attacks.length + " attacks"), h("button", { class: "ghost", onclick: runBenign }, "Normal traffic (false-positive check)"), h("button", { class: "ghost", onclick: resetLab }, "Reset lab data and log")),
    h("div", { id: "labSummary" }),
    h("div", { class: "grid g2" }, r.json.attacks.map(a => h("div", { class: "card", id: "att-" + a.name }, h("h3", {}, a.title), h("p", { class: "small" }, a.what), h("p", { class: "small muted" }, "Defence: " + a.defence), h("p", { class: "small" }, "Expected alert: ", a.expected_rule ? h("code", {}, a.expected_rule) : h("i", {}, "none (the request must simply be refused)")),
      h("button", { class: "small", onclick: () => runOne(a.name) }, "Run"), h("div", { class: "res" })))));
}
function showAttack(x) {
  const d = $("#att-" + x.name + " .res"); if (!d) return;
  d.replaceChildren(h("p", {}, x.passed ? h("span", { class: "pass" }, "PASS") : h("span", { class: "fail" }, "FAIL"), "  alerts fired: " + (x.alerts_fired.join(", ") || "none")),
    h("details", { open: true }, h("summary", {}, "what the gateway answered"), table(["request", "status", "reason", "×"], x.trace.map(t => [t.call, t.status, t.reason, t.count]), (v, i) => i === 1 ? h("b", { class: "s" + String(v)[0] }, v) : String(v))));
}
async function runOne(n) { const r = await api("POST", "/lab/attack/" + n); showAttack(r.json); }
async function runAll() {
  $("#labSummary").replaceChildren(h("p", { class: "muted" }, "running…"));
  const r = await api("POST", "/lab/attack/all");
  r.json.results.forEach(showAttack);
  $("#labSummary").replaceChildren(h("div", { class: "card" }, h("b", {}, r.json.passed + " / " + r.json.total + " attacks detected or blocked as expected."), " Open the Dashboard to see the alerts and verify the chain."));
}
async function runBenign() {
  const r = await api("POST", "/lab/benign");
  $("#labSummary").replaceChildren(h("div", { class: "card" }, "Normal use by 8 users: ", h("b", {}, r.json.requests + " requests"), " → ", h("b", { class: r.json.alerts ? "bad" : "ok" }, r.json.alerts + " alerts"), r.json.alerts ? " (false positives: " + r.json.false_positives.join(", ") + ")" : " (no false positive)"));
}
async function resetLab() { await api("POST", "/lab/reset"); $("#labSummary").replaceChildren(h("div", { class: "card" }, "Lab data, lockouts and audit log reset.")); }

/* ------------------------------------------------------------ RSA lab */
RENDER.rsa = async () => {
  const el = $("#tab-rsa"); el.replaceChildren(h("h1", {}, "RSA lab"),
    h("p", { class: "muted" }, "Small numbers so every step can be checked by hand. Signing: s = m^d mod n. Verifying: s^e mod n = m."),
    h("div", { class: "grid g2" },
      h("div", { class: "card" }, h("h3", {}, "1 · Make a toy key and sign"),
        h("div", { class: "row" }, ...["p:61", "q:53", "e:17", "m:65"].map(s => { const [k, v] = s.split(":"); return h("label", {}, k, h("input", { id: "r_" + k, value: v, style: "width:70px" })); })),
        h("button", { onclick: rsaToy }, "Compute"), h("div", { id: "toyOut" })),
      h("div", { class: "card" }, h("h3", {}, "2 · Forge a signature (no padding)"),
        h("div", { class: "row" }, h("label", {}, "m1", h("input", { id: "f1", value: 5, style: "width:70px" })), h("label", {}, "m2", h("input", { id: "f2", value: 7, style: "width:70px" }))),
        h("button", { onclick: rsaForge }, "Forge sig(m1·m2)"), h("div", { id: "forgeOut" })),
      h("div", { class: "card" }, h("h3", {}, "3 · Small keys fall: factor n"),
        h("div", { class: "row" }, h("label", {}, "n", h("input", { id: "fn", value: 3233, style: "width:150px" })), h("label", {}, "e", h("input", { id: "fe", value: 17, style: "width:70px" }))),
        h("button", { onclick: rsaFactor }, "Factor and recover d"), h("div", { id: "factorOut" })),
      h("div", { class: "card" }, h("h3", {}, "4 · Real key: our signature checked by OpenSSL"),
        h("button", { onclick: rsaOpenssl }, "Sign with the server key, verify with OpenSSL"), h("div", { id: "sslOut" }), h("hr"),
        h("button", { class: "ghost", onclick: async () => { const r = await api("GET", "/auth/public-key", undefined, { token: null }); $("#sslOut").replaceChildren(table(["kid", "status", "bits", "e"], r.json.keys.map(k => [k.kid, k.status, k.bits, k.e])), pre(r.json.keys[r.json.keys.length - 1].pem)); } }, "Show public key (PEM)"))));
};
const rv = id => $("#" + id).value;
async function rsaToy() { const r = await api("POST", "/lab/rsa/toy", { p: +rv("r_p"), q: +rv("r_q"), e: +rv("r_e"), m: +rv("r_m") }, { token: null });
  $("#toyOut").replaceChildren(r.status !== 200 ? h("p", { class: "bad" }, r.json.message) : h("div", {}, table(["n = p·q", "φ = (p-1)(q-1)", "d = e⁻¹ mod φ"], [[r.json.keys.n, r.json.keys.phi, r.json.keys.d]]), h("p", {}, "signature s = " + r.json.m + "^" + r.json.keys.d + " mod " + r.json.keys.n + " = ", h("b", {}, r.json.signature), " → verify: " + r.json.signature + "^" + r.json.keys.e + " mod n = " + r.json.m + " ", r.json.verifies ? h("span", { class: "ok" }, "✔") : h("span", { class: "bad" }, "✘")))); }
async function rsaForge() { const r = await api("POST", "/lab/rsa/forge", { p: +rv("r_p"), q: +rv("r_q"), e: +rv("r_e"), m1: +rv("f1"), m2: +rv("f2") }, { token: null });
  $("#forgeOut").replaceChildren(r.status !== 200 ? h("p", { class: "bad" }, r.json.message) : h("div", {}, h("p", {}, "sig(" + r.json.m1 + ") = " + r.json.s1 + ", sig(" + r.json.m2 + ") = " + r.json.s2 + " → forged sig(" + r.json.forged_message + ") = " + r.json.forged_signature + " ", r.json.verifies ? h("b", { class: "bad" }, "verifies!") : "does not verify"), h("p", { class: "small muted" }, r.json.note))); }
async function rsaFactor() { const r = await api("POST", "/lab/rsa/factor", { n: rv("fn"), e: +rv("fe") }, { token: null });
  $("#factorOut").replaceChildren(r.status !== 200 ? h("p", { class: "bad" }, r.json.message) : r.json.factors ? h("p", {}, "n = " + r.json.factors[0] + " × " + r.json.factors[1] + " → private exponent d = " + r.json.d + ". ", h("span", { class: "muted small" }, r.json.note)) : h("p", {}, "no factor found")); }
async function rsaOpenssl() { const r = await api("GET", "/lab/rsa/compare-openssl", undefined, { token: null });
  $("#sslOut").replaceChildren(!r.json.available ? h("p", { class: "warn" }, r.json.message) : h("p", {}, "OpenSSL says: ", h("b", {}, r.json.openssl_says), " (" + r.json.bits + "-bit key). ", r.json.verified ? h("span", { class: "ok" }, "Our implementation agrees with OpenSSL.") : h("span", { class: "bad" }, "disagreement!"))); }

/* ------------------------------------------------------------ start */
$("#loginBtn").onclick = openLogin; $("#logoutBtn").onclick = doLogout; $("#doLogin").onclick = doLogin;
$("#closeLogin").onclick = () => { $("#modal").hidden = true; };
$("#lp").addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
$("#clearLog").onclick = () => $("#reqlog").replaceChildren();
buildNav(); show("home");
if (!S.token) openLogin();

import { api as requestAPI, apiBytes, me, mockMode, enrollSoon } from "./api.js";
import { esc, icon, spinner, logo, agentLogo, clientName, ago, day, clock, toast, isMac, siteLogo, siteHost } from "./ui.js";

const root = document.getElementById("root");
const $ = (sel, el = document) => el.querySelector(sel);
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

const S = {
  me: null,
  connectors: null,
  connErr: false,
  agents: null,
  approvals: null,
  activity: null,
  q: "",
  cat: "all",
  kb: -1,
  panel: null,
  tests: {},
  testing: {},
  confirm: null,
  busy: {},
  flash: null,
  prompt: null,
  promptErr: false,
  copied: false,
  waiting: false,
  joined: null,
  baseline: null,
  resolved: {},
  vault: null,
  vaultErr: false,
  vaultLoading: false,
  requests: [],
  vq: "",
  modal: null,
};

const ROUTES = { "": "Connectors", vault: "Logins", agents: "Agents", approvals: "Approvals", activity: "Activity" };
const route = () => (location.hash.replace(/^#\/?/, "").split("?")[0] in ROUTES ? location.hash.replace(/^#\/?/, "").split("?")[0] : "");

// ---------- boot ----------

async function boot() {
  let m;
  try {
    m = await me();
  } catch {
    return renderUnreachable();
  }
  if (!m) return renderSignedOut();
  S.me = m.user;
  renderShell();
  window.addEventListener("hashchange", renderView);
  renderView();
  loadConnectors().then(handleReturn);
  loadAgents();
  loadApprovals();
  loadVault();
  setInterval(() => {
    if (document.hidden) return;
    loadApprovals();
    loadRequests();
    if (route() === "activity") loadActivity();
  }, 10000);
}

function renderUnreachable() {
  root.innerHTML = `<header class="top"><div class="top-in"><a class="wordmark" href="/">RalX</a></div></header><div class="center-msg"><h1>RalX can't be reached right now.</h1><p>Check your connection, then try again.</p><button class="btn primary" data-act="reload">Try again</button></div>`;
}

// ---------- data ----------

async function loadConnectors() {
  try {
    S.connectors = (await api("GET", "/api/connectors")).connectors;
    S.connErr = false;
  } catch {
    S.connErr = true;
  }
  renderGrid();
  renderSheet();
  const pending = S.connectors?.some((c) => c.accounts.some((a) => a.status === "pending"));
  if (pending) setTimeout(loadConnectors, 1500);
}
async function loadAgents() {
  try {
    S.agents = (await api("GET", "/api/agents")).agents;
  } catch {
    S.agents ??= [];
  }
  checkJoined();
  renderAgentRows();
}
async function loadApprovals() {
  try {
    S.approvals = (await api("GET", "/api/approvals")).approvals;
  } catch {
    S.approvals ??= [];
  }
  updateNav();
  if (route() === "approvals") renderApprovals();
}
async function loadActivity() {
  try {
    S.activity = (await api("GET", "/api/activity")).events;
  } catch {
    S.activity ??= "error";
  }
  if (route() === "activity") renderActivity();
}

const connector = (slug) => S.connectors?.find((c) => c.slug === slug);
const NOHIT = { hits: [] };
const POPULAR = [
  ["gmail", "Gmail", "Email", "Read, search, draft and send email."],
  ["github", "GitHub", "Developer tools", "Repos, issues and pull requests."],
  ["notion", "Notion", "Files and docs", "Search pages, read databases, write notes."],
  ["slack", "Slack", "Chat", "Read channels and post messages."],
  ["googlecalendar", "Google Calendar", "Calendar", "See your day, find free time, book meetings."],
  ["googledrive", "Google Drive", "Files and docs", "Find, read and upload files."],
].map(([slug, name, category, description]) => ({ slug, name, category, description, accounts: [] }));

// Empty and error states show the product as it will look, faded, under one plain line.
const ghost = (title, caption, body, action = "") =>
  `<div class="ghost"><div class="ghost-head"><h2>${title}</h2><p>${caption}</p>${action}</div><div class="ghost-body" aria-hidden="true" inert>${body.replace(/ data-(i|k|act)="[^"]*"/g, "")}</div></div>`;
const accountCount = () => (S.connectors || []).reduce((n, c) => n + c.accounts.filter((a) => a.status === "active").length, 0);
const pendingApprovals = () => (S.approvals || []).filter((a) => !S.resolved[a.id]);
const clientOf = (agentName) => S.agents?.find((a) => a.name === agentName)?.client;
const toolApp = (tool) => String(tool).split(/[._]/)[0].toLowerCase();

// Back from the provider login: /?connected=gmail
function handleReturn() {
  const u = new URL(location.href);
  const slug = u.searchParams.get("connected");
  if (!slug) return;
  u.searchParams.delete("connected");
  history.replaceState(null, "", u.pathname + u.search + u.hash);
  justConnected(slug);
}
function justConnected(slug) {
  const c = connector(slug);
  if (!c) return;
  toast(`Back from ${esc(c.name)}. Check the account status below.`);
  S.flash = slug;
  renderGrid();
  setTimeout(() => {
    S.flash = null;
    $(`.tile[data-slug="${slug}"]`)?.classList.remove("flash");
  }, 1600);
}

// ---------- shell ----------

function renderShell() {
  const u = S.me;
  root.innerHTML = `
  <header class="top">
    <div class="top-in">
      <a class="wordmark" href="#/" aria-label="RalX, connectors">RalX</a>
      <nav class="tabs" aria-label="Main">
        ${Object.entries(ROUTES)
          .map(([k, v]) => `<a href="#/${k}" data-route="${k}">${v}${k === "approvals" ? '<span class="n" id="appr-n"></span>' : k === "vault" ? '<span class="n" id="vault-n"></span>' : ""}</a>`)
          .join("")}
      </nav>
      <div class="me">
        <button class="me-btn" id="me-btn" aria-haspopup="menu" aria-expanded="false" aria-label="Account">
          ${u.avatar_url ? `<img src="${esc(u.avatar_url)}" alt="" width="28" height="28" data-avatar>` : `<span class="me-email">${esc(u.email)}</span>`}
        </button>
        <div class="menu" id="menu" role="menu" hidden>
          <div class="menu-who"><div>${esc(u.name || "")}</div><div class="menu-email">${esc(u.email)}</div></div>
          <button role="menuitem" data-act="logout">${icon("out", 15)}Sign out</button>
        </div>
      </div>
    </div>
  </header>
  <main id="view" class="view"></main>
  <div id="sheet-root"></div>`;
  const avatar = root.querySelector("[data-avatar]");
  avatar?.addEventListener("error", () => {
    const label = document.createElement("span");
    label.className = "me-email";
    label.textContent = u.email;
    avatar.replaceWith(label);
  });
  $(".tabs")?.addEventListener("scroll", updateNavFade, { passive: true });
  window.addEventListener("resize", revealActiveTab, { passive: true });
  document.fonts.ready.then(revealActiveTab);
}

let activeNavRoute;
function updateNavFade() {
  const tabs = $(".tabs");
  tabs?.classList.toggle("more-right", tabs.scrollLeft + tabs.clientWidth < tabs.scrollWidth - 1);
}
function revealActiveTab() {
  const tabs = $(".tabs"), active = tabs?.querySelector("[aria-current]");
  if (!active) return;
  active.scrollIntoView({ block: "nearest", inline: "nearest" });
  if (active === tabs.lastElementChild) tabs.scrollLeft = tabs.scrollWidth;
  updateNavFade();
}
function updateNav() {
  const r = route();
  document.querySelectorAll(".tabs a").forEach((a) => a.toggleAttribute("aria-current", a.dataset.route === r));
  if (r !== activeNavRoute) {
    activeNavRoute = r;
    if ($(".tabs")) requestAnimationFrame(revealActiveTab);
  }
  const n = $("#appr-n");
  if (n) n.textContent = pendingApprovals().length || "";
  const v = $("#vault-n");
  if (v) v.textContent = S.requests.length || "";
  updateNavFade();
}

function renderView() {
  const r = route();
  updateNav();
  document.title = r ? `${ROUTES[r]} | RalX` : "RalX";
  closeSheet(true);
  closeModal(true);
  stopAgentPoll();
  ({ "": viewConnectors, vault: viewVault, agents: viewAgents, approvals: viewApprovals, activity: viewActivity })[r]();
  window.scrollTo(0, 0);
}

// ---------- connectors ----------

function viewConnectors() {
  $("#view").innerHTML = `
  <div class="page">
    <div class="page-head">
      <h1>Connectors</h1>
      <p class="lede">Connect each account once. Every agent you add can use it.</p>
    </div>
    <div class="search">
      ${icon("search", 18)}
      <input id="q" type="text" inputmode="search" placeholder="Search apps or accounts" autocomplete="off" spellcheck="false" aria-label="Search apps or accounts" aria-controls="grid" value="${esc(S.q)}">
      <button class="clear" data-act="clear" aria-label="Clear search" ${S.q ? "" : "hidden"}>${icon("x", 14)}</button>
      <kbd>${isMac ? "⌘K" : "Ctrl K"}</kbd>
    </div>
    <div class="cols">
      <nav class="cats" id="cats" aria-label="Filter apps"></nav>
      <label class="cats-m"><span class="sr">Show</span><select id="cat-m" aria-label="Show"></select>${icon("down", 16)}</label>
      <div id="grid" class="grid-wrap"></div>
    </div>
  </div>`;
  const q = $("#q");
  q.addEventListener("input", () => {
    S.q = q.value;
    S.kb = -1;
    $(".search .clear").hidden = !S.q;
    renderGrid();
  });
  q.addEventListener("keydown", searchKeys);
  $("#cat-m").addEventListener("change", (e) => setCat(e.target.value));
  renderGrid();
}

function categories() {
  const seen = [];
  (S.connectors || []).forEach((c) => c.category && !seen.includes(c.category) && seen.push(c.category));
  return [["all", "All apps"], ["connected", "Connected"], ...seen.map((c) => [c, c])];
}
function renderCats() {
  const cats = $("#cats");
  if (!cats) return;
  const list = categories();
  if (!list.some(([k]) => k === S.cat)) S.cat = "all";
  cats.innerHTML = list
    .map(([k, v]) => `<button data-act="cat" data-cat="${esc(k)}" aria-pressed="${S.cat === k}">${esc(v)}</button>`)
    .join("")
    .replace(/(<button data-act="cat" data-cat="connected"[^>]*>Connected<\/button>)/, "$1<hr>");
  $("#cat-m").innerHTML = list.map(([k, v]) => `<option value="${esc(k)}" ${S.cat === k ? "selected" : ""}>${esc(v)}</option>`).join("");
}
function setCat(k) {
  S.cat = k;
  S.kb = -1;
  renderGrid();
}

function matches(c) {
  const terms = S.q.toLowerCase().trim().split(/\s+/).filter(Boolean);
  if (!terms.length) return { ok: true, hits: [] };
  const base = `${c.name} ${c.slug} ${c.category} ${c.description}`.toLowerCase();
  const hits = c.accounts.filter((a) => terms.every((t) => `${base} ${a.label}`.toLowerCase().includes(t)) && terms.some((t) => a.label.toLowerCase().includes(t)));
  return { ok: terms.every((t) => base.includes(t)) || hits.length > 0, hits };
}

function visible() {
  const list = (S.connectors || [])
    .map((c) => ({ c, m: matches(c) }))
    .filter(({ c, m }) => m.ok && (S.cat === "all" || (S.cat === "connected" ? c.accounts.length : c.category === S.cat)));
  const on = list.filter((x) => x.c.accounts.length).sort((a, b) => b.c.accounts.length - a.c.accounts.length);
  const off = list.filter((x) => !x.c.accounts.length);
  return { on, off, all: [...on, ...off] };
}

function renderGrid() {
  const grid = $("#grid");
  if (!grid) return;
  renderCats();
  if (S.connErr && !S.connectors) {
    grid.innerHTML = ghost(
      "Your apps didn't load.",
      "RalX couldn't reach the app list just now.",
      `<div class="grid">${POPULAR.map((c) => tile(c, NOHIT, -1)).join("")}</div>`,
      `<button class="btn" data-act="retry">${icon("refresh", 15)}Try again</button>`,
    );
    return;
  }
  if (!S.connectors) {
    grid.innerHTML = `<div class="grid">${'<div class="tile skel"><span></span><i></i><i></i></div>'.repeat(9)}</div>`;
    return;
  }
  const focusKey = document.activeElement?.closest?.("#grid") && document.activeElement.dataset.k;
  const { on, off, all } = visible();
  let i = 0;
  const section = (title, items) =>
    items.length ? `<section class="sec"><h2 class="sec-title">${title}</h2><div class="grid">${items.map(({ c, m }) => tile(c, m, i++)).join("")}</div></section>` : "";
  if (!all.length && S.q) {
    // No match still shows something to do: the apps people connect first, live.
    const picks = ["gmail", "github", "notion"].map(connector).filter(Boolean);
    grid.innerHTML = `<div class="nomatch"><h2>No apps match “${esc(S.q.trim())}”.</h2><p>Try the app's name, or an email address you connected.</p><button class="btn sm" data-act="clear">Clear search</button></div>${section("Popular apps", picks.map((c) => ({ c, m: NOHIT })))}`;
    return;
  }
  if (!all.length) {
    // Connected filter with nothing connected: show their own Gmail as it will look.
    const g = connector("gmail") || POPULAR[0];
    const sample = { ...g, accounts: [{ id: "ghost", label: S.me.email, status: "active" }] };
    grid.innerHTML = ghost(
      "Nothing connected yet.",
      "Connect an account and it shows up here like this, ready for every agent you add.",
      `<div class="grid">${tile(sample, NOHIT, -1)}</div>`,
      `<button class="btn" data-act="cat" data-cat="all">See all apps</button>`,
    );
    return;
  }
  const first = !S.q && S.cat === "all" && !on.length ? firstUse() : "";
  grid.innerHTML = first + section(S.q ? "Connected" : "Your apps", on) + section(on.length || S.q ? "More apps" : "All apps", off);
  if (focusKey) $(`[data-k="${CSS.escape(focusKey)}"]`, grid)?.focus();
}

function firstUse() {
  const picks = ["gmail", "github", "notion"].map(connector).filter(Boolean);
  if (!picks.length) return "";
  // Beside the three starters: their own inbox as it looks once connected.
  const g = picks[0];
  const sample = { ...g, accounts: [{ id: "ghost", label: S.me.email, status: "active" }] };
  return `<section class="first">
    <div class="first-main">
      <h2>Connect your first account</h2>
      <p>Start with the one you'd most like an agent to handle for you.</p>
      <ul>${picks
        .map(
          (c) =>
            `<li>${logo(c.slug, c.logo_url, 36, c.name)}<div><div class="first-name">${esc(c.name)}</div><div class="first-desc">${esc(c.description)}</div></div>${connectBtn(c, "")}</li>`,
        )
        .join("")}</ul>
    </div>
    <div class="first-preview" aria-hidden="true" inert>
      ${tile(sample, NOHIT, -1).replace(/ data-(i|k|act)="[^"]*"/g, "")}
      <div class="first-ask">${logo("claude", null, 22, "")}<span><b>Claude</b> 3 new emails in ${esc(S.me.email)}. One needs a reply today.</span></div>
    </div>
  </section>`;
}

const connectBtn = (c, extra = "sm") =>
  `<button class="btn ${extra}" data-act="connect" data-slug="${c.slug}" data-k="connect:${c.slug}" ${S.busy[c.slug] ? "disabled" : ""}>${S.busy[c.slug] ? `${spinner()}Opening` : "Connect"}</button>`;

function tile(c, m, i) {
  const n = c.accounts.length;
  const cls = ["tile", n && "on", i >= 0 && S.kb === i && "kb", S.flash === c.slug && "flash"].filter(Boolean).join(" ");
  if (!n)
    return `<article class="${cls}" data-slug="${c.slug}" data-i="${i}">
      <div class="tile-top">${logo(c.slug, c.logo_url, 40, c.name)}<div class="tile-id"><h3>${esc(c.name)}</h3><p class="meta">${esc(c.category || "")}</p></div>${connectBtn(c)}</div>
      <p class="desc">${esc(c.description || "")}</p>
    </article>`;
  // Search hits first, then anything that needs attention, then the rest.
  const rank = (a) => (m.hits.includes(a) ? 0 : a.status !== "active" ? 1 : 2);
  const shown = [...c.accounts].sort((a, b) => rank(a) - rank(b)).slice(0, n > 3 ? 2 : 3);
  const note = (a) => (a.status === "error" ? '<span class="peek-note warn">Reconnect</span>' : a.status === "pending" ? '<span class="peek-note">Connecting</span>' : "");
  return `<article class="${cls}" data-slug="${c.slug}" data-i="${i}">
    <div class="tile-top">${logo(c.slug, c.logo_url, 40, c.name)}<div class="tile-id"><h3>${esc(c.name)}</h3><p class="meta">${n} ${n === 1 ? "account" : "accounts"}</p></div>
    <button class="btn sm" data-act="manage" data-slug="${c.slug}" data-k="manage:${c.slug}">Manage</button></div>
    <ul class="peek">${shown
      .map((a) => `<li class="${m.hits.includes(a) ? "hit" : ""}"><span class="dot ${a.status}"></span><span class="peek-label">${esc(a.label)}</span>${note(a)}</li>`)
      .join("")}${n > shown.length ? `<li class="more">and ${n - shown.length} more</li>` : ""}</ul>
    <div class="tile-foot"><button class="link" data-act="connect" data-slug="${c.slug}" data-k="add:${c.slug}" ${S.busy[c.slug] ? "disabled" : ""}>${S.busy[c.slug] ? spinner(12) : icon("plus", 14)}Add another account</button></div>
  </article>`;
}

function searchKeys(e) {
  const tiles = [...document.querySelectorAll("#grid .tile[data-i]")];
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    if (!tiles.length) return;
    e.preventDefault();
    S.kb = Math.max(0, Math.min(tiles.length - 1, S.kb + (e.key === "ArrowDown" ? 1 : -1)));
    tiles.forEach((t) => t.classList.toggle("kb", +t.dataset.i === S.kb));
    tiles[S.kb].scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" });
  } else if (e.key === "Enter") {
    const t = tiles[S.kb >= 0 ? S.kb : 0];
    if (!t || (S.kb < 0 && !S.q)) return;
    e.preventDefault();
    const c = connector(t.dataset.slug);
    c.accounts.length ? openSheet(c.slug) : connect(c.slug);
  } else if (e.key === "Escape") {
    if (S.q) clearSearch();
    else e.target.blur();
  }
}
function clearSearch() {
  S.q = "";
  S.kb = -1;
  const q = $("#q");
  if (q) {
    q.value = "";
    q.focus();
    $(".search .clear").hidden = true;
  }
  renderGrid();
}

async function connect(slug) {
  const c = connector(slug);
  if (!c || S.busy[slug]) return;
  S.busy[slug] = true;
  renderGrid();
  renderSheet();
  try {
    const r = await api("POST", `/api/connectors/${encodeURIComponent(slug)}/connect`, {});
    if (!mockMode) return location.assign(r.redirect_url);
    S.busy[slug] = false;
    await loadConnectors();
    justConnected(slug);
  } catch {
    S.busy[slug] = false;
    renderGrid();
    renderSheet();
    toast(`Couldn't open the ${esc(c.name)} login. Try again.`, "err");
  }
}

// ---------- account sheet ----------

let lastFocus = null;
function openSheet(slug) {
  S.panel = slug;
  S.confirm = null;
  lastFocus = document.activeElement;
  const host = $("#sheet-root");
  host.innerHTML = `<div class="scrim" data-act="close"></div><aside class="sheet" role="dialog" aria-modal="true" aria-labelledby="sheet-title"></aside>`;
  $("#view").inert = true;
  $(".top").inert = true;
  renderSheet();
  requestAnimationFrame(() => host.classList.add("open"));
  $(".sheet [data-act=close]")?.focus({ preventScroll: true });
}
function closeSheet(instant) {
  const host = $("#sheet-root");
  if (!host || !S.panel) return;
  S.panel = null;
  S.confirm = null;
  host.classList.remove("open");
  $("#view").inert = false;
  $(".top").inert = false;
  setTimeout(() => !S.panel && (host.innerHTML = ""), instant || reduced ? 0 : 220);
  if (!instant) lastFocus?.focus?.({ preventScroll: true });
}

function renderSheet() {
  const el = $(".sheet");
  if (!el || !S.panel) return;
  const c = connector(S.panel);
  if (!c) return closeSheet();
  const focusKey = document.activeElement?.closest?.(".sheet") && document.activeElement.dataset.k;
  const n = c.accounts.length;
  const anyTesting = c.accounts.some((a) => S.testing[a.id]);
  el.innerHTML = `
    <header class="sheet-head">
      <button class="btn ghost back" data-act="close" data-k="close">${icon("back", 16)}Back</button>
      ${logo(c.slug, c.logo_url, 44, c.name)}
      <div class="sheet-id"><h2 id="sheet-title">${esc(c.name)}</h2><p>${n ? `${n} ${n === 1 ? "account" : "accounts"}` : "No accounts connected"}</p></div>
      <button class="btn icon ghost x" data-act="close" aria-label="Close" data-k="x">${icon("x", 16)}</button>
    </header>
    <div class="sheet-actions">
      <button class="btn primary" data-act="connect" data-slug="${c.slug}" data-k="add" ${S.busy[c.slug] ? "disabled" : ""}>${S.busy[c.slug] ? `${spinner()}Opening ${esc(c.name)}` : `${icon("plus", 15)}Add another account`}</button>
      ${n ? `<button class="btn" data-act="test-all" data-k="test-all" ${anyTesting ? "disabled" : ""}>${anyTesting ? `${spinner()}Testing` : "Test all"}</button>` : ""}
    </div>
    ${
      n
        ? `<ul class="accts">${c.accounts.map((a) => acctRow(c, a)).join("")}</ul>`
        : `<div class="sheet-ghost">${ghost(
            `No ${esc(c.name)} accounts yet.`,
            "Add one and it sits here like this, with a Test button that shows it working.",
            `<ul class="accts">${acctRow(c, { id: "ghost", label: S.me.email, status: "active", connected_at: new Date().toISOString() })}</ul>`,
          )}</div>`
    }`;
  if (focusKey) $(`[data-k="${CSS.escape(focusKey)}"]`, el)?.focus({ preventScroll: true });
}

function acctRow(c, a) {
  const t = S.tests[a.id];
  const testing = S.testing[a.id];
  const sub =
    a.status === "error"
      ? '<span class="warn">Needs reconnecting</span>'
      : a.status === "pending"
        ? `${spinner(10)}Connecting`
        : `Connected ${day(a.connected_at)}`;
  const actions =
    S.confirm === a.id
      ? `<span class="ask">Remove this account?</span><button class="btn sm ghost" data-act="cancel" data-k="cancel:${a.id}">Cancel</button><button class="btn sm danger" data-act="remove-yes" data-id="${a.id}" data-k="yes:${a.id}">Remove</button>`
      : `${
          a.status === "error"
            ? `<button class="btn sm" data-act="connect" data-slug="${c.slug}" data-k="re:${a.id}">Reconnect</button>`
            : `<button class="btn sm ghost" data-act="test" data-id="${a.id}" data-k="test:${a.id}" ${testing || a.status === "pending" ? "disabled" : ""}>${testing ? `${spinner(12)}Testing` : "Test"}</button>`
        }<button class="btn icon ghost" data-act="remove" data-id="${a.id}" data-k="rm:${a.id}" aria-label="Remove ${esc(a.label)}">${icon("trash", 15)}</button>`;
  return `<li class="acct${S.confirm === a.id ? " confirming" : ""}">
    <span class="dot ${a.status}"></span>
    <div class="acct-id"><div class="acct-label">${esc(a.label)}</div><div class="acct-sub">${sub}</div></div>
    <div class="acct-act">${actions}</div>
    ${t ? `<div class="result ${t.ok ? "ok" : "bad"}">${icon(t.ok ? (c.slug === "gmail" ? "mail" : "check") : "alert", 14)}<span>${esc(t.summary)}</span></div>` : ""}
  </li>`;
}

async function runTest(slug, ids) {
  const c = connector(slug);
  ids.forEach((id) => (S.testing[id] = true));
  renderSheet();
  try {
    const { results } = await api("POST", "/api/test", { slug });
    for (const id of ids) {
      const a = c.accounts.find((x) => x.id === id);
      const r = results.find((x) => x.account === a?.label || x.account === id);
      S.tests[id] = r ? { ok: r.ok, summary: r.summary } : { ok: false, summary: "No answer from this account. Try again." };
    }
  } catch {
    ids.forEach((id) => (S.tests[id] = { ok: false, summary: "The test didn't run. Check your connection and try again." }));
  }
  ids.forEach((id) => delete S.testing[id]);
  renderSheet();
}

async function removeAccount(id) {
  const c = connector(S.panel);
  const idx = c.accounts.findIndex((a) => a.id === id);
  const [gone] = c.accounts.splice(idx, 1);
  S.confirm = null;
  renderSheet();
  renderGrid();
  try {
    await api("DELETE", `/api/accounts/${encodeURIComponent(id)}`);
    toast(`${esc(gone.label)} removed. Agents can't use it any more.`);
  } catch {
    c.accounts.splice(idx, 0, gone);
    renderSheet();
    renderGrid();
    toast(`Couldn't remove ${esc(gone.label)}. Try again.`, "err");
  }
}

// ---------- logins ----------
// Passwords go from this page straight into RalX's encrypted store. Agents only ever get a site name
// and a request id; the values never pass through a chat or a tool call.

const VAULT_MAX_ITEMS = 10000, VAULT_MAX_PAGES = 200;
const vaultOrder = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });
const sortedVault = (items) => items.sort((a, b) => vaultOrder.compare(a.label, b.label) || vaultOrder.compare(a.origin, b.origin) || a.id.localeCompare(b.id));
let vaultGeneration = 0;
const recentVault = new Map();
async function api(method, path, body) {
  const result = await requestAPI(method, path, body);
  const removed = method === "DELETE" && path.match(/^\/api\/vault\/(vi_[a-f0-9]+)$/);
  if (removed) {
    recentVault.delete(removed[1]);
    S.vault = (S.vault || []).filter((item) => item.id !== removed[1]);
    renderVault();
    loadVault();
  }
  return result;
}
async function loadVault() {
  const generation = ++vaultGeneration, items = new Map();
  S.vaultLoading = true;
  S.vaultErr = false;
  try {
    let cursor = "";
    for (let page = 0; ; page++) {
      if (page >= VAULT_MAX_PAGES) throw new Error("Vault page limit");
      const params = new URLSearchParams({ limit: "100" });
      if (cursor) params.set("cursor", cursor);
      const result = await api("GET", `/api/vault?${params}`);
      if (generation !== vaultGeneration) return;
      for (const item of result.items) {
        items.set(item.id, item);
        recentVault.delete(item.id);
      }
      if (items.size > VAULT_MAX_ITEMS) throw new Error("Vault item limit");
      S.vault = sortedVault([...new Map([...recentVault, ...items]).values()]);
      if (!result.next_cursor) {
        recentVault.clear();
        S.vault = sortedVault([...items.values()]);
        break;
      }
      if (typeof result.next_cursor !== "string" || result.next_cursor <= cursor) throw new Error("Invalid vault cursor");
      cursor = result.next_cursor;
      if (route() === "vault") renderVault();
    }
  } catch {
    if (generation !== vaultGeneration) return;
    S.vault = null;
    S.vaultErr = true;
  }
  if (generation !== vaultGeneration) return;
  S.vaultLoading = false;
  await loadRequests();
  if (route() === "vault") renderVault();
}
async function loadRequests() {
  try {
    S.requests = (await api("GET", "/api/vault/requests")).requests || [];
  } catch {}
  updateNav();
  if (route() === "vault") renderRequests();
  openRequestFromHash();
}

function viewVault() {
  $("#view").innerHTML = `
  <div class="page">
    <div class="page-head page-head-row">
      <div>
        <h1>Logins</h1>
        <p class="lede">Your passwords live here, encrypted. Agents sign in with them and never see them.</p>
      </div>
      <div class="head-act">
        <button class="btn" data-act="import" data-k="import">${icon("upload", 15)}Import</button>
        <button class="btn primary" data-act="add-login" data-k="add-login">${icon("plus", 15)}Add login</button>
      </div>
    </div>
    <div id="vault-req"></div>
    <label class="search vault-search">
      ${icon("search", 17)}
      <input id="vq" type="search" placeholder="Search logins" autocomplete="off" spellcheck="false" value="${esc(S.vq)}" aria-label="Search logins">
    </label>
    <div id="vault-list"></div>
  </div>`;
  renderRequests();
  renderVault();
  openRequestFromHash();
}

function renderRequests() {
  const el = $("#vault-req");
  if (!el) return;
  if (!S.requests.length) return (el.innerHTML = "");
  el.innerHTML = `<ul class="rows req">${S.requests.map(reqRow).join("")}</ul>`;
}
function reqRow(r) {
  const who = r.agent ? esc(r.agent) : "An agent";
  return `<li class="row req-row">
    ${siteLogo(r.origin, 36)}
    <div class="row-id">
      <div class="row-title">${who} needs your ${esc(siteHost(r.origin))} login</div>
      <div class="row-sub"><span>Enter it here once. ${r.agent ? esc(r.agent) : "The agent"} signs in without seeing it.</span></div>
    </div>
    <div class="row-act">
      <button class="btn sm ghost" data-act="deny-request" data-id="${esc(r.id)}" data-k="rq-deny:${esc(r.id)}">Deny</button>
      <button class="btn sm primary" data-act="fill-request" data-id="${esc(r.id)}" data-k="rq-fill:${esc(r.id)}">Add login</button>
    </div>
  </li>`;
}

const vaultMatches = (item) => !S.vq || [item.label, item.origin, item.username_hint].some((value) => String(value || "").toLocaleLowerCase().includes(S.vq.toLocaleLowerCase()));
function renderVault() {
  const el = $("#vault-list");
  if (!el) return;
  const list = (S.vault || []).filter(vaultMatches);
  if ((S.vault === null || (S.vaultLoading && !list.length)) && !S.vaultErr) {
    el.innerHTML = `<ul class="rows">${'<li class="row skel"><span></span><i></i></li>'.repeat(4)}</ul>`;
    return;
  }
  if (S.vaultErr && !S.vault) {
    el.innerHTML = `<div class="inline-err">${icon("alert", 15)}<span>Your logins didn't load.</span><button class="btn sm" data-act="retry-vault">Try again</button></div>`;
    return;
  }
  if (!S.vault.length && !S.vq) {
    const sample = [
      ["https://github.com", "GitHub", "h***"],
      ["https://vercel.com", "Vercel", "h***"],
      ["https://supabase.com", "Supabase", "h***"],
      ["https://www.linkedin.com", "LinkedIn", "h***"],
    ].map(([origin, label, hint], k) => ({ id: `g${k}`, origin, label, kind: "login", username_hint: hint, created_at: new Date().toISOString() }));
    el.innerHTML = ghost(
      "No logins yet.",
      "Bring them over from Chrome or 1Password in one go, or add one. They show up here and every agent can sign in with them.",
      `<ul class="rows">${sample.map(vaultRow).join("")}</ul>`,
      `<div class="ghost-acts"><button class="btn" data-act="import">${icon("upload", 15)}Import from Chrome or 1Password</button><button class="btn primary" data-act="add-login">${icon("plus", 15)}Add login</button></div>`,
    );
    return;
  }
  const logins = list.filter((x) => x.kind === "login");
  const priv = list.filter((x) => x.kind !== "login");
  if (!list.length) {
    el.innerHTML = `<div class="vault-nohit">Nothing called “${esc(S.vq)}”. <button class="link" data-act="add-login">Add it</button></div>`;
    return;
  }
  el.innerHTML = `
    ${logins.length ? `<h2 class="sec-title list-title">${logins.length} ${logins.length === 1 ? "login" : "logins"}</h2><ul class="rows">${logins.map(vaultRow).join("")}</ul>` : ""}
    ${priv.length ? `<h2 class="sec-title list-title">Private notes and other items</h2><ul class="rows">${priv.map(vaultRow).join("")}</ul>` : ""}`;
}
function vaultRow(x) {
  const host = siteHost(x.origin);
  const sub = x.kind === "login" ? [host, x.username_hint].filter(Boolean).map(esc).join(", ") : "Kept encrypted. Agents can't open it.";
  return `<li class="row">
    ${siteLogo(x.origin, 36, x.kind)}
    <div class="row-id"><div class="row-title">${esc(x.label)}</div><div class="row-sub"><span>${sub}</span></div></div>
    <div class="row-when">${x.kind === "login" ? `${icon("lock", 13)}` : ""}Added ${day(x.created_at)}</div>
  </li>`;
}

// ---------- modal (add login, import) ----------

let modalFocus = null;
function openModal(kind, data = {}) {
  closeSheet(true);
  S.modal = { kind, busy: false, show: false, err: "", file: null, result: null, ...data };
  modalFocus = document.activeElement;
  const host = $("#sheet-root");
  host.innerHTML = `<div class="scrim" data-act="close-modal"></div><div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"></div>`;
  $("#view").inert = true;
  $(".top").inert = true;
  renderModal();
  requestAnimationFrame(() => host.classList.add("open"));
  requestAnimationFrame(() => $(".modal [autofocus]")?.focus({ preventScroll: true }));
}
function closeModal(instant) {
  const host = $("#sheet-root");
  if (!host || !S.modal) return;
  const req = S.modal.request;
  S.modal = null;
  host.classList.remove("open");
  $("#view").inert = false;
  $(".top").inert = false;
  setTimeout(() => !S.modal && !S.panel && (host.innerHTML = ""), instant || reduced ? 0 : 200);
  if (req && location.hash.includes("request=")) history.replaceState(null, "", location.pathname + location.search + "#/vault");
  if (!instant) modalFocus?.focus?.({ preventScroll: true });
}
function openRequestFromHash() {
  const id = new URLSearchParams(location.hash.split("?")[1] || "").get("request");
  if (!id || S.modal || route() !== "vault") return;
  const r = S.requests.find((x) => x.id === id);
  if (r) openModal("login", { request: r });
}

function renderModal() {
  const el = $(".modal");
  if (!el || !S.modal) return;
  el.innerHTML = S.modal.kind === "import" ? importBody() : loginBody();
}
function loginBody() {
  const m = S.modal;
  const r = m.request;
  const who = r?.agent ? esc(r.agent) : "Your agent";
  return `
  <form class="modal-in" id="login-form" novalidate autocomplete="off">
    <header class="modal-head">
      ${r ? siteLogo(r.origin, 44) : `<span class="logo logo-dim" style="--s:44px">${icon("lock", 20)}</span>`}
      <div class="modal-id">
        <h2 id="modal-title">${r ? `${who} needs your ${esc(siteHost(r.origin))} login` : "Add a login"}</h2>
        <p>${r ? `Type it here, not in the chat. ${who} signs in with it and never sees it.` : "Agents sign in with it. They never see the password."}</p>
      </div>
      <button type="button" class="btn icon ghost x" data-act="close-modal" aria-label="Close">${icon("x", 16)}</button>
    </header>
    <div class="fields">
      <label class="field"><span>Website</span>
        <input name="url" type="url" inputmode="url" placeholder="https://github.com" value="${esc(r?.origin || "")}" ${r ? "readonly" : "autofocus"} required></label>
      <label class="field"><span>Name</span>
        <input name="label" type="text" placeholder="${esc(r ? siteHost(r.origin) : "GitHub")}" value="${esc(r?.label && r.label !== r.origin ? r.label : "")}" maxlength="200"></label>
      <label class="field"><span>Username or email</span>
        <input name="username" type="text" autocomplete="off" spellcheck="false" ${r ? "autofocus" : ""}></label>
      <label class="field"><span>Password</span>
        <span class="pw"><input name="password" type="password" autocomplete="new-password" spellcheck="false" required>
        <button type="button" class="btn icon ghost" data-act="toggle-pw" aria-label="Show password">${icon("eye", 16)}</button></span></label>
      <label class="field"><span>2FA setup key <em>optional</em></span>
        <input name="totp" type="password" autocomplete="off" spellcheck="false" placeholder="The code under the QR, so agents can pass 2FA"></label>
    </div>
    <div class="form-err" id="form-err" role="alert" hidden></div>
    <footer class="modal-foot">
      <span class="foot-note">${icon("lock", 13)}Encrypted before it's stored</span>
      <button type="button" class="btn ghost" data-act="close-modal">Cancel</button>
      <button type="submit" class="btn primary" id="login-submit">Save login</button>
    </footer>
  </form>`;
}
// The login form is never re-rendered after it opens, so a typo or a failed save keeps what was typed.
function formErr(msg) {
  const el = $("#form-err");
  if (!el) return;
  el.hidden = !msg;
  el.innerHTML = msg ? `${icon("alert", 14)}<span>${esc(msg)}</span>` : "";
}
function formBusy(on) {
  const b = $("#login-submit");
  if (!b) return;
  b.disabled = on;
  b.innerHTML = on ? `${spinner()}Saving` : "Save login";
}
function importBody() {
  const m = S.modal;
  if (m.result) {
    const n = m.result;
    return `
    <div class="modal-in">
      <header class="modal-head">
        <span class="logo ok-mark" style="--s:44px">${icon("check", 20)}</span>
        <div class="modal-id"><h2 id="modal-title">${n.logins} ${n.logins === 1 ? "login" : "logins"} moved into RalX</h2>
        <p>Every agent you connect can sign in with them now.${n.private_items ? ` ${n.private_items} other ${n.private_items === 1 ? "item stays" : "items stay"} private.` : ""}</p></div>
        <button type="button" class="btn icon ghost x" data-act="close-modal" aria-label="Close">${icon("x", 16)}</button>
      </header>
      <div class="callout">${icon("trash", 15)}<span>Delete the export file from your Downloads now. It holds every password in plain text.</span></div>
      <footer class="modal-foot"><span></span><button class="btn primary" data-act="close-modal" autofocus>Done</button></footer>
    </div>`;
  }
  const f = m.file;
  return `
  <div class="modal-in">
    <header class="modal-head">
      <span class="logo logo-dim" style="--s:44px">${icon("upload", 20)}</span>
      <div class="modal-id"><h2 id="modal-title">Bring your passwords over</h2>
      <p>From Chrome or 1Password, in one go. The file goes straight into RalX's encrypted store.</p></div>
      <button type="button" class="btn icon ghost x" data-act="close-modal" aria-label="Close">${icon("x", 16)}</button>
    </header>
    <div class="sources">
      <div class="source">${logo("googlechrome", "https://cdn.simpleicons.org/googlechrome", 32, "Chrome")}<div><b>Chrome</b><span>Settings, Passwords, Export passwords. You get a .csv file.</span></div></div>
      <div class="source">${logo("1password", "https://cdn.simpleicons.org/1password", 32, "1Password")}<div><b>1Password</b><span>File, Export, choose 1PUX (keeps 2FA codes) or CSV.</span></div></div>
    </div>
    <label class="drop${f ? " has" : ""}" data-drop>
      <input type="file" id="import-file" accept=".csv,.1pux,text/csv" hidden>
      ${f ? `${icon("check", 18)}<span><b>${esc(f.name)}</b> ${esc(f.label)}</span><span class="drop-swap">Choose another</span>` : `${icon("upload", 18)}<span><b>Drop the export here</b> or click to choose it</span>`}
    </label>
    ${m.err ? `<div class="form-err" role="alert">${icon("alert", 14)}<span>${esc(m.err)}</span></div>` : ""}
    <footer class="modal-foot">
      <span class="foot-note">${icon("lock", 13)}Up to 8 MB, encrypted before it's stored</span>
      <button type="button" class="btn ghost" data-act="close-modal">Cancel</button>
      <button type="button" class="btn primary" data-act="run-import" ${!f || m.busy ? "disabled" : ""} autofocus>${m.busy ? `${spinner()}Importing` : "Import"}</button>
    </footer>
  </div>`;
}

// Format comes from the file itself, read here in your browser: .1pux, or the CSV header.
async function pickImport(file) {
  const m = S.modal;
  if (!m || !file) return;
  m.err = "";
  if (file.size > 8 * 1024 * 1024) {
    m.file = null;
    m.err = "That file is over 8 MB. Export one vault at a time.";
    return renderModal();
  }
  let format = "";
  if (/\.1pux$/i.test(file.name)) format = "1password-1pux";
  else {
    const head = (await file.slice(0, 2048).text()).replace(/^﻿/, "").split(/\r?\n/)[0].toLowerCase();
    const cols = head.split(",").map((s) => s.replace(/"/g, "").trim());
    if (cols.includes("website") || cols.includes("title")) format = "1password-csv";
    else if (cols.includes("url") && cols.includes("password")) format = "chrome-csv";
  }
  if (!format) {
    m.file = null;
    m.err = "That doesn't look like a Chrome or 1Password export. Export again and choose that file.";
    return renderModal();
  }
  m.file = { blob: file, name: file.name, format, label: { "chrome-csv": "from Chrome", "1password-csv": "from 1Password", "1password-1pux": "from 1Password, with 2FA codes" }[format] };
  renderModal();
}
async function runImport() {
  const m = S.modal;
  if (!m?.file || m.busy) return;
  m.busy = true;
  m.err = "";
  renderModal();
  try {
    const bytes = new Uint8Array(await m.file.blob.arrayBuffer());
    m.result = await apiBytes(`/api/vault/import?format=${encodeURIComponent(m.file.format)}`, bytes);
    m.file = null;
    loadVault();
  } catch (e) {
    m.err = e.status === 413 ? e.message : e.status === 0 ? "RalX can't be reached. Nothing was imported." : e.message || "That import didn't work. No passwords were changed.";
  }
  m.busy = false;
  renderModal();
}
async function saveLoginForm(form) {
  const m = S.modal;
  if (!m || m.busy) return;
  const f = Object.fromEntries(new FormData(form));
  let url = String(f.url || "").trim();
  if (url && !/^https?:\/\//i.test(url)) url = "https://" + url;
  let host = "";
  try {
    const u = new URL(url);
    host = u.protocol === "https:" ? u.hostname : "";
  } catch {}
  const bad = !host ? "Enter the website, starting with https://" : !f.password ? "Enter the password." : "";
  formErr(bad);
  if (bad) return $(`.modal [name="${host ? "password" : "url"}"]`)?.focus();
  m.busy = true;
  formBusy(true);
  const req = m.request;
  try {
    const label = String(f.label || "").trim() || host.replace(/^www\./, "");
    const saved = await api("POST", "/api/vault/login", { url, label, username: String(f.username || ""), password: String(f.password), totp: String(f.totp || ""), ...(req ? { request_id: req.id } : {}) });
    const item = { id: saved.id, label, origin: new URL(url).origin, kind: "login", username_hint: f.username ? String(f.username).slice(0, 1) + "***" : "", created_at: new Date().toISOString() };
    recentVault.set(item.id, item);
    S.vq = "";
    if ($("#vq")) $("#vq").value = "";
    S.vault = sortedVault([item, ...(S.vault || []).filter((x) => x.id !== item.id)]);
    S.vaultErr = false;
    renderVault();
    form.reset();
    closeModal();
    toast(req ? `Saved. ${esc(req.agent || "Your agent")} can sign in to ${esc(host.replace(/^www\./, ""))} now.` : `${esc(host.replace(/^www\./, ""))} saved.`);
    loadVault();
  } catch (e) {
    m.busy = false;
    formBusy(false);
    formErr(e.status === 409 ? "This request expired. Ask your agent to try again." : e.status === 0 ? "RalX can't be reached. Nothing was saved." : e.message || "That didn't save. Try again.");
  }
}

// ---------- agents ----------

let agentPoll, tick;
function viewAgents() {
  $("#view").innerHTML = `
  <div class="page">
    <div class="page-head">
      <h1>Agents</h1>
      <p class="lede">Paste one line into any agent. It can use every account you connected, and never sees a password.</p>
    </div>
    <div class="agents-cols">
      <section class="card connect" id="connect-card" aria-live="polite"></section>
      <section class="agent-list">
        <h2 class="sec-title">Your agents</h2>
        <div id="agent-rows"></div>
      </section>
    </div>
  </div>`;
  if (S.joined) S.joined = null;
  renderConnectCard();
  renderAgentRows();
  ensurePrompt();
  agentPoll = setInterval(() => !document.hidden && loadAgents(), 2000);
  tick = setInterval(updateExpiry, 1000);
}
function stopAgentPoll() {
  clearInterval(agentPoll);
  clearInterval(tick);
}

async function ensurePrompt(force) {
  if (!force && S.prompt && new Date(S.prompt.expires_at) > Date.now()) return;
  S.prompt = null;
  S.promptErr = false;
  S.copied = false;
  S.waiting = false;
  renderConnectCard();
  try {
    S.prompt = await api("POST", "/api/agents/prompt", {});
    // Agents that exist before this prompt can't be the one it enrolls. If the list hasn't loaded yet, take it on first load.
    S.baseline = S.agents ? new Set(S.agents.map((a) => a.id)) : "pending";
  } catch {
    S.promptErr = true;
  }
  renderConnectCard();
}

function checkJoined() {
  if (!S.baseline || !S.agents || S.joined) return;
  if (S.baseline === "pending") return void (S.baseline = new Set(S.agents.map((a) => a.id)));
  const fresh = S.agents.find((a) => !S.baseline.has(a.id));
  if (!fresh) return;
  S.joined = fresh;
  S.prompt = null;
  S.baseline = null;
  S.waiting = false;
  S.flash = fresh.id;
  setTimeout(() => {
    S.flash = null;
    document.querySelector(`.row[data-id="${fresh.id}"]`)?.classList.remove("flash");
  }, 1600);
  renderConnectCard();
}

function expiresText() {
  const left = Math.max(0, new Date(S.prompt.expires_at) - Date.now()) / 1000;
  if (!left) return "Expired";
  return `Works once, expires in ${Math.floor(left / 60)}:${String(Math.floor(left % 60)).padStart(2, "0")}`;
}
function updateExpiry() {
  const el = $("#expires");
  if (!el || !S.prompt) return;
  if (new Date(S.prompt.expires_at) <= Date.now()) return renderConnectCard();
  el.textContent = expiresText();
}

function renderConnectCard() {
  const el = $("#connect-card");
  if (!el) return;
  if (S.joined) {
    const n = accountCount();
    el.innerHTML = `<div class="joined">
      ${agentLogo(S.joined.client, 44)}
      <div><h2>${esc(S.joined.name)} is connected</h2><p class="muted">It can use your ${n} ${n === 1 ? "account" : "accounts"} now. Ask it what's in your inbox.</p></div>
    </div>
    <div class="card-foot"><button class="btn" data-act="new-prompt">Connect another agent</button></div>`;
    return;
  }
  const p = S.prompt;
  const expired = p && new Date(p.expires_at) <= Date.now();
  el.innerHTML = `
    <h2>Connect an agent</h2>
    <p class="muted">Paste this into Claude, Codex, your Grok bot or any agent that can run a command.</p>
    <div class="prompt${p ? "" : " loading"}">
      ${
        S.promptErr
          ? `<div class="prompt-msg">The prompt didn't load.<button class="btn sm" data-act="new-prompt">Try again</button></div>`
          : expired
            ? `<div class="prompt-msg">This prompt expired.<button class="btn sm" data-act="new-prompt">Get a new one</button></div>`
            : p
              ? `<pre id="prompt-text" tabindex="0" aria-label="Setup prompt">${esc(p.prompt)}</pre>`
              : "<i></i><i></i><i></i><i></i>"
      }
    </div>
    <div class="card-foot">
      <button class="btn primary copy${S.copied ? " done" : ""}" data-act="copy" ${p && !expired ? "" : "disabled"}>
        <span class="swap">${S.copied ? icon("check", 15) : icon("copy", 15)}</span>${S.copied ? "Copied" : "Copy prompt"}
      </button>
      <span class="expires" id="expires">${p && !expired ? expiresText() : ""}</span>
    </div>
    <div class="waiting${S.waiting ? " live" : ""}"><span class="pulse"></span><span>${S.waiting ? "Waiting for your agent to connect" : "Once your agent runs it, this page updates by itself."}</span></div>`;
}

async function copyPrompt() {
  const text = S.prompt?.prompt;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const r = document.createRange();
    r.selectNodeContents($("#prompt-text"));
    getSelection().removeAllRanges();
    getSelection().addRange(r);
    document.execCommand("copy");
  }
  S.copied = true;
  S.waiting = true;
  renderConnectCard();
  $(".copy")?.focus();
  enrollSoon();
  clearTimeout(copyPrompt.t);
  copyPrompt.t = setTimeout(() => {
    S.copied = false;
    if (!S.joined) {
      const b = $(".copy");
      if (b) {
        b.classList.remove("done");
        b.innerHTML = `<span class="swap">${icon("copy", 15)}</span>Copy again`;
      }
    }
  }, 1800);
}

function renderAgentRows() {
  const el = $("#agent-rows");
  if (!el) return;
  if (!S.agents) {
    el.innerHTML = `<ul class="rows">${'<li class="row skel"><span></span><i></i></li>'.repeat(3)}</ul>`;
    return;
  }
  if (!S.agents.length) {
    const t = Date.now();
    const sample = [
      ["claude", "Claude", 2],
      ["codex", "Codex", 40],
      ["grok", "Grok bot", 180],
    ].map(([client, name, min], k) => ({ id: `g${k}`, name, client, created_at: new Date(t).toISOString(), last_used_at: new Date(t - min * 60000).toISOString() }));
    el.innerHTML = ghost("No agents yet.", "Paste the prompt into Claude, Codex or your Grok bot and it lands here, like this.", `<ul class="rows">${sample.map(agentRow).join("")}</ul>`);
    return;
  }
  const focusKey = document.activeElement?.closest?.("#agent-rows") && document.activeElement.dataset.k;
  el.innerHTML = `<ul class="rows">${S.agents.map(agentRow).join("")}</ul>`;
  if (focusKey) $(`[data-k="${CSS.escape(focusKey)}"]`, el)?.focus();
}

function agentRow(a) {
  return `<li class="row${S.flash === a.id ? " flash" : ""}${S.confirm === a.id ? " confirming" : ""}" data-id="${a.id}">
    ${agentLogo(a.client, 36)}
    <div class="row-id"><div class="row-title">${esc(a.name)}</div><div class="row-sub">${esc(clientName(a.client))}, added ${day(a.created_at)}</div></div>
    <div class="row-when">${a.last_used_at ? `Used ${ago(a.last_used_at)}` : "Not used yet"}</div>
    <div class="row-act">${
      S.confirm === a.id
        ? `<span class="ask">Revoke? It stops working at once.</span><button class="btn sm ghost" data-act="cancel" data-k="cancel:${a.id}">Cancel</button><button class="btn sm danger" data-act="revoke-yes" data-id="${a.id}" data-k="yes:${a.id}">Revoke</button>`
        : `<button class="btn sm ghost" data-act="revoke" data-id="${a.id}" data-k="rv:${a.id}">Revoke</button>`
    }</div>
  </li>`;
}

async function revoke(id) {
  const idx = S.agents.findIndex((a) => a.id === id);
  const [gone] = S.agents.splice(idx, 1);
  S.confirm = null;
  renderAgentRows();
  try {
    await api("DELETE", `/api/agents/${encodeURIComponent(id)}`);
    toast(`${esc(gone.name)} can't use your accounts any more.`);
  } catch {
    S.agents.splice(idx, 0, gone);
    renderAgentRows();
    toast(`Couldn't revoke ${esc(gone.name)}. Try again.`, "err");
  }
}

// ---------- approvals ----------

function viewApprovals() {
  $("#view").innerHTML = `
  <div class="page">
    <div class="page-head">
      <h1>Approvals</h1>
      <p class="lede">Your agents ask here before they send, post, delete, pay or deploy.</p>
    </div>
    <div id="appr"></div>
  </div>`;
  renderApprovals();
}

function renderApprovals() {
  const el = $("#appr");
  if (!el) return;
  if (!S.approvals) {
    el.innerHTML = `<ul class="rows">${'<li class="row skel"><span></span><i></i></li>'.repeat(3)}</ul>`;
    return;
  }
  const list = S.approvals;
  if (!list.length) {
    const t = Date.now();
    const sample = [
      ["Claude", "claude", "gmail.send_email", `Send “Proposal v2 attached” to a client from ${S.me.email}`, 1],
      ["Codex", "codex", "github.merge_pull_request", "Merge pull request #12 into main", 14],
      ["Grok bot", "grok", "slack.post_message", "Post the weekly update in #team", 40],
    ].map(([agent, client, tool, summary, min], k) => ({ id: `g${k}`, agent, client, tool, summary, created_at: new Date(t - min * 60000).toISOString() }));
    el.innerHTML = ghost("Nothing waiting on you.", "When an agent wants to send, post or delete something, it asks here first, like this. One tap and it goes.", `<ul class="rows appr">${sample.map(apprRow).join("")}</ul>`);
    return;
  }
  const focusKey = document.activeElement?.closest?.("#appr") && document.activeElement.dataset.k;
  el.innerHTML = `<ul class="rows appr">${list.map(apprRow).join("")}</ul>`;
  if (focusKey) $(`[data-k="${CSS.escape(focusKey)}"]`, el)?.focus();
}

function apprRow(a) {
  const st = S.resolved[a.id];
  const app = toolApp(a.tool);
  return `<li class="row${st ? ` done ${st}` : ""}" data-id="${a.id}">
    ${agentLogo(a.client || clientOf(a.agent), 36)}
    <div class="row-id">
      <div class="row-title">${esc(a.summary)}</div>
      <div class="row-sub"><span>${esc(a.agent)}</span><span class="tool">${logo(app, null, 16, "")}<code>${esc(a.tool)}</code></span><span>${ago(a.created_at).replace(/^./, (x) => x.toUpperCase())}</span></div>
      ${a.args ? `<div class="approval-review"><div>Account: ${esc(a.account)}</div><pre aria-label="Exact action arguments">${esc(JSON.stringify(a.args, null, 2))}</pre></div>` : ""}
    </div>
    <div class="row-act">${
      st === "approved"
        ? `<span class="outcome ok">${icon("check", 15)}Approved</span>`
        : st === "denied"
          ? `<span class="outcome">Denied</span>`
          : `<button class="btn sm ghost" data-act="deny" data-id="${a.id}" data-k="deny:${a.id}">Deny</button><button class="btn sm primary" data-act="approve" data-id="${a.id}" data-k="ok:${a.id}">Approve</button>`
    }</div>
  </li>`;
}

async function decide(id, verb) {
  const approval = S.approvals?.find((a) => a.id === id);
  if (!approval || S.resolved[id]) return;
  if (verb === "approve" && !approval.args_hash) {
    toast("Refresh and review this action again before approving.", "err");
    await loadApprovals();
    return;
  }
  S.resolved[id] = verb === "approve" ? "approved" : "denied";
  renderApprovals();
  updateNav();
  try {
    const result = await api("POST", `/api/approvals/${encodeURIComponent(id)}/${verb}`, verb === "approve" ? { args_hash: approval.args_hash } : {});
    if (result.result?.ok === false) throw new Error("The provider could not complete this action.");
  } catch (error) {
    delete S.resolved[id];
    renderApprovals();
    updateNav();
    toast(esc(error.message || "That didn't go through. Try again."), "err");
    await loadApprovals();
  }
}

// ---------- activity ----------

function viewActivity() {
  $("#view").innerHTML = `
  <div class="page">
    <div class="page-head">
      <h1>Activity</h1>
      <p class="lede">Everything your agents did with your accounts, newest first.</p>
    </div>
    <div id="act"></div>
  </div>`;
  renderActivity();
  loadActivity();
}

const OUT = { ok: ["Done", "ok"], held: ["Waiting for you", "warn"], denied: ["Denied", "quiet"], error: ["Failed", "bad"], approved: ["Approved", "ok"] };
const human = (tool) => {
  const [, act = tool] = String(tool).split(".");
  const s = act.replace(/_/g, " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
};
function dayLabel(iso) {
  const d = new Date(iso);
  const t = new Date();
  const y = new Date(Date.now() - 86400000);
  if (d.toDateString() === t.toDateString()) return "Today";
  if (d.toDateString() === y.toDateString()) return "Yesterday";
  return d.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long" });
}

function renderActivity() {
  const el = $("#act");
  if (!el) return;
  const t = Date.now();
  const sample = [
    [1, "Claude", "gmail.list_messages", S.me.email, "ok"],
    [3, "Claude", "googlecalendar.list_events", S.me.email, "ok"],
    [9, "Codex", "github.list_pull_requests", "your-github", "ok"],
    [12, "Claude", "gmail.send_email", S.me.email, "held"],
  ].map(([m, agent, tool, account, outcome]) => ({ at: new Date(t - m * 60000).toISOString(), agent, tool, account, outcome }));
  const preview = `<ul class="events">${sample.map(evtRow).join("")}</ul>`;
  if (S.activity === "error") {
    el.innerHTML = ghost("Activity didn't load.", "RalX couldn't fetch the log just now.", preview, `<button class="btn" data-act="retry-activity">${icon("refresh", 15)}Try again</button>`);
    return;
  }
  if (!S.activity) {
    el.innerHTML = `<ul class="rows">${'<li class="row skel"><span></span><i></i></li>'.repeat(5)}</ul>`;
    return;
  }
  if (!S.activity.length) {
    el.innerHTML = ghost("No activity yet.", "Every time an agent reads, drafts or sends with one of your accounts, it shows up here, like this.", preview);
    return;
  }
  const groups = [];
  for (const e of S.activity) {
    const k = dayLabel(e.at);
    if (groups.at(-1)?.k !== k) groups.push({ k, items: [] });
    groups.at(-1).items.push(e);
  }
  el.innerHTML = groups
    .map(
      (g) => `<section class="act-group"><h2 class="sec-title">${g.k}</h2><ul class="events">${g.items.map(evtRow).join("")}</ul></section>`,
    )
    .join("");
}

function evtRow(e) {
  const [word, tone] = OUT[e.outcome] || [e.outcome, "quiet"];
  const app = toolApp(e.tool);
  return `<li class="evt">
    <time datetime="${esc(e.at)}">${clock(e.at)}</time>
    <span class="evt-what">${logo(app, connector(app)?.logo_url, 24, connector(app)?.name || app)}<span class="evt-text"><b>${esc(human(e.tool))}</b>${e.account ? `<span class="evt-acct">${esc(e.account)}</span>` : ""}</span></span>
    <span class="evt-agent">${esc(e.agent)}</span>
    <span class="evt-out ${tone}">${esc(word)}</span>
  </li>`;
}

// ---------- signed out ----------

function renderSignedOut() {
  document.title = "RalX";
  document.body.classList.add("out-body");
  root.innerHTML = `
  <header class="top">
    <div class="top-in">
      <a class="wordmark" href="/" aria-label="RalX">RalX</a>
      <span class="tabs"></span>
      <div class="top-cta"><a class="btn ghost sm" href="/login">Log in</a><a class="btn primary sm" href="/login">Sign up</a></div>
    </div>
  </header>
  <div class="out">
    <section class="out-left">
      <div class="out-copy">
        <h1>Connect your accounts once. <span>Every AI agent can use them.</span></h1>
        <p>Gmail, GitHub, Notion, Slack and the rest. Paste one line into Claude, Codex or your own bot and it gets to work without ever seeing a password.</p>
        <a class="btn primary lg" href="/login">Sign up or log in</a>
        <p class="fine">Anything that sends, posts or deletes waits for your yes.</p>
      </div>
    </section>
    <section class="out-right" aria-label="Example: Claude reads your inbox through RalX">
      <div class="thread" data-step="${reduced ? 9 : 0}">
        <div class="thread-head">${logo("claude", null, 26, "Claude")}<span>Claude</span></div>
        <div class="thread-body">
          <div class="msg me s1">what's in my inbox?</div>
          <div class="tool s2">${logo("gmail", null, 22, "Gmail")}<span class="tool-name">Reading Gmail</span><span class="tool-acc">8 accounts</span><span class="tool-state">${spinner(12)}${icon("check", 14)}</span></div>
          <div class="msg ai">
            <p class="s4">Three things need you today.</p>
            <ul class="mail">
              <li class="s5"><b>Alex Example</b> sent the signed Example Company proposal.<span>owner@example.invalid</span></li>
              <li class="s6"><b>Stripe</b> paid out AED 4,210.<span>billing@example.invalid</span></li>
              <li class="s7"><b>GitHub</b> wants your review on ralx #41.<span>builds@example.invalid</span></li>
            </ul>
            <p class="s8">Want me to draft the reply to Alex?</p>
          </div>
        </div>
        <div class="thread-input"><span>Reply to Claude</span><span class="send">${icon("right", 14)}</span></div>
      </div>
    </section>
  </div>`;
  if (reduced) return;
  const th = $(".thread");
  [[1, 400], [2, 1000], [3, 2300], [4, 2600], [5, 2850], [6, 3050], [7, 3250], [8, 3550]].forEach(([n, t]) => setTimeout(() => (th.dataset.step = n), t));
}

// ---------- events ----------

root.addEventListener("click", (e) => {
  const b = e.target.closest("[data-act]");
  const menu = $("#menu");
  if (menu && !menu.hidden && !e.target.closest(".me")) toggleMenu(false);
  if (e.target.closest("#me-btn")) return toggleMenu(menu.hidden);
  if (!b) {
    const t = e.target.closest(".tile.on");
    if (t && !e.target.closest("button,a")) openSheet(t.dataset.slug);
    return;
  }
  const { act, slug, id, cat } = b.dataset;
  const acts = {
    reload: () => location.reload(),
    cat: () => setCat(cat),
    clear: clearSearch,
    retry: () => {
      S.connErr = false;
      S.connectors = null;
      renderGrid();
      loadConnectors();
    },
    "retry-activity": () => {
      S.activity = null;
      renderActivity();
      loadActivity();
    },
    connect: () => connect(slug),
    manage: () => openSheet(slug),
    close: () => closeSheet(),
    test: () => runTest(S.panel, [id]),
    "test-all": () => runTest(S.panel, connector(S.panel).accounts.filter((a) => a.status === "active").map((a) => a.id)),
    remove: () => {
      S.confirm = id;
      renderSheet();
      $(`.sheet [data-k="yes:${id}"]`)?.focus();
    },
    "remove-yes": () => removeAccount(id),
    cancel: () => {
      const was = S.confirm;
      S.confirm = null;
      S.panel ? renderSheet() : renderAgentRows();
      $(`[data-k="rm:${was}"],[data-k="rv:${was}"]`)?.focus();
    },
    copy: copyPrompt,
    "new-prompt": () => {
      S.joined = null;
      ensurePrompt(true);
    },
    revoke: () => {
      S.confirm = id;
      renderAgentRows();
      $(`[data-k="yes:${id}"]`)?.focus();
    },
    "revoke-yes": () => revoke(id),
    approve: () => decide(id, "approve"),
    deny: () => decide(id, "deny"),
    "add-login": () => openModal("login"),
    import: () => openModal("import"),
    "close-modal": () => closeModal(),
    "run-import": runImport,
    "toggle-pw": () => {
      const input = $('.modal [name="password"]');
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      b.setAttribute("aria-label", show ? "Hide password" : "Show password");
      b.innerHTML = icon(show ? "eyeoff" : "eye", 16);
      input.focus();
    },
    "fill-request": () => {
      const r = S.requests.find((x) => x.id === id);
      if (r) openModal("login", { request: r });
    },
    "deny-request": async () => {
      const r = S.requests.find((x) => x.id === id);
      S.requests = S.requests.filter((x) => x.id !== id);
      renderRequests();
      updateNav();
      try {
        await api("POST", `/api/vault/requests/${encodeURIComponent(id)}/deny`, {});
        toast(`Denied. ${esc(r?.agent || "The agent")} won't get that login.`);
      } catch {
        loadRequests();
        toast("That didn't go through. Try again.", "err");
      }
    },
    "retry-vault": () => {
      S.vaultErr = false;
      S.vault = null;
      renderVault();
      loadVault();
    },
    logout: async () => {
      try {
        await api("POST", "/logout", {});
      } catch {}
      location.href = mockMode ? location.pathname + "?mock=1&scene=signedout" : "/";
    },
  };
  acts[act]?.();
});

root.addEventListener("submit", (e) => {
  if (e.target.id !== "login-form") return;
  e.preventDefault();
  saveLoginForm(e.target);
});
root.addEventListener("change", (e) => {
  if (e.target.id === "import-file") pickImport(e.target.files?.[0]);
});
root.addEventListener("input", (e) => {
  if (e.target.id !== "vq") return;
  S.vq = e.target.value;
  renderVault();
});
for (const type of ["dragenter", "dragover"])
  root.addEventListener(type, (e) => {
    const d = e.target.closest?.("[data-drop]");
    if (!d) return;
    e.preventDefault();
    d.classList.add("over");
  });
root.addEventListener("dragleave", (e) => e.target.closest?.("[data-drop]")?.classList.remove("over"));
root.addEventListener("drop", (e) => {
  const d = e.target.closest?.("[data-drop]");
  if (!d) return;
  e.preventDefault();
  d.classList.remove("over");
  pickImport(e.dataTransfer?.files?.[0]);
});

function toggleMenu(open) {
  const menu = $("#menu");
  menu.hidden = !open;
  $("#me-btn").setAttribute("aria-expanded", open);
  if (open) $("#menu button").focus();
}

document.addEventListener("keydown", (e) => {
  const typing = e.target.closest?.("input,textarea,select,[contenteditable]");
  if (((e.key === "k" || e.key === "K") && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing)) {
    if (!S.me) return;
    e.preventDefault();
    if (S.panel) closeSheet(true);
    if (route() !== "") location.hash = "#/";
    requestAnimationFrame(() => $("#q")?.focus());
  } else if (e.key === "Escape") {
    if (S.modal) closeModal();
    else if (S.panel) closeSheet();
    else if ($("#menu") && !$("#menu").hidden) {
      toggleMenu(false);
      $("#me-btn").focus();
    } else if (S.confirm) $('[data-act="cancel"]')?.click();
  }
});

boot();

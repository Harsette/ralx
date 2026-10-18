// RalX admin app. Everything here talks to the local daemon's admin API,
// which only answers a passkey-signed-in browser. No external scripts.
(() => {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const app = $("#app");
  let csrf = "";
  let state = null;
  let connectors = [];
  let stateKey = "";
  let view = (location.hash.match(/^#(agents|activity)$/) || [])[1] || "connectors";
  let pollTimer = null;
  let actFilter = "all";
  const openDetails = new Set();
  const revealed = new Map(); // credential name -> {fields, until}

  // ---------- helpers ----------
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const icon = (n) => `<span class="i i-${n}" aria-hidden="true"></span>`;
  const passkeyName = () => /Windows/i.test(navigator.userAgent) ? "Windows Hello" : /Macintosh|Mac OS X/i.test(navigator.userAgent) && !/iPhone|iPad/i.test(navigator.userAgent) ? "Touch ID" : "passkey";
  const passkeyMethod = () => passkeyName() === "passkey" ? "your passkey" : passkeyName();
  function ago(ts) {
    if (!ts) return "never";
    const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 45) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return new Date(ts * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short" });
  }
  const clock = (ts) => new Date(ts * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });

  function toast(msg, bad) {
    const t = $("#toast");
    t.textContent = msg;
    t.className = "show" + (bad ? " bad" : "");
    clearTimeout(toast.t);
    toast.t = setTimeout(() => (t.className = bad ? "bad" : ""), bad ? 6000 : 3000);
  }

  async function api(method, path, body) {
    const res = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-RalX-CSRF": csrf || "1" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch (_) {}
    if (res.status === 401 && path !== "/admin/api/session") { boot(); throw new Error(data.error || "Signed out"); }
    if (!res.ok) throw new Error(data.error || `RalX returned ${res.status}`);
    return data;
  }

  // ---------- passkeys (WebAuthn) ----------
  const b64u = {
    toBuf(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u.buffer; },
    from(buf) { const u = new Uint8Array(buf); let s = ""; for (const x of u) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); },
  };
  function creationOptions(o) {
    const pk = o.publicKey || o;
    if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(pk);
    return { ...pk, challenge: b64u.toBuf(pk.challenge), user: { ...pk.user, id: b64u.toBuf(pk.user.id) },
      excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64u.toBuf(c.id) })) };
  }
  function requestOptions(o) {
    const pk = o.publicKey || o;
    if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(pk);
    return { ...pk, challenge: b64u.toBuf(pk.challenge), allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64u.toBuf(c.id) })) };
  }
  function credJSON(c) {
    if (c.toJSON) return c.toJSON();
    const r = c.response, out = { id: c.id, rawId: b64u.from(c.rawId), type: c.type, response: { clientDataJSON: b64u.from(r.clientDataJSON) }, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {} };
    if (r.attestationObject) { out.response.attestationObject = b64u.from(r.attestationObject); if (r.getTransports) out.response.transports = r.getTransports(); }
    if (r.authenticatorData) { out.response.authenticatorData = b64u.from(r.authenticatorData); out.response.signature = b64u.from(r.signature); if (r.userHandle) out.response.userHandle = b64u.from(r.userHandle); }
    if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
    return out;
  }
  async function passkeyGet(options) {
    const cred = await navigator.credentials.get({ publicKey: requestOptions(options) });
    if (!cred) throw new Error("No passkey returned");
    return credJSON(cred);
  }
  async function passkeyCreate(options) {
    const cred = await navigator.credentials.create({ publicKey: creationOptions(options) });
    if (!cred) throw new Error("No passkey created");
    return credJSON(cred);
  }
  // stepUp asks for a fresh Windows Hello check bound to exactly this operation.
  async function stepUp(op) {
    const opts = await api("POST", "/admin/api/stepup/begin", { op });
    return passkeyGet(opts);
  }
  function friendly(e) {
    if (e && e.name === "NotAllowedError") return `${passkeyName()} was cancelled`;
    return (e && e.message) || String(e);
  }

  // ---------- gate screens ----------
  function gate(title, body, actionHTML, fine, setup = false) {
    app.innerHTML = `<div class="gate"><div class="gate-inner">
      <div class="medallion"><img src="logos/ralveto-mark.png" alt=""></div>
      <h1>${title}</h1><p>${body}</p>${actionHTML || ""}${fine ? `<div class="fine">${fine}</div>` : ""}
      ${setup ? `<ol class="setup-progress" aria-label="Setup progress"><li class="complete">${icon("check")} Install</li><li aria-current="step">Create your passkey</li><li>Connect your accounts</li></ol>` : ""}
    </div></div>`;
  }

  function renderSetup(token) {
    gate("Set up RalX.<em>Your key stays with you.</em>", `Use ${passkeyMethod()} to approve actions and see your saved credentials.`,
      `<button class="btn gold" id="go">${icon("fingerprint")} Create ${passkeyName() === "passkey" ? "your passkey" : "with " + passkeyName()}</button><div id="setupMessage" class="setup-message" role="status" hidden></div>`,
      "This link works once, on this computer, for 15 minutes.", true);
    $("#go").onclick = async () => {
      const btn = $("#go"); btn.disabled = true;
      try {
        const opts = await api("POST", "/admin/api/setup/begin", { token });
        const cred = await passkeyCreate(opts);
        const name = /Android|iPhone|iPad/i.test(navigator.userAgent) ? "Phone passkey" : passkeyName() === "passkey" ? "Computer passkey" : passkeyName() + " on this computer";
        const r = await api("POST", "/admin/api/setup/finish", { token, name, credential: cred });
        csrf = r.csrf;
        history.replaceState(null, "", location.pathname);
        startApp();
      } catch (e) {
        const message = $("#setupMessage");
        message.hidden = false;
        const expired = /setup link.*(expired|invalid)/i.test(friendly(e));
        message.textContent = expired ? "This setup link expired. Run ralx open for a fresh one." : friendly(e);
        btn.disabled = expired;
      }
    };
  }

  function renderNeedSetup() {
    gate("Set up RalX.<em>Start with your key.</em>", "Run this command on your computer to create a private setup link. Then add your passkey.",
      `<p class="setup-command"><code>ralx open</code></p>`, "Only your computer can create this link.", true);
  }

  function renderLogin() {
    gate("RalX is locked.<em>Your accounts are waiting.</em>", `Unlock with ${passkeyMethod()} to see your connections, approve held actions and manage agents.`,
      `<button class="btn gold" id="go">${icon("fingerprint")} Unlock with ${passkeyMethod()}</button>`);
    const go = async () => {
      const btn = $("#go"); btn.disabled = true;
      try {
        const b = await api("POST", "/admin/api/login/begin");
        const cred = await passkeyGet(b.options);
        const r = await api("POST", "/admin/api/login/finish", { ceremony: b.ceremony, credential: cred });
        csrf = r.csrf;
        startApp();
      } catch (e) { toast(friendly(e), true); btn.disabled = false; }
    };
    $("#go").onclick = go;
  }

  async function boot() {
    clearInterval(pollTimer);
    let s;
    try { s = await api("GET", "/admin/api/session"); } catch (e) { gate("RalX isn't answering", esc(friendly(e)), ""); return; }
    const m = location.hash.match(/#setup=([A-Za-z0-9_-]+)/);
    if (m) return renderSetup(m[1]);
    const d = location.hash.match(/#drop=([A-Za-z0-9_-]+)/);
    if (d) return renderDrop(d[1]);
    if (s.setup_needed) return renderNeedSetup();
    if (!s.authenticated) return renderLogin();
    csrf = s.csrf || csrf;
    const c = location.hash.match(/#connect=([A-Za-z0-9_-]+)/);
    if (c) return renderConsent(c[1]);
    startApp();
  }

  // One-time paste link: the key goes straight into the vault.
  async function renderDrop(token) {
    let info;
    try { info = await api("GET", "/drop/" + encodeURIComponent(token)); }
    catch (e) { gate("This paste link expired", "Ask for a new one.", ""); return; }
    gate(`Paste your ${esc(info.label)} key`, "It goes straight into the RalX vault. Agents will use it without ever seeing it.",
      `<div class="consent"><label for="dVal">Key</label><input id="dVal" type="password" autocomplete="off" spellcheck="false">
        <div class="consent-btns"><button class="btn gold" id="dOk">Save to the vault</button></div></div>`);
    $("#dVal").focus();
    $("#dOk").onclick = async () => {
      const btn = $("#dOk"); btn.disabled = true;
      try {
        const r = await api("POST", "/drop/submit", { token, value: $("#dVal").value });
        history.replaceState(null, "", location.pathname);
        gate("Saved", r && r.note ? esc(r.note) : `${esc(info.label)} is in the vault. You can close this tab.`, "");
      } catch (e) { toast(friendly(e), true); btn.disabled = false; }
    };
  }

  // Consent for a chat agent (ChatGPT, Grok, Muse...) adding RalX as a connector.
  async function renderConsent(id) {
    let info;
    try { info = await api("GET", "/oauth/request/" + encodeURIComponent(id)); }
    catch (e) { gate("This sign-in expired", esc(friendly(e)) + ". Start again from the app you were connecting.", ""); return; }
    const warn = info.verified ? "" : `<p class="unverified">${icon("alert")} RalX can't confirm who this is${info.claimed_name ? ` (it calls itself “${esc(info.claimed_name)}”)` : ""}. Only approve if you just added RalX in an app yourself.</p>`;
    gate(`${esc(info.client_name || "An app")} wants to plug into RalX`,
      `It will act as an agent you can revoke any time. It never sees your keys; anything that deploys, deletes, pays, emails or posts still waits for you. After you approve, you go back to ${esc(info.redirect_host)}.`,
      `${warn}<div class="consent">
        <label for="cAgent">Agent name</label><input id="cAgent" value="${esc(info.suggested_agent)}" autocomplete="off" spellcheck="false">
        <label for="cAccess">Access</label>
        <select id="cAccess"><option value="all">Everything (risky actions still wait for you)</option><option value="read">Read only</option></select>
        <div class="consent-btns"><button class="btn quiet" id="cDeny">Deny</button><button class="btn gold" id="cOk">${icon("fingerprint")} Approve</button></div>
      </div>`);
    $("#cOk").onclick = async () => {
      const btn = $("#cOk"); btn.disabled = true;
      try {
        const agentName = $("#cAgent").value.trim().toLowerCase();
        const access = $("#cAccess").value === "read" ? "read" : "full";
        // Bind the passkey to the exact agent + access shown, so they can't be swapped.
        const assertion = await stepUp("oauth.approve:" + id + ":" + agentName + ":" + access);
        const r = await api("POST", "/oauth/approve", { id, agent: agentName, access, assertion });
        gate("Connected", `${esc(info.client_name)} is plugged in as agent “${esc(r.agent)}”. Sending you back…`, "");
        location.href = r.redirect;
      } catch (e) { toast(friendly(e), true); btn.disabled = false; }
    };
    $("#cDeny").onclick = async () => {
      try { const r = await api("POST", "/oauth/deny", { id }); location.href = r.redirect; } catch (e) { toast(friendly(e), true); }
    };
  }

  // ---------- main app ----------
  async function startApp() {
    await refresh(true);
    clearInterval(pollTimer);
    pollTimer = setInterval(() => refresh(false).catch(() => {}), 3000);
  }

  async function refresh(force) {
    const s = await api("GET", "/admin/api/state");
    // The public URL only shows approvals; connectors stay on this PC or the tailnet.
    const c = s.remote ? { connectors: [] } : await api("GET", "/admin/api/connectors");
    const key = JSON.stringify([c.connectors, s.agents, s.pending, s.enrollments, s.approvals, s.audit && s.audit[0] && s.audit[0].id, s.passkeys, s.warnings]);
    state = s;
    connectors = c.connectors || [];
    if (force || key !== stateKey) { stateKey = key; render(); }
    if (enrollSheet) enrollSheet.update();
  }

  function setView(v) {
    view = v;
    history.replaceState(null, "", "#" + v);
    render();
    window.scrollTo({ top: 0 });
  }

  const agentLook = (name) => {
    const n = (name || "").toLowerCase();
    if (n.includes("claude")) return `<span class="logo l-claude"></span>`;
    if (n.includes("codex") || n.includes("chatgpt") || n.includes("dot")) return `<span class="logo l-openai"></span>`;
    if (n.includes("hermes") || n.includes("light")) return `<img class="photo" src="logos/hermes.png" alt="">`;
    if ((n === "owner" || n === "hamza")) return `<img src="logos/ralveto-mark.png" alt="">`;
    return icon("bot");
  };
  const gateWords = { deletes: "Deletes something permanently", emails: "Sends an email as you", posts: "Posts publicly as you",
    deploys: "Deploys or merges code", pays: "Spends money", publishes: "Makes something public", sensitive: "Sensitive action" };

  function render() {
    if (!state) return;
    const pend = (state.pending || []).concat(state.enrollments || []);
    app.innerHTML = `
      <header class="top"><div class="top-inner">
        <div class="brand"><img src="logos/ralveto-mark.png" alt="">RalX</div>
        <nav class="tabs" aria-label="Sections">
          ${["connectors", "agents", "activity"].map((v) => `<button class="tab" data-v="${v}" ${view === v ? 'aria-current="page"' : ""}>${{ connectors: "Connectors", agents: "Agents", activity: "Activity" }[v]}${v === "connectors" && pend.length ? `<span class="count">${pend.length}</span>` : ""}</button>`).join("")}
        </nav>
        <button class="btn quiet small lock" id="lock" title="Lock RalX">${icon("lock")} Lock</button>
      </div></header>
      <main>
        <h1 class="page-title">${{connectors: "Your connections", agents: "Your agents", activity: "Your activity"}[view]}</h1>
        ${noticeHTML(state.warnings || [])}
        ${view === "agents" ? agentsHTML() : view === "activity" ? activityHTML() : homeHTML()}
      </main>`;
    app.querySelectorAll(".tab").forEach((b) => (b.onclick = () => setView(b.dataset.v)));
    $("#lock").onclick = async () => { try { await api("POST", "/admin/api/logout"); } catch (_) {} csrf = ""; boot(); };
    bind();
  }

  // ---- home: approvals waiting (only when there are any), then every connector ----
  const connLogo = (id) => ({
    google: `<span class="logo l-google"></span>`, github: `<span class="logo l-github"></span>`,
    vercel: `<span class="logo l-vercel"></span>`, cloudflare: `<span class="logo l-cloudflare"></span>`,
    notion: `<span class="logo l-notion"></span>`, uploadpost: `<img src="logos/uploadpost.png" alt="">`,
  }[id] || icon("plug"));
  const svcName = (s) => ({ gmail: "Gmail", drive: "Drive", youtube: "YouTube" }[s] || s);

  function homeHTML() {
    const pend = state.pending || [];
    const enr = state.enrollments || [];
    const appr = pend.length || enr.length ? `<section class="home-pend"><div class="section-head"><h2>Waiting for you</h2><span class="sub">Nothing runs until you approve with ${passkeyMethod()}.</span></div>
        <div class="list">${enr.map(enrollHTML).join("")}${pend.slice().reverse().map(apprHTML).join("")}</div></section>` : "";
    if (state.remote) return appr || `<div class="empty">Nothing waiting. Connectors are managed on your PC.</div>`;
    const on = connectors.filter((c) => c.status === "connected").length;
    return `${appr}${loginsHTML()}
      <section><div class="section-head"><h2>Connectors</h2><span class="sub">${on} of ${connectors.length} connected</span>
        <span class="actions"><button class="btn small" id="connectAgent">${icon("bot")} Connect an agent</button></span></div>
        <div class="list conns">${connectors.map(connRow).join("")}</div>
        <p class="aside">Another MCP server, like Composio: run <code>ralx admin mcp add &lt;name&gt; &lt;https url&gt; --header x-api-key</code> in an admin terminal.</p>
      </section>`;
  }

  function loginsHTML() {
    const logins = state.logins || [];
    return `<section class="home-pend"><div class="section-head"><h2>Logins</h2><span class="sub">${logins.length} saved</span><span class="actions"><button class="btn small" id="addLogin">${icon("plus")} Add login</button></span></div>
      <div class="list">${logins.map((l) => `<div class="row"><div class="ico">${icon("key")}</div>
        <div class="main"><div class="title">${esc(l.name || l.username)} <span class="state">${l.kind === "test" ? "Test" : "Real"}</span></div>
          <div class="desc">${esc(l.username)}</div><div class="desc">${esc(l.origins.join(", "))}</div></div>
        <div class="side"><span class="acct-what">${l.last_used_at ? "Used " + ago(l.last_used_at) : "Not used yet"}</span></div></div>`).join("")}</div></section>`;
  }
  function connRow(c) {
    const accts = c.accounts || [];
    const word = { connected: `<span class="ok">Connected</span>`, error: `<span class="bad">Needs you</span>`, setup_needed: "Optional" }[c.status] || "Not connected";
    let action = "";
    if (c.connect === "google") {
      action = c.status === "setup_needed" ? `<button class="btn small primary" data-gclient="1">${icon("plus")} Add sign-in app</button>`
        : accts.length ? `<button class="btn small" data-gconnect="">${icon("plus")} Add another Gmail</button>`
        : `<button class="btn small primary" data-gconnect="">Connect</button>`;
    } else if (c.connect !== "admin") {
      const broken = accts.some((a) => a.status !== "ok");
      action = !accts.length ? `<button class="btn small primary" data-conn="${esc(c.id)}">Connect</button>`
        : broken && !(c.id === "uploadpost" && !accts[0].profile) ? `<button class="btn small primary" data-conn="${esc(c.id)}">${icon("refresh")} Reconnect</button>` : "";
    }
    const lines = accts.map((a) => acctLine(c, a)).join("");
    const reason = !accts.length && c.reason ? `<div class="desc">${esc(c.reason)}</div>` : "";
    return `<div class="row conn" data-id="${esc(c.id)}"><div class="ico">${connLogo(c.id)}</div>
      <div class="main"><div class="title">${esc(c.name)} <span class="state">${word}</span></div>
        <div class="desc">${esc((c.services || []).join(", "))}</div>${reason}
        ${c.connect === "admin" && c.help ? `<div class="desc">${esc(c.help)}</div>` : ""}</div>
      <div class="side">${action}</div>${lines ? `<div class="accts">${lines}</div>` : ""}</div>`;
  }

  function acctLine(c, a) {
    const google = c.connect === "google";
    const what = google ? (a.services || []).map(svcName).join(", ") : c.id === "uploadpost" && a.profile ? "posts as " + a.profile : "";
    const tools = [];
    if (google && a.status !== "ok") tools.push(`<button class="btn small primary" data-gconnect="${esc(a.label)}">${icon("refresh")} Reconnect</button>`);
    if (c.id === "uploadpost") tools.push(`<button class="btn small ${a.profile ? "quiet" : "primary"}" data-profile="${esc(a.name)}">${a.profile ? "Profile" : "Set profile"}</button>`);
    if (!google && c.connect === "key") tools.push(`<button class="btn small quiet icon-only" data-reveal="${esc(a.name)}" title="Show key" aria-label="Show ${esc(c.name)} key">${icon("eye")}</button>`);
    if (c.connect !== "admin") tools.push(`<button class="btn small quiet icon-only danger" data-del="${esc(a.name)}" title="Disconnect" aria-label="Disconnect ${esc(a.label)}">${icon("unplug")}</button>`);
    return `<div class="acct"><span class="dot ${a.status === "ok" ? "on" : "bad"}"></span>
      <div class="acct-main"><div class="acct-name">${esc(a.label)}${what ? `<span class="acct-what">${esc(what)}</span>` : ""}</div>
        ${a.status !== "ok" && a.reason ? `<div class="acct-why">${esc(a.reason)}</div>` : ""}
        ${a.status !== "ok" && c.detail ? `<details class="acct-detail"><summary>Details</summary><code class="mono">${esc(c.detail)}</code></details>` : ""}
        ${revealHTML(a.name)}</div>
      <div class="acct-tools">${tools.join("")}</div></div>`;
  }

  function prettyDetail(e) {
    return String(e.detail || "").replace(/\bapr_[a-z0-9]+\s*/g, "").replace(/ via pipe\b/, " (admin command line)").replace(/ via passkey\b/, "");
  }

  // One collapsible notice line; the count is always visible, the detail opens on tap.
  let noticesOpen = false;
  function noticeHTML(warnings) {
    if (!warnings.length) return "";
    const n = warnings.length;
    const head = `${n} protection ${n === 1 ? "note" : "notes"}`;
    return `<div class="notice ${noticesOpen ? "open" : ""}">
      <button class="notice-head" id="noticeToggle" aria-expanded="${noticesOpen}">${icon("shield")}<span>${esc(head)}</span><span class="chev">${noticesOpen ? "▲" : "▼"}</span></button>
      ${noticesOpen ? `<div class="notice-body">${warnings.map((w) => `<div class="notice-issue"><span>${esc(w)}</span>${/runs as you/.test(w) ? `<button class="btn small" data-protection-command="ralx admin install">${icon("copy")} Copy service command</button>` : /Windows.*admin/.test(w) ? `<button class="btn small" data-protection-command="UserAccountControlSettings.exe">${icon("copy")} Copy UAC settings command</button>` : ""}</div>`).join("")}</div>` : ""}
    </div>`;
  }

  function nice(name) {
    return ({ "claude-code": "Claude Code", codex: "Codex", hermes: "Hermes" }[name]) || name;
  }

  // Turn a raw action detail into something Hamza can read.
  function plainDetail(e) {
    let d = prettyDetail(e);
    if (e.outcome === "error") {
      if (/HTTP 401|Bad credentials|invalid_grant|unauthor/i.test(d)) return "the service rejected the saved login (needs reconnecting)";
      if (/HTTP 403|insufficient|forbidden/i.test(d)) return "the service refused (not enough access)";
      if (/HTTP 404|not found/i.test(d)) return "not found";
      if (/timed out|timeout/i.test(d)) return "timed out";
      if (/exited \d+:\s*(.+)/i.test(d)) return d.replace(/^.*exited \d+:\s*/i, "").split(/[\n\/]/)[0].slice(0, 120) || "the command failed";
      return d.slice(0, 120);
    }
    return d;
  }

  function apprHTML(a) {
    let args = "";
    try { args = JSON.stringify(JSON.parse(typeof a.args === "string" ? a.args : JSON.stringify(a.args)), null, 2); } catch (_) { args = String(a.args); }
    return `<div class="appr" data-appr="${esc(a.id)}">
      <div class="ico">${agentLook(a.agent_name)}</div>
      <div><div class="what">${esc(a.summary)}</div>
        <div class="who">${esc(nice(a.agent_name))} asked ${ago(a.created_at)}. <span class="why">${esc(gateWords[a.gate_reason] || a.gate_reason)}.</span></div>
        <details data-id="${esc(a.id)}" ${openDetails.has(a.id) ? "open" : ""}><summary>Exactly what will run</summary><pre class="mono">${esc(a.action)}\n${esc(args)}</pre></details>
      </div>
      <div class="btns"><button class="btn quiet" data-deny="${esc(a.id)}">${icon("x")} Deny</button><button class="btn primary" data-approve="${esc(a.id)}">${icon("fingerprint")} Approve</button></div>
    </div>`;
  }

  const clientName = (c) => ({ "claude-code": "Claude Code", codex: "Codex" }[c] || "An agent");
  function enrollHTML(r) {
    return `<div class="appr" data-enroll="${esc(r.id)}">
      <div class="ico">${agentLook(r.client === "other" ? r.name : r.client)}</div>
      <div><div class="what">Connect ${esc(r.name)} as an agent</div>
        <div class="who">${esc(clientName(r.client))} asked ${ago(r.created_at)}. Fingerprint <b class="fp mono">${esc(r.fingerprint)}</b> should match what your agent shows.</div>
        <div class="who"><span class="why">Can use every connector.</span> Risky actions still wait for you.</div>
      </div>
      <div class="btns"><button class="btn quiet" data-enroll-deny="${esc(r.id)}">${icon("x")} Deny</button><button class="btn primary" data-enroll-ok="${esc(r.id)}">${icon("fingerprint")} Approve</button></div>
    </div>`;
  }

  function actHTML(e) {
    const actor = (e.actor === "owner" || e.actor === "hamza") ? "You" : nice(e.actor);
    const d = plainDetail(e);
    return `<div class="act"><span class="t">${clock(e.ts)}</span><span class="a" title="${esc(e.actor)}">${esc(actor)}</span><span class="d" title="${esc(prettyDetail(e))}"><b>${esc(e.action)}</b> ${esc(d)}</span><span class="o o-${esc(e.outcome)}">${esc(outcomeWord(e.outcome))}</span></div>`;
  }
  function outcomeWord(o) {
    return ({ ok: "ok", executed: "done", held: "held", approved: "approved", denied: "denied", error: "failed", failed: "failed", rejected: "refused", invalid: "bad input", started: "started" }[o]) || o;
  }

  function revealHTML(name) {
    if (!name) return "";
    const r = revealed.get(name);
    if (!r || r.until < Date.now()) return "";
    const secs = Math.ceil((r.until - Date.now()) / 1000);
    return `<div class="reveal">${Object.entries(r.fields).map(([k, v]) => `<div class="field"><span class="k">${esc(k)}</span><code class="mono">${esc(v)}</code><button class="btn small quiet" data-copy="${esc(name)}|${esc(k)}">${icon("copy")}</button></div>`).join("")}
      <div class="timer">Hidden again in ${secs}s. <button class="link" data-hide="${esc(name)}">Hide now</button></div></div>`;
  }

  // ---- agents ----
  function agentsHTML() {
    const agents = state.agents || [];
    const lastUse = {};
    for (const e of state.audit || []) lastUse[e.actor] = Math.max(lastUse[e.actor] || 0, e.ts);
    return `
      <section><div class="section-head"><h2>Agents</h2><span class="sub">Each agent has its own RalX key. Revoke one and its next call fails.</span>
        <span class="actions"><button class="btn small" id="addAgent">${icon("plus")} Add agent</button></span></div>
        <div class="list">${agents.map((a) => `<div class="row"><div class="ico">${agentLook(a.name)}</div>
            <div class="main"><div class="title">${esc(nice(a.name))}</div>
              <div class="desc">${a.revoked_at ? `<span class="bad">Revoked ${ago(a.revoked_at)}</span>` : Math.max(a.last_seen_at || 0, lastUse[a.name] || 0) ? "Last used " + ago(Math.max(a.last_seen_at || 0, lastUse[a.name] || 0)) : "Not used yet"}${a.policy && a.policy.allow && a.policy.allow.length ? ", limited to " + esc(a.policy.allow.join(", ")) : ""}</div></div>
            <div class="side">${a.revoked_at ? "" : `<button class="btn small quiet danger" data-revoke="${esc(a.id)}" data-name="${esc(nice(a.name))}">${icon("x")} Revoke</button>`}</div></div>`).join("") || `<div class="empty">No agents yet.</div>`}
        </div></section>
      <section class="section"><div class="section-head"><h2>Your passkeys</h2><span class="sub">Approvals and showing a credential always need one of these.</span>
        <span class="actions"><button class="btn small" id="addPasskey">${icon("plus")} Add a passkey</button></span></div>
        <div class="list">${(state.passkeys || []).map((p) => `<div class="row"><div class="ico">${icon("fingerprint")}</div><div class="main"><div class="title">${esc(p.name)}</div>
          <div class="desc">Works on ${esc(p.rp_id === "localhost" ? "this PC" : p.rp_id)}, added ${ago(p.created_at)}, ${p.last_used_at ? "used " + ago(p.last_used_at) : "not used yet"}</div></div></div>`).join("")}
          ${(state.public_origins || []).filter((o) => o !== state.this_origin).map((o) => `<div class="row"><div class="ico">${icon("key")}</div><div class="main"><div class="title">Approve from your phone</div>
          <div class="desc">Register a passkey on your phone for ${esc(o.replace("https://", ""))}.</div></div><div class="side"><button class="btn small" data-pair="${esc(o)}">${icon("plus")} Pair phone</button></div></div>`).join("")}
        </div></section>`;
  }

  // ---- activity ----
  function activityHTML() {
    const all = state.audit || [];
    const sets = { all: () => true, held: (e) => e.outcome === "held" || e.action === "approval", problems: (e) => /error|failed|rejected|denied|invalid/.test(e.outcome) };
    const rows = all.filter(sets[actFilter]);
    return `<section><div class="section-head"><h2>Activity</h2><span class="sub">Every call, without secrets.</span>
      <span class="actions filters">${[["all", "All"], ["held", "Approvals"], ["problems", "Problems"]].map(([k, l]) => `<button class="btn small ${actFilter === k ? "primary" : "quiet"}" data-filter="${k}">${l}</button>`).join("")}</span></div>
      <div class="list">${rows.map(actHTML).join("") || `<div class="empty">Nothing here.</div>`}</div></section>`;
  }

  // ---------- actions ----------
  function bind() {
    app.querySelectorAll("[data-protection-command]").forEach((b) => b.onclick = async () => {
      try { await navigator.clipboard.writeText(b.dataset.protectionCommand); b.textContent = "Copied"; }
      catch (_) { toast("Copy this command: " + b.dataset.protectionCommand); }
    });
    const nt = $("#noticeToggle");
    if (nt) nt.onclick = () => { noticesOpen = !noticesOpen; render(); };
    app.querySelectorAll("details[data-id]").forEach((d) => d.addEventListener("toggle", () => (d.open ? openDetails.add(d.dataset.id) : openDetails.delete(d.dataset.id))));
    app.querySelectorAll("[data-approve]").forEach((b) => (b.onclick = () => approve(b.dataset.approve, b)));
    app.querySelectorAll("[data-deny]").forEach((b) => (b.onclick = () => deny(b.dataset.deny, b)));
    app.querySelectorAll("[data-reveal]").forEach((b) => (b.onclick = () => reveal(b.dataset.reveal, b)));
    app.querySelectorAll("[data-hide]").forEach((b) => (b.onclick = () => { revealed.delete(b.dataset.hide); render(); }));
    app.querySelectorAll("[data-copy]").forEach((b) => (b.onclick = () => copy(b.dataset.copy)));
    app.querySelectorAll("[data-del]").forEach((b) => (b.onclick = () => removeCred(b.dataset.del)));
    app.querySelectorAll("[data-revoke]").forEach((b) => (b.onclick = () => revoke(b.dataset.revoke, b.dataset.name)));
    app.querySelectorAll("[data-filter]").forEach((b) => (b.onclick = () => { actFilter = b.dataset.filter; render(); }));
    app.querySelectorAll("[data-gconnect]").forEach((b) => (b.onclick = () => connectGoogle(b.dataset.gconnect, b)));
    app.querySelectorAll("[data-gclient]").forEach((b) => (b.onclick = addGoogleClient));
    app.querySelectorAll("[data-conn]").forEach((b) => (b.onclick = () => connect(b.dataset.conn, b)));
    app.querySelectorAll("[data-profile]").forEach((b) => (b.onclick = () => editProfile(b.dataset.profile)));
    app.querySelectorAll("[data-pair]").forEach((b) => (b.onclick = () => pairPhone(b.dataset.pair, b)));
    app.querySelectorAll("[data-enroll-ok]").forEach((b) => (b.onclick = () => approveEnroll(b.dataset.enrollOk, b)));
    app.querySelectorAll("[data-enroll-deny]").forEach((b) => (b.onclick = () => denyEnroll(b.dataset.enrollDeny, b)));
    const ca = $("#connectAgent"); if (ca) ca.onclick = () => connectAgent(ca);
    const al = $("#addLogin"); if (al) al.onclick = addLoginSheet;
    const ag = $("#addAgent"); if (ag) ag.onclick = addAgent;
    const ap = $("#addPasskey"); if (ap) ap.onclick = addPasskey;
  }

  async function approve(id, btn) {
    btn.disabled = true;
    try {
      const assertion = await stepUp("approve:" + id);
      await api("POST", `/admin/api/approvals/${encodeURIComponent(id)}/approve`, { assertion });
      toast("Approved. Running it now.");
      await refresh(true);
    } catch (e) { toast(friendly(e), true); btn.disabled = false; }
  }
  async function approveEnroll(id, btn) {
    btn.disabled = true;
    try {
      const assertion = await stepUp("enroll.approve:" + id);
      const r = await api("POST", `/admin/api/enroll/${encodeURIComponent(id)}/approve`, { assertion });
      toast(`${r.name} approved. It picks up its key on its next check.`);
      await refresh(true);
    } catch (e) { toast(friendly(e), true); btn.disabled = false; }
  }
  async function denyEnroll(id, btn) {
    btn.disabled = true;
    try { await api("POST", `/admin/api/enroll/${encodeURIComponent(id)}/deny`); toast("Denied. That agent gets nothing."); await refresh(true); }
    catch (e) { toast(friendly(e), true); btn.disabled = false; }
  }

  // "Connect an agent": a one-time prompt to paste into Claude Code or Codex. The
  // sheet then shows the agent's request as soon as it arrives, ready to approve.
  let enrollSheet = null;
  async function connectAgent(btn) {
    btn.disabled = true;
    let r;
    try { r = await api("POST", "/admin/api/enroll/code"); }
    catch (e) { toast(friendly(e), true); btn.disabled = false; return; }
    btn.disabled = false;
    sheet(`<h3>Connect an agent</h3><p>Paste this into Claude Code or Codex on this PC. It works once, until ${esc(clock(r.expires_at))}.</p>
      <pre class="keybox mono prompt" id="ePrompt">${esc(r.prompt)}</pre>
      <div class="enroll-wait" id="eWait">${icon("clock")} Waiting for your agent to run it</div>
      <div class="foot"><button class="btn quiet" data-close>Close</button><button class="btn primary" id="eCopy">${icon("copy")} Copy prompt</button></div>`,
      (el, close) => {
        const back = el;
        el.querySelector("#eCopy").onclick = () => navigator.clipboard.writeText(r.prompt).then(() => toast("Copied. Paste it into your agent."), () => toast("Couldn't copy; select the text instead", true));
        enrollSheet = {
          update() {
            if (!document.body.contains(back)) { enrollSheet = null; return; }
            const req = (state.enrollments || []).find((x) => x.code_id === r.code_id);
            const w = back.querySelector("#eWait");
            if (!req || w.dataset.req === req.id) return;
            w.dataset.req = req.id;
            w.className = "enroll-wait asking";
            w.innerHTML = `<div><b>${esc(req.name)}</b> is asking. Fingerprint <b class="fp mono">${esc(req.fingerprint)}</b></div>
              <button class="btn primary small" id="eOk">${icon("fingerprint")} Approve</button>`;
            w.querySelector("#eOk").onclick = async (ev) => { await approveEnroll(req.id, ev.currentTarget); if (!(state.enrollments || []).some((x) => x.id === req.id)) close(); };
          },
        };
        enrollSheet.update();
      });
  }

  async function deny(id, btn) {
    btn.disabled = true;
    try { await api("POST", `/admin/api/approvals/${encodeURIComponent(id)}/deny`); toast("Denied. The agent will be told."); await refresh(true); }
    catch (e) { toast(friendly(e), true); btn.disabled = false; }
  }
  async function reveal(name, btn) {
    btn.disabled = true;
    try {
      const assertion = await stepUp("reveal:" + name);
      const r = await api("POST", "/admin/api/credentials/reveal", { name, assertion });
      revealed.set(name, { fields: r.fields, until: Date.now() + 30000 });
      render();
      const tick = setInterval(() => {
        const v = revealed.get(name);
        if (!v || v.until < Date.now()) { revealed.delete(name); clearInterval(tick); }
        if (view === "connectors") render();
      }, 1000);
    } catch (e) { toast(friendly(e), true); btn.disabled = false; }
  }
  async function copy(ref) {
    const [name, k] = ref.split("|");
    const r = revealed.get(name);
    if (!r) return;
    try { await navigator.clipboard.writeText(r.fields[k]); toast("Copied. Clipboard clears in 30 s."); setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30000); }
    catch (_) { toast("Couldn't copy", true); }
  }

  // ---------- sheets ----------
  function addLoginSheet() {
    sheet(`<h3>Add login</h3><p>Save a website login to your vault. The password is write-only here.</p>
      <form id="loginForm"><label for="loginWebsite">Website</label><input id="loginWebsite" type="url" required placeholder="https://app.example.com" autocomplete="off">
      <label for="loginUsername">Username</label><input id="loginUsername" required autocomplete="off">
      <label for="loginPassword">Password</label><input id="loginPassword" type="password" required autocomplete="new-password">
      <label for="loginName">Name (optional)</label><input id="loginName" autocomplete="off">
      <div class="foot"><button class="btn quiet" type="button" data-close>Cancel</button><button class="btn primary" type="submit">Save</button></div></form>`, (el, close) => {
        el.querySelector("#loginForm").onsubmit = async (e) => {
          e.preventDefault();
          const button = el.querySelector("button[type=submit]"); button.disabled = true;
          try {
            await api("POST", "/admin/api/logins", { website: el.querySelector("#loginWebsite").value.trim(), username: el.querySelector("#loginUsername").value.trim(), password: el.querySelector("#loginPassword").value, name: el.querySelector("#loginName").value.trim() });
            el.querySelector("#loginPassword").value = ""; close(); toast("Login saved to the vault."); await refresh(true);
          } catch (err) { toast(friendly(err), true); button.disabled = false; }
        };
      });
  }

  function sheet(html, onReady) {
    const back = document.createElement("div");
    back.className = "sheet-back";
    back.innerHTML = `<div class="sheet" role="dialog" aria-modal="true">${html}</div>`;
    document.body.appendChild(back);
    const close = () => back.remove();
    back.addEventListener("click", (e) => { if (e.target === back) close(); });
    back.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    back.querySelectorAll("[data-close]").forEach((b) => (b.onclick = close));
    const first = back.querySelector("input,select,textarea,button.primary,button");
    if (first) first.focus();
    onReady && onReady(back, close);
    return close;
  }

  function confirmSheet(title, body, actionLabel, danger) {
    return new Promise((resolve) => {
      sheet(`<h3>${title}</h3><p>${body}</p><div class="foot"><button class="btn quiet" data-close>Cancel</button><button class="btn ${danger ? "primary" : "primary"}" id="ok">${actionLabel}</button></div>`,
        (el, close) => { el.querySelector("#ok").onclick = () => { close(); resolve(true); }; el.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => resolve(false))); });
    });
  }

  async function revoke(id, name) {
    if (!(await confirmSheet(`Revoke ${esc(name)}?`, "Its RalX key stops working immediately; its next call fails. Held actions it asked for won't run.", "Revoke"))) return;
    try { await api("POST", `/admin/api/agents/${encodeURIComponent(id)}/revoke`); toast(`${name} revoked.`); await refresh(true); }
    catch (e) { toast(friendly(e), true); }
  }

  async function removeCred(name) {
    const g = name.startsWith("google:");
    if (!(await confirmSheet(g ? "Disconnect Google?" : "Remove this key?", g ? "RalX revokes its access at Google and deletes the tokens. Agents lose Gmail, Drive and YouTube until you connect again." : "It's deleted from the vault. Actions that need it stop working.", g ? "Disconnect" : "Remove"))) return;
    try { await api("POST", "/admin/api/credentials/delete", { name }); toast("Removed."); await refresh(true); }
    catch (e) { toast(friendly(e), true); }
  }

  // Sign-in pages open in a new tab. The tab is opened on the click itself so the
  // browser doesn't block it while RalX asks for the passkey and the URL.
  async function openSignIn(getURL, btn, done) {
    const tab = window.open("about:blank", "_blank");
    btn.disabled = true;
    try {
      const u = await getURL();
      if (tab) { tab.opener = null; tab.location.href = u; } else location.href = u;
      toast(done);
    } catch (e) { if (tab) tab.close(); toast(friendly(e), true); }
    btn.disabled = false;
  }

  // hint = an account email to reconnect it; empty = Google's account chooser, so
  // the same button adds another Gmail.
  function connectGoogle(hint, btn) {
    openSignIn(async () => (await api("POST", "/admin/api/connect/google", { services: ["drive", "gmail", "youtube"], login_hint: hint || "" })).auth_url,
      btn, "Pick the account in the Google tab. This page updates by itself.");
  }

  function connect(id, btn) {
    const c = connectors.find((x) => x.id === id);
    if (!c) return;
    if (c.connect === "key") return keySheet(c);
    if (c.connect === "cli") {
      return openSignIn(async () => (await api("POST", `/admin/api/connect/cli/${encodeURIComponent(id)}`)).url,
        btn, `Approve in the ${c.name} tab. This page updates by itself.`);
    }
    if (c.connect === "mcp_oauth") {
      const name = (c.credential || id).replace(/^mcp:/, "");
      return openSignIn(async () => {
        const assertion = await stepUp("upstream:" + name);
        return (await api("POST", "/admin/api/upstreams/oauth", { name, url: c.url, assertion })).auth_url;
      }, btn, `Sign in to ${c.name} in the new tab. This page updates by itself.`);
    }
  }

  function keySheet(c) {
    const up = c.id === "uploadpost";
    const cur = (c.accounts || [])[0];
    sheet(`<h3>Connect ${esc(c.name)}</h3><p>${esc(c.help || "Paste the key once.")} Agents use it through RalX and never see it.</p>
      <label for="kValue">${up ? "API key" : "Token"}</label><input id="kValue" type="password" autocomplete="off" spellcheck="false">
      ${up ? `<label for="kProfile">Profile to post as</label><input id="kProfile" value="${esc((cur && cur.profile) || "")}" placeholder="profile username" autocomplete="off">` : ""}
      <div class="foot"><button class="btn quiet" data-close>Cancel</button><button class="btn primary" id="kSave">${icon("fingerprint")} Save</button></div>`,
      (el, close) => {
        el.querySelector("#kSave").onclick = async () => {
          const value = el.querySelector("#kValue").value.trim();
          if (!value) return toast("Paste the key first", true);
          const meta = up ? { profile: el.querySelector("#kProfile").value.trim() } : {};
          const label = cur ? cur.label : c.name;
          try {
            const assertion = await stepUp("credential.put:" + c.credential);
            await api("POST", "/admin/api/credentials", { name: c.credential, kind: "api_key", provider: c.id, label, meta, keep_meta: true, fields: { [c.field]: value }, assertion });
            close(); toast(`${c.name} saved to the vault.`); await refresh(true);
          } catch (e) { toast(friendly(e), true); }
        };
      });
  }

  function addGoogleClient() {
    sheet(`<h3>Add the Google sign-in app</h3><p>Pick the client JSON you downloaded from Google Cloud (Desktop app type). It goes into the vault; delete the download afterwards.</p>
      <input type="file" id="gFile" accept="application/json,.json">
      <div class="foot"><button class="btn quiet" data-close>Cancel</button><button class="btn primary" id="gSave">${icon("fingerprint")} Save</button></div>`,
      (el, close) => {
        el.querySelector("#gSave").onclick = async () => {
          const f = el.querySelector("#gFile").files[0];
          if (!f) return toast("Choose the JSON file", true);
          try {
            const j = JSON.parse(await f.text());
            const c = j.installed;
            if (!c || !c.client_id || !c.client_secret) throw new Error(j.web ? "That's a Web client; RalX needs a Desktop app client" : "Not a Google Desktop client JSON");
            const assertion = await stepUp("credential.put:google-oauth-client");
            await api("POST", "/admin/api/credentials", { name: "google-oauth-client", label: `RalX Google OAuth client (${c.project_id})`, meta: { project_id: c.project_id, client_id: c.client_id }, fields: { client_id: c.client_id, client_secret: c.client_secret }, assertion });
            close(); toast("Google sign-in app saved."); await refresh(true);
          } catch (e) { toast(friendly(e), true); }
        };
      });
  }

  function editProfile(name) {
    const c = (state.credentials || []).find((x) => x.name === name);
    sheet(`<h3>Upload-Post profile</h3><p>Posts go out as this Upload-Post profile.</p><label for="pName">Profile username</label><input id="pName" value="${esc((c && c.meta && c.meta.profile) || "")}">
      <div class="foot"><button class="btn quiet" data-close>Cancel</button><button class="btn primary" id="pSave">Save</button></div>`,
      (el, close) => {
        el.querySelector("#pSave").onclick = async () => {
          try { await api("POST", "/admin/api/credentials/meta", { name, meta: { profile: el.querySelector("#pName").value.trim() } }); close(); toast("Saved."); await refresh(true); }
          catch (e) { toast(friendly(e), true); }
        };
      });
  }

  function addAgent() {
    sheet(`<h3>Add an agent</h3><p>It gets its own RalX key, shown once. Put it in that agent's config; you can revoke it any time.</p>
      <label for="aName">Name</label><input id="aName" placeholder="e.g. claude-code" autocomplete="off">
      <div id="aKey"></div>
      <div class="foot"><button class="btn quiet" data-close>Close</button><button class="btn primary" id="aSave">${icon("fingerprint")} Create</button></div>`,
      (el) => {
        el.querySelector("#aSave").onclick = async () => {
          const name = el.querySelector("#aName").value.trim().toLowerCase();
          if (!/^[a-z0-9][a-z0-9._-]{0,40}$/.test(name)) return toast("Use letters, numbers, dots or dashes", true);
          try {
            const assertion = await stepUp("agent.create:" + name);
            const r = await api("POST", "/admin/api/agents", { name, assertion });
            el.querySelector("#aKey").innerHTML = `<div class="keybox mono">${esc(r.key)}</div><p style="margin-top:8px">Copy it now; RalX only stores a hash.</p>`;
            el.querySelector("#aSave").remove();
            await refresh(true);
          } catch (e) { toast(friendly(e), true); }
        };
      });
  }

  async function pairPhone(origin, btn) {
    btn.disabled = true;
    try {
      const assertion = await stepUp("pair:" + origin);
      const r = await api("POST", "/admin/api/pair", { origin, assertion });
      sheet(`<h3>Open this on your phone</h3><p>It works once, for 15 minutes. Your phone will ask to save a passkey for RalX; after that you can approve from anywhere.</p>
        <div class="keybox mono">${esc(r.url)}</div>
        <div class="foot"><button class="btn quiet" data-close>Done</button><button class="btn primary" id="pCopy">${icon("copy")} Copy link</button></div>`,
        (el) => { el.querySelector("#pCopy").onclick = () => navigator.clipboard.writeText(r.url).then(() => toast("Copied")); });
    } catch (e) { toast(friendly(e), true); }
    btn.disabled = false;
  }

  async function addPasskey() {
    try {
      const assertion = await stepUp("passkey.add");
      const opts = await api("POST", "/admin/api/passkeys/begin", { assertion });
      const cred = await passkeyCreate(opts);
      await api("POST", "/admin/api/passkeys/finish", { name: "Passkey added " + new Date().toLocaleDateString(), credential: cred });
      toast("Passkey added."); await refresh(true);
    } catch (e) { toast(friendly(e), true); }
  }

  boot();
})();

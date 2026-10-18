// Mock backend: same routes and JSON as API-CONTRACT.md, held in memory.
// Scenes: ?mock=1 (full), &scene=empty, &scene=error, &scene=signedout.

const now = Date.now();
const at = (min) => new Date(now - min * 60000).toISOString();

const catalog = [
  ["gmail", "Gmail", "Email", "Read, search, draft and send email."],
  ["outlook", "Outlook", "Email", "Read and send Microsoft 365 mail."],
  ["googlecalendar", "Google Calendar", "Calendar", "See your day, find free time, book meetings."],
  ["calendly", "Calendly", "Calendar", "Share booking links and see who booked."],
  ["googledrive", "Google Drive", "Files and docs", "Find, read and upload files."],
  ["googledocs", "Google Docs", "Files and docs", "Read and write documents."],
  ["googlesheets", "Google Sheets", "Files and docs", "Read rows, add rows, update cells."],
  ["notion", "Notion", "Files and docs", "Search pages, read databases, write notes."],
  ["dropbox", "Dropbox", "Files and docs", "Find and share files."],
  ["github", "GitHub", "Developer tools", "Repos, issues and pull requests."],
  ["linear", "Linear", "Developer tools", "Create and update issues."],
  ["vercel", "Vercel", "Developer tools", "Projects, deployments and domains."],
  ["supabase", "Supabase", "Developer tools", "Query tables and manage projects."],
  ["sentry", "Sentry", "Developer tools", "Read errors and resolve issues."],
  ["slack", "Slack", "Chat", "Read channels and post messages."],
  ["discord", "Discord", "Chat", "Read servers and send messages."],
  ["whatsapp", "WhatsApp", "Chat", "Send and read business messages."],
  ["zoom", "Zoom", "Chat", "Schedule meetings and pull recordings."],
  ["asana", "Asana", "Work", "Tasks, projects and due dates."],
  ["trello", "Trello", "Work", "Boards, lists and cards."],
  ["jira", "Jira", "Work", "Issues, sprints and boards."],
  ["airtable", "Airtable", "Work", "Read and update bases."],
  ["figma", "Figma", "Work", "Read files, frames and comments."],
  ["hubspot", "HubSpot", "Sales", "Contacts, deals and notes."],
  ["salesforce", "Salesforce", "Sales", "Leads, accounts and opportunities."],
  ["intercom", "Intercom", "Sales", "Read and reply to conversations."],
  ["stripe", "Stripe", "Payments", "Payments, customers and payouts."],
  ["shopify", "Shopify", "Payments", "Orders, products and customers."],
  ["youtube", "YouTube", "Social", "Upload videos and read analytics."],
  ["twitter", "X", "Social", "Read your timeline and post."],
  ["linkedin", "LinkedIn", "Social", "Post updates to your profile."],
].map(([slug, name, category, description]) => ({ slug, name, category, description, logo_url: null, auth: slug === "stripe" ? "key" : "oauth", accounts: [] }));

const gmail = [
  ["owner@example.invalid", "active", 40000],
  ["personal@example.invalid", "active", 38000],
  ["hello@example.invalid", "active", 30000],
  ["creator@example.invalid", "active", 26000],
  ["ops@example.invalid", "error", 21000],
  ["billing@example.invalid", "active", 14000],
  ["builds@example.invalid", "active", 9000],
  ["clients@example.invalid", "active", 3000],
];
const inbox = {
  "owner@example.invalid": "Example Company: signed proposal attached, from Alex Example, 9:42",
  "personal@example.invalid": "Your Emirates booking is confirmed, from Emirates, 8:15",
  "hello@example.invalid": "Can I feature your AI stack on my podcast?, from Sana Q., yesterday",
  "creator@example.invalid": "Pass purchase: Lifetime access, from Gumroad, yesterday",
  "billing@example.invalid": "Payout of AED 4,210 is on its way, from Stripe, 11:02",
  "builds@example.invalid": "[example/ralx] Review requested on #41, from GitHub, 10:37",
  "clients@example.invalid": "Next week's workshop agenda, from Sam Example, 7:58",
};

let id = 1;
const acct = (label, status, minAgo) => ({ id: `acc_${id++}`, label, status, connected_at: at(minAgo) });

function fullState() {
  const c = structuredClone(catalog);
  const by = Object.fromEntries(c.map((x) => [x.slug, x]));
  by.gmail.accounts = gmail.map((g) => acct(...g));
  by.github.accounts = [acct("example-user", "active", 50000)];
  by.notion.accounts = [acct("My workspace", "active", 45000)];
  by.googlecalendar.accounts = [acct("owner@example.invalid", "active", 39000)];
  by.googledrive.accounts = [acct("owner@example.invalid", "active", 39000), acct("personal@example.invalid", "active", 12000)];
  by.slack.accounts = [acct("Ralveto", "active", 20000)];
  return {
    me: { user: { id: "usr_1", email: "owner@example.invalid", name: "Example User", avatar_url: "" } },
    connectors: c,
    agents: [
      { id: "agt_1", name: "Grokbot", client: "grok", created_at: at(7200), last_used_at: at(4) },
      { id: "agt_2", name: "Claude Code on laptop", client: "claude-code", created_at: at(2900), last_used_at: at(38) },
      { id: "agt_3", name: "Codex", client: "codex", created_at: at(1500), last_used_at: at(60 * 26) },
    ],
    approvals: [
      { id: "apr_1", agent: "Grokbot", tool: "gmail.send_email", summary: "Send “Proposal v2 attached” to alex@example.invalid from owner@example.invalid", created_at: at(3) },
      { id: "apr_2", agent: "Claude Code on laptop", tool: "github.merge_pull_request", summary: "Merge example/ralx #41 “Cloud UI” into main", created_at: at(17) },
      { id: "apr_3", agent: "Codex", tool: "slack.post_message", summary: "Post the weekly update in #example-team", created_at: at(52) },
    ],
    activity: [
      [4, "Grokbot", "gmail.list_messages", "owner@example.invalid", "ok"],
      [5, "Grokbot", "gmail.list_messages", "billing@example.invalid", "ok"],
      [9, "Grokbot", "gmail.send_email", "owner@example.invalid", "held"],
      [38, "Claude Code on laptop", "github.list_pull_requests", "example-user", "ok"],
      [41, "Claude Code on laptop", "github.merge_pull_request", "example-user", "held"],
      [70, "Codex", "notion.search", "My workspace", "ok"],
      [95, "Grokbot", "googlecalendar.list_events", "owner@example.invalid", "ok"],
      [130, "Grokbot", "gmail.list_messages", "ops@example.invalid", "error"],
      [60 * 20, "Codex", "slack.post_message", "Ralveto", "denied"],
      [60 * 21, "Grokbot", "googledrive.upload_file", "owner@example.invalid", "ok"],
      [60 * 26, "Codex", "github.create_issue", "example-user", "ok"],
    ].map(([m, agent, tool, account, outcome]) => ({ at: at(m), agent, tool, account, outcome })),
  };
}

const params = new URLSearchParams(location.search);
const scene = params.get("scene") || "full";
let s = fullState();
for (const a of s.approvals) {
  a.account = "sample_account";
  a.tool = a.id === "apr_1" ? "GMAIL_SEND_EMAIL" : a.id === "apr_2" ? "GITHUB_CREATE_AN_ISSUE" : "SLACK_SEND_MESSAGE";
  a.args = a.id === "apr_1" ? { recipient_email: "review@example.invalid", body: "Synthetic approval preview <script>example</script>" } : a.id === "apr_2" ? { title: "Review the sample UI", body: "Synthetic GitHub issue" } : { channel: "sample-team", text: "Synthetic weekly update" };
  a.summary = a.id === "apr_1" ? "Send a sample email to review@example.invalid" : a.id === "apr_2" ? "Create a sample GitHub issue" : "Post a sample update in sample-team";
  a.args_hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(a.args)))), (x) => x.toString(16).padStart(2, "0")).join("");
}
const daysAgo = (d) => new Date(Date.now() - d * 86400000).toISOString();
s.vault = [
  ["github.com", "GitHub", "h***", 2],
  ["vercel.com", "Vercel", "h***", 3],
  ["supabase.com", "Supabase", "h***", 5],
  ["app.hubspot.com", "HubSpot", "o***", 9],
  ["www.figma.com", "Figma", "h***", 12],
  ["dashboard.stripe.com", "Stripe", "b***", 20],
  ["portal.dewa.gov.ae", "DEWA", "h***", 31],
].map(([host, label, hint, d], k) => ({ id: `vi_${k}`, label, origin: `https://${host}`, kind: "login", username_hint: hint, created_at: daysAgo(d) }));
s.vault.push({ id: "vi_note", label: "Emirates ID scan notes", origin: "", kind: "private", username_hint: "", created_at: daysAgo(40) });
s.requests = [{ id: "lr_1", origin: "https://www.linkedin.com", label: "LinkedIn", agent: "Grokbot", client: "grok", expires: Math.floor(Date.now() / 1000) + 840, status: "pending" }];
if (scene === "empty") {
  s.connectors.forEach((c) => (c.accounts = []));
  s.agents = [];
  s.approvals = [];
  s.activity = [];
  s.vault = [];
  s.requests = [];
}
let pendingCode = null;

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const ok = (data) => ({ ok: true, status: 200, data: structuredClone(data) });
const fail = (status, error) => ({ ok: false, status, data: { error } });

export async function mock(method, path, body) {
  await wait(path === "/api/test" ? 900 : 160 + Math.random() * 120);
  if (scene === "signedout") return fail(401, "signed out");
  if (scene === "error" && path === "/api/connectors") return fail(503, "upstream unavailable");
  let m;
  if (path === "/api/me") return ok(s.me);
  if (path === "/logout") return ok({ ok: true });
  if (path === "/api/connectors") return ok({ connectors: s.connectors });
  if ((m = path.match(/^\/api\/connectors\/([\w-]+)\/connect$/))) {
    // Real flow redirects to Composio and back to /?connected=slug. Here we come straight back.
    const c = s.connectors.find((x) => x.slug === m[1]);
    const n = c.accounts.length;
    const label = c.slug === "gmail" ? `owner+${n + 1}@example.invalid` : c.slug === "github" ? "example-user" : `Account ${n + 1}`;
    const a = acct(label, "pending", 0);
    c.accounts.push(a);
    setTimeout(() => (a.status = "active"), 1400);
    const u = new URL(location.href);
    u.searchParams.set("connected", c.slug);
    return ok({ redirect_url: u.pathname + u.search + u.hash });
  }
  if ((m = path.match(/^\/api\/accounts\/([\w-]+)$/)) && method === "DELETE") {
    s.connectors.forEach((c) => (c.accounts = c.accounts.filter((a) => a.id !== m[1])));
    return ok({ ok: true });
  }
  if (path === "/api/test") {
    const list = s.connectors.filter((c) => !body?.slug || c.slug === body.slug);
    return ok({
      results: list.flatMap((c) =>
        c.accounts.map((a) =>
          a.status === "error"
            ? { slug: c.slug, account: a.label, ok: false, summary: "Google stopped accepting this login. Reconnect it." }
            : { slug: c.slug, account: a.label, ok: true, summary: inbox[a.label] || (c.slug === "github" ? "3 open pull requests, latest #41 Cloud UI" : "Connected and answering") },
        ),
      ),
    });
  }
  if (path === "/api/agents/prompt") {
    pendingCode = Math.random().toString(36).slice(2, 10).toUpperCase();
    const base = location.origin;
    return ok({
      code: pendingCode,
      expires_at: new Date(Date.now() + 15 * 60000).toISOString(),
      prompt: `Connect to my RalX so you can use my accounts. Run: curl -s -X POST ${base}/api/enroll -H "content-type: application/json" -d '{"code":"${pendingCode}","name":"<your name>","client":"<claude, codex, grok or other>"}' and save the key it returns as RALX_KEY. Then add the MCP server ${base}/mcp with the header "Authorization: Bearer $RALX_KEY". Call /api/v1/whoami to confirm, and tell me which accounts you can now use.`,
    });
  }
  if (path === "/api/agents" && method === "GET") return ok({ agents: s.agents });
  if ((m = path.match(/^\/api\/agents\/([\w-]+)$/)) && method === "DELETE") {
    s.agents = s.agents.filter((a) => a.id !== m[1]);
    return ok({ ok: true });
  }
  if (path === "/api/approvals") return ok({ approvals: s.approvals });
  if ((m = path.match(/^\/api\/approvals\/([\w-]+)\/(approve|deny)$/))) {
    const a = s.approvals.find((x) => x.id === m[1]);
    if (!a) return fail(409, "Approval already handled");
    if (m[2] === "approve" && body?.args_hash !== a.args_hash) return fail(409, "Approval arguments changed. Refresh and review them again.");
    s.approvals = s.approvals.filter((x) => x.id !== m[1]);
    s.activity.unshift({ at: new Date().toISOString(), agent: a.agent, tool: a.tool, account: "", outcome: m[2] === "approve" ? "ok" : "denied" });
    return ok({ ok: true, result: m[2] === "approve" ? "Done" : undefined });
  }
  if (path === "/api/activity") return ok({ events: s.activity });
  if ((path.split("?")[0] === "/api/vault" && method === "GET") || (path === "/api/vault/search" && method === "POST")) {
    const params = method === "POST" ? body || {} : Object.fromEntries(new URL(path, location.href).searchParams);
    if (method === "GET" && Object.hasOwn(params, "q")) return fail(400, "Use POST /api/vault/search for search.");
    const q = (params.q || "").toLowerCase(), cursor = params.cursor || "", limit = Number(params.limit || 100);
    const rows = s.vault.filter((x) => x.id > cursor && (!q || `${x.label} ${x.origin} ${x.username_hint}`.toLowerCase().includes(q))).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    const items = rows.slice(0, limit);
    return ok({ items, ...(rows.length > limit ? { next_cursor: items.at(-1).id } : {}) });
  }
  if (path === "/api/vault/requests" && method === "GET") return ok({ requests: s.requests });
  if ((m = path.match(/^\/api\/vault\/requests\/([\w-]+)\/deny$/))) {
    s.requests = s.requests.filter((r) => r.id !== m[1]);
    return ok({ ok: true });
  }
  if (path === "/api/vault/login") {
    let origin = "";
    try {
      const u = new URL(body?.url || "");
      origin = u.protocol === "https:" ? u.origin : "";
    } catch {}
    if (!origin || !body?.password) return fail(400, "Enter a name, an HTTPS website and a password.");
    const id = `vi_${Date.now()}`;
    s.vault.unshift({ id, label: body.label || new URL(origin).hostname, origin, kind: "login", username_hint: body.username ? body.username[0] + "***" : "", created_at: new Date().toISOString() });
    s.requests = s.requests.filter((r) => r.id !== body.request_id);
    return ok({ id, saved: true });
  }
  if (path.startsWith("/api/vault/import")) {
    const extra = [
      ["notion.so", "Notion"],
      ["linear.app", "Linear"],
      ["dash.cloudflare.com", "Cloudflare"],
    ].map(([host, label], k) => ({ id: `vi_imp${k}`, label, origin: `https://${host}`, kind: "login", username_hint: "h***", created_at: new Date().toISOString() }));
    s.vault = [...extra, ...s.vault];
    return ok({ imported: 214, logins: 207, private_items: 7, original_preserved: true });
  }
  return fail(404, "not found");
}

// The agent side of the prompt: once the owner copies it, an agent "enrolls" a few seconds later.
export function mockEnrollSoon(ms = 4500) {
  const code = pendingCode;
  setTimeout(() => {
    if (!code || code !== pendingCode) return;
    pendingCode = null;
    s.agents.unshift({ id: `agt_${Date.now()}`, name: "Claude on MacBook", client: "claude", created_at: new Date().toISOString(), last_used_at: new Date().toISOString() });
  }, ms);
}

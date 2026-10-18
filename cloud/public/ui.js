// Small shared helpers: escaping, icons, logos, time, toast.

export const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// Stroke icons, 24px grid, drawn at 1.6 weight (Lucide geometry, ISC).
const paths = {
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2.5"/><path d="M4 16V5a2 2 0 0 1 2-2h11"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  back: '<path d="m15 18-6-6 6-6"/>',
  down: '<path d="m6 9 6 6 6-6"/>',
  right: '<path d="m9 18 6-6-6-6"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3"/>',
  alert: '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 2.4 17.5A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>',
  out: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  app: '<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>',
  bot: '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 8V4M9 14h.01M15 14h.01"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4L21 8M21 3v5h-5"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  upload: '<path d="M12 15V4M7 9l5-5 5 5"/><path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  eyeoff: '<path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6C3.8 8.4 2 12 2 12s3.6 7 10 7a9.7 9.7 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  note: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h7M9 17h5"/>',
};
export const icon = (name, size = 16, cls = "") =>
  `<svg class="i ${cls}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name]}</svg>`;

export const spinner = (size = 14) => `<span class="spin" style="width:${size}px;height:${size}px" aria-hidden="true"></span>`;

// Logos: API logo_url, then Composio's logo CDN, then Simple Icons, then a neutral mark.
// Composio answers unknown slugs with a 200 grid placeholder (no CORS, so it can't be detected),
// so only slugs checked to have a real mark (17 Oct 2026) go to it. Everything else tries Simple Icons, which 404s honestly.
const composio = new Set(
  "gmail outlook googlecalendar calendly googledrive googledocs googlesheets notion dropbox github linear vercel supabase sentry slack discord whatsapp zoom asana trello jira airtable figma hubspot salesforce intercom stripe shopify youtube twitter linkedin grok cursor cloudflare".split(" "),
);
// Composio's Claude and OpenAI marks are app icons with their own backing; the flat marks sit better on our tile.
const local = { openai: "/logos/openai.svg" };
const alias = { "claude-code": "claude", codex: "openai", chatgpt: "openai" };
const simple = { twitter: "x", outlook: "microsoftoutlook" };
const known = (s) => composio.has(s) || s in local || s === "claude";

export function logoChain(slug, url) {
  const s = alias[String(slug || "").toLowerCase()] || String(slug || "").toLowerCase();
  const chain = [];
  if (url) chain.push(url);
  if (local[s]) return [...chain, local[s]];
  if (composio.has(s)) chain.push(`https://logos.composio.dev/api/${s}`);
  if (s) chain.push(`https://cdn.simpleicons.org/${encodeURIComponent(simple[s] || s)}`);
  return chain;
}

export function logo(slug, url, size = 40, name = "") {
  const chain = logoChain(slug, url);
  return `<span class="logo" style="--s:${size}px"><img src="${esc(chain[0])}" data-chain="${esc(chain.slice(1).join("|"))}" alt="${esc(name)}" width="${Math.round(size * 0.6)}" height="${Math.round(size * 0.6)}" decoding="async" draggable="false"></span>`;
}

// One capturing listener walks every logo down its chain; the last stop is the neutral mark.
document.addEventListener(
  "error",
  (e) => {
    const img = e.target;
    if (!(img instanceof HTMLImageElement) || !img.closest(".logo")) return;
    const rest = (img.dataset.chain || "").split("|").filter(Boolean);
    if (rest.length) {
      img.dataset.chain = rest.slice(1).join("|");
      img.src = rest[0];
    } else img.closest(".logo").innerHTML = icon("app", 18, "fallback");
  },
  true,
);

// Saved logins: the site's real mark when we know the brand, a plain globe otherwise. Never a guessed logo.
const sites = {
  "github.com": "github", "vercel.com": "vercel", "supabase.com": "supabase", "notion.so": "notion", "notion.com": "notion",
  "slack.com": "slack", "linear.app": "linear", "figma.com": "figma", "stripe.com": "stripe", "cloudflare.com": "cloudflare",
  "hubspot.com": "hubspot", "linkedin.com": "linkedin", "x.com": "twitter", "twitter.com": "twitter", "discord.com": "discord",
  "zoom.us": "zoom", "dropbox.com": "dropbox", "youtube.com": "youtube", "shopify.com": "shopify", "airtable.com": "airtable",
  "atlassian.net": "jira", "asana.com": "asana", "trello.com": "trello", "salesforce.com": "salesforce", "intercom.com": "intercom",
  "calendly.com": "calendly", "sentry.io": "sentry", "whatsapp.com": "whatsapp", "cursor.com": "cursor", "google.com": "gmail",
};
export function siteSlug(origin) {
  let host = "";
  try {
    host = new URL(origin).hostname.toLowerCase();
  } catch {
    return "";
  }
  const parts = host.split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const s = sites[parts.slice(i).join(".")];
    if (s) return s;
  }
  return "";
}
export const siteHost = (origin) => {
  try {
    return new URL(origin).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
};
export function siteLogo(origin, size = 36, kind = "login") {
  const s = siteSlug(origin);
  if (s) return logo(s, null, size, "");
  return `<span class="logo logo-dim" style="--s:${size}px">${icon(kind === "login" ? "globe" : "note", Math.round(size * 0.46))}</span>`;
}

const clientNames = { claude: "Claude", "claude-code": "Claude Code", codex: "Codex", chatgpt: "ChatGPT", grok: "Grok", cursor: "Cursor", hermes: "Hermes" };
export const clientName = (c) => clientNames[String(c || "").toLowerCase()] || c || "Agent";
export const agentLogo = (client, size = 36) => {
  const c = String(client || "").toLowerCase();
  if (known(alias[c] || c)) return logo(c, null, size, clientName(c));
  return `<span class="logo logo-dim" style="--s:${size}px">${icon("bot", Math.round(size * 0.48))}</span>`;
};

export function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  const n = (v, unit) => `${v} ${unit}${v === 1 ? "" : "s"} ago`;
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`;
  if (s < 86400) return n(Math.round(s / 3600), "hour");
  if (s < 86400 * 2) return "yesterday";
  if (s < 86400 * 7) return n(Math.floor(s / 86400), "day");
  return `on ${day(iso)}`;
}
export const day = (iso) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
export const clock = (iso) => new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });

let toastTimer;
export function toast(html, kind = "ok") {
  let el = document.getElementById("toast");
  el.className = `toast show ${kind}`;
  el.innerHTML = `${kind === "ok" ? icon("check", 15) : icon("alert", 15)}<span>${html}</span>`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
}

export const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

const json = (body, status = 200, extra = {}) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra } });
const hash = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map(b => b.toString(16).padStart(2, '0')).join('');
export async function onRequest({ request, env }) {
  if (request.method !== 'POST') return json({ error: 'Use POST.' }, 405, { Allow: 'POST' });
  const origin = request.headers.get('Origin');
  if (origin && origin !== new URL(request.url).origin) return json({ error: 'Please join from the RalX website.' }, 403);
  if (request.headers.get('Sec-Fetch-Site') === 'cross-site') return json({ error: 'Please join from the RalX website.' }, 403);
  if (Number(request.headers.get('Content-Length') || 0) > 2048) return json({ error: 'That request is too large.' }, 413);
  let data;
  try {
    const text = await request.text();
    if (new TextEncoder().encode(text).byteLength > 2048) return json({ error: 'That request is too large.' }, 413);
    const type = request.headers.get('Content-Type') || '';
    if (type.includes('application/json')) data = JSON.parse(text);
    else if (type.includes('application/x-www-form-urlencoded')) data = Object.fromEntries(new URLSearchParams(text));
    else return json({ error: 'Use JSON or form data.' }, 415);
  } catch { return json({ error: 'Please send a valid email address.' }, 400); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return json({ error: 'Please send a valid email address.' }, 400);
  if (data.website) return json({ ok: true });
  const email = typeof data.email === 'string' ? data.email.trim().toLowerCase() : '';
  if (email.length > 254 || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email)) return json({ error: 'Please enter a valid email address.' }, 400);
  if (!env.WAITLIST || typeof env.WAITLIST.get !== 'function' || typeof env.WAITLIST.put !== 'function') return json({ error: 'The waitlist is not ready yet. Please email hello@ralveto.com.' }, 503);
  try {
    // Basic abuse control. KV is eventually consistent, so this is not an atomic quota.
    const ip = request.headers.get('CF-Connecting-IP') || 'local';
    const minute = Math.floor(Date.now() / 60000);
    const rateKey = 'rate:' + await hash(ip + ':' + minute);
    if (await env.WAITLIST.get(rateKey)) return json({ error: 'Please wait a minute before trying again.' }, 429, { 'Retry-After': '60' });
    await env.WAITLIST.put(rateKey, '1', { expirationTtl: 120 });
    const key = 'email:' + await hash(email);
    if (!await env.WAITLIST.get(key)) await env.WAITLIST.put(key, JSON.stringify({ email, timestamp: new Date().toISOString() }));
    return json({ ok: true });
  } catch { return json({ error: 'That did not save. Please try again shortly.' }, 503); }
}

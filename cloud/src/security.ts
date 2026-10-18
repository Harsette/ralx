export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export const now = () => Math.floor(Date.now() / 1000);
export const iso = () => new Date().toISOString();
export function token(prefix = "") {
  return (
    prefix +
    Array.from(crypto.getRandomValues(new Uint8Array(32)), (x) =>
      x.toString(16).padStart(2, "0"),
    ).join("")
  );
}
export async function hash(value: string) {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
    (x) => x.toString(16).padStart(2, "0"),
  ).join("");
}
export function cookie(req: Request, name: string) {
  return req.headers
    .get("Cookie")
    ?.split(";")
    .map((x) => x.trim())
    .find((x) => x.startsWith(name + "="))
    ?.slice(name.length + 1);
}
export function setCookie(name: string, value: string, age: number) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
}
export async function body(req: Request) {
  if (
    !req.headers
      .get("Content-Type")
      ?.toLowerCase()
      .split(";",1)[0].trim().match(/^application\/json$/)
  )
    throw new HttpError(415, "Send application/json");
  if (Number(req.headers.get("Content-Length")) > 65536)
    throw new HttpError(413, "Request too large");
  const bytes = await boundedBytes(req, 65536);
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw 0;
    return value;
  } catch {
    throw new HttpError(400, "Invalid JSON object");
  }
}
export function origin(req: Request, base: string) {
  if (req.headers.get("Origin") !== base)
    throw new HttpError(403, "Open RalX to make this change");
}
export function text(value: unknown, max = 120) {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new HttpError(400, "Invalid text");
  return value.trim();
}
const sensitive =
  /^(?:authorization|cookie|set-cookie|token|secret|access_?token|refresh_?token|id_?token|client_?secret|api_?key|x-api-key|password|credentials|connection_data|custom_auth_params|custom_connection_data)$/i;
export async function boundedBytes(message: Request | Response, max: number) {
  const reader = message.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > max) {
      await reader.cancel();
      throw new HttpError(
        message instanceof Request ? 413 : 502,
        "Response or request too large",
      );
    }
    chunks.push(value);
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
export function scrub(value: unknown, secrets: string[], depth = 0): any {
  if (depth > 30) return "[withheld]";
  if (typeof value === "string") {
    let out = value;
    for (const s of secrets.filter(Boolean))
      out = out.split(s).join("[redacted]");
    return out.replace(
      /\b(?:sk_(?:live|test)_|ralx_)[A-Za-z0-9_-]{16,}/g,
      "[redacted]",
    );
  }
  if (Array.isArray(value))
    return value.map((v) => scrub(v, secrets, depth + 1));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        scrub(k, secrets, depth + 1),
        sensitive.test(k) ? "[redacted]" : scrub(v, secrets, depth + 1),
      ]),
    );
  return value;
}
async function encryptionKey(key: string) {
  return crypto.subtle.importKey(
    "raw",
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key)),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );
}
export async function seal(value: unknown, key: string, aad: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
    await encryptionKey(key),
    new TextEncoder().encode(JSON.stringify(value)),
  );
  const bytes = new Uint8Array(iv.length + data.byteLength);
  bytes.set(iv); bytes.set(new Uint8Array(data), iv.length);
  let binary = "";
  for (let offset=0;offset<bytes.length;offset+=32768)
    binary += String.fromCharCode(...bytes.subarray(offset,offset+32768));
  return btoa(binary);
}
export async function open(value: string, key: string, aad: string) {
  const bytes = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  return JSON.parse(
    new TextDecoder().decode(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: bytes.slice(0, 12),
          additionalData: new TextEncoder().encode(aad),
        },
        await encryptionKey(key),
        bytes.slice(12),
      ),
    ),
  );
}

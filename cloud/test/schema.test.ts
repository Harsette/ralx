import { test, expect } from "vitest";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import worker, { type Env } from "../src/index";

test("startup refuses pre-release vault schema with a plain recovery message", async () => {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('fixture')}}", d1Databases: ["DB"] }));
  try {
    const DB = await mf.getD1Database("DB");
    await DB.prepare("CREATE TABLE vault_items (id TEXT PRIMARY KEY, user_id TEXT, source_id TEXT, label TEXT, origin TEXT, kind TEXT, payload TEXT, created_at TEXT)").run();
    const e = { DB, BASE_URL: "https://example.invalid", ASSETS: { fetch: async () => new Response("fixture") } } as unknown as Env;
    const r = await worker.fetch(new Request("https://example.invalid/"), e);
    expect(r.status).toBe(503);
    expect(await r.json()).toEqual({ error: "this database has a pre-release vault table; recreate your local dev DB with npm run db:local" });
  } finally { await mf.dispose(); }
});

test("fresh database applies sealed 0003 and every later migration", async () => {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('fixture')}}", d1Databases: ["DB"] }));
  try {
    const DB = await mf.getD1Database("DB");
    for (const name of readdirSync(new URL("../migrations/", import.meta.url)).filter(n => n.endsWith(".sql")).sort())
      for (const sql of readFileSync(new URL("../migrations/" + name, import.meta.url), "utf8").split(";").filter(s => s.trim())) await DB.prepare(sql).run();
    const columns = (await DB.prepare("PRAGMA table_info(vault_items)").all()).results.map(c => c.name);
    expect(columns).toContain("updated_at");
    expect(columns).not.toContain("label");
    expect((await DB.prepare("SELECT * FROM device_authorizations").all()).results).toEqual([]);
    const e = { DB, BASE_URL: "https://example.invalid", ASSETS: { fetch: async () => new Response("fixture") } } as unknown as Env;
    expect((await worker.fetch(new Request("https://example.invalid/"), e)).status).toBe(200);
  } finally { await mf.dispose(); }
});

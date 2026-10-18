import { beforeAll, afterAll, beforeEach, afterEach, test, expect, vi } from "vitest";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync, readdirSync } from "node:fs";
import worker, { type Env } from "../src/index";
import { hash, now } from "../src/security";

const base = "https://ralx.example.invalid";
const clients = ["claude-code", "claude-desktop", "codex", "cursor", "vscode", "windsurf", "gemini", "antigravity"];
let mf: Miniflare, e: Env;
const logs: string[] = [];
async function request(path: string, data?: any, user = "", extra: Record<string,string> = {}) {
  return worker.fetch(new Request(base + path, {method: data === undefined ? "GET" : "POST", headers: {
    "Content-Type":"application/json", "CF-Connecting-IP":"192.0.2.1",
    ...(user ? {Cookie:"__Host-ralx=" + user, Origin:base} : {}), ...extra,
  }, ...(data === undefined ? {} : {body:JSON.stringify(data)})}), e);
}
async function issue() {
  const r = await request("/device/code", {machine_name:"Synthetic computer", clients});
  expect(r.status, await r.clone().text()).toBe(200);
  return await r.json() as any;
}
async function review(d: any, user = "alice") {
  const r = await request("/api/device?user_code=" + d.user_code, undefined, user);
  expect(r.status, await r.clone().text()).toBe(200);
  return await r.json() as any;
}
async function decide(d: any, action = "approve", user = "alice") {
  const page = await review(d, user);
  return request("/api/device/" + action, {user_code:d.user_code, csrf:page.csrf}, user);
}
async function poll(d: any) { return request("/device/token", {device_code:d.device_code}); }
beforeAll(async () => {
  mf = new Miniflare(convertV4MiniflareOptions({modules:true, script:"export default {fetch(){return new Response('fixture')}}", d1Databases:["DB"]}));
  e = {DB:await mf.getD1Database("DB"), BASE_URL:base, SESSION_SECRET:"synthetic-session", ENCRYPTION_KEY:"synthetic-key", WORKOS_CLIENT_ID:"synthetic-client", WORKOS_API_KEY:"synthetic-workos", ASSETS:{fetch:async()=>new Response("synthetic asset")}} as Env;
  for(const name of readdirSync(new URL("../migrations/", import.meta.url)).filter(n=>n.endsWith(".sql")).sort())
    for(const sql of readFileSync(new URL("../migrations/"+name,import.meta.url),"utf8").split(";").filter(s=>s.trim())) await e.DB.prepare(sql).run();
  for(const user of ["alice","bob"]) {
    await e.DB.prepare("INSERT INTO users(id,email) VALUES (?,?)").bind(user,user+"@example.invalid").run();
    await e.DB.prepare("INSERT INTO sessions(hash,user_id,expires) VALUES (?,?,?)").bind(await hash(user+e.SESSION_SECRET),user,now()+3600).run();
  }
});
beforeEach(async()=>{
  for(const table of ["device_clients","device_authorizations","agents","activity","limits"]) {
    try { await e.DB.prepare("DELETE FROM "+table).run(); } catch {}
  }
  logs.length=0;
  vi.spyOn(console,"log").mockImplementation((...args)=>logs.push(args.join(" ")));
  vi.spyOn(console,"error").mockImplementation((...args)=>logs.push(args.join(" ")));
});
afterEach(()=>vi.restoreAllMocks());
afterAll(async()=>{await mf.dispose();});

test("device happy path creates eight separate revocable identities and consumes codes",async()=>{
  const d=await issue();
  expect(d).toMatchObject({expires_in:600,interval:5,verification_uri:base+"/device"});
  expect(d.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXYZ23456789]{4}-[BCDFGHJKLMNPQRSTVWXYZ23456789]{4}$/);
  expect(new URL(d.verification_uri_complete).origin).toBe(base);
  expect((await review(d)).clients).toEqual(clients);
  expect((await decide(d)).status).toBe(200);
  const grant=await(await poll(d)).json() as any;
  expect(grant.machine_grant).toBeTruthy();expect(grant.expires_in).toBe(120);
  expect((await poll(d)).status).toBe(400);
  expect((await decide(d)).status).toBe(409);
  const keys=[];
  for(const client of clients){
    const r=await request("/device/enroll",{machine_grant:grant.machine_grant,client});
    expect(r.status,await r.clone().text()).toBe(200);keys.push((await r.json() as any).key);
  }
  expect(new Set(keys).size).toBe(8);
  expect((await request("/device/enroll",{machine_grant:grant.machine_grant,client:clients[0]})).status).toBe(400);
  const agents=await(await request("/api/agents",undefined,"alice")).json() as any;
  expect(agents.agents).toHaveLength(8);
  const rows=JSON.stringify((await e.DB.prepare("SELECT * FROM device_authorizations").all()).results);
  for(const secret of [d.device_code,d.user_code,d.user_code.replace("-",""),grant.machine_grant,...keys]) expect(rows).not.toContain(secret);
  const audit=JSON.stringify((await e.DB.prepare("SELECT * FROM activity").all()).results);
  expect(audit).toContain("device.approve");
  for(const secret of [d.device_code,d.user_code,grant.machine_grant,...keys]) {expect(audit).not.toContain(secret);expect(logs.join("\n")).not.toContain(secret);}
});
test("device denial is terminal and audited without codes",async()=>{
  const d=await issue();expect((await decide(d,"deny")).status).toBe(200);
  expect(await(await poll(d)).json()).toMatchObject({error:"access_denied"});
  expect((await decide(d)).status).toBe(409);
  const audit=JSON.stringify((await e.DB.prepare("SELECT * FROM activity").all()).results);
  expect(audit).toContain("device.deny");expect(audit).not.toContain(d.user_code);
});
test("device expiry prevents review polling approval and grant exchange",async()=>{
  const d=await issue();const page=await review(d);
  await e.DB.prepare("UPDATE device_authorizations SET expires=0").run();
  expect(await(await poll(d)).json()).toMatchObject({error:"expired_token"});
  expect((await request("/api/device?user_code="+d.user_code,undefined,"alice")).status).toBe(400);
  expect((await request("/api/device/approve",{user_code:d.user_code,csrf:page.csrf},"alice")).status).toBe(400);
  const next=await issue();await decide(next);const grant=await(await poll(next)).json() as any;
  await e.DB.prepare("UPDATE device_authorizations SET grant_expires=0").run();
  expect((await request("/device/enroll",{machine_grant:grant.machine_grant,client:"codex"})).status).toBe(400);
});
test("device polling returns pending and persistent slow_down",async()=>{
  const d=await issue();expect(await(await poll(d)).json()).toMatchObject({error:"authorization_pending"});
  expect(await(await poll(d)).json()).toMatchObject({error:"slow_down",interval:10});
  expect(await(await poll(d)).json()).toMatchObject({error:"slow_down",interval:15});
});
test("device review binds the approving user and rejects wrong user and session",async()=>{
  const d=await issue();const page=await review(d);
  expect((await request("/api/device?user_code="+d.user_code,undefined,"bob")).status).toBe(403);
  expect((await request("/api/device/approve",{user_code:d.user_code,csrf:page.csrf},"bob")).status).toBe(403);
  expect((await request("/api/device/approve",{user_code:d.user_code,csrf:page.csrf})).status).toBe(401);
});
test("device approval rejects cross-origin missing-CSRF and form submissions",async()=>{
  const d=await issue();const page=await review(d);
  expect((await request("/api/device/approve",{user_code:d.user_code,csrf:page.csrf},"alice",{Origin:"https://evil.invalid"})).status).toBe(403);
  expect((await request("/api/device/deny",{user_code:d.user_code},"alice")).status).toBe(403);
  expect((await request("/api/device/approve",{user_code:d.user_code,csrf:page.csrf},"alice",{"Content-Type":"text/plain"})).status).toBe(415);
  expect((await decide(d)).status).toBe(200);
});
test("device brute force is limited per IP and user code across IPs",async()=>{
  for(let i=0;i<10;i++) await request("/api/device?user_code=BCDF-GHJK",undefined,"alice",{"CF-Connecting-IP":"192.0.2."+(i+2)});
  expect((await request("/api/device?user_code=BCDF-GHJK",undefined,"alice",{"CF-Connecting-IP":"192.0.2.99"})).status).toBe(429);
  for(let i=0;i<10;i++) await request("/device/code",{machine_name:"Synthetic",clients});
  expect((await request("/device/code",{machine_name:"Synthetic",clients})).status).toBe(429);
});
test("device grant cannot enroll an unapproved client or authenticate MCP",async()=>{
  const d=await issue();await decide(d);const g=await(await poll(d)).json() as any;
  expect((await request("/device/enroll",{machine_grant:g.machine_grant,client:"attacker"})).status).toBe(400);
  expect((await request("/mcp",{jsonrpc:"2.0",id:1,method:"initialize"},"",{Authorization:"Bearer "+g.machine_grant})).status).toBe(401);
});

test("device slow_down persists but a correctly spaced poll can complete approval",async()=>{
  const d=await issue();await poll(d);await poll(d);
  await decide(d);
  expect(await(await poll(d)).json()).toMatchObject({error:"slow_down",interval:15});
  await e.DB.prepare("UPDATE device_authorizations SET next_poll=0").run();
  expect((await(await poll(d)).json() as any).machine_grant).toBeTruthy();
});

test("device concurrent token and client redemption each issue exactly one credential",async()=>{
  const d=await issue();await decide(d);
  const responses=await Promise.all([poll(d),poll(d)]);
  expect(responses.filter(r=>r.status===200)).toHaveLength(1);
  const g=await responses.find(r=>r.status===200)!.json() as any;
  const enroll=()=>request("/device/enroll",{machine_grant:g.machine_grant,client:"codex"});
  const redeemed=await Promise.all([enroll(),enroll()]);
  expect(redeemed.map(r=>r.status).sort()).toEqual([200,400]);
  expect((await e.DB.prepare("SELECT count(*) AS n FROM agents").first<any>()).n).toBe(1);
});

test("device WorkOS login preserves review URL without storing human code or allowing foreign returns",async()=>{
  const d=await issue();
  const login=await request("/login?device="+d.user_code);
  expect(login.status).toBe(302);
  const cookies=login.headers.getSetCookie();
  expect(cookies.some(c=>c.startsWith("__Host-ralx-device="+d.user_code))).toBe(true);
  const state=new URL(login.headers.get("Location")!).searchParams.get("state")!;
  const states=JSON.stringify((await e.DB.prepare("SELECT * FROM oauth_states").all()).results);
  expect(states).not.toContain(d.user_code);
  vi.spyOn(globalThis,"fetch").mockResolvedValue(Response.json({user:{id:"alice",email:"alice@example.invalid",first_name:"Synthetic"}}));
  const callback=await worker.fetch(new Request(base+"/callback?state="+state+"&code=synthetic",{headers:{Cookie:cookies.map(c=>c.split(";")[0]).join("; ")}}),e);
  expect(callback.status,await callback.clone().text()).toBe(302);
  expect(callback.headers.get("Location")).toBe("/device?user_code="+d.user_code);
  expect((await request("/login?device=https://evil.invalid/")).status).toBe(400);
});

import type { Env } from "./index";
import { HttpError, body, cookie, hash, iso, now, origin, text, token } from "./security";

// Device secrets, human codes and machine grants are only persisted as hashes.
// A grant authorizes exactly one enrollment for each reviewed client, for 120s.
const clients = new Set(["claude-code", "claude-desktop", "codex", "cursor", "vscode", "windsurf", "gemini", "antigravity"]);
type Dependencies = {
  owner: (r: Request, e: Env) => Promise<{id:string}>;
  limited: (e: Env, key: string, max: number) => Promise<void>;
};
type Device = {device_hash:string; user_hash:string; machine_name:string; clients:string; expires:number; interval:number; next_poll:number; status:string; user_id:string|null};
const json = (value: unknown, status = 200) => Response.json(value, {status, headers:{"Cache-Control":"no-store"}});
function code(value: unknown) {
  const s = text(value, 9).toUpperCase().replace("-", "");
  if (!/^[BCDFGHJKLMNPQRSTVWXYZ23456789]{8}$/.test(s)) throw new HttpError(400,"Enter the code shown in your terminal");
  return s;
}
const csrf = (req:Request,e:Env,d:Device) => hash("device-csrf:"+cookie(req,"__Host-ralx")+":"+e.SESSION_SECRET+":"+d.device_hash);

export async function deviceRoute(req: Request, e: Env, deps: Dependencies): Promise<Response | undefined> {
  const url = new URL(req.url), p=url.pathname;
  if (!["/device/code","/device/token","/device/enroll","/api/device","/api/device/approve","/api/device/deny"].includes(p)) return;
  const ip = await hash(req.headers.get("CF-Connecting-IP") || "unknown");
  if(req.headers.has("Origin")) origin(req,e.BASE_URL);
  if (p === "/device/code" && req.method === "POST") {
    await deps.limited(e,"device-issue:"+ip,10);
    const b=await body(req), machine=text(b.machine_name,120);
    if (/[\x00-\x1f\x7f]/.test(machine)) throw new HttpError(400,"Invalid computer name");
    if(!Array.isArray(b.clients) || !b.clients.length || b.clients.length>clients.size || b.clients.some((c:unknown)=>typeof c!=="string" || !clients.has(c)) || new Set(b.clients).size!==b.clients.length)
      throw new HttpError(400,"Choose installed RalX clients");
    const device=token("dc_"), alphabet="BCDFGHJKLMNPQRSTVWXYZ23456789";
    // Rejection sampling avoids modulo bias.
    let human="";
    while(human.length<8) for(const n of crypto.getRandomValues(new Uint8Array(16))) if(n<Math.floor(256/alphabet.length)*alphabet.length && human.length<8) human+=alphabet[n%alphabet.length];
    const dh=await hash(device), uh=await hash(human);
    // Delete old requests and their unused slots together. No secret appears here.
    await e.DB.batch([
      e.DB.prepare("DELETE FROM device_clients WHERE device_hash IN (SELECT device_hash FROM device_authorizations WHERE expires<?)").bind(now()-86400),
      e.DB.prepare("DELETE FROM device_authorizations WHERE expires<?").bind(now()-86400),
      e.DB.prepare("INSERT INTO device_authorizations(device_hash,user_hash,machine_name,clients,expires) VALUES (?,?,?,?,?)").bind(dh,uh,machine,JSON.stringify(b.clients),now()+600),
      ...b.clients.map((c:string)=>e.DB.prepare("INSERT INTO device_clients(device_hash,client) VALUES (?,?)").bind(dh,c)),
    ]);
    const user_code=human.slice(0,4)+"-"+human.slice(4);
    return json({device_code:device,user_code,verification_uri:e.BASE_URL+"/device",verification_uri_complete:e.BASE_URL+"/device?user_code="+user_code,interval:5,expires_in:600});
  }
  if(p === "/device/token" && req.method === "POST") {
    await deps.limited(e,"device-poll:"+ip,120);
    const b=await body(req), dh=await hash(text(b.device_code,100)), n=now();
    // One atomic update serializes concurrent polls and increases the interval.
    const d=await e.DB.prepare("UPDATE device_authorizations SET polled_early=CASE WHEN next_poll>? THEN 1 ELSE 0 END,interval=CASE WHEN next_poll>? THEN interval+5 ELSE interval END,next_poll=?+CASE WHEN next_poll>? THEN interval+5 ELSE interval END WHERE device_hash=? AND status IN ('pending','approved','denied') RETURNING *")
      .bind(n,n,n,n,dh).first<Device & {polled_early:number}>();
    if(!d) return json({error:"invalid_grant"},400);
    if(d.expires<=n) return json({error:"expired_token"},400);
    if(d.status==="denied") return json({error:"access_denied"},400);
    if(d.polled_early) return json({error:"slow_down",interval:d.interval},400);
    if(d.status==="pending") return json({error:"authorization_pending",interval:d.interval},400);
    const grant=token("mg_");
    const consumed=await e.DB.prepare("UPDATE device_authorizations SET status='consumed',grant_hash=?,grant_expires=? WHERE device_hash=? AND status='approved' RETURNING device_hash")
      .bind(await hash(grant),n+120,dh).first();
    if(!consumed) return json({error:"invalid_grant"},400);
    return json({machine_grant:grant,expires_in:120});
  }
  if(p === "/device/enroll" && req.method === "POST") {
    await deps.limited(e,"device-enroll:"+ip,60);
    const b=await body(req), gh=await hash(text(b.machine_grant,100)), client=text(b.client,40);
    // DELETE RETURNING atomically consumes this client's slot, just like /api/enroll.
    const slot=await e.DB.prepare("DELETE FROM device_clients WHERE client=? AND device_hash IN (SELECT device_hash FROM device_authorizations WHERE grant_hash=? AND status='consumed' AND grant_expires>?) RETURNING device_hash")
      .bind(client,gh,now()).first<{device_hash:string}>();
    if(!slot) return json({error:"invalid_grant"},400);
    const d=await e.DB.prepare("SELECT user_id FROM device_authorizations WHERE device_hash=?").bind(slot.device_hash).first<{user_id:string}>();
    const key=token("ralx_"), id=token("ag_");
    await e.DB.prepare("INSERT INTO agents(id,user_id,hash,name,client,created_at) VALUES (?,?,?,?,?,?)")
      .bind(id,d!.user_id,await hash(key),"setup-"+client,client,iso()).run();
    return json({key,base_url:e.BASE_URL,mcp_url:e.BASE_URL+"/mcp"});
  }
  if(p.startsWith("/api/device")) {
    const user=await deps.owner(req,e);
    await deps.limited(e,"device-review-ip:"+ip,30);
    const b=req.method==="GET"?{user_code:url.searchParams.get("user_code")}:await body(req);
    if(req.method!=="GET") origin(req,e.BASE_URL);
    const uh=await hash(code(b.user_code));
    await deps.limited(e,"device-review-code:"+uh,10);
    const d=await e.DB.prepare("UPDATE device_authorizations SET user_id=COALESCE(user_id,?) WHERE user_hash=? AND expires>? RETURNING *")
      .bind(user.id,uh,now()).first<Device>();
    if(!d) throw new HttpError(400,"Code expired or not found. Run setup again.");
    if(d.user_id!==user.id) throw new HttpError(403,"This request belongs to another signed-in user");
    if(p==="/api/device" && req.method==="GET") return json({machine_name:d.machine_name,clients:JSON.parse(d.clients),status:d.status,expires_at:d.expires,csrf:await csrf(req,e,d)});
    if(req.method==="POST" && (p.endsWith("/approve") || p.endsWith("/deny"))) {
      if(b.csrf!==await csrf(req,e,d)) throw new HttpError(403,"Refresh this page before connecting");
      const status=p.endsWith("/approve")?"approved":"denied";
      // Decision and audit are one transaction. No names or codes in the audit.
      const decision=token("decision_");
      const results=await e.DB.batch([
        e.DB.prepare("UPDATE device_authorizations SET status=?,grant_hash=? WHERE device_hash=? AND user_id=? AND status='pending' AND expires>?").bind(status,decision,d.device_hash,user.id,now()),
        e.DB.prepare("INSERT INTO activity(user_id,at,agent,tool,account,outcome) SELECT user_id,?,'Computer setup',?,'',? FROM device_authorizations WHERE device_hash=? AND grant_hash=?")
          .bind(iso(),status==="approved"?"device.approve":"device.deny",status,d.device_hash,decision),
      ]);
      if(!results[0].meta.changes) throw new HttpError(409,"Request already handled");
      return json({ok:true,status});
    }
  }
  throw new HttpError(405,"Method not allowed");
}

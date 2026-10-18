import {test,expect} from "vitest";
import {build} from "esbuild";
import {Miniflare,convertV4MiniflareOptions} from "miniflare";
import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";
import {hash,now,open} from "../src/security";

test("actual Workers runtime completes native Google OAuth, reads both services and rejects redirects",async()=>{
  // Test-only wrapper times the production decrypt function inside workerd.
  const bundle=await build({stdin:{resolveDir:fileURLToPath(new URL("../src/",import.meta.url)),contents:`
    import worker from './index.ts';import {open} from './security.ts';
    export default {async fetch(req,e){
      if(new URL(req.url).pathname==='/synthetic-decrypt-benchmark'){
        const rows=(await e.DB.prepare("SELECT id,payload FROM vault_items WHERE user_id='runtime' ORDER BY id LIMIT 1000").all()).results;
        const start=performance.now();let count=0;
        for(const row of rows){const fields=await open(row.payload,e.ENCRYPTION_KEY,'vault:'+row.id+':runtime');if(fields.password.startsWith('synthetic-runtime-password-')&&fields.label&&fields.origin)count++;}
        return Response.json({count,decrypt_ms:performance.now()-start});
      }
      return worker.fetch(req,e);
    }};`},bundle:true,write:false,format:"esm",platform:"browser",target:"es2022"});
  let redirect=false, outboundFailure="";
  const urls:string[]=[];
  const base="https://ralx.example.invalid";
  const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:bundle.outputFiles[0].text,
    compatibilityDate:"2026-10-17",d1Databases:["DB"],bindings:{BASE_URL:base,GOOGLE_CLIENT_ID:"synthetic-client",GOOGLE_CLIENT_SECRET:"synthetic-private",SESSION_SECRET:"synthetic-session",ENCRYPTION_KEY:"synthetic-encryption"},
    outboundService:async(request:Request)=>{
      try {
      const u=new URL(request.url);urls.push(request.url);
      if(u.origin==="https://oauth2.googleapis.com") {
        const body=new URLSearchParams(await request.text());expect(body.get("code_verifier")).toBeTruthy();
        return Response.json({access_token:"synthetic-google-access",refresh_token:"synthetic-google-refresh",expires_in:3600,scope:"openid email https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive"});
      }
      if(u.origin==="https://openidconnect.googleapis.com") return Response.json({sub:"synthetic-sub",email:"runtime@example.invalid",email_verified:true});
      expect(request.headers.get("Authorization")).toBe("Bearer synthetic-google-access");
      if(redirect) return new Response(null,{status:302,headers:{Location:"https://attacker.invalid/"}});
      if(u.pathname==="/gmail/v1/users/me/profile") return Response.json({emailAddress:"runtime@example.invalid",messagesTotal:3});
      if(u.pathname==="/drive/v3/about") return Response.json({user:{emailAddress:"runtime@example.invalid"}});
      throw Error("Unexpected destination");
      } catch(err) {outboundFailure=String(err);return Response.json({error:"synthetic fixture failed"},{status:500});}
    },
  } as any));
  try {
    const db=await mf.getD1Database("DB");
    for(const name of ["0001_initial.sql","0002_native_accounts.sql","0003_private_vault.sql"])
      for(const statement of readFileSync(new URL("../migrations/"+name,import.meta.url),"utf8").split(";").filter(x=>x.trim())) await db.prepare(statement).run();
    await db.prepare("INSERT INTO users(id,email) VALUES ('runtime','runtime@example.invalid')").run();
    await db.prepare("INSERT INTO sessions(hash,user_id,expires) VALUES (?,'runtime',?)").bind(await hash("synthetic-cookie"+"synthetic-session"),now()+3600).run();
    const ownerHeaders={Cookie:"__Host-ralx=synthetic-cookie",Origin:base,"Content-Type":"application/json"};
    // Exercise encryption and grouped D1 bindings in workerd, not only Node.
    const csv="name,url,username,password\n"+Array.from({length:5000},(_,i)=>`Synthetic ${i},https://site${i}.invalid,u${i},synthetic-runtime-password-${i}`).join("\n");
    const imported=await mf.dispatchFetch(base+"/api/vault/import?format=chrome-csv",{method:"POST",headers:{...ownerHeaders,"Content-Type":"application/octet-stream"},body:csv});
    expect(imported.status,await imported.clone().text()).toBe(200);
    expect(await imported.json()).toMatchObject({imported:5000,logins:5000});
    expect((await db.prepare("SELECT count(*) n FROM vault_items").first<any>()).n).toBe(5000);
    const metadata=await(await mf.dispatchFetch(base+"/api/vault",{headers:ownerHeaders})).text();
    expect(metadata).not.toContain("synthetic-runtime-password");
    const timing=await(await mf.dispatchFetch(base+"/synthetic-decrypt-benchmark")).json() as any;
    expect(timing.count).toBe(1000);expect(timing.decrypt_ms).toBeGreaterThanOrEqual(0);
    console.log(`WORKER_DECRYPT_1000 count=${timing.count} decrypt_ms=${timing.decrypt_ms}`);
    // Workers may freeze performance.now between I/O events. Also measure the
    // identical production decrypt loop with Node's advancing high-resolution clock.
    const encrypted=(await db.prepare("SELECT id,payload FROM vault_items ORDER BY id LIMIT 1000").all<any>()).results;
    const decryptStart=performance.now();let decrypted=0;
    for(const row of encrypted){const fields=await open(row.payload,"synthetic-encryption",`vault:${row.id}:runtime`);expect(fields.label).toBeTruthy();expect(fields.origin).toBeTruthy();decrypted++;}
    expect(decrypted).toBe(1000);
    console.log(`NODE_DECRYPT_1000 count=${decrypted} wall_ms=${(performance.now()-decryptStart).toFixed(2)}`);
    const pageStart=performance.now();
    const page=await(await mf.dispatchFetch(base+"/api/vault?limit=1000",{headers:ownerHeaders})).json() as any;
    expect(page.items).toHaveLength(1000);expect(page.next_cursor).toBeTruthy();
    console.log(`WORKER_LIST_1000 items=${page.items.length} wall_ms=${(performance.now()-pageStart).toFixed(2)}`);
    const start=await(await mf.dispatchFetch(base+"/api/connectors/gmail/connect",{method:"POST",headers:ownerHeaders,body:"{}"})).json() as any;
    const state=new URL(start.redirect_url).searchParams.get("state")!;
    const callback=await mf.dispatchFetch(base+"/oauth/google/callback?state="+state+"&code=synthetic",{headers:ownerHeaders,redirect:"manual"});
    expect(callback.status,outboundFailure+await callback.clone().text()).toBe(302);
    const row=await db.prepare("SELECT * FROM native_accounts").first<any>();
    expect(row.payload).not.toContain("synthetic-google-refresh");
    const prompt=await(await mf.dispatchFetch(base+"/api/agents/prompt",{method:"POST",headers:ownerHeaders,body:"{}"})).json() as any;
    const enrolled=await(await mf.dispatchFetch(base+"/api/enroll",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:prompt.code})})).json() as any;
    for(const tool of ["GMAIL_GET_PROFILE","GOOGLEDRIVE_GET_ABOUT"]){
      const r=await mf.dispatchFetch(base+"/api/v1/call",{method:"POST",headers:{Authorization:"Bearer "+enrolled.key,"Content-Type":"application/json"},body:JSON.stringify({tool,args:{},account:row.id})});
      expect(r.status,await r.clone().text()).toBe(200);
      const output=await r.text();expect(output).toContain("runtime@example.invalid");expect(output).not.toContain("synthetic-google-access");
    }
    redirect=true;
    const rejected=await mf.dispatchFetch(base+"/api/v1/call",{method:"POST",headers:{Authorization:"Bearer "+enrolled.key,"Content-Type":"application/json"},body:JSON.stringify({tool:"GMAIL_GET_PROFILE",args:{},account:row.id})});
    expect(rejected.status).toBe(502);
    expect(urls.some(url=>url.startsWith("https://attacker.invalid"))).toBe(false);
  } finally {await mf.dispose();}
},60000);

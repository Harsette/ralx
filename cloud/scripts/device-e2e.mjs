// Local-only synthetic proof. Browser driver opens ready.json's signin URL,
// approves once, checks Agents, revokes Codex, then visits /fixture/finish.
// No installed daemon, real HOME, credentials or network providers are used.
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { createHash } from "node:crypto";
import { createServer } from "node:net";
import { mkdtemp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";

const cloud=fileURLToPath(new URL("../",import.meta.url));
const binary=path.resolve(process.argv[2] || path.join(cloud,"../tmp/device-proof/ralx.exe"));
const proof=path.resolve(cloud,"../tmp/device-proof");await mkdir(proof,{recursive:true});
const home=await mkdtemp(path.join(tmpdir(),"ralx-device-synthetic-"));
const appdata=path.join(home,"AppData","Roaming");
const env={...process.env,HOME:home,USERPROFILE:home,APPDATA:appdata,LOCALAPPDATA:path.join(home,"AppData","Local"),XDG_CONFIG_HOME:path.join(home,".config"),RALX_SETUP_SANDBOX:"1",RALX_SETUP_ADDR:"127.0.0.1:17329",RALX_SETUP_NO_BROWSER:"1",RALX_AGENT_KEY:"",RALX_AGENT_KEY_FILE:"",RALX_URL:"",CLAUDE_CONFIG_DIR:"",CODEX_HOME:""};
const files={
 "claude-code":path.join(home,".claude.json"),
 "claude-desktop":path.join(appdata,"Claude","claude_desktop_config.json"),
 codex:path.join(home,".codex","config.toml"),cursor:path.join(home,".cursor","mcp.json"),
 vscode:path.join(appdata,"Code","User","mcp.json"),windsurf:path.join(home,".codeium","windsurf","mcp_config.json"),gemini:path.join(home,".gemini","settings.json"),antigravity:path.join(home,".gemini","config","mcp_config.json"),
};
const originals={};
for(const [name,file] of Object.entries(files)) {
  await mkdir(path.dirname(file),{recursive:true});if(name==="claude-code")await mkdir(path.join(home,".claude"));
  originals[name]=name==="codex"?"# keep byte-identical\r\nmodel='synthetic'\r\n":"{\r\n  \"synthetic_keep\": true\r\n}\r\n";
  await writeFile(file,originals[name]);
}
const socket=createServer();await new Promise(r=>socket.listen(0,"127.0.0.1",r));const port=socket.address().port;await new Promise(r=>socket.close(r));
assert.notEqual(port,7317);const base=`http://127.0.0.1:${port}`;
const session="synthetic-device-browser-session",secret="synthetic-device-session-secret";
const bundle=await build({stdin:{resolveDir:path.join(cloud,"src"),contents:`
import worker from './index.ts';
export default {async fetch(req,e){
 if(new URL(req.url).pathname==='/fixture/session')return new Response(null,{status:302,headers:{Location:'/device'+new URL(req.url).search,'Set-Cookie':'__Host-ralx=${session}; Secure; HttpOnly; SameSite=Lax; Path=/'}});
 return worker.fetch(req,e);
}};`},bundle:true,write:false,format:"esm",platform:"browser",target:"es2022"});
const appLogs=[];let finish;
const finished=new Promise(r=>finish=r);
const types={".html":"text/html",".js":"text/javascript",".css":"text/css",".woff2":"font/woff2",".svg":"image/svg+xml"};
const mf=new Miniflare(convertV4MiniflareOptions({host:"127.0.0.1",port,modules:true,script:bundle.outputFiles[0].text,compatibilityDate:"2026-10-17",d1Databases:["DB"],
 bindings:{BASE_URL:base,WORKOS_CLIENT_ID:"synthetic",WORKOS_API_KEY:"synthetic",SESSION_SECRET:secret,ENCRYPTION_KEY:"synthetic-device-encryption"},
 handleStructuredLogs:entry=>appLogs.push(JSON.stringify(entry)),
 serviceBindings:{ASSETS:async req=>{
  const u=new URL(req.url);
  if(u.pathname==="/fixture/finish"){finish();return new Response("Synthetic proof finishing");}
  const name=u.pathname==="/"?"/index.html":u.pathname;
  const file=path.resolve(cloud,"public","."+name);
  if(!file.startsWith(path.join(cloud,"public")+path.sep))return new Response("Not found",{status:404});
  try{return new Response(await readFile(file),{headers:{"Content-Type":types[path.extname(file)]||"application/octet-stream"}});}catch{return new Response("Not found",{status:404});}
 }},outboundService:()=>{throw Error("Synthetic proof forbids external providers");},
}));
const sha=v=>createHash("sha256").update(v).digest("hex");
const transcript=[];const note=s=>{transcript.push(s);console.log(s);};
let setup;
try {
 await mf.ready;const db=await mf.getD1Database("DB");
 for(const file of (await readdir(path.join(cloud,"migrations"))).filter(n=>n.endsWith(".sql")).sort())for(const sql of (await readFile(path.join(cloud,"migrations",file),"utf8")).split(";").filter(s=>s.trim()))await db.prepare(sql).run();
 await db.prepare("INSERT INTO users(id,email,name) VALUES ('synthetic-device','synthetic-device@example.invalid','Synthetic User')").run();
 await db.prepare("INSERT INTO sessions(hash,user_id,expires) VALUES (?,'synthetic-device',?)").bind(sha(session+secret),Math.floor(Date.now()/1000)+3600).run();
 setup=spawn(binary,["setup","--mode","cloud","--url",base,"--clients","all","--yes","--no-browser"],{env,windowsHide:true});
 let output="",ready=false;setup.stdout.on("data",chunk=>{
  output+=chunk;
  const match=output.match(/Connect this computer: (http[^\r\n]+)/);
  if(match&&!ready){ready=true;const url=new URL(match[1]);writeFile(path.join(proof,"ready.json"),JSON.stringify({base,home,signin:base+"/fixture/session"+url.search,verify:match[1]}));note("DEVICE_REQUEST_READY: 8 clients, browser approval required even with --yes");}
 });setup.stderr.on("data",chunk=>output+=chunk);
 const setupDone=new Promise((resolve,reject)=>setup.once("exit",code=>code===0?resolve():reject(Error("setup failed: "+output))));
 await setupDone;
 const ok=(output.match(/^\[OK\] \S+\s+ready$/gm)||[]).length;assert.equal(ok,8);note("SETUP: 8/8 configs written with separate identities; no local daemon");
 const keys=[];for(const name of Object.keys(files)){const identity=JSON.parse(await readFile(path.join(home,".ralx","agents","setup-"+name+".json"),"utf8"));keys.push(identity.Key||identity.key);}
 assert.equal(new Set(keys).size,8);
 // Read actual registrations, then execute their exact command, args and env.
 async function handshake(name,expectSuccess=true){
  const source=await readFile(files[name],"utf8");let config;
  if(name==="claude-code")config=JSON.parse(source).mcpServers.ralx;
  else {
   const block=source.slice(source.indexOf("[mcp_servers.ralx]"));
   const value=k=>{const m=block.match(new RegExp("^"+k+"\\s*=\\s*(['\\\"])(.*?)\\1","m"));assert(m,k);return m[1]==='"'?JSON.parse(m[1]+m[2]+m[1]):m[2];};
   const args=block.match(/^args\s*=\s*\[(.*?)\]/m)[1].match(/['"]([^'"]+)['"]/g).map(x=>x.slice(1,-1));
   config={command:value("command"),args,env:{RALX_AGENT_KEY_FILE:value("RALX_AGENT_KEY_FILE")}};
  }
  const child=spawn(config.command,config.args,{env:{...env,...config.env},windowsHide:true});let out="";child.stdout.on("data",v=>out+=v);child.stderr.resume();
  child.stdin.end(JSON.stringify({jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-03-26",capabilities:{},clientInfo:{name:"synthetic-proof",version:"1"}}})+"\n"+JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/list"})+"\n");
  const exit=await new Promise(r=>child.once("exit",r));
  if(expectSuccess){assert.equal(exit,0);const replies=out.trim().split("\n").map(x=>JSON.parse(x));assert.equal(replies[0].result.serverInfo.name,"ralx");assert(replies[1].result.tools.some(t=>t.name==="RALX_ACCOUNTS"));}
  else {assert.notEqual(exit,0);assert.equal(out,"");}
 }
 await handshake("codex");await handshake("claude-code");note("MCP: actual Codex + Claude Code registrations -> initialize + tools/list PASS");
 note("BROWSER_NEXT: open /#agents, verify 8 agents, revoke setup-codex, then /fixture/finish");
 await finished;
 const rows=(await db.prepare("SELECT client,revoked FROM agents ORDER BY client").all()).results;assert.equal(rows.length,8);assert.equal(rows.filter(r=>r.revoked).length,1);assert.equal(rows.find(r=>r.client==="codex").revoked,1);
 await handshake("codex",false);await handshake("claude-code");
 for(let i=0;i<keys.length;i++){const r=await fetch(base+"/mcp",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+keys[i]},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list"})});assert.equal(r.status,Object.keys(files)[i]==="codex"?401:200);}
 note("REVOKE: Codex next MCP call refused; all other 7 identities still work");
 const uninstall=spawn(binary,["uninstall"],{env,windowsHide:true});uninstall.stdout.resume();uninstall.stderr.resume();assert.equal(await new Promise(r=>uninstall.once("exit",r)),0);
 for(const [name,file] of Object.entries(files))assert.equal(await readFile(file,"utf8"),originals[name]);
 note("UNINSTALL: all 8 original configs restored byte-identical");
 const codes=output.match(/Code: ([^\r\n]+)/)?.[1];assert(!appLogs.join("\n").includes(codes));
 const audit=JSON.stringify((await db.prepare("SELECT * FROM activity").all()).results);assert(!audit.includes(codes));for(const key of keys)assert(!audit.includes(key));
 note("LOGS: browser code + agent credentials absent from Worker application logs and audit");
 await writeFile(path.join(proof,"e2e-transcript.txt"),transcript.join("\n")+"\n");
}finally{if(setup?.exitCode===null)setup.kill();await mf.dispose();}

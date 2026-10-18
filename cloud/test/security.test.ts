import {
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
  test,
  expect,
  vi,
} from "vitest";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { createHash } from "node:crypto";
import worker, { type Env, enrollmentPrompt } from "../src/index";
import { spawnSync } from "node:child_process";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { hash, token, now, seal, open, scrub } from "../src/security";
import { testSummary } from "../src/providers";
import { zipSync, strToU8, deflateSync } from "fflate";
import { importVault, MAX_IMPORT } from "../src/private-vault";
const syntheticLogin={label:"Synthetic login",url:"https://example.invalid/login",username:"test@example.invalid",password:"synthetic-vault-password-37",totp:"JBSWY3DPEHPK3PXP"};
async function upload(bytes:Uint8Array,format="chrome-csv",headers:Record<string,string>={}){
  return worker.fetch(new Request(base+"/api/vault/import?format="+format,{method:"POST",headers:{Cookie:"__Host-ralx="+session,Origin:base,"Content-Type":"application/octet-stream",...headers},body:bytes}),e);
}
function archive(items:any[],attachment=strToU8("synthetic attachment bytes")){
  return zipSync({"export.attributes":strToU8(JSON.stringify({version:3,description:"1Password Unencrypted Export"})),"export.data":strToU8(JSON.stringify({accounts:[{uuid:"synthetic-account",vaults:[{uuid:"synthetic-vault",items}]}]})),"files/synthetic-attachment":attachment},{level:0});
}
function item(extra:any={}){return {uuid:"synthetic-item",categoryUuid:"001",state:"active",overview:{title:"Synthetic site",url:syntheticLogin.url},details:{loginFields:[{designation:"username",value:syntheticLogin.username},{designation:"password",value:syntheticLogin.password}],sections:[{fields:[{value:{totp:syntheticLogin.totp}}]}]},...extra};}
const entryPaths=["manual","chrome-csv","1password-csv","1password-1pux"];
test.each(entryPaths.slice(1))("partial login edits preserve unchanged 201-character imported names: %s",async(format)=>{
  const label="synthetic-long-import-".padEnd(201,"n"),username="synthetic-import-user-"+"u".repeat(5000);
  expect(label).toHaveLength(201);
  expect((await enterMetadata(format,{...syntheticLogin,label,username,notes:"synthetic-import-note"})).status).toBe(200);
  const row=await e.DB.prepare("SELECT * FROM vault_items").first<any>();
  const before=await open(row.payload,e.ENCRYPTION_KEY,`vault:${row.id}:user_test`);
  expect((await req("/api/vault/"+row.id,"PATCH",{password:"synthetic-new-password"})).status).toBe(200);
  const after=await e.DB.prepare("SELECT payload FROM vault_items WHERE id=?").bind(row.id).first<any>();
  expect(await open(after.payload,e.ENCRYPTION_KEY,`vault:${row.id}:user_test`)).toEqual({...before,password:"synthetic-new-password"});
  expect((await req("/api/vault/"+row.id,"PATCH",{label})).status).toBe(400);
  expect((await req("/api/vault/"+row.id,"PATCH",{url:"http://insecure.invalid"})).status).toBe(400);
});
async function enterMetadata(format:string,b:any){
  if(format==="manual")return req("/api/vault/login","POST",b);
  if(format==="1password-1pux")return upload(archive([item({overview:{title:b.label,url:b.url,urls:[{url:"https://synthetic-secondary-62.invalid/path"}]},details:{notesPlain:b.notes,loginFields:[{designation:"username",value:b.username},{designation:"password",value:b.password}],sections:[{fields:[{value:{string:"synthetic-extra-field-62"}}]}]}})]),format);
  const fields=[b.label,b.url,b.username,b.password,b.notes,"synthetic-extra-field-62"];
  return upload(strToU8((format==="chrome-csv"?"name,url":"title,website")+",username,password,notes,custom\n"+fields.map(x=>'"'+x.replaceAll('"','""')+'"').join(",")),format);
}
async function storedVault(){
  const out=[];
  for(const table of ["vault_items","vault_imports","vault_chunks","vault_origins","login_requests"])
    out.push(...(await e.DB.prepare("SELECT * FROM "+table).all()).results);
  return JSON.stringify(out);
}
function inspectQueries(inspect:(sql:string,values:any[])=>void){
  // Miniflare's RPC proxy does not expose replaceable method properties. Wrap
  // the environment binding instead, and pass real bound statements to batch.
  const db=e.DB;
  e.DB={prepare(sql:string){
    const statement=db.prepare(sql);
    return {bind(...values:any[]){inspect(sql,values);return statement.bind(...values);},run:statement.run.bind(statement),all:statement.all.bind(statement),first:statement.first.bind(statement)};
  },batch:db.batch.bind(db)} as any;
  return ()=>{e.DB=db;};
}
function captureWrites(){
  const bindings:unknown[][]=[];
  const restore=inspectQueries((sql,values)=>{if(/\b(?:INSERT|UPDATE)\b/i.test(sql))bindings.push(values);});
  return {bindings,restore};
}
for(const [variant,password,label,notes] of [
  ["trim"," synthetic-secret-62 ","synthetic-secret-62","synthetic-note-62"],
  ["case","SYNTHETIC-secret-62","synthetic-secret-62","synthetic-note-62"],
  ["unicode","caf\u00e9-synthetic-62","cafe\u0301-synthetic-62","synthetic-note-62"],
  ["fragment","synthetic-password-62",("synthetic-note-fragment-62-"+"n".repeat(240)).slice(0,200),"synthetic-note-fragment-62-"+"n".repeat(240)],
])test.each(entryPaths)(`sealed metadata blocks ${variant} plaintext reproduction: %s`,async(format)=>{
  const b={label,password,notes,username:"synthetic-username-62",url:"https://synthetic-site-62.invalid/private-path"};
  const writes=captureWrites();
  try{
    expect((await enterMetadata(format,b)).status).toBe(200);
    expect(writes.bindings.length).toBeGreaterThan(0);
    for(const plain of [await storedVault(),JSON.stringify(writes.bindings)])
      for(const fragment of [label,password,password.trim(),notes.slice(0,200),b.username,"synthetic-site-62","private-path","synthetic-extra-field-62","synthetic-secondary-62"])
        expect(plain).not.toContain(fragment);
  }finally{writes.restore();}
});
test.each(entryPaths)("sealed metadata prevents older-name later-secret leaks: %s",async(format)=>{
  const value="synthetic-retroactive-secret-62";
  expect((await req("/api/vault/login","POST",{...syntheticLogin,label:value})).status).toBe(200);
  expect((await enterMetadata(format,{...syntheticLogin,password:value,notes:"synthetic-retro-note-62"})).status).toBe(200);
  expect(await storedVault()).not.toContain(value);
});
test("origin save responses do not reveal stored secret guesses",async()=>{
  expect((await req("/api/vault/login","POST",{...syntheticLogin,password:"https://synthetic-guess-62.invalid"})).status).toBe(200);
  const outputs=[];
  for(const suffix of [61,62]){
    const response=await req("/api/vault/login","POST",{...syntheticLogin,url:`https://synthetic-guess-${suffix}.invalid`});
    const result=await response.json() as any;delete result.id;
    outputs.push({status:response.status,body:result});
  }
  expect(outputs[0]).toEqual(outputs[1]);expect(outputs[0]).toEqual({status:200,body:{saved:true}});
});
test("origin lookup responses do not reveal stored secret guesses",async()=>{
  await req("/api/vault/login","POST",{...syntheticLogin,password:"https://synthetic-guess-62.invalid"});
  const results=[];
  for(const n of [61,62]){
    const response=await req(`/api/vault?origin=https://synthetic-guess-${n}.invalid`);
    results.push({status:response.status,body:await response.text()});
  }
  expect(results[0]).toEqual(results[1]);expect(JSON.parse(results[0].body)).toEqual({items:[]});
});
test("sealed vault supports search pagination exact origins edit delete and user isolation",async()=>{
  const first=await(await req("/api/vault/login","POST",{...syntheticLogin,label:"synthetic-search-62",notes:"synthetic-edit-note-62",custom:"synthetic-manual-extra-62"})).json() as any;
  await req("/api/vault/login","POST",{...syntheticLogin,label:"synthetic-search-63",url:"https://other.invalid"});
  const page=await(await req("/api/vault/search","POST",{limit:1,q:"synthetic-search"})).json() as any;
  expect(page.items).toHaveLength(1);expect(page.next_cursor).toBeTruthy();
  const next=await(await req("/api/vault/search","POST",{limit:1,q:"synthetic-search",cursor:page.next_cursor})).json() as any;
  expect(next.items).toHaveLength(1);expect(next.items[0].id).not.toBe(page.items[0].id);
  const exact=await(await req("/api/vault?origin="+encodeURIComponent("https://EXAMPLE.invalid:443/elsewhere"))).json() as any;
  expect(exact.items.map((x:any)=>x.id)).toEqual([first.id]);
  expect((await(await req("/api/vault?origin=https://example.invalid.evil.invalid")).json() as any).items).toEqual([]);
  expect((await req("/api/vault/"+first.id,"PATCH",{label:"synthetic-edited-62",url:"https://edited.invalid/path",username:"synthetic-edited-user-62",notes:"synthetic-new-note-62"})).status).toBe(200);
  const edited=await(await req("/api/vault/search","POST",{q:"synthetic-edited-62",origin:"https://edited.invalid"})).json() as any;
  expect(edited.items).toHaveLength(1);expect(edited.items[0].label).toBe("synthetic-edited-62");
  expect((await(await req("/api/vault?origin=https://example.invalid")).json() as any).items).toEqual([]);
  const row=await e.DB.prepare("SELECT * FROM vault_items WHERE id=?").bind(first.id).first<any>();
  const opened=await open(row.payload,e.ENCRYPTION_KEY,`vault:${first.id}:user_test`);
  expect(opened.notes).toBe("synthetic-new-note-62");expect(opened.custom).toBe("synthetic-manual-extra-62");expect(opened.password).toBe(syntheticLogin.password);
  await expect(open(row.payload,e.ENCRYPTION_KEY,`vault:${first.id}:user_other`)).rejects.toThrow();
  await expect(open(row.payload,e.ENCRYPTION_KEY,"vault:other:user_test")).rejects.toThrow();
  expect((await req("/api/vault/"+first.id,"DELETE",{})).status).toBe(200);
  expect((await(await req("/api/vault/search","POST",{q:"synthetic-edited-62"})).json() as any).items).toEqual([]);
});
test("sealed pending requests and edits never bind login metadata in plaintext",async()=>{
  const {key}=await enroll();const writes=captureWrites();
  try{
    const url="https://synthetic-request-site-62.invalid/path",label="synthetic-request-label-62";
    const result=await(await req("/api/v1/call","POST",{tool:"RALX_REQUEST_LOGIN",args:{url,label}},key)).json() as any;
    expect(result.request_id).toBeTruthy();
    expect((await(await req("/api/vault/requests")).json() as any).requests[0]).toMatchObject({label,origin:"https://synthetic-request-site-62.invalid"});
    const save=await(await req("/api/vault/login","POST",{...syntheticLogin,url,label,request_id:result.request_id})).json() as any;
    expect(save.saved).toBe(true);
    expect((await req("/api/vault/"+save.id,"PATCH",{label:"synthetic-update-label-62",username:"synthetic-update-user-62",url:"https://synthetic-update-site-62.invalid",notes:"synthetic-update-note-62"})).status).toBe(200);
    for(const plain of [await storedVault(),JSON.stringify(writes.bindings)])
      for(const fragment of ["synthetic-request-site-62",label,"synthetic-update-label-62","synthetic-update-user-62","synthetic-update-site-62","synthetic-update-note-62",syntheticLogin.password])expect(plain).not.toContain(fragment);
  }finally{writes.restore();}
});
test("sealed 1PUX secondary origins stay searchable and replaced hashes disappear on reimport",async()=>{
  expect((await enterMetadata("1password-1pux",{...syntheticLogin,notes:"synthetic-note-62"})).status).toBe(200);
  const result=await(await req("/api/vault?origin=https://synthetic-secondary-62.invalid/other")).json() as any;
  expect(result.items).toHaveLength(1);
  expect((await upload(archive([item()]),"1password-1pux")).status).toBe(200);
  expect((await(await req("/api/vault?origin=https://synthetic-secondary-62.invalid")).json() as any).items).toEqual([]);
  expect((await(await req("/api/vault?origin=https://example.invalid")).json() as any).items).toHaveLength(1);
});
test("sparse vault searches batch reads independently of the requested page size",async()=>{
  const csv="name,url,username,password\n"+Array.from({length:250},(_,i)=>`synthetic-batched-${i},https://synthetic-batch.invalid,u,synthetic-batch-password`).join("\n");
  expect((await upload(strToU8(csv))).status).toBe(200);
  let reads=0;
  const restore=inspectQueries((sql)=>{if(sql.startsWith("SELECT * FROM vault_items"))reads++;});
  try{
    const response=await req("/api/vault/search","POST",{limit:1,q:"no-synthetic-match"});
    expect(response.status).toBe(200);expect((await response.json() as any).items).toEqual([]);
    expect(reads).toBeGreaterThan(0);expect(reads).toBeLessThanOrEqual(4);
  }finally{restore();}
});
function zip64CommentArchive(){
  // The last directory comment is also interpreted as a ZIP64 locator by fflate.
  // Use a harmless 32 KiB declaration for the unchecked entry, never a huge allocation.
  const blank=archive([item()],new Uint8Array(4096));
  const bv=new DataView(blank.buffer),end=blank.length-22,start=bv.getUint32(end+16,true),size=bv.getUint32(end+12,true);
  let last=start;for(let i=1;i<bv.getUint16(end+10,true);i++)last+=46+bv.getUint16(last+28,true)+bv.getUint16(last+30,true)+bv.getUint16(last+32,true);
  const local=bv.getUint32(last+42,true),data=local+30+bv.getUint16(local+26,true)+bv.getUint16(local+28,true);
  const attachment=new Uint8Array(4096),v=new DataView(attachment.buffer);
  v.setUint32(0,0x06064b50,true);v.setUint32(4,44,true);
  v.setUint32(32,bv.getUint16(end+10,true)+1,true);v.setUint32(48,data+56,true);
  attachment.set(blank.subarray(start,start+size),56);
  const name=strToU8("unchecked"),compressed=deflateSync(strToU8("synthetic unchecked entry"));
  const central=56+size,extraLocal=central+46+name.length;
  v.setUint32(central,0x02014b50,true);v.setUint16(central+10,8,true);
  v.setUint32(central+20,compressed.length,true);v.setUint32(central+24,32768,true);
  v.setUint16(central+28,name.length,true);v.setUint32(central+42,data+extraLocal,true);attachment.set(name,central+46);
  v.setUint32(extraLocal,0x04034b50,true);v.setUint16(extraLocal+8,8,true);
  v.setUint16(extraLocal+26,name.length,true);attachment.set(name,extraLocal+30);attachment.set(compressed,extraLocal+30+name.length);
  const ordinary=archive([item()],attachment),crafted=new Uint8Array(ordinary.length+20);
  crafted.set(ordinary.subarray(0,end),0);crafted.set(ordinary.subarray(end),end+20);
  const cv=new DataView(crafted.buffer);cv.setUint16(last+32,20,true);cv.setUint32(end+20+12,size+20,true);
  cv.setUint32(end,0x07064b50,true);cv.setUint32(end+8,data,true);cv.setUint32(end+16,1,true);
  return crafted;
}
test("1PUX rejects ZIP64 locators hidden in directory comments before extracting an alternate directory",async()=>{
  expect((await upload(zip64CommentArchive(),"1password-1pux")).status).toBe(400);
  for(const table of ["vault_items","vault_imports","vault_chunks"])
    expect((await e.DB.prepare(`SELECT count(*) n FROM ${table}`).first<any>()).n).toBe(0);
});
test("1PUX enforces actual inflated lengths and still imports ordinary compressed archives",async()=>{
  let state=62;
  const seed=Uint8Array.from({length:1024},()=>{state=(Math.imul(state,1664525)+1013904223)|0;return state>>>24;});
  const attachment=new Uint8Array(8192);for(let i=0;i<8;i++)attachment.set(seed,i*seed.length);
  const bytes=zipSync({"export.attributes":strToU8(JSON.stringify({version:3,description:"1Password Unencrypted Export"})),"export.data":strToU8(JSON.stringify({accounts:[{vaults:[{items:[item()]}]}]})),"files/compressed":attachment},{level:6});
  const bad=bytes.slice(),v=new DataView(bad.buffer),end=bad.length-22;
  let central=v.getUint32(end+16,true);
  for(let i=1;i<v.getUint16(end+10,true);i++)central+=46+v.getUint16(central+28,true)+v.getUint16(central+30,true)+v.getUint16(central+32,true);
  const local=v.getUint32(central+42,true),prefix=zipSync({prefix:attachment.subarray(0,512)},{level:0});
  const crc=new DataView(prefix.buffer).getUint32(14,true);
  for(const [offset,value] of [[central+24,512],[local+22,512],[central+16,crc],[local+14,crc]])v.setUint32(offset,value,true);
  expect((await upload(bad,"1password-1pux")).status).toBe(400);
  expect((await e.DB.prepare("SELECT count(*) n FROM vault_items").first<any>()).n).toBe(0);
  expect((await upload(bytes,"1password-1pux")).status).toBe(200);
  const imported=await e.DB.prepare("SELECT id FROM vault_imports").first<any>();
  expect(await restoredArchive(imported.id)).toEqual(Buffer.from(bytes));
});
test.each(["chrome-csv","1password-csv","1password-1pux"])("long private notes and exact names are sealed together: %s",async(format)=>{
  for(const length of [260,5000]){
    const note="synthetic-private-note-"+"n".repeat(length-23);
    const bytes=format==="1password-1pux"
      ?archive([item({overview:{title:note,url:syntheticLogin.url},details:{notesPlain:note,loginFields:[{designation:"password",value:syntheticLogin.password}]}})])
      :strToU8((format==="chrome-csv"?"name,url,username,password,note":"title,website,username,password,notes")+`\n${note},${syntheticLogin.url},tester,${syntheticLogin.password},${note}`);
    expect((await upload(bytes,format)).status).toBe(200);
    const rows=(await e.DB.prepare("SELECT * FROM vault_items").all<any>()).results;
    for(const row of rows){
      expect(row).not.toHaveProperty("label");
      expect(row).not.toHaveProperty("origin");
      const fields=await open(row.payload,e.ENCRYPTION_KEY,`vault:${row.id}:user_test`);
      expect(fields.label).toBe(note);expect(fields.origin).toBe("https://example.invalid");
    }
    const {key}=await enroll();
    const response=await req("/api/v1/call","POST",{tool:"RALX_LOGINS",args:{}},key);
    expect(response.status).toBe(200);
    expect((await response.json() as any).logins).toHaveLength(1);
  }
});
async function restoredArchive(id:string){
  const rows=(await e.DB.prepare("SELECT * FROM vault_chunks WHERE import_id=? ORDER BY part").bind(id).all<any>()).results;
  const parts=[];for(const r of rows){const v=await open(r.payload,e.ENCRYPTION_KEY,`import:${id}:user_test:${r.part}`);parts.push(Buffer.from(v.data,"base64"));}return Buffer.concat(parts);
}

test.each(["manual","chrome-csv","1password-csv","1password-1pux"])("existing vault secrets cannot be reused as plaintext item names: %s",async(format)=>{
  const secret="synthetic-existing-secret-62";
  expect((await req("/api/vault/login","POST",{...syntheticLogin,password:secret})).status).toBe(200);
  const response=format==="manual"
    ?await req("/api/vault/login","POST",{...syntheticLogin,label:secret})
    :await upload(format==="1password-1pux"
      ?archive([item({overview:{title:secret,url:syntheticLogin.url}})])
      :strToU8((format==="chrome-csv"?"name,url":"title,website")+`,username,password\n${secret},${syntheticLogin.url},tester,${syntheticLogin.password}`),format);
  expect(response.status).toBe(200);
  const rows=(await e.DB.prepare("SELECT * FROM vault_items").all<any>()).results;
  expect(rows).toHaveLength(2);
  expect(JSON.stringify(rows)).not.toContain(secret);
  const listed=await(await req("/api/vault")).json() as any;
  expect(listed.items.some((row:any)=>row.label===secret)).toBe(true);
});

test("reduced 1PUX indexes still protect existing private custom values",async()=>{
  const secret="synthetic-reduced-custom-secret-62";
  const bytes=archive([item({details:{notesPlain:"synthetic long note "+"n".repeat(500000),sections:[{fields:[{value:{string:secret}}]}]}})]);
  expect((await upload(bytes,"1password-1pux")).status).toBe(200);
  expect((await req("/api/vault/login","POST",{...syntheticLogin,label:secret})).status).toBe(200);
  const rows=(await e.DB.prepare("SELECT * FROM vault_items").all<any>()).results;
  expect(JSON.stringify(rows)).not.toContain(secret);
});
test("sealed writes do not read other records and damaged ciphertext fails closed on listing",async()=>{
  const otherSecret="synthetic-other-user-secret-62";
  await e.DB.prepare("INSERT INTO vault_items(id,user_id,source,kind,payload,created_at,updated_at) VALUES ('other','user_other','manual','private',?,'synthetic','synthetic')")
    .bind(await seal({label:"Other",origin:"",password:otherSecret},e.ENCRYPTION_KEY,"vault:other:user_other")).run();
  expect((await req("/api/vault/login","POST",{...syntheticLogin,label:otherSecret})).status).toBe(200);
  expect((await(await req("/api/vault")).json() as any).items[0].label).toBe(otherSecret);
  await e.DB.prepare("UPDATE vault_items SET payload='invalid' WHERE user_id='user_test'").run();
  expect((await req("/api/vault")).status).toBe(500);
  expect((await req("/api/vault/login","POST",syntheticLogin)).status).toBe(200);
  expect((await upload(strToU8(`name,url,username,password\nSite,${syntheticLogin.url},u,synthetic-new-password`))).status).toBe(200);
  expect((await e.DB.prepare("SELECT count(*) n FROM vault_items").first<any>()).n).toBe(4);
});

test("manual names matching whitespace-padded secrets stay sealed",async()=>{
  const secret=" synthetic-existing-secret-62 ";
  expect((await req("/api/vault/login","POST",{...syntheticLogin,password:secret})).status).toBe(200);
  expect((await req("/api/vault/login","POST",{...syntheticLogin,label:secret})).status).toBe(200);
  expect(await storedVault()).not.toContain(secret.trim());
});
test("vault owner routes require sessions, exact origins and correct media types",async()=>{
  for(const [path,method] of [["/api/vault","GET"],["/api/vault/requests","GET"],["/api/vault/login","POST"],["/api/vault/import","POST"],["/api/vault/requests/fake/deny","POST"]]){
    expect((await req(path,method,method==="GET"?undefined:{},"")).status).toBe(401);
    if(method==="GET")continue;
    for(const o of [undefined,"null","https://evil.invalid"]){
      const headers:Record<string,string>={Cookie:"__Host-ralx="+session,"Content-Type":"application/json"};if(o)headers.Origin=o;
      expect((await worker.fetch(new Request(base+path,{method,headers,body:"{}"}),e)).status).toBe(403);
    }
    for(const ct of ["text/plain","application/json-evil","application/x-www-form-urlencoded"])
      expect((await req(path,method,{},"owner",{"Content-Type":ct})).status).toBe(415);
  }
  expect((await upload(strToU8("x"),"chrome-csv",{"Content-Type":"application/json"})).status).toBe(415);
  expect((await req("/api/vault/login","POST",syntheticLogin,"owner",{"Content-Type":"application/json; charset=utf-8"})).status).toBe(200);
});
test("quoted CSV, HTTP/private records, stable repeated imports and encrypted D1 rows",async()=>{
  const data=strToU8('name,url,username,password,note\r\n"Synthetic, ""quoted""",https://example.invalid/path,tester,synthetic-csv-secret,"line one\nline two"\r\nHTTP,http://insecure.invalid,user,synthetic-http-secret,private\r\nPrivate,,user,synthetic-private-secret,private\r\n');
  const r=await upload(data);expect(r.status).toBe(200);expect(await r.json()).toMatchObject({imported:3,logins:1,private_items:2,original_preserved:true});
  const first=(await e.DB.prepare("SELECT * FROM vault_items ORDER BY id").all<any>()).results;
  expect(first.find(x=>x.kind==="login")).not.toHaveProperty("label");
  const decoded=await open(first.find(x=>x.kind==="login").payload,e.ENCRYPTION_KEY,`vault:${first.find(x=>x.kind==="login").id}:user_test`);
  expect(decoded.original.note).toBe("line one\nline two");expect(decoded.label).toBe('Synthetic, "quoted"');
  expect((await upload(data)).status).toBe(200);
  expect((await e.DB.prepare("SELECT id FROM vault_items ORDER BY id").all()).results).toEqual(first.map(x=>({id:x.id})));
  const imports=(await e.DB.prepare("SELECT * FROM vault_imports").all<any>()).results;
  expect(await restoredArchive(imports[0].id)).toEqual(Buffer.from(data));
  const stored=JSON.stringify([(await e.DB.prepare("SELECT * FROM vault_items").all()).results,(await e.DB.prepare("SELECT * FROM vault_chunks").all()).results,imports]);
  for(const secret of ["synthetic-csv-secret","synthetic-http-secret","synthetic-private-secret","line one"])expect(stored).not.toContain(secret);
});
test("1Password CSV retains original fields and duplicate private entries stay distinct",async()=>{
  const data=strToU8('title,website,username,password,one-time password,notes\nPrivate,,u,synthetic-pw-a,JBSWY3DP,note\nPrivate,,u,synthetic-pw-b,JBSWY3DP,note');
  expect((await upload(data,"1password-csv")).status).toBe(200);
  expect((await upload(data,"1password-csv")).status).toBe(200);
  const rows=(await e.DB.prepare("SELECT * FROM vault_items").all<any>()).results;expect(rows).toHaveLength(2);
  for(const r of rows){const f=await open(r.payload,e.ENCRYPTION_KEY,`vault:${r.id}:user_test`);expect(f.original["one-time password"]).toBe("JBSWY3DP");expect(r.kind).toBe("private");}
});
test("1PUX seals private, archived, custom fields and preserves attachment bytes",async()=>{
  const custom="synthetic-custom-secret-73", secretHost="synthetic-host-secret";
  const items=[item(),item({uuid:"private",categoryUuid:"003",overview:{title:custom,url:"https://"+secretHost+".invalid"},details:{notesPlain:"synthetic private note",sections:[{fields:[{value:{string:custom}},{v:{string:secretHost}}]}]}}),item({uuid:"archived",state:"archived"})];
  const bytes=archive(items);expect((await upload(bytes,"1password-1pux")).status).toBe(200);
  const rows=(await e.DB.prepare("SELECT * FROM vault_items").all<any>()).results;expect(rows.filter(x=>x.kind==="private")).toHaveLength(2);
  for(const r of rows){const f=await open(r.payload,e.ENCRYPTION_KEY,`vault:${r.id}:user_test`);expect(items).toContainEqual(f.original);}
  const imported=await e.DB.prepare("SELECT id FROM vault_imports").first<any>();expect(await restoredArchive(imported.id)).toEqual(Buffer.from(bytes));
  const {key}=await enroll();
  for(const response of [await req("/api/v1/call","POST",{tool:"RALX_LOGINS",args:{}},key),await req("/mcp","POST",{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"RALX_LOGINS",arguments:{}}},key)]){
    expect(response.status).toBe(200);const out=await response.text();for(const s of [custom,secretHost,syntheticLogin.password,syntheticLogin.totp,"synthetic private note"])expect(out).not.toContain(s);
  }
  const owner=await(await req("/api/vault")).json() as any;
  expect(owner.items.find((x:any)=>x.label===custom).origin).toBe("https://"+secretHost+".invalid");
  expect(await storedVault()).not.toContain(custom);
});
test("vault and request data are scoped to owner and requesting agent",async()=>{
  const {key}=await enroll();const other=await enroll();
  const request=await(await req("/api/v1/call","POST",{tool:"RALX_REQUEST_LOGIN",args:{url:syntheticLogin.url,label:"Synthetic"}},key)).json() as any;
  expect((await req("/api/v1/login-requests/"+request.request_id,"GET",undefined,other.key)).status).toBe(404);
  const saved=await(await req("/api/vault/login","POST",syntheticLogin)).json() as any;expect(saved.saved).toBe(true);
  const before=await(await req("/api/vault")).text();
  const otherSession=token();await e.DB.prepare("INSERT INTO users(id,email) VALUES ('user_other','other@example.invalid')").run();
  await e.DB.prepare("INSERT INTO sessions VALUES (?,'user_other',?)").bind(await hash(otherSession+e.SESSION_SECRET),now()+100).run();
  const old=session;session=otherSession;
  try{
    expect(await(await req("/api/vault")).json()).toEqual({items:[]});expect(await(await req("/api/vault/requests")).json()).toEqual({requests:[]});
    expect((await(await req("/api/vault/search","POST",{origin:"https://example.invalid",q:"Synthetic"})).json() as any).items).toEqual([]);
    expect((await req("/api/vault/"+saved.id,"PATCH",{label:"Other"})).status).toBe(404);
    expect((await req("/api/vault/"+saved.id,"DELETE",{})).status).toBe(404);
    expect((await req("/api/vault/login","POST",{...syntheticLogin,request_id:request.request_id})).status).toBe(409);
    await req("/api/vault/requests/"+request.request_id+"/deny","POST",{});
  }finally{session=old;}
  expect(await(await req("/api/vault")).text()).toBe(before);
  expect((await e.DB.prepare("SELECT status FROM login_requests").first<any>()).status).toBe("pending");
});
test("login request expiry, denial, revocation and exact origin binding prevent writes",async()=>{
  const {key}=await enroll();
  const make=async(url=syntheticLogin.url)=>await(await req("/api/v1/call","POST",{tool:"RALX_REQUEST_LOGIN",args:{url}},key)).json() as any;
  expect((await req("/api/v1/call","POST",{tool:"RALX_REQUEST_LOGIN",args:{url:"http://example.invalid"}},key)).status).toBe(400);
  const r=await make();expect((await make()).request_id).toBe(r.request_id);
  expect((await req("/api/vault/login","POST",{...syntheticLogin,url:"https://other.invalid",request_id:r.request_id})).status).toBe(409);
  await e.DB.prepare("UPDATE login_requests SET expires=?").bind(now()-1).run();
  expect(await(await req("/api/v1/login-requests/"+r.request_id,"GET",undefined,key)).json()).toMatchObject({status:"expired"});
  expect((await req("/api/vault/login","POST",{...syntheticLogin,request_id:r.request_id})).status).toBe(409);
  const denied=await make();await req("/api/vault/requests/"+denied.request_id+"/deny","POST",{});
  expect((await req("/api/vault/login","POST",{...syntheticLogin,request_id:denied.request_id})).status).toBe(409);
  expect(await(await req("/api/v1/login-requests/"+denied.request_id,"GET",undefined,key)).json()).toMatchObject({status:"denied"});
  const revoked=await make();const a=await e.DB.prepare("SELECT id FROM agents").first<any>();await req("/api/agents/"+a.id,"DELETE",{});
  expect((await req("/api/vault/login","POST",{...syntheticLogin,request_id:revoked.request_id})).status).toBe(409);
  expect((await req("/api/v1/login-requests/"+revoked.request_id,"GET",undefined,key)).status).toBe(401);
  expect((await e.DB.prepare("SELECT count(*) n FROM vault_items").first<any>()).n).toBe(0);
});
test("atomic save claim accepts once and rolls back if request completion fails",async()=>{
  const {key}=await enroll();const make=async()=>await(await req("/api/v1/call","POST",{tool:"RALX_REQUEST_LOGIN",args:{url:syntheticLogin.url}},key)).json() as any;
  const r=await make();
  const results=await Promise.all([1,2,3].map(()=>req("/api/vault/login","POST",{...syntheticLogin,request_id:r.request_id})));
  expect(results.map(x=>x.status).sort()).toEqual([200,409,409]);expect((await e.DB.prepare("SELECT count(*) n FROM vault_items").first<any>()).n).toBe(1);
  expect(await(await req("/api/v1/login-requests/"+r.request_id,"GET",undefined,key)).json()).toMatchObject({status:"saved"});
  const second=await make();await e.DB.prepare("CREATE TRIGGER synthetic_request_failure BEFORE UPDATE ON login_requests BEGIN SELECT RAISE(ABORT,'synthetic failure'); END").run();
  try{expect((await req("/api/vault/login","POST",{...syntheticLogin,request_id:second.request_id})).status).toBe(500);expect((await e.DB.prepare("SELECT count(*) n FROM vault_items").first<any>()).n).toBe(1);}
  finally{await e.DB.prepare("DROP TRIGGER synthetic_request_failure").run();}
});
test("bounded ZIP refuses CRC damage, ZIP64, truncated, overlapping and expansion fixtures atomically",async()=>{
  const valid=archive([item()]);
  const crc=valid.slice();const view=new DataView(crc.buffer);let cp=0;while(view.getUint32(cp,true)!==0x02014b50)cp++;view.setUint32(cp+16,0,true);view.setUint32(14,0,true);
  const zip64=valid.slice();const zv=new DataView(zip64.buffer);zv.setUint32(zip64.length-22+16,0xffffffff,true);
  const expand=zipSync({"export.attributes":strToU8(JSON.stringify({version:3,description:"1Password Unencrypted Export"})),"export.data":strToU8("x".repeat(100000))},{level:9});
  const overlap=valid.slice();new DataView(overlap.buffer).setUint32(cp+42,1,true);
  for(const bad of [crc,zip64,expand,overlap,valid.subarray(0,valid.length-1),strToU8("not zip")]){
    expect((await upload(bad,"1password-1pux")).status).toBe(400);
    expect((await e.DB.prepare("SELECT count(*) n FROM vault_imports").first<any>()).n).toBe(0);
  }
  expect((await upload(valid,"1password-1pux")).status).toBe(200);
});
test("large items and binary archives encrypt and reconstruct exactly, including reduced indexes",async()=>{
  const bytes=archive([item({details:{...item().details,notesPlain:"synthetic large note "+"x".repeat(510000)}})]);
  expect((await upload(bytes,"1password-1pux")).status).toBe(200);
  const r=await e.DB.prepare("SELECT * FROM vault_items").first<any>();const f=await open(r.payload,e.ENCRYPTION_KEY,`vault:${r.id}:user_test`);
  expect(f.original_import).toBeTruthy();expect(f.password).toBe(syntheticLogin.password);
  expect(await restoredArchive(f.original_import)).toEqual(Buffer.from(bytes));
  const huge={text:"synthetic "+"x".repeat(700000)};expect(await open(await seal(huge,e.ENCRYPTION_KEY,"large"),e.ENCRYPTION_KEY,"large")).toEqual(huge);
});
test("import rejects malformed CSV, item and byte limits, and D1 failures without partial rows",async()=>{
  for(const bytes of [strToU8('name,url,username,password\n"unfinished'),strToU8('url,username,password\nhttps://a.invalid,u,p,extra'),strToU8('url,url,username,password\na,b,u,p')])expect((await upload(bytes)).status).toBe(400);
  expect((await upload(new Uint8Array(MAX_IMPORT+1))).status).toBe(413);
  const data=strToU8('name,url,username,password\n'+Array.from({length:5001},(_,i)=>`Site${i},https://a.invalid,u,synthetic${i}`).join('\n'));expect((await upload(data)).status).toBe(400);
  await e.DB.prepare("CREATE TRIGGER synthetic_import_failure BEFORE INSERT ON vault_items BEGIN SELECT RAISE(ABORT,'synthetic failure'); END").run();
  try{expect((await upload(strToU8('name,url,username,password\nSite,https://a.invalid,u,synthetic'))).status).toBe(500);for(const t of ["vault_items","vault_imports","vault_chunks"])expect((await e.DB.prepare(`SELECT count(*) n FROM ${t}`).first<any>()).n).toBe(0);}
  finally{await e.DB.prepare("DROP TRIGGER synthetic_import_failure").run();}
});
let mf: Miniflare, e: Env, session: string;
const base = "https://ralx.example.invalid";
const fetchMock = vi.fn(async (input: any, init: any) => {
  const u = String(input);
  if (u === "https://oauth2.googleapis.com/token") return Response.json({
    access_token:"synthetic-refreshed-access",refresh_token:"synthetic-rotated-refresh",expires_in:3600,
    scope:"openid email https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive",
  });
  if (u === "https://openidconnect.googleapis.com/v1/userinfo") return Response.json({sub:"synthetic-google-sub",email:"test@example.invalid",email_verified:true});
  if (u.includes("/gmail/v1/users/me/messages?")) return Response.json({messages:[{id:"msg_synthetic"}]});
  if (u.includes("/gmail/v1/users/me/messages/msg_synthetic?")) return Response.json({id:"msg_synthetic",payload:{headers:[{name:"Subject",value:"Hello"},{name:"From",value:"sender@example.invalid"}]},snippet:"synthetic-oauth-secret "+e.GOOGLE_CLIENT_SECRET});
  if (u.includes("/gmail/v1/users/me/messages/send")) return Response.json({id:"sent_synthetic",access_token:"synthetic-oauth-secret"});
  if (u.includes("/drive/v3/about")) return Response.json({user:{emailAddress:"test@example.invalid"}});
  if (u.includes("/authenticate"))
    return Response.json({
      user: {
        id: "user_test",
        email: "test@example.invalid",
        first_name: "Test",
      },
      access_token: "synthetic-workos-access",
    });
  throw Error("Unexpected fetch " + u);
});
beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default {fetch(){return new Response("test")}}',
      compatibilityDate: "2026-10-17",
      d1Databases: ["DB"],
    }),
  );
  e = {
    DB: (await mf.getD1Database("DB")) as any,
    BASE_URL: base,
    WORKOS_API_KEY: "synthetic-workos-key",
    GOOGLE_CLIENT_ID: "synthetic-google-client",
    GOOGLE_CLIENT_SECRET: "synthetic-google-client-secret",
    WORKOS_CLIENT_ID: "client_synthetic",
    SESSION_SECRET: "synthetic-session-secret",
    ENCRYPTION_KEY: "synthetic-encryption-key",
    ASSETS: { fetch: async () => new Response("RalX") } as any,
  };
  const sql = readFileSync(
    new URL("../migrations/0001_initial.sql", import.meta.url),
    "utf8",
  );
  for (const statement of sql.split(";").filter((x) => x.trim()))
    await e.DB.prepare(statement).run();
  for (const statement of readFileSync(new URL("../migrations/0002_native_accounts.sql",import.meta.url),"utf8").split(";").filter(x=>x.trim()))
    await e.DB.prepare(statement).run();
  for (const statement of readFileSync(new URL("../migrations/0003_private_vault.sql",import.meta.url),"utf8").split(";").filter(x=>x.trim()))
    await e.DB.prepare(statement).run();
});
afterAll(async () => {
  await mf.dispose();
});
beforeEach(async () => {
  for (const table of [
    "users",
    "sessions",
    "oauth_states",
    "codes",
    "agents",
    "approvals",
    "activity",
    "limits",
    "auth_configs",
    "native_accounts",
    "provider_states",
    "vault_origins", "vault_items", "vault_chunks", "vault_imports", "login_requests",
  ])
    await e.DB.prepare("DELETE FROM " + table).run();
  await e.DB.prepare("INSERT INTO users(id,email) VALUES (?,?)")
    .bind("user_test", "test@example.invalid")
    .run();
  session = token();
  await e.DB.prepare(
    "INSERT INTO sessions(hash,user_id,expires) VALUES (?,?,?)",
  )
    .bind(await hash(session + e.SESSION_SECRET), "user_test", now() + 3600)
    .run();
  await seedAccount("ca_one","user_test");
  await seedAccount("ca_other","user_other");
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockClear();
});
afterEach(() => vi.unstubAllGlobals());
async function seedAccount(id:string,user="user_test",expires=now()+3600) {
  await e.DB.prepare("INSERT INTO native_accounts(id,user_id,provider,subject,label,scopes,payload,created_at,status) VALUES (?,?,'google',?,?,?,?,?,'active')")
    .bind(id,user,id,"synthetic@example.invalid","https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive",
      await seal({access_token:"synthetic-oauth-secret",refresh_token:"synthetic-google-refresh",expires,client_id:e.GOOGLE_CLIENT_ID},e.ENCRYPTION_KEY,`${id}:${user}:google`),"2026-10-17").run();
}
const isSend=(u:unknown)=>String(u).includes("/gmail/v1/users/me/messages/send");
function sentArgs(init:any) {
  const mime=Buffer.from(JSON.parse(init.body).raw,"base64url").toString("utf8");
  const [headers,...body]=mime.split("\r\n\r\n");
  const subject=headers.match(/Subject: =\?UTF-8\?B\?([^?]*)\?=/)?.[1];
  return {recipient_email:headers.match(/To: (.*)/)?.[1],body:Buffer.from(body.join("\r\n\r\n"),"base64").toString("utf8"),...(subject?{subject:Buffer.from(subject,"base64").toString("utf8")}:{})};
}
async function req(
  path: string,
  method = "GET",
  data?: unknown,
  auth = "owner",
  extra: Record<string, string> = {},
) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...extra,
  };
  if (auth === "owner") {
    headers.Cookie = "__Host-ralx=" + session;
    if (method !== "GET") headers.Origin = base;
  } else if (auth) headers.Authorization = "Bearer " + auth;
  return worker.fetch(
    new Request(base + path, {
      method,
      headers,
      body: data === undefined ? undefined : JSON.stringify(data),
    }),
    e,
  );
}
async function enroll() {
  const p = (await (await req("/api/agents/prompt", "POST", {})).json()) as any;
  const r = (await (
    await req(
      "/api/enroll",
      "POST",
      { code: p.code, name: "Test", client: "test" },
      "",
    )
  ).json()) as any;
  return { p, ...r };
}
test("every owner route requires a session", async () => {
  for (const [path, method] of [
    ["/api/me", "GET"],
    ["/api/connectors", "GET"],
    ["/api/connectors/gmail/connect", "POST"],
    ["/api/accounts/ca_one", "DELETE"],
    ["/api/test", "POST"],
    ["/api/agents/prompt", "POST"],
    ["/api/agents", "GET"],
    ["/api/agents/ag_one", "DELETE"],
    ["/api/approvals", "GET"],
    ["/api/approvals/ap_one/approve", "POST"],
    ["/api/approvals/ap_one/deny", "POST"],
    ["/api/activity", "GET"],
    ["/logout", "POST"],
  ])
    expect(
      (await req(path, method, method === "GET" ? undefined : {}, "")).status,
    ).toBe(401);
});
test("owner writes reject missing, hostile, and null Origin or wrong content type", async () => {
  for (const o of ["", "https://evil.invalid", "null"]) {
    const r = await worker.fetch(
      new Request(base + "/api/agents/prompt", {
        method: "POST",
        headers: {
          Cookie: "__Host-ralx=" + session,
          Origin: o,
          "Content-Type": "application/json",
        },
        body: "{}",
      }),
      e,
    );
    expect(r.status).toBe(403);
  }
  expect(
    (
      await req("/api/agents/prompt", "POST", {}, "owner", {
        "Content-Type": "text/plain",
      })
    ).status,
  ).toBe(415);
});
test("code single-use, expiry and hash-only storage", async () => {
  const { p, key } = await enroll();
  expect(key).toMatch(/^ralx_/);
  expect((await req("/api/enroll", "POST", { code: p.code }, "")).status).toBe(
    400,
  );
  const a = await e.DB.prepare("SELECT * FROM agents").first<any>();
  expect(a.hash).toBe(await hash(key));
  expect(JSON.stringify(a)).not.toContain(key);
  const code = token();
  await e.DB.prepare("INSERT INTO codes(hash,user_id,expires) VALUES (?,?,?)")
    .bind(await hash(code), "user_test", now() - 1)
    .run();
  expect((await req("/api/enroll", "POST", { code }, "")).status).toBe(400);
  const stored = await e.DB.prepare("SELECT * FROM codes").first<any>();
  expect(stored.hash).toBe(await hash(code));
  expect(JSON.stringify(stored)).not.toContain(code);
});
test("concurrent enrollment consumes code once", async () => {
  const p = (await (await req("/api/agents/prompt", "POST", {})).json()) as any;
  const results = await Promise.all(
    Array.from({ length: 4 }, () =>
      req("/api/enroll", "POST", { code: p.code }, ""),
    ),
  );
  expect(results.filter((r) => r.status === 200)).toHaveLength(1);
});
test("REST and MCP initialize/list work and revoke kills the next call", async () => {
  const { key } = await enroll();
  expect((await req("/api/v1/whoami", "GET", undefined, key)).status).toBe(200);
  expect(
    ((await (await req("/api/v1/tools", "GET", undefined, key)).json()) as any)
      .tools.length,
  ).toBe(14);
  const init = (await (
    await req(
      "/mcp",
      "POST",
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18" },
      },
      key,
    )
  ).json()) as any;
  expect(init.result.serverInfo.name).toBe("ralx");
  const list = (await (
    await req(
      "/mcp",
      "POST",
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      key,
    )
  ).json()) as any;
  expect(list.result.tools[0].inputSchema.properties.ralx_account).toBeTruthy();
  const a = await e.DB.prepare("SELECT id FROM agents").first<any>();
  await req("/api/agents/" + a.id, "DELETE", {});
  for (const path of ["/api/v1/whoami", "/api/v1/tools", "/mcp"])
    expect(
      (
        await req(
          path,
          path === "/mcp" ? "POST" : "GET",
          path === "/mcp" ? {} : undefined,
          key,
        )
      ).status,
    ).toBe(401);
});
test("writes held, args encrypted, exact payload executed only once after approval", async () => {
  const { key } = await enroll();
  const args = {
    recipient_email: "test@example.invalid",
    body: "Synthetic message",
  };
  const held = (await (
    await req(
      "/api/v1/call",
      "POST",
      { tool: "GMAIL_SEND_EMAIL", args, account: "ca_one" },
      key,
    )
  ).json()) as any;
  expect(held.held).toBe(true);
  expect(
    fetchMock.mock.calls.filter(([u]) => isSend(u)),
  ).toHaveLength(0);
  const row = await e.DB.prepare("SELECT * FROM approvals").first<any>();
  expect(row.payload).not.toContain("Synthetic message");
  const owner = (await (await req("/api/approvals")).json()) as any;
  expect(owner.approvals[0].args).toEqual(args);
  expect(
    (await req(`/api/approvals/${held.approval_id}/approve`, "POST", { args_hash: owner.approvals[0].args_hash }))
      .status,
  ).toBe(200);
  const call = fetchMock.mock.calls.find(([u]) =>
    isSend(u),
  )!;
  expect(sentArgs(call[1])).toMatchObject(args);
  expect(
    (await req(`/api/approvals/${held.approval_id}/approve`, "POST", {}))
      .status,
  ).toBe(409);
});
test.each(["REST", "MCP"])("%s owner sees and approves exact token-shaped arguments", async (transport) => {
  const { key } = await enroll();
  const args = {
    recipient_email: "ralx_attacker000000000000@example.invalid",
    body: "Send literal sk_test_synthetic000000000000 content",
  };
  const response = await req(
    transport === "REST" ? "/api/v1/call" : "/mcp",
    "POST",
    transport === "REST"
      ? { tool: "GMAIL_SEND_EMAIL", args, account: "ca_one" }
      : { jsonrpc: "2.0", id: 1, method: "tools/call", params: {
          name: "GMAIL_SEND_EMAIL", arguments: { ...args, ralx_account: "ca_one" },
        } },
    key,
  );
  expect(response.status).toBe(200);
  expect(await response.text()).not.toContain(args.recipient_email);
  const { approvals } = await (await req("/api/approvals")).json() as any;
  const view = approvals[0];
  expect(view.args).toEqual(args);
  expect(view.args_hash).toBe(await hash(JSON.stringify(view.args)));
  const approved = await req(`/api/approvals/${view.id}/approve`, "POST", { args_hash: view.args_hash });
  expect(approved.status).toBe(200);
  const calls = fetchMock.mock.calls.filter(([u]) => isSend(u));
  expect(calls).toHaveLength(1);
  expect(sentArgs(calls[0][1])).toEqual(view.args);
});

test("approval refuses missing, wrong, stale and internally inconsistent argument hashes", async () => {
  const { key } = await enroll();
  const held = await (await req("/api/v1/call", "POST", {
    tool: "GMAIL_SEND_EMAIL", args: { recipient_email:"test@example.invalid", body: "original synthetic content" }, account: "ca_one",
  }, key)).json() as any;
  const { approvals } = await (await req("/api/approvals")).json() as any;
  const view = approvals[0];
  for (const data of [{}, { args_hash: "0".repeat(64) }])
    expect((await req(`/api/approvals/${held.approval_id}/approve`, "POST", data)).status).toBe(409);
  const row = await e.DB.prepare("SELECT * FROM approvals").first<any>();
  const aad = [row.id, row.user_id, row.agent_id, row.tool, row.account].join(":");
  const payload = await open(row.payload, e.ENCRYPTION_KEY, aad);
  payload.args_json = JSON.stringify({ body: "replacement synthetic content" });
  const replace = async () => e.DB.prepare("UPDATE approvals SET payload=? WHERE id=?")
    .bind(await seal(payload, e.ENCRYPTION_KEY, aad), row.id).run();
  await replace();
  expect((await req("/api/approvals")).status).toBe(409);
  expect((await req(`/api/approvals/${row.id}/approve`, "POST", { args_hash: view.args_hash })).status).toBe(409);
  payload.args_hash = await hash(payload.args_json);
  await replace();
  expect((await req(`/api/approvals/${row.id}/approve`, "POST", { args_hash: view.args_hash })).status).toBe(409);
  expect(fetchMock.mock.calls.filter(([u]) => isSend(u))).toHaveLength(0);
});

test("concurrent decisions execute the reviewed arguments at most once", async () => {
  const { key } = await enroll();
  await req("/api/v1/call", "POST", {
    tool: "GMAIL_SEND_EMAIL", args: {recipient_email:"test@example.invalid",body:"Synthetic message"}, account: "ca_one",
  }, key);
  const { approvals: [view] } = await (await req("/api/approvals")).json() as any;
  const responses = await Promise.all(Array.from({ length: 4 }, () =>
    req(`/api/approvals/${view.id}/approve`, "POST", { args_hash: view.args_hash }),
  ));
  expect(responses.map((r) => r.status).sort()).toEqual([200, 409, 409, 409]);
  expect(fetchMock.mock.calls.filter(([u]) => isSend(u))).toHaveLength(1);
});

test("legacy pending approvals remain visible and require a fresh exact-args hash", async () => {
  const { key } = await enroll();
  const args = { recipient_email: "ralx_legacy000000000000000@example.invalid", body:"Synthetic message" };
  const held = await (await req("/api/v1/call", "POST", {
    tool: "GMAIL_SEND_EMAIL", args, account: "ca_one",
  }, key)).json() as any;
  const row = await e.DB.prepare("SELECT * FROM approvals").first<any>();
  const aad = [row.id, row.user_id, row.agent_id, row.tool, row.account].join(":");
  await e.DB.prepare("UPDATE approvals SET payload=? WHERE id=?")
    .bind(await seal({ args, version: "test-version" }, e.ENCRYPTION_KEY, aad), row.id).run();
  const listed = await req("/api/approvals");
  expect(listed.status).toBe(200);
  const { approvals: [view] } = await listed.json() as any;
  expect(view.args).toEqual(args);
  expect(view.args_hash).toBe(await hash(JSON.stringify(args)));
  expect((await req(`/api/approvals/${held.approval_id}/approve`, "POST", {})).status).toBe(409);
  expect((await req(`/api/approvals/${held.approval_id}/approve`, "POST", { args_hash: view.args_hash })).status).toBe(200);
  const call = fetchMock.mock.calls.find(([u]) => isSend(u))!;
  expect(sentArgs(call[1])).toEqual(view.args);
});

test("revocation and denial prevent a pending write", async () => {
  const { key } = await enroll();
  const held = (await (
    await req(
      "/api/v1/call",
      "POST",
      { tool: "GMAIL_SEND_EMAIL", args: {recipient_email:"test@example.invalid",body:"Synthetic message"}, account: "ca_one" },
      key,
    )
  ).json()) as any;
  const a = await e.DB.prepare("SELECT id FROM agents").first<any>();
  await req("/api/agents/" + a.id, "DELETE", {});
  expect(
    (await req(`/api/approvals/${held.approval_id}/approve`, "POST", {}))
      .status,
  ).toBe(409);
  expect(
    fetchMock.mock.calls.filter(([u]) => isSend(u)),
  ).toHaveLength(0);
});
test("cross-owner account and credential overrides are denied", async () => {
  const { key } = await enroll();
  for (const b of [
    { tool: "GMAIL_FETCH_EMAILS", args: {}, account: "ca_other" },
    {
      tool: "GMAIL_FETCH_EMAILS",
      args: { custom_auth_params: { api_key: "synthetic" } },
      account: "ca_one",
    },
    { tool: "UNKNOWN_DEPLOY", args: {} },
  ])
    expect(
      (await req("/api/v1/call", "POST", b, key)).status,
    ).toBeGreaterThanOrEqual(400);
});
test("read output, errors and audit contain no provider keys or OAuth tokens", async () => {
  const log = vi.spyOn(console, "log"),
    err = vi.spyOn(console, "error");
  const { key } = await enroll();
  const output = await (
    await req(
      "/api/v1/call",
      "POST",
      {
        tool: "GMAIL_FETCH_EMAILS",
        args: { query: "in:inbox" },
        account: "ca_one",
      },
      key,
    )
  ).text();
  expect(output).toContain("Hello");
  for (const v of [e.GOOGLE_CLIENT_SECRET, "synthetic-oauth-secret", key])
    expect(output).not.toContain(v);
  const activity = await (await req("/api/activity")).text();
  expect(activity).not.toContain("Synthetic message");
  expect(log).not.toHaveBeenCalled();
  expect(err).not.toHaveBeenCalled();
  log.mockRestore();
  err.mockRestore();
});

test("provider test summaries scrub objects before serialization and truncation", async () => {
  const normal = fetchMock.getMockImplementation()!;
  const result = { successful: true, data: {
    name: "Synthetic profile",
    nested: [{ AccessToken: "synthetic-short-token", credentials: { value: "synthetic-private" } }],
    message: "sk_test_synthetic000000000000",
    echo: e.GOOGLE_CLIENT_SECRET,
  } };
  fetchMock.mockImplementation(async (input, init) => {
    if (String(input).includes("/drive/v3/about")) return Response.json(result.data);
    return normal(input, init);
  });
  try {
    const response = await req("/api/test", "POST", { slug: "googledrive" });
    expect(response.status).toBe(200);
    const output = await response.text();
    expect(output).toContain("Synthetic profile");
    for (const value of ["synthetic-short-token", "synthetic-private", result.data.message, e.GOOGLE_CLIENT_SECRET])
      expect(output).not.toContain(value);
    expect(output).toContain("[redacted]");
  } finally { fetchMock.mockImplementation(normal); }
  const crossingSecret = "synthetic-crossing-secret-" + "z".repeat(40);
  const summary = testSummary("github", { data: { name: "x".repeat(1570) + crossingSecret } }, [crossingSecret]);
  expect(summary).not.toContain("synthetic-crossing");
  expect(testSummary("gmail", { data: { messages: [{ subject: "Normal mail", sender: "sender@example.invalid" }] } }, []))
    .toContain("Normal mail. From: sender@example.invalid");
});

test("REST, MCP, approved results and activity keep structured provider secrets scrubbed", async () => {
  const { key } = await enroll();
  const normal = fetchMock.getMockImplementation()!;
  fetchMock.mockImplementation(async (input, init) => (String(input).includes("/drive/v3/about") || isSend(input))
    ? Response.json({ name: "Safe synthetic output", nested: [
        { access_token: "synthetic-short-token", RefreshToken: "synthetic-refresh" },
        { content: "ralx_synthetic000000000000", echo: e.GOOGLE_CLIENT_SECRET },
      ] }) : normal(input, init));
  try {
    const outputs = [await (await req("/api/v1/call", "POST", { tool: "GOOGLEDRIVE_GET_ABOUT", args: {} }, key)).text()];
    outputs.push(await (await req("/mcp", "POST", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "GOOGLEDRIVE_GET_ABOUT", arguments: {} } }, key)).text());
    await req("/api/v1/call", "POST", { tool: "GMAIL_SEND_EMAIL", args: {recipient_email:"test@example.invalid",body:"Synthetic message"} }, key);
    const { approvals: [view] } = await (await req("/api/approvals")).json() as any;
    const approved = await req(`/api/approvals/${view.id}/approve`, "POST", { args_hash: view.args_hash });
    expect(approved.status).toBe(200);
    outputs.push(await approved.text());
    for (const output of outputs) {
      expect(output).toContain("Safe synthetic output");
      for (const secret of ["synthetic-short-token", "synthetic-refresh", "ralx_synthetic000000000000", e.GOOGLE_CLIENT_SECRET])
        expect(output).not.toContain(secret);
    }
    const activity = await (await req("/api/activity")).text();
    expect(activity).not.toContain("Safe synthetic output");
    expect(activity).not.toContain("synthetic-short-token");
  } finally { fetchMock.mockImplementation(normal); }
});
test("callback binds state, consumes it and creates hash-only session", async () => {
  const login = await req("/login", "GET", undefined, "");
  const url = new URL(login.headers.get("Location")!);
  const state = url.searchParams.get("state")!;
  expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  expect(
    (
      await req(
        "/callback?state=" + state + "&code=synthetic",
        "GET",
        undefined,
        "",
      )
    ).status,
  ).toBe(400);
  const callback = await req(
    "/callback?state=" + state + "&code=synthetic",
    "GET",
    undefined,
    "",
    { Cookie: "__Host-ralx-state=" + state },
  );
  expect(callback.status).toBe(302);
  const value = callback.headers
    .get("Set-Cookie")!
    .match(/__Host-ralx=([^;]+)/)![1];
  expect(
    await e.DB.prepare("SELECT hash FROM sessions WHERE hash=?")
      .bind(await hash(value + e.SESSION_SECRET))
      .first(),
  ).toBeTruthy();
  expect(
    (
      await req(
        "/callback?state=" + state + "&code=synthetic",
        "GET",
        undefined,
        "",
        { Cookie: "__Host-ralx-state=" + state },
      )
    ).status,
  ).toBe(400);
});
test("encryption binds approval identity and recursive scrubbing removes credential fields", async () => {
  expect(
    scrub(
      { nested: { refresh_token: "synthetic", message: e.GOOGLE_CLIENT_SECRET } },
      [e.GOOGLE_CLIENT_SECRET],
    ),
  ).toEqual({ nested: { refresh_token: "[redacted]", message: "[redacted]" } });
  expect(await seal({ a: 1 }, e.ENCRYPTION_KEY, "approval")).not.toContain(
    '"a"',
  );
});
test("paste prompt pins the cross-platform setup script without provider secrets", () => {
  const prompt=enrollmentPrompt(base,"en_synthetic");
  expect(prompt).toContain("CLIENT");
  expect(prompt).toContain("codex, claude, hermes or grok");
  expect(prompt).not.toContain("python");
  expect(prompt).not.toContain(e.GOOGLE_CLIENT_SECRET);
  const command=prompt.split('\n\n')[1];
  const source=JSON.parse(command.slice('node -e '.length,-' CLIENT'.length));
  expect(()=>new Function(source)).not.toThrow();
  expect(source).toContain(createHash('sha256').update(readFileSync(new URL('../public/ralx.mjs',import.meta.url))).digest('hex'));
  const check=spawnSync(process.execPath,['--check',new URL('../public/ralx.mjs',import.meta.url).pathname.replace(/^\/([A-Z]:)/,'$1')],{encoding:'utf8'});
  expect(check.status,check.stderr).toBe(0);
});

test("denied approvals, hostile browser agent calls and oversized bodies fail safely", async () => {
  const { key } = await enroll();
  const held = (await (
    await req(
      "/api/v1/call",
      "POST",
      { tool: "GMAIL_SEND_EMAIL", args: {recipient_email:"test@example.invalid",body:"Synthetic message"}, account: "ca_one" },
      key,
    )
  ).json()) as any;
  expect(
    (await req(`/api/approvals/${held.approval_id}/deny`, "POST", {})).status,
  ).toBe(200);
  expect(
    (await req(`/api/approvals/${held.approval_id}/approve`, "POST", {}))
      .status,
  ).toBe(409);
  expect(
    (
      await req("/api/v1/whoami", "GET", undefined, key, {
        Origin: "https://evil.invalid",
      })
    ).status,
  ).toBe(403);
  expect(
    (
      await req(
        "/api/v1/call",
        "POST",
        { tool: "GMAIL_FETCH_EMAILS", args: { query: "x".repeat(70000) } },
        key,
      )
    ).status,
  ).toBe(413);
});
test("multiple accounts require an explicit account and retain all account ids", async () => {
  const { key } = await enroll();
  const normal = fetchMock.getMockImplementation()!;
  await seedAccount("ca_two");
  try {
    const identity = (await (
      await req("/api/v1/whoami", "GET", undefined, key)
    ).json()) as any;
    expect(identity.connected.filter((x:any)=>x.slug==="gmail").map((x: any) => x.account)).toEqual([
      "ca_one",
      "ca_two",
    ]);
    expect(
      (
        await req(
          "/api/v1/call",
          "POST",
          { tool: "GMAIL_FETCH_EMAILS", args: {} },
          key,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await req(
          "/api/v1/call",
          "POST",
          { tool: "GMAIL_FETCH_EMAILS", args: {}, account: "ca_two" },
          key,
        )
      ).status,
    ).toBe(200);
  } finally {
    fetchMock.mockImplementation(normal);
  }
});

test("native Google consent uses PKCE and single-use state bound to the signed-in user",async()=>{
  const start=await(await req("/api/connectors/gmail/connect","POST",{})).json() as any;
  const url=new URL(start.redirect_url), state=url.searchParams.get("state")!;
  expect(url.origin).toBe("https://accounts.google.com");
  expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  expect(url.searchParams.get("redirect_uri")).toBe(base+"/oauth/google/callback");
  expect(url.searchParams.get("access_type")).toBe("offline");
  const row=await e.DB.prepare("SELECT * FROM provider_states").first<any>();
  expect(row.hash).toBe(await hash(state));
  expect(JSON.stringify(row)).not.toContain(state);
  const callback="/oauth/google/callback?state="+state+"&code=synthetic";
  expect((await req(callback,"GET",undefined,"")).status).toBe(401);
  expect((await req(callback)).status).toBe(302);
  expect((await req(callback)).status).toBe(400);
  const exchange=fetchMock.mock.calls.find(([u])=>String(u)==="https://oauth2.googleapis.com/token")!;
  expect(new URLSearchParams(exchange[1].body).get("code_verifier")).toBe(row.verifier);
  const account=await e.DB.prepare("SELECT * FROM native_accounts WHERE subject='synthetic-google-sub'").first<any>();
  expect(account.payload).not.toContain("synthetic-refreshed-access");
  expect(account.payload).not.toContain("synthetic-rotated-refresh");
  expect(account.user_id).toBe("user_test");
  const {key}=await enroll();
  const identity=await(await req("/api/v1/whoami","GET",undefined,key)).text();
  expect(identity).toContain("test@example.invalid");
  expect(identity).not.toContain("synthetic-rotated-refresh");
  expect(fetchMock.mock.calls.every(([u])=>!String(u).includes("composio"))).toBe(true);
});

test("cancelled, expired or wrong-owner Google state grants no access",async()=>{
  const start=await(await req("/api/connectors/gmail/connect","POST",{})).json() as any;
  const state=new URL(start.redirect_url).searchParams.get("state")!;
  await e.DB.prepare("UPDATE provider_states SET user_id='user_other'").run();
  expect((await req("/oauth/google/callback?state="+state+"&code=synthetic")).status).toBe(400);
  await e.DB.prepare("UPDATE provider_states SET user_id='user_test',expires=?").bind(now()-1).run();
  expect((await req("/oauth/google/callback?state="+state+"&code=synthetic")).status).toBe(400);
  const next=await(await req("/api/connectors/googledrive/connect","POST",{})).json() as any;
  const denied=await req("/oauth/google/callback?state="+new URL(next.redirect_url).searchParams.get("state")+"&error=access_denied");
  expect(denied.headers.get("Location")).toBe("/?connect_error=google");
  expect(fetchMock.mock.calls.some(([u])=>String(u)==="https://oauth2.googleapis.com/token")).toBe(false);
});

test("native tokens refresh privately once and invalid grants require reconnect",async()=>{
  await e.DB.prepare("DELETE FROM native_accounts WHERE id='ca_one'").run();
  await seedAccount("ca_one","user_test",now()-10);
  const {key}=await enroll();
  for(let n=0;n<2;n++) expect((await req("/api/v1/call","POST",{tool:"GOOGLEDRIVE_GET_ABOUT",args:{},account:"ca_one"},key)).status).toBe(200);
  expect(fetchMock.mock.calls.filter(([u])=>String(u)==="https://oauth2.googleapis.com/token")).toHaveLength(1);
  const row=await e.DB.prepare("SELECT * FROM native_accounts WHERE id='ca_one'").first<any>();
  expect(row.payload).not.toContain("synthetic-rotated-refresh");
  expect((await open(row.payload,e.ENCRYPTION_KEY,"ca_one:user_test:google")).refresh_token).toBe("synthetic-rotated-refresh");
  await e.DB.prepare("DELETE FROM native_accounts WHERE id='ca_one'").run();
  await seedAccount("ca_one","user_test",now()-10);
  const normal=fetchMock.getMockImplementation()!;
  fetchMock.mockImplementation(async(input,init)=>String(input)==="https://oauth2.googleapis.com/token"?Response.json({error:"invalid_grant"},{status:400}):normal(input,init));
  try {
    expect((await req("/api/v1/call","POST",{tool:"GOOGLEDRIVE_GET_ABOUT",args:{},account:"ca_one"},key)).status).toBe(409);
    expect((await e.DB.prepare("SELECT status FROM native_accounts WHERE id='ca_one'").first<any>()).status).toBe("error");
  } finally {fetchMock.mockImplementation(normal);}
});

test("disconnect blocks the next native call and scope and type mismatches fail closed",async()=>{
  const {key}=await enroll();
  for(const args of [{query:{}},{max_results:51},{max_results:1.5}])
    expect((await req("/api/v1/call","POST",{tool:"GMAIL_FETCH_EMAILS",args,account:"ca_one"},key)).status).toBe(400);
  await e.DB.prepare("UPDATE native_accounts SET scopes='https://www.googleapis.com/auth/gmail.readonly' WHERE id='ca_one'").run();
  const held=await(await req("/api/v1/call","POST",{tool:"GMAIL_DELETE_MESSAGE",args:{message_id:"msg_synthetic"},account:"ca_one"},key)).json() as any;
  const {approvals:[view]}=await(await req("/api/approvals")).json() as any;
  expect((await req(`/api/approvals/${held.approval_id}/approve`,"POST",{args_hash:view.args_hash})).status).toBe(409);
  expect((await req("/api/accounts/ca_one","DELETE",{})).status).toBe(200);
  expect((await req("/api/v1/call","POST",{tool:"GMAIL_FETCH_EMAILS",args:{},account:"ca_one"},key)).status).toBe(400);
  expect(fetchMock.mock.calls.some(([u])=>String(u).includes("/trash"))).toBe(false);
});

test("fresh client setup saves a private stand-in key and works through CLI and stdio MCP",async()=>{
  const temporary=await mkdtemp(join(tmpdir(),"ralx-fresh-client-"));
  const server=createServer(async(incoming,outgoing)=>{
    try {
      const chunks:Buffer[]=[]; for await(const chunk of incoming) chunks.push(Buffer.from(chunk));
      const response=await worker.fetch(new Request(base+incoming.url,{method:incoming.method,headers:incoming.headers as any,
        ...(["GET","HEAD"].includes(incoming.method!)?{}:{body:Buffer.concat(chunks)})}),e);
      outgoing.writeHead(response.status,Object.fromEntries(response.headers));outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {outgoing.writeHead(500);outgoing.end('{}');}
  });
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  const address=server.address() as any;
  const script=join(temporary,"ralx.mjs"),preload=join(temporary,"redirect.mjs");
  await writeFile(script,readFileSync(new URL("../public/ralx.mjs",import.meta.url)),{mode:0o600});
  await writeFile(preload,`const direct=globalThis.fetch;globalThis.fetch=(url,init)=>{const u=new URL(url);if(u.origin!==${JSON.stringify(base)})throw Error('Unexpected destination');return direct('http://127.0.0.1:${address.port}'+u.pathname+u.search,init)};`);
  const run=(args:string[],input="")=>new Promise<{code:number|null;output:string;error:string}>(resolve=>{
    const child=spawn(process.execPath,["--import",pathToFileURL(preload).href,script,...args],{env:{...process.env,RALX_URL:base,CODEX_HOME:join(temporary,"codex"),CLAUDE_CONFIG_DIR:join(temporary,"claude")},windowsHide:true,stdio:["pipe","pipe","pipe"]});
    let output="",error="";child.stdout.on("data",d=>output+=d);child.stderr.on("data",d=>error+=d);
    child.on("close",code=>resolve({code,output,error}));child.stdin.end(input);
  });
  try {
    const prompt=await(await req("/api/agents/prompt","POST",{})).json() as any;
    const setup=await run(["enroll",prompt.code,"agent","Fresh synthetic agent"]);
    expect(setup.code,setup.error).toBe(0);
    expect(setup.output).toContain('"connected":true');
    expect(setup.output).toContain('"service":"gmail"');
    expect(setup.output).toContain('"service":"googledrive"');
    const stored=JSON.parse(await readFile(join(temporary,"connection.json"),"utf8"));
    expect(stored.key).toMatch(/^ralx_[a-f0-9]{64}$/);
    for(const secret of [stored.key,"synthetic-oauth-secret","synthetic-google-refresh",e.GOOGLE_CLIENT_SECRET!])
      expect(setup.output+setup.error).not.toContain(secret);
    expect((await run(["status"])).code).toBe(0);
    const codexProbe=spawnSync(process.platform==="win32"?"codex.exe":"codex",["--version"],{encoding:"utf8",windowsHide:true});
    if(codexProbe.status===0){
      await mkdir(join(temporary,"codex"));
      const codexSetup=await run(["enroll",prompt.code,"codex"]);
      expect(codexSetup.code,codexSetup.error).toBe(0);
      expect(JSON.parse(codexSetup.output.trim().split("\n")[0]).mcp_registered).toBe(true);
      const registered=spawnSync(process.platform==="win32"?"codex.exe":"codex",["mcp","get","ralx-cloud","--json"],{env:{...process.env,CODEX_HOME:join(temporary,"codex")},encoding:"utf8",windowsHide:true});
      expect(registered.status,registered.stderr).toBe(0);
      expect(registered.stdout).toContain(script.replaceAll("\\","\\\\"));
      expect(registered.stdout).not.toContain(stored.key);
    }
    const mcp=await run(["mcp"],[{jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-06-18"}},
      {jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"RALX_ACCOUNTS",arguments:{}}},
      {jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"GMAIL_FETCH_EMAILS",arguments:{ralx_account:"ca_one"}}}].map(x=>JSON.stringify(x)).join("\n")+"\n");
    expect(mcp.code,mcp.error).toBe(0);
    const messages=mcp.output.trim().split("\n").map(x=>JSON.parse(x));
    expect(messages[0].result.serverInfo.name).toBe("ralx");
    expect(messages[1].result.content[0].text).toContain("ca_one");
    expect(messages[2].result.content[0].text).toContain("Hello");
    expect(mcp.output+mcp.error).not.toContain(stored.key);
    await req("/api/agents/prompt","POST",{});
    expect((await run(["enroll",prompt.code,"agent"])).code).toBe(0);
    expect((await e.DB.prepare("SELECT count(*) AS n FROM agents").first<any>()).n).toBe(1);
  } finally {
    await new Promise<void>((resolve,reject)=>server.close(err=>err?reject(err):resolve()));
    if (!resolve(temporary).startsWith(resolve(tmpdir())+sep+"ralx-fresh-client-")) throw Error("Unsafe cleanup target");
    await rm(temporary,{recursive:true,force:true});
  }
},20000);

// Exercise the Worker-served app.js against real public routes without adding a DOM dependency.
async function vaultAppHarness(override?:(method:string,path:string,body:any,next:()=>Promise<any>)=>Promise<any>){
  const original=e.ASSETS;
  e.ASSETS={fetch:async(request:Request)=>new Response(readFileSync(new URL("../public/"+(new URL(request.url).pathname.slice(1)||"index.html"),import.meta.url),"utf8"))} as any;
  let code:string;
  try{
    expect(await(await req("/")).text()).toContain('src="/app.js"');
    code=await(await req("/app.js")).text();
  }finally{e.ASSETS=original;}
  const handlers:Record<string,Function>={},timers=new Map<number,Function>(),calls:string[]=[];
  const element=()=>({innerHTML:"",value:"",inert:false,classList:{remove(){}},addEventListener(type:string,fn:Function){handlers[type]=fn;}});
  const list=element(),input=element(),root=element(),elements:any={"#vault-list":list,"#vq":input,"#view":element(),"#sheet-root":element(),".top":element()};
  const api=async(method:string,path:string,body?:any)=>{
    calls.push(path);
    const next=async()=>{const response=await req(path,method,body),data=await response.json() as any;if(!response.ok)throw Object.assign(new Error(data.error),{status:response.status});return data;};
    return override?override(method,path,body,next):next();
  };
  const context:any={URL,URLSearchParams,Date,Map,Set,console,api,requestAPI:api,matchMedia:()=>({matches:true}),location:{hash:"#/vault"},document:{getElementById:()=>root,querySelector:(s:string)=>elements[s]||null,querySelectorAll:()=>[],addEventListener(){}},setTimeout:(fn:Function)=>{const id=timers.size+1;timers.set(id,fn);return id;},clearTimeout:(id:number)=>timers.delete(id),esc:(x:any)=>String(x??""),icon:()=>"",spinner:()=>"",siteLogo:()=>"",siteHost:(x:string)=>{try{return new URL(x).hostname;}catch{return "";}},day:()=>"today",toast(){},FormData:class{constructor(private form:any){}[Symbol.iterator](){return Object.entries(this.form.fields)[Symbol.iterator]();}}};
  runInNewContext(code.replace(/^import .*$/gm,"").replace(/\nboot\(\);\s*$/,"\nglobalThis.app={S,loadVault,saveLoginForm,api};"),context);
  return {app:context.app,list,input,calls,handlers,async debounce(){const queued=[...timers.values()];timers.clear();for(const fn of queued)await fn();}};
}
async function importSyntheticLogins(count:number){
  const data="name,url,username,password\n"+Array.from({length:count},(_,i)=>`Synthetic login ${String(i+1).padStart(4,"0")},https://synthetic-login.invalid,synthetic-user-${i},synthetic-password-${i}`).join("\n");
  expect((await upload(strToU8(data))).status).toBe(200);
}
test("Worker-served Logins app automatically renders all 101 imported logins",async()=>{
  await importSyntheticLogins(101);const h=await vaultAppHarness();await h.app.loadVault();
  expect(h.app.S.vault).toHaveLength(101);expect(h.list.innerHTML.match(/class="row"/g)).toHaveLength(101);
  expect(h.calls.some(x=>x.includes("cursor="))).toBe(true);
});
test("Worker-served Logins renders 101 names alphabetically with numeric and website ties for lists and search",async()=>{
  const expected=[{label:"account 2",origin:"https://a.invalid"},{label:"Account 2",origin:"https://z.invalid"},...Array.from({length:99},(_,i)=>({label:`${i%2?"account":"Account"} ${i+3}`,origin:"https://synthetic-sort.invalid"}))];
  const csv="name,url,username,password\n"+expected.map((x,i)=>`${x.label},${x.origin},synthetic-sort-user,synthetic-sort-password-${i}`).join("\n");
  expect((await upload(strToU8(csv))).status).toBe(200);
  const h=await vaultAppHarness();await h.app.loadVault();
  const rendered=()=>[...h.list.innerHTML.matchAll(/class="row-title">([^<]*)</g)].map(x=>x[1]);
  expect(rendered()).toEqual(expected.map(x=>x.label));
  expect(h.app.S.vault.slice(0,2).map((x:any)=>x.origin)).toEqual(["https://a.invalid","https://z.invalid"]);
  h.handlers.input({target:{id:"vq",value:"account"}});await h.debounce();
  expect(rendered()).toEqual(expected.map(x=>x.label));
  expect(h.app.S.vault.slice(0,2).map((x:any)=>x.origin)).toEqual(["https://a.invalid","https://z.invalid"]);
});
test("Worker-served Logins search never puts search text in request URLs",async()=>{
  await importSyntheticLogins(101);const h=await vaultAppHarness();await h.app.loadVault();
  const calls=h.calls.length,search="synthetic-private-search-value-62";
  h.handlers.input({target:{id:"vq",value:search}});await h.debounce();
  expect(h.calls.every(path=>!decodeURIComponent(path).includes(search))).toBe(true);
  expect(h.calls).toHaveLength(calls);
});
test("Worker-served Logins search finds last-page rows as background pages arrive",async()=>{
  await importSyntheticLogins(101);let release:()=>void=()=>{},reached:()=>void=()=>{};
  const gate=new Promise<void>(r=>{release=r;}),secondPage=new Promise<void>(r=>{reached=r;});
  const last=await e.DB.prepare("SELECT id,payload FROM vault_items ORDER BY id DESC LIMIT 1").first<any>();
  const fields=await open(last.payload,e.ENCRYPTION_KEY,`vault:${last.id}:user_test`);
  const h=await vaultAppHarness(async(method,path,_body,next)=>{if(method==="GET"&&path.includes("cursor=")){reached();await gate;}return next();});
  const loading=h.app.loadVault();await secondPage;
  try{
    h.handlers.input({target:{id:"vq",value:fields.label}});
    expect(h.list.innerHTML).toContain("skel");
  }finally{release();await loading;}
  await h.debounce();expect(h.app.S.vault).toHaveLength(101);
  expect(h.list.innerHTML.match(/class="row"/g)).toHaveLength(1);expect(h.list.innerHTML).toContain(fields.label);
  expect(h.calls.every(path=>!decodeURIComponent(path).includes(fields.label))).toBe(true);
});
test("Worker-served Logins complete reload removes save-then-delete phantom rows",async()=>{
  await importSyntheticLogins(101);let hold=false,release:()=>void=()=>{};
  const gate=new Promise<void>(r=>{release=r;});
  const h=await vaultAppHarness(async(method,path,_body,next)=>{if(hold&&method==="GET"&&path.startsWith("/api/vault"))await gate;return next();});
  await h.app.loadVault();hold=true;h.app.S.modal={busy:false};
  try{
    await h.app.saveLoginForm({fields:{...syntheticLogin,label:"Synthetic deleted before reload"},reset(){}});
    const id=h.app.S.vault.find((x:any)=>x.label==="Synthetic deleted before reload").id;
    expect((await req("/api/vault/"+id,"DELETE",{})).status).toBe(200);
    hold=false;release();await h.app.loadVault();
    expect(h.app.S.vault.some((x:any)=>x.id===id)).toBe(false);expect(h.list.innerHTML).not.toContain("Synthetic deleted before reload");
  }finally{hold=false;release();await h.app.loadVault();}
});
test("Worker-served Logins successful client delete clears optimistic rows immediately",async()=>{
  await importSyntheticLogins(101);let hold=false,release:()=>void=()=>{};
  const gate=new Promise<void>(r=>{release=r;});
  const h=await vaultAppHarness(async(method,path,_body,next)=>{if(hold&&method==="GET"&&path.startsWith("/api/vault"))await gate;return next();});
  await h.app.loadVault();hold=true;h.app.S.modal={busy:false};
  try{
    await h.app.saveLoginForm({fields:{...syntheticLogin,label:"Synthetic immediate delete"},reset(){}});
    const id=h.app.S.vault.find((x:any)=>x.label==="Synthetic immediate delete").id;
    expect(await h.app.api("DELETE","/api/vault/"+id,{})).toEqual({deleted:true});
    expect(h.app.S.vault.some((x:any)=>x.id===id)).toBe(false);expect(h.list.innerHTML).not.toContain("Synthetic immediate delete");
  }finally{hold=false;release();await h.app.loadVault();}
});
test("vault server search uses authenticated POST JSON bodies",async()=>{
  await req("/api/vault/login","POST",syntheticLogin);
  const response=await req("/api/vault/search","POST",{q:syntheticLogin.username});
  expect(response.status).toBe(200);expect((await response.json() as any).items).toHaveLength(1);
  expect((await req("/api/vault/search","POST",{q:"synthetic"},"")).status).toBe(401);
  expect((await req("/api/vault?q")).status).toBe(400);
  expect((await worker.fetch(new Request(base+"/api/vault/search",{method:"POST",headers:{Cookie:"__Host-ralx="+session,Origin:"https://evil.invalid","Content-Type":"application/json"},body:JSON.stringify({q:syntheticLogin.username})}),e)).status).toBe(403);
  const {key}=await enroll();
  const agent=await req("/api/v1/call","POST",{tool:"RALX_LOGINS",args:{q:syntheticLogin.username}},key);
  expect(agent.status).toBe(200);expect((await agent.json() as any).logins).toHaveLength(1);
  const mcp=await(await req("/mcp","POST",{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"RALX_LOGINS",arguments:{q:syntheticLogin.username}}},key)).json() as any;
  expect(JSON.parse(mcp.result.content[0].text).logins).toHaveLength(1);
});
test("Worker-served Logins app shows newly saved login in sorted position before background reload completes",async()=>{
  await importSyntheticLogins(101);let hold=false,release:()=>void=()=>{};
  const wait=new Promise<void>(resolve=>{release=resolve;});
  const h=await vaultAppHarness(async(method,path,_body,next)=>{if(hold&&method==="GET"&&path.startsWith("/api/vault"))await wait;return next();});
  await h.app.loadVault();hold=true;h.app.S.modal={busy:false};h.app.S.vq="old search";
  try{
    await h.app.saveLoginForm({fields:{...syntheticLogin,label:"Synthetic login 50.5"},reset(){}});
    expect(h.app.S.vq).toBe("");
    const names=[...h.list.innerHTML.matchAll(/class="row-title">([^<]*)</g)].map(x=>x[1]);
    expect(names[50]).toBe("Synthetic login 50.5");
  }finally{release();await h.app.loadVault();}
});

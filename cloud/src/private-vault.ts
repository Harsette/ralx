import { vaultZip } from "./vault-zip";
import { HttpError, token, iso, now, seal, open, text } from "./security";
import type { NativeEnv } from "./native-google";

export const MAX_IMPORT = 8 * 1024 * 1024;
type Parsed = {source_id:string;label:string;origin:string;kind:string;fields:Record<string,unknown>};
type Row = {id:string;user_id:string;kind:string;payload:string;created_at:string;updated_at:string};
const invalid = () => new HttpError(400,"This export could not be imported. No passwords were changed.");
const aad = (id:string,user:string) => `vault:${id}:${user}`;
const decode = (bytes:Uint8Array) => new TextDecoder("utf-8",{fatal:true,ignoreBOM:false}).decode(bytes);
export function loginOrigin(value:unknown) {
  if(typeof value!=="string" || value.length>4096) return "";
  try {const u=new URL(value);return u.protocol==="https:"&&!u.username&&!u.password?u.origin:"";} catch {return "";}
}
function rowsCSV(input:string) {
  const rows:string[][]=[];let row:string[]=[],field="",quoted=false,closed=false;
  input=input.replace(/^\uFEFF/,"");
  for(let i=0;i<input.length;i++) {
    const c=input[i];
    if(quoted) {if(c==='"'){if(input[i+1]==='"'){field+='"';i++;}else{quoted=false;closed=true;}}else field+=c;}
    else if(c==='"'&&!field&&!closed) quoted=true;
    else if(c===","||c==="\n"||c==="\r") {
      row.push(field);field="";closed=false;
      if(c!==","){if(c==="\r"&&input[i+1]==="\n")i++;if(row.some(v=>v!==""))rows.push(row);row=[];}
    } else {if(closed||c==='"')throw invalid();field+=c;}
    if(field.length>1024*1024||rows.length>5000||row.length>64) throw invalid();
  }
  if(quoted)throw invalid();if(field||row.length){row.push(field);rows.push(row);}return rows;
}
function csv(format:string,bytes:Uint8Array):Parsed[] {
  const rows=rowsCSV(decode(bytes)),header=rows.shift()?.map(s=>s.trim().toLowerCase());
  if(!header||new Set(header).size!==header.length)throw invalid();
  const website=format==="1password-csv"?"website":"url",label=format==="1password-csv"?"title":"name";
  if(![website,"username","password"].every(k=>header.includes(k)))throw invalid();
  const counts=new Map<string,number>();
  return rows.map((row,index)=>{
    if(row.length!==header.length)throw invalid();
    const original=Object.fromEntries(header.map((h,i)=>[h,row[i]]));
    const origin=loginOrigin(original[website]),title=original[label]||origin||"Imported login";
    const identity=JSON.stringify([title.slice(0,200),origin,original.username]);const ordinal=counts.get(identity)||0;counts.set(identity,ordinal+1);
    return {source_id:JSON.stringify([identity,ordinal]),label:title,origin,kind:origin&&original.password?"login":"private",
      fields:{username:original.username,password:original.password,totp:original["one-time password"]||"",notes:original.note||original.notes||"",original,row:index+2}};
  });
}
function onepassword(bytes:Uint8Array):Parsed[] {
  const files=vaultZip(bytes);
  if(!files["export.data"]||!files["export.attributes"])throw invalid();
  const attrs=JSON.parse(decode(files["export.attributes"]));
  if(Number(attrs.version)!==3||attrs.description!=="1Password Unencrypted Export")throw invalid();
  const doc=JSON.parse(decode(files["export.data"]));if(!Array.isArray(doc.accounts))throw invalid();
  const items:Parsed[]=[];const ids=new Set<string>();
  for(const [ai,account] of doc.accounts.entries()) {
    if(!Array.isArray(account.vaults))throw invalid();
    for(const [vi,vault] of account.vaults.entries()) {
      if(!Array.isArray(vault.items))throw invalid();
      for(const [ii,item] of vault.items.entries()) {
        if(!item||typeof item!=="object"||Array.isArray(item)||items.length>=5000)throw invalid();
        const identity=JSON.stringify([account.uuid||account.id||ai,vault.uuid||vault.id||vi,item.uuid||item.id||ii]);
        if(ids.has(identity))throw invalid();ids.add(identity);
        const details=item.details||{},overview=item.overview||{};
        let username="",password="",totp="";
        if(Array.isArray(details.loginFields))for(const f of details.loginFields){
          if(f?.designation==="username"&&typeof f.value==="string")username=f.value;
          if(f?.designation==="password"&&typeof f.value==="string")password=f.value;
        }
        if(Array.isArray(details.sections))for(const section of details.sections)if(Array.isArray(section?.fields))for(const f of section.fields){
          const value=f?.value||f?.v;
          if(value&&typeof value.totp==="string"&&!totp)totp=value.totp;
        }
        const urls=[overview.url,...(Array.isArray(overview.urls)?overview.urls.map((u:any)=>u?.url):[])];
        const origins=[...new Set(urls.map(loginOrigin).filter(Boolean))];
        const active=item.state===undefined||item.state==="active";
        items.push({source_id:identity,label:typeof overview.title==="string"?overview.title:"1Password item",origin:origins[0]||"",
          kind:active&&String(item.categoryUuid)==="001"&&origins.length&&password?"login":"private",
          fields:{username,password,totp,origins,notes:details.notesPlain||"",original:item}});
      }
    }
  }
  return items;
}
// Domain-separated HMACs prevent offline guesses of origin and import identity.
async function keyed(e:NativeEnv,user:string,purpose:string,value:string) {
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(e.ENCRYPTION_KEY),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return Array.from(new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(JSON.stringify(["private-vault-v2",user,purpose,value])))),x=>x.toString(16).padStart(2,"0")).join("");
}
async function originHashes(e:NativeEnv,user:string,fields:any) {
  const origins=[...new Set([fields.origin,...(Array.isArray(fields.origins)?fields.origins:[])].map(loginOrigin).filter(Boolean))];
  return Promise.all(origins.map(origin=>keyed(e,user,"origin",origin)));
}
function summary(r:Row,fields:any) {
  return {id:r.id,label:fields.label,origin:fields.origin,kind:r.kind,created_at:r.created_at,username_hint:typeof fields.username==="string"&&fields.username?fields.username.slice(0,1)+"***":""};
}
export async function vaultPage(e:NativeEnv,user:string,params:Record<string,unknown>={},loginsOnly=false) {
  const limit=Number(params.limit??100),q=params.q??"",origin=params.origin??null;
  let cursor=params.cursor??"";
  if(!Number.isInteger(limit)||limit<1||limit>1000||typeof q!=="string"||q.length>200||typeof cursor!=="string"||cursor.length>100)throw new HttpError(400,"Invalid vault search.");
  const normalized=origin===null?null:loginOrigin(origin);
  if(origin!==null&&!normalized)throw new HttpError(400,"Use an HTTPS website.");
  const originHash=normalized?await keyed(e,user,"origin",normalized):null;
  const items=[];let scanned=0;
  // Bound each read, decryption work and response. A cursor continues sparse searches.
  while(scanned<1000&&items.length<limit){
    const count=Math.min(100,1000-scanned);
    const sql="SELECT * FROM vault_items WHERE user_id=? AND id>?"+(loginsOnly?" AND kind='login'":"")+(originHash?" AND id IN (SELECT item_id FROM vault_origins WHERE user_id=? AND origin_hash=?)":"")+" ORDER BY id LIMIT ?";
    const values=originHash?[user,cursor,user,originHash,count]:[user,cursor,count];
    const rows=(await e.DB.prepare(sql).bind(...values).all<Row>()).results;
    for(const row of rows){
      cursor=row.id;scanned++;
      const fields=await open(row.payload,e.ENCRYPTION_KEY,aad(row.id,user));
      if(!q||[fields.label,fields.origin,fields.username].some(v=>typeof v==="string"&&v.toLocaleLowerCase().includes(q.toLocaleLowerCase())))items.push(summary(row,fields));
      if(items.length===limit)return {items,next_cursor:cursor};
    }
    if(rows.length<count)return {items};
  }
  return {items,next_cursor:cursor};
}
export async function loginRequests(e:NativeEnv,user:string) {
  const rows=(await e.DB.prepare("SELECT r.id,r.payload,r.expires,r.status,a.name AS agent,a.client FROM login_requests r JOIN agents a ON a.id=r.agent_id AND a.user_id=r.user_id AND a.revoked=0 WHERE r.user_id=? AND r.status='pending' AND r.expires>? ORDER BY r.expires DESC LIMIT 20").bind(user,now()).all<any>()).results;
  const requests=[];
  for(const {payload,...r} of rows)requests.push({...r,...await open(payload,e.ENCRYPTION_KEY,`request:${r.id}:${user}`)});
  return requests;
}
function groups<T>(rows:T[]) {
  const result:string[]=[];let group:T[]=[],size=2;
  for(const row of rows){const n=JSON.stringify(row).length+1;if(n>900000)throw invalid();if(size+n>900000){result.push(JSON.stringify(group));group=[];size=2;}group.push(row);size+=n;}
  if(group.length)result.push(JSON.stringify(group));return result;
}
export async function importVault(e:NativeEnv,user:string,format:string,bytes:Uint8Array) {
  if(!bytes.length||bytes.length>MAX_IMPORT)throw new HttpError(413,"Choose an export smaller than 8 MB.");
  if(!["chrome-csv","1password-csv","1password-1pux"].includes(format))throw invalid();
  let parsed:Parsed[];try{parsed=format==="1password-1pux"?onepassword(bytes):csv(format,bytes);}catch{throw invalid();}
  if(!parsed.length||parsed.length>5000)throw invalid();
  const importId=token("im_"),at=iso();
  const rows=[];
  for(const item of parsed){
    const id="vi_"+(await keyed(e,user,"import-identity",JSON.stringify([format,item.source_id]))).slice(0,40);
    // Large original fields remain in the authenticated encrypted import chunks.
    const reduced=JSON.stringify(item.fields).length>=500000;
    const fields={...(reduced?{username:item.fields.username,password:item.fields.password,totp:item.fields.totp,origins:item.fields.origins,original_import:importId,source_id:item.source_id}:item.fields),label:item.label,origin:item.origin};
    rows.push({id,kind:item.kind,origins:await originHashes(e,user,fields),payload:await seal(fields,e.ENCRYPTION_KEY,aad(id,user))});
  }
  const chunks=[];
  for(let offset=0,part=0;offset<bytes.length;offset+=196608,part++) {
    let raw="";const chunk=bytes.subarray(offset,offset+196608);for(let n=0;n<chunk.length;n+=32768)raw+=String.fromCharCode(...chunk.subarray(n,n+32768));
    chunks.push({part,payload:await seal({data:btoa(raw)},e.ENCRYPTION_KEY,`import:${importId}:${user}:${part}`)});
  }
  const rowGroups=groups(rows),chunkGroups=groups(chunks);
  if(rowGroups.length*3+chunkGroups.length>90)throw new HttpError(413,"This export needs smaller batches. No passwords were changed.");
  const statements=[e.DB.prepare("INSERT INTO vault_imports(id,user_id,format,items,created_at) VALUES (?,?,?,?,?)").bind(importId,user,format,parsed.length,at)];
  for(const group of chunkGroups)statements.push(e.DB.prepare("INSERT INTO vault_chunks(import_id,part,payload) SELECT ?,json_extract(value,'$.part'),json_extract(value,'$.payload') FROM json_each(?)").bind(importId,group));
  for(const group of rowGroups){
    statements.push(e.DB.prepare("INSERT INTO vault_items(id,user_id,source,kind,payload,created_at,updated_at) SELECT json_extract(value,'$.id'),?,?,json_extract(value,'$.kind'),json_extract(value,'$.payload'),?,? FROM json_each(?) WHERE true ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,payload=excluded.payload,updated_at=excluded.updated_at").bind(user,format,at,at,group));
    statements.push(e.DB.prepare("DELETE FROM vault_origins WHERE user_id=? AND item_id IN (SELECT json_extract(value,'$.id') FROM json_each(?))").bind(user,group));
    statements.push(e.DB.prepare("INSERT INTO vault_origins(item_id,user_id,origin_hash) SELECT json_extract(i.value,'$.id'),?,o.value FROM json_each(?) i,json_each(json_extract(i.value,'$.origins')) o").bind(user,group));
  }
  await e.DB.batch(statements);
  return {imported:parsed.length,logins:parsed.filter(x=>x.kind==="login").length,private_items:parsed.filter(x=>x.kind!=="login").length,original_preserved:true};
}
function validateLogin(b:any,partial=false) {
  const changed=(key:string)=>!partial||Object.hasOwn(b,key);
  if(changed("label"))text(b.label,200);
  const origin=changed("url")?loginOrigin(b.url):"";
  if((changed("url")&&!origin)||(changed("username")&&(typeof b.username!=="string"||b.username.length>4096))||(changed("password")&&(typeof b.password!=="string"||!b.password||b.password.length>16384))||(changed("totp")&&(typeof(b.totp??"")!=="string"||String(b.totp||"").length>4096))||(changed("notes")&&typeof(b.notes??"")!=="string"))throw new HttpError(400,"Enter a name, an HTTPS website and a password.");
  return origin;
}
export async function saveLogin(e:NativeEnv,user:string,b:any) {
  const origin=validateLogin(b),id=token("vi_"),at=iso();
  const {request_id,...content}=b;
  const fields={...content,original:content,label:b.label,origin,origins:[origin],totp:b.totp||"",notes:b.notes||""};
  const payload=await seal(fields,e.ENCRYPTION_KEY,aad(id,user)),originHash=await keyed(e,user,"origin",origin);
  const insert="INSERT INTO vault_items(id,user_id,source,kind,payload,created_at,updated_at) SELECT ?,?,'manual','login',?,?,?";
  const values=[id,user,payload,at,at];
  const statements=[];
  if(request_id){
    // The conditional insert and request completion share one D1 transaction.
    statements.push(e.DB.prepare(insert+" WHERE EXISTS (SELECT 1 FROM login_requests r JOIN agents a ON a.id=r.agent_id AND a.user_id=r.user_id AND a.revoked=0 WHERE r.id=? AND r.user_id=? AND r.origin_hash=? AND r.status='pending' AND r.expires>?)").bind(...values,request_id,user,originHash,now()));
    statements.push(e.DB.prepare("UPDATE login_requests SET item_id=?,status='saved' WHERE id=? AND user_id=? AND status='pending' AND EXISTS (SELECT 1 FROM vault_items WHERE id=? AND user_id=?)").bind(id,request_id,user,id,user));
  }else statements.push(e.DB.prepare(insert).bind(...values));
  statements.push(e.DB.prepare("INSERT INTO vault_origins(item_id,user_id,origin_hash) SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM vault_items WHERE id=? AND user_id=?)").bind(id,user,originHash,id,user));
  const results=await e.DB.batch(statements);
  if(!results[0].meta.changes)throw new HttpError(409,"This login request expired. Ask the agent to try again.");
  return {id,saved:true};
}
export async function editLogin(e:NativeEnv,user:string,id:string,b:any) {
  const row=await e.DB.prepare("SELECT * FROM vault_items WHERE id=? AND user_id=?").bind(id,user).first<Row>();
  if(!row)throw new HttpError(404,"Login not found.");
  const previous=await open(row.payload,e.ENCRYPTION_KEY,aad(id,user));
  const origin=validateLogin(b,true),fields={...previous,...b,origin:previous.origin};
  if(Object.hasOwn(b,"url")){fields.origin=origin;fields.origins=[origin];}
  const hashes=await originHashes(e,user,fields),payload=await seal(fields,e.ENCRYPTION_KEY,aad(id,user));
  // Compare the ciphertext we read so concurrent edits cannot silently replace one another.
  const results=await e.DB.batch([
    e.DB.prepare("UPDATE vault_items SET payload=?,updated_at=? WHERE id=? AND user_id=? AND payload=?").bind(payload,iso(),id,user,row.payload),
    e.DB.prepare("DELETE FROM vault_origins WHERE item_id=? AND user_id=? AND EXISTS (SELECT 1 FROM vault_items WHERE id=? AND user_id=? AND payload=?)").bind(id,user,id,user,payload),
    e.DB.prepare("INSERT OR IGNORE INTO vault_origins(item_id,user_id,origin_hash) SELECT ?,?,value FROM json_each(?) WHERE EXISTS (SELECT 1 FROM vault_items WHERE id=? AND user_id=? AND payload=?)").bind(id,user,JSON.stringify(hashes),id,user,payload),
  ]);
  if(!results[0].meta.changes)throw new HttpError(409,"This login changed. Refresh and try again.");
  return {id,saved:true};
}
export async function deleteLogin(e:NativeEnv,user:string,id:string) {
  const results=await e.DB.batch([
    e.DB.prepare("DELETE FROM vault_items WHERE id=? AND user_id=?").bind(id,user),
    e.DB.prepare("DELETE FROM vault_origins WHERE item_id=? AND user_id=?").bind(id,user),
  ]);
  if(!results[0].meta.changes)throw new HttpError(404,"Login not found.");
  return {deleted:true};
}
export async function requestLogin(e:NativeEnv,user:string,agent:string,args:any) {
  const origin=loginOrigin(args.url);if(!origin)throw new HttpError(400,"Use an HTTPS website.");
  const originHash=await keyed(e,user,"origin",origin);
  const existing=await e.DB.prepare("SELECT id FROM login_requests WHERE user_id=? AND agent_id=? AND origin_hash=? AND status='pending' AND expires>?").bind(user,agent,originHash,now()).first<{id:string}>();
  const id=existing?.id||token("lr_"),label=text(args.label||origin,200);
  if(!existing){
    const count=await e.DB.prepare("SELECT count(*) AS n FROM login_requests WHERE agent_id=? AND status='pending' AND expires>?").bind(agent,now()).first<{n:number}>();
    if(count!.n>=5)throw new HttpError(429,"Finish the pending private login requests first.");
    const payload=await seal({origin,label},e.ENCRYPTION_KEY,`request:${id}:${user}`);
    await e.DB.prepare("INSERT INTO login_requests(id,user_id,agent_id,origin_hash,payload,expires) VALUES (?,?,?,?,?,?)").bind(id,user,agent,originHash,payload,now()+900).run();
  }
  return {request_id:id,open_url:e.BASE_URL+"/#/vault?request="+id,status:"waiting_for_private_entry",instructions:"Open this RalX page to enter the login privately. Never put a password, OTP or key in chat or tool arguments."};
}

import { HttpError, hash, token, now, iso, seal, open, boundedBytes, scrub } from "./security";

export interface NativeEnv {
  DB: D1Database;
  BASE_URL: string;
  ENCRYPTION_KEY: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
}
export type NativeAccount = {id:string;user_id:string;provider:string;subject:string;label:string;scopes:string;payload:string;created_at:string;status:string};
const endpoint = "https://oauth2.googleapis.com/token";
const scopes = ["openid", "email", "https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/drive"];
const aad = (a: Pick<NativeAccount,"id"|"user_id"|"provider">) => `${a.id}:${a.user_id}:${a.provider}`;
export const googleSlugs = new Set(["gmail", "googledrive"]);

async function readJson(r: Response) {
  const data = await boundedBytes(r, 4 * 1024 * 1024);
  if (!r.ok) throw new HttpError(r.status === 401 ? 409 : 502, r.status === 401 ? "Reconnect this Google account" : `Google request failed (${r.status})`);
  try { return JSON.parse(new TextDecoder().decode(data)); } catch { throw new HttpError(502,"Google returned an unreadable response"); }
}
function configured(e: NativeEnv) {
  if (!e.GOOGLE_CLIENT_ID || !e.GOOGLE_CLIENT_SECRET) throw new HttpError(503,"Google connection setup is still in progress");
}
export async function startGoogle(e:NativeEnv,user:string,slug:string) {
  configured(e);
  if (!googleSlugs.has(slug)) throw new HttpError(404,"Native connector unavailable");
  await e.DB.prepare("DELETE FROM provider_states WHERE expires<=?").bind(now()).run();
  const state=token(), verifier=token()+token();
  const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier)));
  const challenge=btoa(String.fromCharCode(...digest)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  await e.DB.prepare("INSERT INTO provider_states(hash,user_id,provider,slug,verifier,expires) VALUES (?,?,?,?,?,?)").bind(await hash(state),user,"google",slug,verifier,now()+600).run();
  const q=new URLSearchParams({client_id:e.GOOGLE_CLIENT_ID!,redirect_uri:e.BASE_URL+"/oauth/google/callback",response_type:"code",scope:scopes.join(" "),access_type:"offline",prompt:"consent select_account",include_granted_scopes:"true",state,code_challenge:challenge,code_challenge_method:"S256"});
  return {redirect_url:"https://accounts.google.com/o/oauth2/v2/auth?"+q};
}
export async function finishGoogle(e:NativeEnv,user:string,url:URL) {
  configured(e);
  const state=url.searchParams.get("state");
  if(!state) throw new HttpError(400,"Google sign-in expired. Try connecting again.");
  const row=await e.DB.prepare("DELETE FROM provider_states WHERE hash=? AND user_id=? AND provider='google' AND expires>? RETURNING *").bind(await hash(state),user,now()).first<any>();
  if(!row) throw new HttpError(400,"Google sign-in expired. Try connecting again.");
  if(url.searchParams.has("error")) return new Response(null,{status:302,headers:{Location:"/?connect_error=google","Cache-Control":"no-store"}});
  const code=url.searchParams.get("code");
  if(!code || code.length>4096) throw new HttpError(400,"Google sign-in did not complete");
  const t=await readJson(await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:e.GOOGLE_CLIENT_ID!,client_secret:e.GOOGLE_CLIENT_SECRET!,code,code_verifier:row.verifier,redirect_uri:e.BASE_URL+"/oauth/google/callback",grant_type:"authorization_code"}),redirect:"manual",signal:AbortSignal.timeout(20000)}));
  if(typeof t.access_token!=="string") throw new HttpError(502,"Google did not return an access token");
  const profile=await readJson(await fetch("https://openidconnect.googleapis.com/v1/userinfo",{headers:{Authorization:"Bearer "+t.access_token},redirect:"manual",signal:AbortSignal.timeout(15000)}));
  if(!profile.sub || !profile.email || profile.email_verified!==true) throw new HttpError(400,"Google did not verify the account email");
  const previous=await e.DB.prepare("SELECT * FROM native_accounts WHERE user_id=? AND provider='google' AND subject=?").bind(user,profile.sub).first<NativeAccount>();
  const a={id:previous?.id||token("ga_"),user_id:user,provider:"google"};
  const old=previous?await open(previous.payload,e.ENCRYPTION_KEY,aad(previous)):null;
  const refresh_token=t.refresh_token||old?.refresh_token;
  if(!refresh_token) throw new HttpError(400,"Google did not grant background access. Connect again and allow access.");
  const granted=String(t.scope||"").split(" ");
  if(!granted.some((s:string)=>s.includes("gmail.")) && !granted.includes("https://www.googleapis.com/auth/drive")) throw new HttpError(400,"No Gmail or Drive access was granted");
  const payload=await seal({refresh_token,access_token:t.access_token,expires:now()+Number(t.expires_in||3600),client_id:e.GOOGLE_CLIENT_ID},e.ENCRYPTION_KEY,aad(a));
  await e.DB.prepare("INSERT INTO native_accounts(id,user_id,provider,subject,label,scopes,payload,created_at,status) VALUES (?,?,?,?,?,?,?,?, 'active') ON CONFLICT(user_id,provider,subject) DO UPDATE SET label=excluded.label,scopes=excluded.scopes,payload=excluded.payload,status='active'").bind(a.id,user,"google",profile.sub,profile.email,granted.join(" "),payload,previous?.created_at||iso()).run();
  return new Response(null,{status:302,headers:{Location:"/?connected="+encodeURIComponent(row.slug),"Cache-Control":"no-store"}});
}
export async function nativeRows(e:NativeEnv,user:string) {
  return (await e.DB.prepare("SELECT * FROM native_accounts WHERE user_id=? ORDER BY created_at DESC").bind(user).all<NativeAccount>()).results;
}
export async function googleAccounts(e:NativeEnv,user:string) {
  return (await nativeRows(e,user)).filter(a=>a.provider==="google").flatMap(a=>[
    ...(a.scopes.includes("gmail.")?["gmail"]:[]),
    ...(a.scopes.includes("/auth/drive")?["googledrive"]:[]),
  ].map(slug=>({id:a.id,user_id:user,alias:a.label,created_at:a.created_at,status:a.status==="active"?"ACTIVE":"ERROR",toolkit:{slug}})));
}
export async function removeNative(e:NativeEnv,user:string,id:string) {
  // Remove local access immediately. Revoking a shared Google grant would also
  // affect other installations using the same Google OAuth project.
  const r=await e.DB.prepare("DELETE FROM native_accounts WHERE id=? AND user_id=? RETURNING id").bind(id,user).first();
  if(!r) throw new HttpError(404,"Account not found");
}
async function access(e:NativeEnv,a:NativeAccount) {
  configured(e);
  let data=await open(a.payload,e.ENCRYPTION_KEY,aad(a));
  if(data.client_id!==e.GOOGLE_CLIENT_ID) throw new HttpError(409,"Reconnect this Google account");
  if(data.expires<now()+60) {
    const r=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:e.GOOGLE_CLIENT_ID!,client_secret:e.GOOGLE_CLIENT_SECRET!,refresh_token:data.refresh_token,grant_type:"refresh_token"}),redirect:"manual",signal:AbortSignal.timeout(15000)});
    if(r.status===400 || r.status===401) {
      await e.DB.prepare("UPDATE native_accounts SET status='error' WHERE id=? AND user_id=? AND payload=?").bind(a.id,a.user_id,a.payload).run();
      throw new HttpError(409,"Google requires this account to be reconnected");
    }
    const t=await readJson(r);
    data={...data,access_token:t.access_token,refresh_token:t.refresh_token||data.refresh_token,expires:now()+Number(t.expires_in||3600)};
    if(typeof data.access_token!=="string") throw new HttpError(502,"Google refresh failed");
    const payload=await seal(data,e.ENCRYPTION_KEY,aad(a));
    const updated=await e.DB.prepare("UPDATE native_accounts SET payload=? WHERE id=? AND user_id=? AND payload=? RETURNING id").bind(payload,a.id,a.user_id,a.payload).first();
    if(!updated) {
      const current=await e.DB.prepare("SELECT * FROM native_accounts WHERE id=? AND user_id=? AND status='active'").bind(a.id,a.user_id).first<NativeAccount>();
      if(!current) throw new HttpError(409,"Account disconnected");
      data=await open(current.payload,e.ENCRYPTION_KEY,aad(current));
    }
  }
  return data;
}
const str={type:"string"};
const num={type:"integer",minimum:1,maximum:50};
const spec=(slug:string,read:boolean,description:string,properties:Record<string,unknown>,required:string[]=[])=>({slug,read,description,input_schema:{type:"object",properties,required,additionalProperties:false}});
export const googleTools = {
  GMAIL_FETCH_EMAILS:spec("gmail",true,"Search Gmail directly through Google's Gmail API.",{query:str,max_results:num,page_token:str}),
  GMAIL_GET_PROFILE:spec("gmail",true,"Read the connected Gmail account profile.",{}),
  GMAIL_FETCH_MESSAGE_BY_MESSAGE_ID:spec("gmail",true,"Read a Gmail message, including its body.",{message_id:str},["message_id"]),
  GMAIL_SEND_EMAIL:spec("gmail",false,"Send an email. RalX asks its owner to approve the exact recipient, subject and body.",{recipient_email:str,subject:str,body:str},["recipient_email","body"]),
  GMAIL_DELETE_MESSAGE:spec("gmail",false,"Move a Gmail message to Trash after owner approval.",{message_id:str},["message_id"]),
  GOOGLEDRIVE_LIST_FILES:spec("googledrive",true,"List or search Google Drive files directly. query uses Google Drive query syntax.",{query:str,max_results:num,page_token:str}),
  GOOGLEDRIVE_FIND_FILE:spec("googledrive",true,"Search Google Drive files by name.",{query:str,max_results:num},["query"]),
  GOOGLEDRIVE_GET_FILE_METADATA:spec("googledrive",true,"Read Google Drive file metadata.",{file_id:str},["file_id"]),
  GOOGLEDRIVE_READ_FILE:spec("googledrive",true,"Read a text file, Google Doc or Google Sheet directly from Drive.",{file_id:str},["file_id"]),
  GOOGLEDRIVE_GET_ABOUT:spec("googledrive",true,"Read the connected Google Drive account and storage details.",{}),
  GOOGLEDRIVE_DELETE_FILE:spec("googledrive",false,"Move a Google Drive file to Trash after owner approval.",{file_id:str},["file_id"]),
};
function id(value:unknown) { if(typeof value!=="string"||!value||value.length>512||/[\s\r\n]/.test(value)) throw new HttpError(400,"Invalid resource id"); return encodeURIComponent(value); }
function count(value:unknown) { if(value===undefined) return 10; if(!Number.isInteger(value)||Number(value)<1||Number(value)>50) throw new HttpError(400,"max_results must be between 1 and 50"); return Number(value); }
export async function executeGoogle(e:NativeEnv,user:string,account:string,tool:string,args:any) {
  const a=await e.DB.prepare("SELECT * FROM native_accounts WHERE id=? AND user_id=? AND provider='google' AND status='active'").bind(account,user).first<NativeAccount>();
  if(!a) throw new HttpError(409,"Account disconnected");
  const spec = googleTools[tool as keyof typeof googleTools];
  if (!spec) throw new HttpError(404,"Native Google tool unavailable");
  const granted = new Set(a.scopes.split(" "));
  if (spec.slug === "gmail" && !["https://www.googleapis.com/auth/gmail.modify", "https://mail.google.com/", ...(spec.read ? ["https://www.googleapis.com/auth/gmail.readonly"] : tool === "GMAIL_SEND_EMAIL" ? ["https://www.googleapis.com/auth/gmail.send","https://www.googleapis.com/auth/gmail.compose"] : [])].some(s=>granted.has(s)))
    throw new HttpError(409,"Reconnect this Google account with Gmail access");
  if (spec.slug === "googledrive" && !["https://www.googleapis.com/auth/drive", ...(spec.read ? ["https://www.googleapis.com/auth/drive.readonly"] : [])].some(s=>granted.has(s)))
    throw new HttpError(409,"Reconnect this Google account with Drive access");
  const data=await access(e,a);
  const request=async(path:string,method="GET",payload?:unknown,raw=false)=>{
    const host=path.startsWith("/gmail/")?"https://gmail.googleapis.com":"https://www.googleapis.com";
    if(!(await e.DB.prepare("SELECT id FROM native_accounts WHERE id=? AND user_id=? AND status='active'").bind(a.id,user).first())) throw new HttpError(409,"Account disconnected");
    const r=await fetch(host+path,{method,headers:{Authorization:"Bearer "+data.access_token,"Content-Type":"application/json"},body:payload===undefined?undefined:JSON.stringify(payload),redirect:"manual",signal:AbortSignal.timeout(20000)});
    if(raw) { if(!r.ok) throw new HttpError(502,`Google request failed (${r.status})`); return new TextDecoder().decode(await boundedBytes(r,2*1024*1024)); }
    return readJson(r);
  };
  let result:any;
  const gmail="/gmail/v1/users/me";
  if(tool==="GMAIL_GET_PROFILE") result=await request(gmail+"/profile");
  else if(tool==="GMAIL_FETCH_EMAILS") {
    const q=new URLSearchParams({q:args.query||"in:inbox",maxResults:String(count(args.max_results))}); if(args.page_token) q.set("pageToken",String(args.page_token));
    const list=await request(gmail+"/messages?"+q);
    const messages=[];
    const source=(list.messages||[]).slice(0,count(args.max_results));
    for(let offset=0;offset<source.length;offset+=5) {
      const batch=await Promise.all(source.slice(offset,offset+5).map(async(m:any)=>{
      const detail=await request(gmail+"/messages/"+id(m.id)+"?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date");
      const header=(name:string)=>detail.payload?.headers?.find((h:any)=>h.name.toLowerCase()===name.toLowerCase())?.value;
      return {id:detail.id,thread_id:detail.threadId,subject:header("Subject"),from:header("From"),date:header("Date"),snippet:detail.snippet};
      }));
      messages.push(...batch);
    }
    result={messages,next_page_token:list.nextPageToken};
  } else if(tool==="GMAIL_FETCH_MESSAGE_BY_MESSAGE_ID") result=await request(gmail+"/messages/"+id(args.message_id)+"?format=full");
  else if(tool==="GMAIL_DELETE_MESSAGE") result=await request(gmail+"/messages/"+id(args.message_id)+"/trash","POST",{});
  else if(tool==="GMAIL_SEND_EMAIL") {
    if(typeof args.recipient_email!=="string"||/[\r\n]/.test(args.recipient_email)||!/^\S+@\S+\.\S+$/.test(args.recipient_email)||/[\r\n]/.test(args.subject||"")) throw new HttpError(400,"Use a valid recipient and a one-line subject");
    const subject="=?UTF-8?B?"+btoa(String.fromCharCode(...new TextEncoder().encode(args.subject||"")))+"?=";
    const mime=`To: ${args.recipient_email}\r\nSubject: ${subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n`+btoa(String.fromCharCode(...new TextEncoder().encode(args.body)));
    const raw=btoa(mime).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
    result=await request(gmail+"/messages/send","POST",{raw});
  } else if(tool==="GOOGLEDRIVE_GET_ABOUT") result=await request("/drive/v3/about?fields=user,storageQuota");
  else if(tool==="GOOGLEDRIVE_LIST_FILES"||tool==="GOOGLEDRIVE_FIND_FILE") {
    const q=new URLSearchParams({pageSize:String(count(args.max_results)),fields:"files(id,name,mimeType,modifiedTime,webViewLink,description),nextPageToken",q:tool==="GOOGLEDRIVE_FIND_FILE"?"trashed = false and name contains '"+String(args.query).replace(/\\/g,"\\\\").replace(/'/g,"\\'")+"'":args.query||"trashed = false"});
    if(args.page_token) q.set("pageToken",String(args.page_token));
    result=await request("/drive/v3/files?"+q);
  } else if(tool==="GOOGLEDRIVE_GET_FILE_METADATA") result=await request("/drive/v3/files/"+id(args.file_id)+"?fields=id,name,mimeType,description,modifiedTime,webViewLink,size");
  else if(tool==="GOOGLEDRIVE_DELETE_FILE") result=await request("/drive/v3/files/"+id(args.file_id),"PATCH",{trashed:true});
  else if(tool==="GOOGLEDRIVE_READ_FILE") {
    const path="/drive/v3/files/"+id(args.file_id);
    const meta=await request(path+"?fields=id,name,mimeType,size");
    const exportMime=meta.mimeType==="application/vnd.google-apps.spreadsheet"?"text/csv":"text/plain";
    if(!meta.mimeType.startsWith("application/vnd.google-apps.")&&!meta.mimeType.startsWith("text/")&&!/json|xml/.test(meta.mimeType)) throw new HttpError(400,"Use this tool for text files, Google Docs or Google Sheets");
    result={...meta,content:await request(path+(meta.mimeType.startsWith("application/vnd.google-apps.")?"/export?mimeType="+encodeURIComponent(exportMime):"?alt=media"),"GET",undefined,true)};
  } else throw new HttpError(404,"Native Google tool unavailable");
  return {successful:true,data:scrub(result,[data.access_token,data.refresh_token,e.GOOGLE_CLIENT_SECRET||""])};
}

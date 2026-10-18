import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,dirname,extname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {createServer} from 'node:net';
import {spawn} from 'node:child_process';

// Local synthetic proof only. Run while holding the project's .heavy.lock.
const cloud=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const evidence=resolve(cloud,'../tmp/verification/vault-sealed-20261018');
const lock=resolve(cloud,'../..','.heavy.lock');
if(!(await readFile(lock,'utf8')).startsWith('ralx/vault-fixes-r1 '))throw Error('This branch must hold .heavy.lock');
await mkdir(evidence,{recursive:true});
const publicDir=resolve(cloud,'public');
const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));
const port=probe.address().port;await new Promise(r=>probe.close(r));
const base=`https://127.0.0.1:${port}`;
const bundle=await build({entryPoints:[resolve(cloud,'src/index.ts')],bundle:true,write:false,format:'esm',platform:'browser',target:'es2022'});
const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:bundle.outputFiles[0].text,host:'127.0.0.1',port,https:true,compatibilityDate:'2026-10-17',d1Databases:['DB'],bindings:{BASE_URL:base,SESSION_SECRET:'synthetic-ui-session-secret',ENCRYPTION_KEY:'synthetic-ui-encryption-key',WORKOS_CLIENT_ID:'synthetic-ui-client'},serviceBindings:{ASSETS:async(req)=>{
  const path=new URL(req.url).pathname, file=resolve(publicDir,'.'+(path==='/'?'/index.html':path));
  if(!file.startsWith(publicDir+sep))return new Response('Not found',{status:404});
  try{return new Response(await readFile(file),{headers:{'Content-Type':({'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.woff2':'font/woff2'})[extname(file)]||'application/octet-stream'}});}catch{return new Response('Not found',{status:404});}
}}}));
let browser,cdp,session;
const errors=[],requests=[];
const pause=(ms)=>new Promise(r=>setTimeout(r,ms));
class CDP {
  constructor(ws){this.ws=ws;this.id=0;this.pending=new Map();this.events=new Map();ws.addEventListener('message',e=>{const m=JSON.parse(e.data);if(m.id){const p=this.pending.get(m.id);if(p){clearTimeout(p.timeout);this.pending.delete(m.id);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result);}}else for(const f of this.events.get(m.method)||[])f(m);});}
  on(name,fn){this.events.set(name,[...(this.events.get(name)||[]),fn]);}
  send(method,params={},sessionId=session){return new Promise((resolve,reject)=>{const id=++this.id,timeout=setTimeout(()=>{this.pending.delete(id);reject(Error(`CDP timeout: ${method}`));},10000);this.pending.set(id,{resolve,reject,timeout});this.ws.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});}
  async evaluate(expression){const r=await this.send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;}
}
async function until(expression){for(let i=0;i<100;i++){if(await cdp.evaluate(expression))return;await pause(100);}throw Error('Page condition timed out: '+expression);}
try{
  await mf.ready;const db=await mf.getD1Database('DB');
  for(const name of ['0001_initial.sql','0002_native_accounts.sql','0003_private_vault.sql'])for(const sql of (await readFile(resolve(cloud,'migrations',name),'utf8')).split(';').filter(x=>x.trim()))await db.prepare(sql).run();
  await db.prepare("INSERT INTO users(id,email) VALUES ('synthetic-ui-owner','synthetic-ui@example.invalid')").run();
  const cookie='synthetic-ui-cookie',hash=createHash('sha256').update(cookie+'synthetic-ui-session-secret').digest('hex');
  await db.prepare("INSERT INTO sessions(hash,user_id,expires) VALUES (?,'synthetic-ui-owner',?)").bind(hash,Math.floor(Date.now()/1000)+3600).run();
  const csv='name,url,username,password\n'+Array.from({length:101},(_,i)=>`Synthetic login ${String(i+1).padStart(3,'0')},https://synthetic-login.invalid,synthetic-ui-user-${i},synthetic-ui-password-${i}`).join('\n');
  const imported=await mf.dispatchFetch(base+'/api/vault/import?format=chrome-csv',{method:'POST',headers:{Cookie:'__Host-ralx='+cookie,Origin:base,'Content-Type':'application/octet-stream'},body:csv});
  if(imported.status!==200)throw Error('Synthetic import failed: '+await imported.text());
  const profile=resolve(evidence,'round4-headless-profile-'+Date.now());await mkdir(profile);
  const executable=process.env.RALX_HEADLESS_BROWSER||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
  browser=spawn(executable,['--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-extensions','--disable-component-update','--disable-sync','--no-service-autorun','--ignore-certificate-errors','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{windowsHide:true,stdio:'ignore'});
  let active;for(let i=0;i<100;i++){try{active=(await readFile(resolve(profile,'DevToolsActivePort'),'utf8')).trim().split('\n');break;}catch{await pause(100);}}
  if(!active)throw Error('Headless browser did not start');
  const ws=new WebSocket(`ws://127.0.0.1:${active[0]}${active[1]}`);await new Promise((r,j)=>{ws.addEventListener('open',r,{once:true});ws.addEventListener('error',j,{once:true});});cdp=new CDP(ws);
  const targets=await cdp.send('Target.getTargets',{},null);const target=targets.targetInfos.find(x=>x.type==='page');
  session=(await cdp.send('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
  await cdp.send('Page.enable');await cdp.send('Runtime.enable');await cdp.send('Network.enable');
  cdp.on('Runtime.exceptionThrown',m=>errors.push(m.params.exceptionDetails.text));
  cdp.on('Network.requestWillBeSent',m=>{if(m.params.request.url.startsWith(base+'/api/vault?'))requests.push(m.params.request.url);});
  cdp.on('Fetch.requestPaused',m=>{const own=m.params.request.url.startsWith(base+'/');cdp.send(own?'Fetch.continueRequest':'Fetch.failRequest',own?{requestId:m.params.requestId}:{requestId:m.params.requestId,errorReason:'BlockedByClient'}).catch(e=>errors.push(String(e)));});
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]});
  if(!(await cdp.send('Network.setCookie',{name:'__Host-ralx',value:cookie,url:base,path:'/',secure:true,httpOnly:true,sameSite:'Lax'})).success)throw Error('Synthetic cookie failed');
  await cdp.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  await cdp.send('Page.navigate',{url:base+'/#/vault'});
  await until("document.querySelector('#vault-list h2')?.textContent==='101 logins' && document.querySelectorAll('#vault-list li.row').length===101");
  await cdp.evaluate('document.fonts.ready.then(()=>true)');
  const shots=[];
  const expected=Array.from({length:101},(_,i)=>'Synthetic login '+String(i+1).padStart(3,'0'));
  const titles=await cdp.evaluate("[...document.querySelectorAll('#vault-list .row-title')].map(x=>x.textContent)");
  if(JSON.stringify(titles)!==JSON.stringify(expected))throw Error('Rendered login order is incorrect');
  for(const viewport of [{width:1440,height:1000,mobile:false,name:'desktop'},{width:390,height:844,mobile:true,name:'390'},{width:390,height:844,mobile:true,name:'390-nav-end'}]){
    await cdp.send('Emulation.setDeviceMetricsOverride',{...viewport,deviceScaleFactor:1,name:undefined});
    if(viewport.name==='390-nav-end'){
      await cdp.evaluate("(()=>{const tabs=document.querySelector('.tabs');tabs.scrollLeft=tabs.scrollWidth;return true;})()");
      await until("!document.querySelector('.tabs').classList.contains('more-right')");
    }
    await cdp.evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))).then(()=>true)');
    const state=await cdp.evaluate("(()=>{const nav=document.querySelector('.tabs');return {count:document.querySelectorAll('#vault-list li.row').length,heading:document.querySelector('#vault-list h2').textContent,width:innerWidth,scrollWidth:document.documentElement.scrollWidth,navMoreRight:nav.classList.contains('more-right'),navMask:getComputedStyle(nav).maskImage,navScrollLeft:nav.scrollLeft};})()");
    if(viewport.name==='390'&&(!state.navMoreRight||state.navMask==='none'))throw Error('Scrollable nav has no right fade');
    if(viewport.name==='390-nav-end'&&(state.navMoreRight||state.navMask!=='none'))throw Error('Nav fade did not disappear at the end');
    if(state.count!==101||state.scrollWidth>state.width)throw Error('Logins viewport check failed: '+JSON.stringify(state));
    const path=resolve(evidence,`round4-logins-${viewport.name}.png`),shot=await cdp.send('Page.captureScreenshot',{format:'png',fromSurface:true,captureBeyondViewport:false});
    await writeFile(path,Buffer.from(shot.data,'base64'));shots.push({path,...state});
  }
  // A fresh load on the rightmost route must reveal the active tab by itself.
  await cdp.send('Page.navigate',{url:base+'/?nav-load-proof=1#/activity'});
  await until("(()=>{const nav=document.querySelector('.tabs'),active=nav?.querySelector('[aria-current]');if(active?.dataset.route!=='activity')return false;const n=nav.getBoundingClientRect(),a=active.getBoundingClientRect();return a.left>=n.left&&a.right<=n.right&&!nav.classList.contains('more-right');})()");
  await cdp.send('Page.navigate',{url:base+'/?nav-load-proof=1#/vault'});
  await until("document.querySelectorAll('#vault-list li.row').length===101");
  const beforeSearch=requests.length;
  await cdp.evaluate("document.querySelector('#vq').focus()");await cdp.send('Input.insertText',{text:'Synthetic login 101'});
  await until("document.querySelectorAll('#vault-list li.row').length===1 && document.querySelector('#vault-list .row-title')?.textContent==='Synthetic login 101'");
  if(requests.length!==beforeSearch||requests.some(x=>new URL(x).searchParams.has('q')||decodeURIComponent(x).includes('Synthetic login 101')))throw Error('Local search leaked into a request URL');
  if(errors.length)throw Error('Browser errors: '+JSON.stringify(errors));
  const proof={synthetic_only:true,local_workerd:true,browser:'one headless Edge instance',shots,sorted:true,active_tab_visible_on_load:true,local_search:true,paginated_requests:requests.length,errors};
  await writeFile(resolve(evidence,'round4-browser-proof.json'),JSON.stringify(proof,null,2));console.log(JSON.stringify(proof,null,2));
}finally{
  if(cdp){await cdp.send('Browser.close',{},null).catch(()=>{});cdp.ws.close();}
  if(browser&&!browser.killed)browser.kill();
  await mf.dispose();
}

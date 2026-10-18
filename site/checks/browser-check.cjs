const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core');
const root=path.resolve(__dirname,'../..'),out=path.resolve(process.env.PROOF_DIR||path.join(root,'tmp/landing-proof')),url='http://127.0.0.1:7431';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const receipt=process.env.RESUME_ASSETS?JSON.parse(fs.readFileSync(path.join(out,'receipt.json'),'utf8')):{checkedAt:new Date().toISOString(),origin:url,checks:{},screenshots:[],performance:{},diagnostics:{}};
function save(){fs.writeFileSync(path.join(out,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');fs.writeFileSync(path.join(__dirname,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');}
(async()=>{
 fs.mkdirSync(out,{recursive:true});
 if(!fs.readFileSync(path.resolve(root,'../.heavy.lock'),'utf8').startsWith('landing '))throw Error('landing heavy lock is required');
 if(process.env.RESUME_ASSETS){delete receipt.failure;receipt.assetsResumedAt=new Date().toISOString();}
 let browser;
 try{
  if(!process.env.SKIP_PERF){
   receipt.performance=await require('./performance.cjs').measure({chromium,url,out});
  }else receipt.performance=JSON.parse(fs.readFileSync(path.join(out,'performance.json'),'utf8'));
  receipt.checks.phoneTaskBudget=receipt.performance.runs.every(r=>r.cpuThrottle!==4||r.longestTaskFirst3s<=200);
  receipt.checks.frameBudget=receipt.performance.runs.every(r=>r.loadFrameP95<=(r.cpuThrottle===4?50:34)&&r.scrollFrameP95<=(r.cpuThrottle===4?50:34));
  save();if(process.env.PERF_ONLY)return;
  assert.equal(receipt.performance.runs.length,6);assert.equal(receipt.checks.phoneTaskBudget,true);assert.equal(receipt.checks.frameBudget,true);
  browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe',args:['--no-first-run','--disable-extensions']});
  if(!process.env.RESUME_ASSETS){
  for(const [label,width,height,dpr] of [['desktop',1440,900,1],['phone',390,844,2]]){
   const context=await browser.newContext({viewport:{width,height},deviceScaleFactor:dpr,isMobile:label==='phone',hasTouch:label==='phone',permissions:['clipboard-read','clipboard-write']});const page=await context.newPage();const errors=[],badResponses=[];
   page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text())});page.on('response',r=>{if(r.status()>=400)badResponses.push({url:r.url(),status:r.status()})});
   await page.goto(url,{waitUntil:'networkidle'});await page.evaluate(()=>{document.documentElement.style.scrollBehavior='auto';return document.fonts.ready;});
   if(label==='desktop'){
    const text=await page.locator('#install-code').innerText();await page.locator('#copy').click();await page.waitForFunction(()=>document.querySelector('#copy').textContent.includes('Copied'));assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),text);receipt.checks.copyPrompt=true;
    await page.getByRole('tab',{name:'Terminal',exact:true}).click();for(const os of ['windows','mac','linux']){await page.locator('#os').selectOption(os);const command=await page.locator('#install-code').innerText();assert.ok(command.includes(os==='windows'?'install.ps1':'install.sh'));await page.locator('#copy').click();assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),command);}receipt.checks.terminalTabsAndClipboard=true;
    await page.getByRole('tab',{name:'Ask your agent',exact:true}).click();
    // Submit through the actual form to the actual local Pages Function.
    const email=`landing-proof-${Date.now()}@example.test`;await page.locator('#email').fill(email);const responsePromise=page.waitForResponse(r=>r.url().endsWith('/api/waitlist')&&r.request().method()==='POST');await page.getByRole('button',{name:'Join the RalX Cloud waitlist'}).click();const response=await responsePromise;assert.equal(response.status(),200);await page.waitForFunction(()=>document.querySelector('#waitlist-status').textContent.includes('on the list'));receipt.checks.waitlist={status:response.status(),response:await response.json(),email,visible:await page.locator('#waitlist-status').innerText()};
    await page.locator('#waitlist-status').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(out,'waitlist-success.png')});receipt.screenshots.push('waitlist-success.png');
    const invalid=await page.request.post(url+'/api/waitlist',{data:{email:'bad'}});assert.equal(invalid.status(),400);const honey=await page.request.post(url+'/api/waitlist',{data:{email:'spam@example.test',website:'spam'}});assert.equal(honey.status(),200);const rate=await page.request.post(url+'/api/waitlist',{data:{email:'again@example.test'}});assert.equal(rate.status(),429);receipt.checks.localPostFailures={invalid:invalid.status(),honeypot:honey.status(),rate:rate.status()};
    await page.evaluate(()=>{document.querySelector('#waitlist-status').textContent='';window.scrollTo(0,0)});
   }
   await page.evaluate(()=>window.scrollTo(0,0));
   await page.locator('img[loading=lazy]').evaluateAll(images=>images.forEach(i=>i.loading='eager'));await page.waitForFunction(()=>[...document.images].every(i=>i.complete));
   const ids=await page.locator('main>section').evaluateAll(elements=>elements.map(e=>e.id));
   for(const id of ids){await page.locator('#'+id).evaluate(e=>e.scrollIntoView({block:'start',behavior:'instant'}));await sleep(id==='how'?1450:200);const section=await page.locator('#'+id).evaluate(e=>({id:e.id,top:Math.floor(e.getBoundingClientRect().top+scrollY),height:Math.ceil(e.getBoundingClientRect().height)}));const start=section.id==='hero'?0:section.top;const end=section.top+section.height;let count=0;for(let y=start;y<end;y+=Math.floor(height*.8)){await page.evaluate(y=>window.scrollTo(0,y),y);await sleep(180);await page.locator('img[loading=lazy]').evaluateAll(images=>images.forEach(i=>i.loading='eager'));await page.waitForFunction(()=>[...document.images].every(i=>i.complete));const file=`${label}-${section.id}-${String(++count).padStart(2,'0')}.png`;await page.screenshot({path:path.join(out,file),fullPage:false});receipt.screenshots.push(file);if(y+height>=end)break;}}
   receipt.diagnostics[label]=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,brokenImages:[...document.images].filter(i=>!i.naturalWidth).map(i=>i.src),viewport:[innerWidth,innerHeight,devicePixelRatio],headingItalics:[...document.querySelectorAll('h1,section h2')].map(e=>({text:e.textContent,count:e.querySelectorAll('em').length}))}));receipt.diagnostics[label].consoleErrors=errors;receipt.diagnostics[label].badResponses=badResponses;
   assert.equal(receipt.diagnostics[label].overflow,false);assert.deepEqual(receipt.diagnostics[label].brokenImages,[]);assert.deepEqual(errors,[]);assert.deepEqual(badResponses,[]);assert.ok(receipt.diagnostics[label].headingItalics.every(h=>h.count===1));
   await page.locator('summary').first().click();assert.equal(await page.locator('details').first().getAttribute('open'),'');receipt.checks.faq=true;
   for(const legal of ['privacy','terms']){await page.goto(url+'/'+legal,{waitUntil:'networkidle'});assert.ok((await page.locator('.draft').innerText()).includes('Draft, last updated 18 October 2026'));assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:path.join(out,`${label}-${legal}.png`)});receipt.screenshots.push(`${label}-${legal}.png`);await page.screenshot({path:path.join(out,`${label}-${legal}-full.png`),fullPage:true});receipt.screenshots.push(`${label}-${legal}-full.png`);}
   await context.close();save();console.log(label,'captures complete');
  }
  }
  const context=await browser.newContext({viewport:{width:1440,height:900}}),page=await context.newPage();
  await page.goto(url,{waitUntil:'networkidle'});
  receipt.checks.assetResponses=[];
  for(const [asset,width,height]of [['/og.png',1200,630],['/favicon-16.png',16,16],['/favicon-32.png',32,32],['/apple-touch-icon.png',180,180],['/icon-192.png',192,192],['/icon-512.png',512,512],['/favicon.svg',512,512]]){
   const response=await page.request.get(url+asset);assert.equal(response.status(),200);assert.ok(response.headers()['content-type'].startsWith('image/'));
   const dimensions=await page.evaluate(src=>new Promise((resolve,reject)=>{const image=new Image();image.onload=()=>resolve([image.naturalWidth,image.naturalHeight]);image.onerror=reject;image.src=src;}),asset);assert.deepEqual(dimensions,[width,height]);receipt.checks.assetResponses.push({asset,status:response.status(),type:response.headers()['content-type'],dimensions});
  }
  assert.equal(await page.locator('meta[property="og:image"]').getAttribute('content'),'https://ralx.ralveto.com/og.png');
  for(const theme of ['light','dark']){await page.emulateMedia({colorScheme:theme});await page.goto('http://127.0.0.1:7432/',{waitUntil:'networkidle'});await page.waitForFunction(()=>[...document.images].every(i=>i.complete));assert.deepEqual(await page.evaluate(()=>[...document.images].filter(i=>!i.naturalWidth&&!i.src.includes('shields.io')&&!i.src.includes('badge.svg')).map(i=>i.src)),[]);for(let y=0,i=1;y<await page.locator('body').evaluate(e=>e.scrollHeight);y+=720,i++){await page.evaluate(y=>scrollTo(0,y),y);const name=`readme-${theme}-${String(i).padStart(2,'0')}.png`;await page.screenshot({path:path.join(out,name)});receipt.screenshots.push(name);}await page.screenshot({path:path.join(out,`readme-${theme}-full.png`),fullPage:true});receipt.screenshots.push(`readme-${theme}-full.png`);}
  await context.close();receipt.checks.readmePreview='Python Markdown fenced code + tables, GitHub Markdown CSS, light and dark media. Local preview; not proof of live GitHub rendering.';save();console.log(JSON.stringify({performance:receipt.performance,diagnostics:receipt.diagnostics,screenshotCount:receipt.screenshots.length},null,2));
 }finally{if(browser)await browser.close();save();}
})().catch(e=>{receipt.failure=e.stack;save();console.error(e);process.exitCode=1;});

const fs=require('fs'),path=require('path');
const percentile=(values,p)=>{const s=[...values].sort((a,b)=>a-b);return s.length?Number(s[Math.ceil(s.length*p)-1].toFixed(2)):0;};
exports.measure=async({chromium,url,out})=>{
 const result={checkedAt:new Date().toISOString(),taskMeasurement:'PerformanceObserver longtask entries, at least 50ms. A zero maximum means no task of 50ms or longer was observed.',method:(process.env.PERF_DIAGNOSTIC?'One fresh diagnostic browser process and context;':'Six fresh browser processes and contexts;')+' 390x844 CSS, DPR2, cold browser cache, loopback network without throttling. Load frames: rAF intervals from first callback through navigation time 3000ms. Scroll frames: rAF-driven 1000 CSS px/s top-to-bottom pass, including lazy video. Nearest-rank p95; no runs discarded.',runs:[]};
 for(const rate of (process.env.PERF_DIAGNOSTIC?[4]:[4,1]))for(let run=1;run<=(process.env.PERF_DIAGNOSTIC?1:3);run++){
  const browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH||'C:/Program Files/Google/Chrome/Application/chrome.exe',args:['--no-first-run','--disable-extensions']});
  try{
   const context=await browser.newContext({viewport:{width:390,height:844},deviceScaleFactor:2,isMobile:true,hasTouch:true});
   const page=await context.newPage(),cdp=await context.newCDPSession(page);
   await cdp.send('Emulation.setCPUThrottlingRate',{rate});await cdp.send('Network.enable');await cdp.send('Network.setCacheDisabled',{cacheDisabled:true});
   if(process.env.PERF_TRACE)await cdp.send('Tracing.start',{categories:'devtools.timeline,v8,blink.user_timing',transferMode:'ReturnAsStream'});
   await page.addInitScript(()=>{
    window.proof={tasks:[],lcp:[],frames:[]};
    new PerformanceObserver(l=>window.proof.tasks.push(...l.getEntries().map(e=>({start:e.startTime,duration:e.duration})))).observe({type:'longtask',buffered:true});
    new PerformanceObserver(l=>window.proof.lcp.push(...l.getEntries().map(e=>({time:e.startTime,size:e.size,element:e.element?.tagName})))).observe({type:'largest-contentful-paint',buffered:true});
    let last;function frame(t){if(last!==undefined&&t<=3000)window.proof.frames.push(t-last);last=t;if(t<3000)requestAnimationFrame(frame);}requestAnimationFrame(frame);
   });
   await page.goto(url,{waitUntil:'load'});await page.waitForTimeout(3300);
   const data=await page.evaluate(()=>({proof:window.proof,viewport:[innerWidth,innerHeight,devicePixelRatio],resourceBytes:performance.getEntriesByType('resource').reduce((a,e)=>a+e.transferSize,0)}));
   if(process.env.PERF_TRACE){const complete=new Promise(r=>cdp.once('Tracing.tracingComplete',r));await cdp.send('Tracing.end');const {stream}=await complete;let raw='';while(true){const chunk=await cdp.send('IO.read',{handle:stream});raw+=chunk.data;if(chunk.eof)break;}await cdp.send('IO.close',{handle:stream});fs.writeFileSync(path.join(out,`trace-${rate}x-${run}.json`),raw);}
   await page.evaluate(()=>{document.documentElement.style.scrollBehavior='auto';scrollTo(0,0);});
   const scrollFrames=await page.evaluate(()=>new Promise(resolve=>{const frames=[];let start,last;function tick(t){if(start===undefined)start=t;if(last!==undefined)frames.push(t-last);last=t;const y=(t-start);scrollTo(0,y);if(y<document.documentElement.scrollHeight-innerHeight)requestAnimationFrame(tick);else resolve(frames);}requestAnimationFrame(tick);}));
   const item={cpuThrottle:rate,run,viewport:data.viewport,longestTaskFirst3s:Math.max(0,...data.proof.tasks.filter(e=>e.start<3000).map(e=>e.duration)),lcp:data.proof.lcp.at(-1)?.time,loadFrameP95:percentile(data.proof.frames,.95),scrollFrameP95:percentile(scrollFrames,.95),loadFrameCount:data.proof.frames.length,scrollFrameCount:scrollFrames.length,resourceBytes:data.resourceBytes,longTasks:data.proof.tasks};
   if(!Number.isFinite(item.lcp)||!item.loadFrameCount||!item.scrollFrameCount)throw Error('Incomplete performance observation: '+JSON.stringify(item));
   result.runs.push(item);fs.writeFileSync(path.join(out,'performance.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(item));
  }finally{await browser.close();}
 }
 return result;
};

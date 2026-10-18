(() => {
  const code = document.querySelector('#install-code');
  if (!code) return;
  const prompt = 'Install RalX for me: follow https://github.com/Harsette/ralx/blob/main/AGENT_INSTALL.md';
  const commands = {windows:'irm https://raw.githubusercontent.com/Harsette/ralx/main/install.ps1 | iex',mac:'curl -fsSL https://raw.githubusercontent.com/Harsette/ralx/main/install.sh | sh',linux:'curl -fsSL https://raw.githubusercontent.com/Harsette/ralx/main/install.sh | sh'};
  const os = document.querySelector('#os');
  os.value = /Win/i.test(navigator.userAgentData?.platform || navigator.platform) ? 'windows' : /Linux/i.test(navigator.platform) ? 'linux' : 'mac';
  let method = 'agent', timer;
  const button = document.querySelector('#copy'), original = button.innerHTML;
  function update() {code.textContent = method === 'agent' ? prompt : commands[os.value]; document.querySelector('#os-label').hidden = method !== 'terminal';document.querySelector('#install-panel').setAttribute('aria-labelledby',`tab-${method}`);button.innerHTML=original;button.setAttribute('aria-label',method==='agent'?'Copy install prompt':'Copy install command');}
  const tabs = [...document.querySelectorAll('[data-method]')];
  tabs.forEach((tab,i) => { tab.addEventListener('click', () => {method=tab.dataset.method; tabs.forEach(t=>{t.setAttribute('aria-selected', String(t===tab));t.tabIndex=t===tab?0:-1;});update();});tab.addEventListener('keydown',e=>{if(['ArrowRight','ArrowLeft','Home','End'].includes(e.key)){e.preventDefault();const next=tabs[e.key==='Home'?0:e.key==='End'?tabs.length-1:(i+1)%tabs.length];next.click();next.focus();}});});
  os.addEventListener('change',update);
  button.addEventListener('click',async()=>{clearTimeout(timer);try{await navigator.clipboard.writeText(code.textContent);button.innerHTML='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m5 12 4 4L19 6"/></svg><span>Copied</span>';document.querySelector('#copy-status').textContent='Copied. Paste it into your '+(method==='agent'?'agent.':'terminal.');timer=setTimeout(()=>button.innerHTML=original,2500);}catch{document.querySelector('#copy-status').textContent='Copy was blocked. Select and copy the text above.';const selection=window.getSelection();const range=document.createRange();range.selectNodeContents(code);selection.removeAllRanges();selection.addRange(range);}});
  const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
  // Native CSS port of Magic UI's Border Beam: a light follows the frame's perimeter.
  const motionObserver=new IntersectionObserver(entries=>entries.forEach(entry=>entry.target.classList.toggle('in-view',entry.isIntersecting)),{threshold:.05});
  document.querySelectorAll('.beam').forEach(frame=>{const track=document.createElement('span');track.className='border-track';track.setAttribute('aria-hidden','true');track.append(document.createElement('span'));frame.append(track);motionObserver.observe(frame);});
  document.querySelectorAll('.dark').forEach(section=>motionObserver.observe(section));
  const video=document.querySelector('#demo-video');
  const caption=document.querySelector('#demo-caption'),textTrack=video.textTracks[0];
  if(textTrack){textTrack.mode='hidden';textTrack.addEventListener('cuechange',()=>{caption.textContent=[...(textTrack.activeCues||[])].map(cue=>cue.text).join(' ')||'Signed in. Passwords the agent saw: 0.';});}

  new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){if(!video.dataset.loaded){video.querySelector('source').src=video.querySelector('source').dataset.src;video.dataset.loaded='true';video.load();}if(!reduce)video.play().catch(()=>{});}else video.pause();}),{threshold:.2}).observe(video);
  new IntersectionObserver((entries,observer)=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('in-view');observer.unobserve(entry.target);}}),{threshold:.4}).observe(document.querySelector('.flow'));
  const stars=document.querySelector('#stars');
  setTimeout(()=>fetch('https://api.github.com/users/Harsette/repos?per_page=100&sort=pushed',{credentials:'omit',signal:AbortSignal.timeout(4000)}).then(r=>r.ok?r.json():null).then(repos=>{const data=Array.isArray(repos)?repos.find(repo=>repo.name.toLowerCase()==='ralx'):null;if(data&&Number.isSafeInteger(data.stargazers_count)){stars.textContent='☆ '+new Intl.NumberFormat('en',{notation:'compact'}).format(data.stargazers_count);stars.hidden=false;}}).catch(()=>{}),3500);
  const form=document.querySelector('#waitlist'),status=document.querySelector('#waitlist-status');
  form.addEventListener('submit',async event=>{event.preventDefault();if(!form.reportValidity())return;const submit=form.querySelector('button');submit.disabled=true;status.textContent='Adding your email…';try{const response=await fetch('/api/waitlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(form))),signal:AbortSignal.timeout(12000)});const data=await response.json();if(!response.ok)throw new Error(data.error||'That did not save. Please try again.');status.textContent='You’re on the list. We’ll email when Cloud is ready.';form.reset();}catch(error){status.textContent=error.name==='TimeoutError'?'That took too long. Please try again.':error.message==='Failed to fetch'?'Could not connect. Please try again.':error.message;}finally{submit.disabled=false;}});
})();

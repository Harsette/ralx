import { esc, agentLogo, clientName, icon } from "./ui.js";

const root=document.getElementById("device-content");
const names={"claude-desktop":"Claude Desktop",vscode:"VS Code",windsurf:"Windsurf",gemini:"Gemini CLI",antigravity:"Antigravity"};
let code=new URL(location.href).searchParams.get("user_code") || "";
async function api(path, data) {
  const r=await fetch(path,{method:data?"POST":"GET",credentials:"same-origin",headers:data?{"Content-Type":"application/json"}:{},...(data?{body:JSON.stringify(data)}:{})});
  const value=await r.json();
  if(!r.ok) throw Object.assign(new Error(value.error||"Request failed. Try again."),{status:r.status});
  return value;
}
function entry() {
  root.innerHTML='<p class="muted">Enter the code shown in your terminal.</p><form class="device-entry"><label for="user-code">Connection code</label><input id="user-code" name="user_code" placeholder="BCDF-GHJK" maxlength="9" autocomplete="off" required /><button class="btn primary">Continue</button></form>';
  root.querySelector("form").onsubmit=event=>{
    event.preventDefault();code=root.querySelector("input").value.trim().toUpperCase().replace(/\s/g,"");
    if(code.length===8) code=code.slice(0,4)+"-"+code.slice(4);
    history.replaceState(null,"","/device?user_code="+encodeURIComponent(code));load();
  };
}
async function load() {
  if(!code) return entry();
  try {
    const d=await api("/api/device?user_code="+encodeURIComponent(code));
    if(d.status!=="pending") return finished(d.status);
    const me=await api("/api/me");
    root.innerHTML=`<p class="muted">Check that this code matches your terminal.</p><p class="device-code">${esc(code)}</p>
      <div class="device-details"><h2 class="sec-title">Computer</h2><p class="device-machine">${esc(d.machine_name)}</p><p class="muted">Connecting to ${esc(me.user.email)}</p></div>
      <h2 class="sec-title">Agents to connect</h2><div class="rows">${d.clients.map(c=>`<div class="row">${agentLogo(c === "claude-desktop" ? "claude" : c,32)}<div class="row-id"><div class="row-title">${esc(names[c]||clientName(c))}</div></div>${icon("check",16)}</div>`).join("")}</div>
      <p class="device-note">Only approve if you started setup on this computer. You can remove each agent later in Agents.</p>
      <div class="device-actions"><button class="btn primary" data-action="approve">Approve</button><button class="btn" data-action="deny">Deny</button></div><p id="device-error" role="alert"></p>`;
    for(const button of root.querySelectorAll("[data-action]")) button.onclick=async()=>{
      for(const b of root.querySelectorAll("button")) b.disabled=true;
      try {const r=await api("/api/device/"+button.dataset.action,{user_code:code,csrf:d.csrf});finished(r.status);}
      catch(err){document.getElementById("device-error").textContent=err.message;for(const b of root.querySelectorAll("button")) b.disabled=false;}
    };
  } catch(err) {
    if(err.status===401) {
      root.innerHTML=`<p class="muted">Sign in to review this computer and its agents.</p><div class="device-actions"><a class="btn primary" href="/login?device=${encodeURIComponent(code)}">Sign in to RalX</a></div>`;
    } else {
      root.innerHTML=`<p role="alert">${esc(err.message)}</p><div class="device-actions"><button class="btn">Try another code</button></div>`;
      root.querySelector("button").onclick=()=>{code="";history.replaceState(null,"","/device");entry();};
    }
  }
}
function finished(status) {
  const denied=status==="denied";
  document.querySelector("h1").textContent=denied?"Connection denied":"Computer approved";
  document.querySelector(".lede").textContent=denied?"No agents were connected.":"Return to your terminal to finish connecting your agents.";
  root.innerHTML='<div class="device-actions"><a class="btn" href="/#agents">Open Agents</a></div>';
}
load();

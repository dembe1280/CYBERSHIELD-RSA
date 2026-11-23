const API_BASE = window.CYBERSHIELD_API || "http://127.0.0.1:8000";
const $ = (id) => document.getElementById(id);
const themeToggle = $("themeToggle");
document.documentElement.dataset.theme = localStorage.getItem("cs-theme") || "light";
function updateThemeLabel(){themeToggle.innerHTML=document.documentElement.dataset.theme==="dark"?"☀ <span>Light mode</span>":"☾ <span>Dark mode</span>";}
updateThemeLabel();
themeToggle.addEventListener("click",()=>{const next=document.documentElement.dataset.theme==="dark"?"light":"dark";document.documentElement.dataset.theme=next;localStorage.setItem("cs-theme",next);updateThemeLabel();});
$("menuToggle").addEventListener("click",()=>$("topbar")?.classList.toggle("nav-open"));
document.querySelector(".topbar").id="topbar";
$("year").textContent=new Date().getFullYear();

const tools={
 url:{title:"URL scanner",desc:"Check a website link against Google Safe Browsing threat reports.",label:"Website URL",placeholder:"https://example.com",hint:"Do not open the link first. Avoid private links containing tokens or reset codes.",button:"Check this link"},
 message:{title:"Scam message checker",desc:"Review a message for common scam patterns such as urgency, impersonation and requests for codes.",label:"Message text",placeholder:"Paste the suspicious SMS or WhatsApp message…",hint:"Remove names, account numbers, OTPs and other personal information first.",button:"Review message"},
 email:{title:"Phishing email checker",desc:"Review email wording and sender details for common phishing indicators.",label:"Email content and sender",placeholder:"From: example@domain.com\\nSubject: Urgent account notice\\n\\nPaste the email text…",hint:"Do not paste attachments, passwords, account numbers or private correspondence.",button:"Review email"},
 phone:{title:"Phone number reports",desc:"Look up community-submitted reports for a phone number.",label:"Phone number",placeholder:"+27 00 000 0000",hint:"A report is an unverified community signal, not proof that a person is a scammer.",button:"Check reports"},
 password:{title:"Password strength",desc:"Estimate password strength locally in this browser. Your input is never sent to the server.",label:"Password to assess",placeholder:"Enter a password you do not currently use",hint:"Never enter a password you use on a real account. This check runs only in your browser.",button:"Check strength"}
};
let currentTool="url";
function showResult(kind,title,message,extra=""){
 const box=$("result");box.className="result-box "+kind;
 const symbols={good:"✓",bad:"!",warn:"!",info:"i"};
 box.innerHTML=`<span class="result-symbol">${symbols[kind]||"i"}</span><div><b>${escapeHTML(title)}</b><p>${escapeHTML(message)}</p>${extra}</div>`;
}
function escapeHTML(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function selectTool(name){
 currentTool=name;const t=tools[name];
 $("toolTitle").textContent=t.title;$("toolDescription").textContent=t.desc;$("inputLabel").textContent=t.label;
 $("toolInput").placeholder=t.placeholder;$("inputHint").textContent=t.hint;$("submitButton").innerHTML=t.button+" <span>→</span>";
 $("toolInput").value="";$("toolInput").type="text";$("toolInput").rows=name==="password"?1:3;
 document.querySelectorAll(".tool-card").forEach(b=>b.classList.toggle("active",b.dataset.tool===name));
 if(name==="url")showResult("info","Ready to check","The URL will be checked against Google Safe Browsing if the backend is configured.");
 else if(name==="password")showResult("info","Private browser check","Use a test password only. The value stays in this browser.");
 else showResult("info","Ready for review","Your result will include the signals found and what they do — and do not — mean.");
}
document.querySelectorAll("[data-tool]").forEach(b=>b.addEventListener("click",()=>{selectTool(b.dataset.tool);$("workspace").scrollIntoView({behavior:"smooth",block:"center"});}));
function scorePassword(p){
 let score=0;const checks=[p.length>=12,p.length>=16,/[a-z]/.test(p),/[A-Z]/.test(p),/[0-9]/.test(p),/[^A-Za-z0-9]/.test(p)];
 score=checks.filter(Boolean).length;
 if(/(.)\1{2,}/.test(p))score-=1;
 if(/password|qwerty|letmein|admin|123456|iloveyou/i.test(p))score=0;
 return Math.max(0,Math.min(6,score));
}
function localTextReview(text,kind){
 const s=text.toLowerCase(),signals=[];
 const patterns=[
  [/urgent|immediately|within \d+ hours|act now|final warning/,"Urgency or pressure language"],
  [/verify your account|account suspended|account blocked|unusual activity/,"Account verification or suspension claim"],
  [/otp|one.time.pin|verification code|pin code|passcode/,"Request or mention of a verification code"],
  [/click here|tap here|open this link|follow this link/,"Prompt to open a link"],
  [/prize|winner|you have won|claim your reward|free gift/,"Unexpected prize or reward"],
  [/payment required|pay now|outstanding fee|delivery fee|customs fee/,"Unexpected payment request"],
  [/bank|fnb|standard bank|capitec|nedbank|absa|paypal/,"Financial brand or payment service mentioned"],
  [/gift card|crypto|bitcoin|voucher/,"Unusual payment method"]
 ];
 for(const [re,label] of patterns)if(re.test(s))signals.push(label);
 if(kind==="email"){
  const from=(text.match(/(?:from:\s*)([^\s<>]+)/i)||[])[1];
  if(from&&/@(gmail|outlook|yahoo)\./i.test(from))signals.push("Free email provider used as sender for a claimed organisation (verify independently)");
  if(/dear customer|dear user|valued customer/i.test(s))signals.push("Generic greeting");
  if(/password|banking details|card number|identity number/i.test(s))signals.push("Sensitive information referenced");
 }
 if(text.length<25)signals.push("Very little text supplied; assessment may be incomplete");
 const level=signals.length>=4?"high":signals.length>=2?"medium":"low";
 return {signals,level};
}
async function submit(){
 const value=$("toolInput").value.trim();if(!value){showResult("warn","Input required","Enter something to check first.");return;}
 $("submitButton").disabled=true;$("submitButton").textContent="Checking…";
 try{
  if(currentTool==="url"){
   const r=await fetch(API_BASE+"/api/scan/url",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:value})});
   const d=await r.json();if(!r.ok)throw Error(d.detail||"URL check failed.");
   if(d.verdict==="THREAT_FOUND")showResult("bad","Potential threat found",d.message,`<p><b>Threat types:</b> ${escapeHTML((d.threat_types||[]).join(", "))}</p><p><b>Source:</b> ${escapeHTML((d.checked_by||[]).join(", "))}</p>`);
   else if(d.verdict==="NO_MATCH_FOUND")showResult("good","No known match found",d.message,`<p><b>Source:</b> ${escapeHTML((d.checked_by||[]).join(", "))}</p>`);
   else showResult("warn","Not checked",d.message);
  }else if(currentTool==="message"||currentTool==="email"){
   const r=await fetch(API_BASE+(currentTool==="message"?"/api/analyze/message":"/api/analyze/email"),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text:value})});
   const d=await r.json();if(!r.ok)throw Error(d.detail||"Text review failed.");
   renderTextResult(d);
  }else if(currentTool==="phone"){
   const r=await fetch(API_BASE+"/api/phone/reports?number="+encodeURIComponent(value));
   const d=await r.json();if(!r.ok)throw Error(d.detail||"Phone lookup failed.");
   if(!d.report_count)showResult("info","No community reports found","There are no reports for this number in the CyberShield community database. That does not mean the number is safe.");
   else showResult("warn",`${d.report_count} community report(s)`, "These reports are unverified and may be inaccurate. Do not treat them as proof of wrongdoing.",`<p><b>Categories:</b> ${escapeHTML((d.categories||[]).join(", "))}</p>`);
  }else if(currentTool==="password"){
   const n=scorePassword(value);const label=n>=5?"Stronger pattern":n>=3?"Moderate pattern":"Weak pattern";
   showResult(n>=5?"good":n>=3?"warn":"bad",label,`Local estimate: ${n}/6 checks met. Use a unique long passphrase and a password manager. This is not a breach check. Your input was not sent to the server.`);
  }
 }catch(e){showResult("warn","Could not complete check",e.message+" Check that the backend is running and configured.");}
 finally{$("submitButton").disabled=false;$("submitButton").innerHTML=tools[currentTool].button+" <span>→</span>";}
}
function renderTextResult(d){
 const kind=d.risk_level==="high"?"bad":d.risk_level==="medium"?"warn":"good";
 const signals=(d.signals||[]).map(s=>`<li>${escapeHTML(s)}</li>`).join("");
 showResult(kind,`${d.risk_level.toUpperCase()} number of warning signs`,d.summary,`<p><b>Signals identified:</b></p>${signals?`<ul>${signals}</ul>`:"<p>No common patterns were detected in the supplied text.</p>"}<p><b>Important:</b> This is a pattern review, not a definitive scam verdict.</p>`);
}
$("toolForm").addEventListener("submit",e=>{e.preventDefault();submit();});
selectTool("url");

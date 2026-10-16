"use strict";
let current = null;
let severityFilter = "All";
const $ = (id) => document.getElementById(id);
const fmt = (n) => new Intl.NumberFormat("en-US").format(n);
const el = (tag, cls, text) => {const node = document.createElement(tag); if(cls)node.className=cls; if(text!==undefined)node.textContent=text; return node;};
const empty = (message) => el("div", "empty", message);
const safeDate = (value) => (value || "").replace("T", " ").slice(0, 19);
function err(message) {$("error").textContent=message; $("error").hidden=false;}
function clearErr() {$("error").hidden=true;}
async function getJSON(url, options) {
  const response=await fetch(url,options);
  const data=await response.json();
  if(!response.ok) throw new Error(data.error || "Could not analyze logs");
  return data;
}
function render(data) {
  current=data;clearErr();
  const s=data.summary;
  $("total-metric").textContent=fmt(s.total);
  $("failed-metric").textContent=fmt(s.failed);
  $("ips-metric").textContent=fmt(s.ips);
  $("findings-metric").textContent=fmt(s.findings);
  $("risk-metric").textContent=s.risk+"/100";
  $("failure-percent").textContent=s.total ? (100*s.failed/s.total).toFixed(1)+"% of all logins" : "No sign-ins";
  $("nav-alerts").textContent=s.findings;
  $("invalid").hidden=!data.invalid_count;
  $("invalid").textContent=data.invalid_count+" invalid CSV row(s) skipped. "+data.invalid_rows.slice(0,3).join(" · ");
  renderChart(data.timeline);
  renderDonut(data.findings);
  renderIPs(data.top_ips);
  renderFindings();
  renderLogs();
}
function renderChart(data) {
  const host=$("activity-chart");host.replaceChildren();
  if(!data.length){host.append(empty("No activity available"));return;}
  const d=data.slice(-24),max=Math.max(1,...d.map(x=>Math.max(x.success,x.failed)));
  const w=780,h=245,l=34,r=12,t=13,b=34,iw=w-l-r,ih=h-t-b;
  const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");
  svg.setAttribute("viewBox",`0 0 ${w} ${h}`);svg.setAttribute("role","img");svg.setAttribute("aria-label","Hourly successful and failed authentication counts");
  function add(tag,attrs,text){const e=document.createElementNS("http://www.w3.org/2000/svg",tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,String(v));if(text!==undefined)e.textContent=text;svg.append(e);return e;}
  const px=i=>l+(d.length===1?iw/2:i/(d.length-1)*iw),py=n=>t+ih*(1-n/max);
  for(let i=0;i<=4;i++){let y=t+(ih*i/4);add("line",{x1:l,y1:y,x2:w-r,y2:y,class:"chart-grid"});add("text",{x:0,y:y+4,class:"chart-axis"},String(Math.round(max*(1-i/4))));}
  function path(key,cls){add("polyline",{points:d.map((p,i)=>`${px(i)},${py(p[key])}`).join(" "),class:cls});}
  path("success","chart-blue");path("failed","chart-pink");
  for(let i=0;i<d.length;i+=Math.max(1,Math.ceil(d.length/6))){add("text",{x:px(i),y:h-9,"text-anchor":"middle",class:"chart-axis"},d[i].hour.slice(11,16));}
  host.append(svg);
}
function renderDonut(findings) {
  const types=["Brute Force","Password Spraying","Success After Failures"], colors=["#5bc5ff","#9f8afb","#ff7397"];
  const counts=types.map(type=>findings.filter(f=>f.detection===type).length);
  const total=findings.length || 1;
  let start=0;
  const segments=counts.map((count,index)=>{const end=start+count/total*100;const str=`${colors[index]} ${start}% ${end}%`;start=end;return str;});
  const host=$("donut-container");host.replaceChildren();
  const donut=el("div","donut");donut.style.background=findings.length?`conic-gradient(${segments.join(",")})`:"#2b3a4e";
  const hole=el("div","donut-hole");hole.append(el("strong", "",String(findings.length)),el("small","","FINDINGS"));donut.append(hole);host.append(donut);
  const legend=$("category-legend");legend.replaceChildren();
  types.forEach((type,i)=>{const row=el("div","category-item");const name=el("span");const icon=el("i");icon.style.background=colors[i];name.append(icon,document.createTextNode(type));row.append(name,el("b","",String(counts[i])));legend.append(row);});
}
function renderIPs(rows) {
  const tbody=$("ip-table");tbody.replaceChildren();
  if(!rows.length){tbody.append(empty("No source IPs"));return;}
  let max=Math.max(1,...rows.map(row=>row.failed));
  rows.forEach(row=>{const tr=el("tr");const bar=el("div","bar-track");const fill=el("div","bar-fill");fill.style.width=(100*row.failed/max).toFixed(1)+"%";bar.append(fill);
    tr.append(el("td","mono",row.ip),el("td","",fmt(row.events)),el("td","",fmt(row.failed)));
    const td=el("td");td.append(bar);tr.append(td);tbody.append(tr);});
}
function renderFindings() {
  const host=$("findings-list");host.replaceChildren();if(!current)return;
  const findings=current.findings.filter(f=>severityFilter==="All"||f.severity===severityFilter);
  if(!findings.length){host.append(empty("No findings for this severity."));return;}
  findings.forEach(f=>{const card=el("article","finding"),summary=el("div","finding-summary"),left=el("div");
    left.append(el("h4","",f.detection),el("p","mono",f.ip_address+"  ·  "+f.username));summary.append(left,el("span","sev sev-"+f.severity,f.severity));card.append(summary,el("p","finding-desc",f.description));
    const bottom=el("div","finding-bottom");bottom.append(el("span","",`${fmt(f.count)} matching attempts  ·  Last seen: ${safeDate(f.last_seen)} UTC`));
    const link=el("a","","MITRE "+f.mitre_technique+" ↗");link.href=f.mitre_url;link.target="_blank";link.rel="noopener noreferrer";bottom.append(link);card.append(bottom);
    const details=el("details"),label=el("summary","","Analyst recommendation"),info=el("p","",f.recommendation);details.append(label,info);card.append(details);host.append(card);
  });
}
function renderLogs() {
  const tbody=$("logs-table");tbody.replaceChildren();if(!current)return;
  const q=$("log-search").value.trim().toLowerCase();
  const logs=current.events.filter(e=>!q||e.username.toLowerCase().includes(q)||e.ip_address.includes(q)).slice(0,250);
  if(!logs.length){const tr=el("tr"),td=el("td","empty","No matching log entries.");td.colSpan=4;tr.append(td);tbody.append(tr);return;}
  logs.forEach(event=>{const tr=el("tr");tr.append(el("td","mono",safeDate(event.timestamp)),el("td","mono",event.ip_address),el("td","",event.username),el("td",event.status==="success"?"status-success":"status-failed",event.status.toUpperCase()));tbody.append(tr);});
}
function switchTab(tab) {
  document.querySelectorAll(".tab").forEach(node=>node.hidden=node.id!=="tab-"+tab);
  document.querySelectorAll(".nav-btn").forEach(node=>node.classList.toggle("active",node.dataset.tab===tab));
  const names={overview:"Overview",findings:"Threat findings",logs:"Authentication logs",method:"Detection rules"};
  $("current-section").textContent=names[tab]||"Overview";
}
function csvEscape(value) {const str=String(value??"");return /[",\n\r]/.test(str)?'"'+str.replace(/"/g,'""')+'"':str;}
function exportCSV(filename,rows,columns) {
  if(!current)return;
  const lines=[columns.join(","),...rows.map(obj=>columns.map(key=>csvEscape(obj[key])).join(","))].join("\r\n");
  const blob=new Blob(["\ufeff",lines],{type:"text/csv;charset=utf-8"});const href=URL.createObjectURL(blob);
  const link=el("a");link.href=href;link.download=filename;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(href),1000);
}
async function reloadSample(){try {$("source-label").textContent="Synthetic demo";render(await getJSON("/api/sample"));}catch(e){err(e.message);}}
document.querySelectorAll(".nav-btn").forEach(n=>n.addEventListener("click",()=>switchTab(n.dataset.tab)));
document.querySelectorAll("[data-switch]").forEach(n=>n.addEventListener("click",()=>switchTab(n.dataset.switch)));
document.querySelectorAll(".filter").forEach(n=>n.addEventListener("click",()=>{severityFilter=n.dataset.severity;document.querySelectorAll(".filter").forEach(b=>b.classList.toggle("active",b===n));renderFindings();}));
$("sample-btn").addEventListener("click",reloadSample);
$("download-sample").addEventListener("click",()=>{window.location.href="/api/sample/csv";});
$("upload-input").addEventListener("change",async e=>{const file=e.target.files?.[0];if(!file)return;if(file.size>5*1024*1024){err("Maximum CSV size is 5 MB.");return;}
  try {const data=await getJSON("/api/analyze",{method:"POST",headers:{"Content-Type":"text/csv"},body:file});render(data);$("source-label").textContent=file.name;}
  catch(error){err(error.message);}finally{e.target.value="";}});
$("log-search").addEventListener("input",renderLogs);
$("export-findings").addEventListener("click",()=>exportCSV("authsentinel_findings.csv",current?.findings||[],["detection","severity","ip_address","username","count","first_seen","last_seen","description","recommendation","mitre_technique","mitre_url"]));
$("export-logs").addEventListener("click",()=>exportCSV("authsentinel_valid_events.csv",current?.events||[],["timestamp","ip_address","username","status"]));
reloadSample();

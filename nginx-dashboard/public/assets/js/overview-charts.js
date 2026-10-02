'use strict';
/**
 * Graphiques Chart.js de la page "Vue d'ensemble" : requêtes/erreurs dans le
 * temps (chart) et requêtes/sec en fenêtre glissante, globale ou par vhost
 * (rpsChart). Extrait de public/index.html (voir CHANGELOG.md). Distinct de
 * public/assets/js/graph.js (schéma SVG des vhosts).
 */
function initChart(){
  const ctx = document.getElementById('chart-req').getContext('2d');
  chart = new Chart(ctx,{type:'line',data:{labels:[],datasets:[
    {label:'Requêtes',data:[],borderColor:'#00e87a',backgroundColor:'#00e87a18',fill:true,tension:.4,pointRadius:0,borderWidth:1.5},
    {label:'Erreurs',data:[],borderColor:'#ff4d6a',backgroundColor:'#ff4d6a18',fill:true,tension:.4,pointRadius:0,borderWidth:1.5}
  ]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:300},
    plugins:{legend:{labels:{color:'#9ba3b8',font:{family:"'JetBrains Mono'",size:11},boxWidth:12}},
      tooltip:{mode:'index',intersect:false,backgroundColor:'#1c202a',borderColor:'#ffffff18',borderWidth:1,titleColor:'#e8eaf0',bodyColor:'#9ba3b8',titleFont:{family:"'JetBrains Mono'",size:11},bodyFont:{family:"'JetBrains Mono'",size:10}}},
    scales:{x:{grid:{color:'#ffffff08'},ticks:{color:'#5a6278',font:{family:"'JetBrains Mono'",size:9},maxTicksLimit:8}},
      y:{grid:{color:'#ffffff08'},ticks:{color:'#5a6278',font:{family:"'JetBrains Mono'",size:9}},beginAtZero:true}}}});
}

let rpsChart = null;
let rpsWindowMinutes = 5;
let rpsVhostsLoaded = false;

function initRpsChart(){
  const ctx = document.getElementById('chart-rps').getContext('2d');
  rpsChart = new Chart(ctx,{type:'line',data:{labels:[],datasets:[
    {label:'req/s',data:[],borderColor:'#00e87a',backgroundColor:'#00e87a18',fill:true,tension:.4,pointRadius:0,borderWidth:1.5}
  ]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:300},
    plugins:{legend:{display:false},
      tooltip:{mode:'index',intersect:false,backgroundColor:'#1c202a',borderColor:'#ffffff18',borderWidth:1,titleColor:'#e8eaf0',bodyColor:'#9ba3b8',titleFont:{family:"'JetBrains Mono'",size:11},bodyFont:{family:"'JetBrains Mono'",size:10}}},
    scales:{x:{grid:{color:'#ffffff08'},ticks:{color:'#5a6278',font:{family:"'JetBrains Mono'",size:9},maxTicksLimit:8}},
      y:{grid:{color:'#ffffff08'},ticks:{color:'#5a6278',font:{family:"'JetBrains Mono'",size:9}},beginAtZero:true}}}});
}

function setRpsWindow(minutes){
  rpsWindowMinutes = minutes;
  document.querySelectorAll('.rps-win').forEach(b => b.classList.toggle('active', +b.dataset.win === minutes));
  loadRpsChart();
}

/** Peuple le filtre vhost une seule fois par chargement de page — pas a chaque sondage. */
async function loadRpsVhostOptions(){
  if (rpsVhostsLoaded) return;
  const d = await api('/zones').catch(() => null);
  const sel = document.getElementById('rps-vhost');
  if (!sel || !d?.zones?.length) return;
  for (const z of d.zones) {
    const opt = document.createElement('option');
    opt.value = z.name;
    opt.textContent = z.name;
    sel.appendChild(opt);
  }
  rpsVhostsLoaded = true;
}

async function loadRpsChart(){
  if (!rpsChart) return;
  const vhost = document.getElementById('rps-vhost')?.value || '';
  const qs = new URLSearchParams({ window: String(rpsWindowMinutes) });
  if (vhost) qs.set('vhost', vhost);
  const d = await api('/metrics/rate?' + qs.toString()).catch(() => null);
  if (!d) return;
  rpsChart.data.labels = d.timestamps.map(ts => new Date(ts).toLocaleTimeString('fr',
    rpsWindowMinutes > 15 ? {hour:'2-digit',minute:'2-digit'} : {hour:'2-digit',minute:'2-digit',second:'2-digit'}));
  rpsChart.data.datasets[0].data = d.rps;
  rpsChart.update('none');
}

function updateChart(h){
  if(!chart)return;
  chart.data.labels=h.timestamps.map(t=>new Date(t).toLocaleTimeString('fr',{hour:'2-digit',minute:'2-digit',second:'2-digit'}));
  chart.data.datasets[0].data=h.requests;
  chart.data.datasets[1].data=h.errors;
  chart.update('none');
}

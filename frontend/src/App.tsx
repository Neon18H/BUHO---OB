import { Activity, BellRing, Database, ShieldAlert } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

const demo = [{t:'00:00',v:24},{t:'00:05',v:32},{t:'00:10',v:20},{t:'00:15',v:40}];

function Dashboard() {
  return <div className="space-y-4 noc-grid p-4 rounded-xl">
    <div className="grid md:grid-cols-4 gap-3">
      {[['Agents Online','84',Activity],['Alerts','19',BellRing],['Servers','42',Database],['Threats','3',ShieldAlert]].map(([t,v,I],i)=> <div className="noc-card" key={i}><div className="text-xs text-sky-300">{t}</div><div className="text-2xl font-semibold flex items-center gap-2"><I size={20}/>{v}</div></div>)}
    </div>
    <div className="noc-card h-72"><div className="text-sm mb-3">Operative Activity</div><ResponsiveContainer width="100%" height="88%"><LineChart data={demo}><XAxis dataKey="t" stroke="#7dd3fc"/><YAxis stroke="#7dd3fc"/><Tooltip /><Line dataKey="v" stroke="#22d3ee" /></LineChart></ResponsiveContainer></div>
  </div>;
}

const labels: Record<string,string> = {
  login:'Access Control', register:'Workspace Bootstrap', overview:'Mission Overview', agentsOverview:'Agent Operations', agentDetail:'Agent Profile', servers:'Server Atlas', serverDetail:'Server Profile', apps:'Application Inventory', appDetail:'Application Profile', logs:'Logs Intelligence', alerts:'Alerts Center', threats:'Threat Matrix'
};

export default function App({page}:{page:string}) {
  return <div className="space-y-4"><div><h1 className="text-2xl font-semibold">{labels[page] || 'Buho NOC'}</h1><p className="text-sky-200/70 text-sm">Acción Nocturna UI embedded in Django.</p></div>{page==='overview'?<Dashboard/>:<div className="noc-card">React module mounted for <strong>{page}</strong>.</div>}</div>;
}

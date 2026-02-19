'use client';

import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useApiQuery } from '@/lib/hooks/useApiQuery';
import { endpoints } from '@/lib/api/endpoints';
import { Bar, BarChart, CartesianGrid, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

const fallback = {
  kpi: { agentsOnline: 12, agentsOffline: 3, servers: 7, apps: 16, alerts24h: 18, threats7d: 4 },
  cpuRam: [{ name: 'srv-1', cpu: 42, ram: 65 }, { name: 'srv-2', cpu: 51, ram: 59 }],
  logs: [{ level: 'INFO', count: 150 }, { level: 'WARN', count: 26 }, { level: 'ERROR', count: 9 }],
  alerts: [{ name: 'Network', value: 6 }, { name: 'Auth', value: 4 }, { name: 'App', value: 8 }],
  topApps: [{ name: 'api-gateway', errorRate: '2.6%' }, { name: 'billing', errorRate: '1.7%' }]
};

export default function OverviewPage() {
  const { data } = useApiQuery(['overview'], endpoints.overview, fallback);
  const k = data?.kpi || fallback.kpi;

  return (
    <section className="space-y-4">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-6">
        {Object.entries(k).map(([key, value]) => <Card key={key}><p className="text-xs uppercase text-slate-400">{key}</p><p className="text-2xl font-semibold">{value}</p></Card>)}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card><h3 className="mb-2">CPU/RAM promedio</h3><ResponsiveContainer width="100%" height={220}><LineChart data={data?.cpuRam || fallback.cpuRam}><CartesianGrid stroke="#1e293b" /><XAxis dataKey="name" /><YAxis /><Tooltip /><Line dataKey="cpu" stroke="#22d3ee" /><Line dataKey="ram" stroke="#60a5fa" /></LineChart></ResponsiveContainer></Card>
        <Card><h3 className="mb-2">Logs por severidad</h3><ResponsiveContainer width="100%" height={220}><BarChart data={data?.logs || fallback.logs}><CartesianGrid stroke="#1e293b" /><XAxis dataKey="level" /><YAxis /><Tooltip /><Bar dataKey="count" fill="#22d3ee" /></BarChart></ResponsiveContainer></Card>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card><h3 className="mb-2">Alerts por tipo</h3><ResponsiveContainer width="100%" height={220}><PieChart><Pie data={data?.alerts || fallback.alerts} dataKey="value" nameKey="name" outerRadius={80} fill="#22d3ee" /><Tooltip /></PieChart></ResponsiveContainer></Card>
        <Card><h3 className="mb-2">Top apps por error rate</h3><div className="space-y-2">{(data?.topApps || fallback.topApps).map((app: {name:string; errorRate:string}) => <div className="flex items-center justify-between rounded-xl border border-slate-800 px-3 py-2" key={app.name}><span>{app.name}</span><Badge>{app.errorRate}</Badge></div>)}</div></Card>
      </div>
    </section>
  );
}

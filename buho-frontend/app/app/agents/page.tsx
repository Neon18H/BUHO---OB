'use client';

import Link from 'next/link';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useApiQuery } from '@/lib/hooks/useApiQuery';
import { endpoints } from '@/lib/api/endpoints';
import { useState } from 'react';

const fallback = [
  { id: '1', hostname: 'noc-eu-01', provider: 'Railway', os: 'Ubuntu 22.04', last_seen: 'now', status: 'online', version: '2.4.1', tags: ['prod'] },
  { id: '2', hostname: 'edge-us-01', provider: 'AWS', os: 'Debian', last_seen: '2m', status: 'offline', version: '2.4.1', tags: ['edge'] },
];

export default function AgentsPage() {
  const [q, setQ] = useState('');
  const { data } = useApiQuery(['agents'], endpoints.agents, fallback);
  const rows = (data || fallback).filter((a) => a.hostname.toLowerCase().includes(q.toLowerCase()));

  return <Card>
    <div className="mb-3 flex items-center justify-between"><Input placeholder="Search agents" className="max-w-sm" value={q} onChange={(e)=>setQ(e.target.value)} /><Button>Deploy Agent</Button></div>
    <table className="w-full text-sm"><thead><tr className="text-left text-slate-400"><th>hostname</th><th>provider</th><th>os</th><th>last_seen</th><th>status</th><th>version</th></tr></thead>
      <tbody>{rows.map((a)=> <tr key={a.id} className="border-t border-slate-800"><td><Link className="text-accent" href={`/app/agents/${a.id}`}>{a.hostname}</Link></td><td>{a.provider}</td><td>{a.os}</td><td>{a.last_seen}</td><td>{a.status}</td><td>{a.version}</td></tr>)}</tbody></table>
  </Card>;
}

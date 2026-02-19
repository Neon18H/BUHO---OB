'use client';

import { useParams } from 'next/navigation';
import { Card } from '@/components/ui/card';
import { useApiQuery } from '@/lib/hooks/useApiQuery';
import { endpoints } from '@/lib/api/endpoints';

const fallback = { metrics: { cpu: 38, ram: 62, disk: 55, net: 120 }, apps: ['api-gateway', 'worker'], processes: ['python', 'nginx'], logs: [], alerts: [], threats: [] };

export default function AgentDetail() {
  const { id } = useParams<{ id: string }>();
  const { data } = useApiQuery(['agent', id], () => endpoints.agent(id), fallback);

  return <section className="grid gap-4 lg:grid-cols-2">
    <Card><h2 className="mb-2 text-xl">Agent {id} Metrics</h2><p>CPU {data?.metrics.cpu}% · RAM {data?.metrics.ram}% · Disk {data?.metrics.disk}% · Net {data?.metrics.net} Mb/s</p></Card>
    <Card><h3 className="mb-2">Apps</h3>{(data?.apps || []).map((a:string)=><p key={a}>{a}</p>)}</Card>
    <Card><h3 className="mb-2">Processes</h3>{(data?.processes || []).map((p:string)=><p key={p}>{p}</p>)}</Card>
    <Card><h3 className="mb-2">Threats</h3><p>{(data?.threats || []).length} findings</p></Card>
  </section>;
}

'use client';

import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

export default function LogsPage() {
  return <Card className="space-y-3">
    <div className="grid gap-2 md:grid-cols-5"><Input placeholder="level" /><Input placeholder="contains" /><Input placeholder="server" /><Input placeholder="app" /><Input placeholder="time range" /></div>
    <table className="w-full text-sm"><thead><tr className="text-left text-slate-400"><th>timestamp</th><th>level</th><th>source</th><th>message</th></tr></thead><tbody><tr className="border-t border-slate-800"><td>2026-02-19T20:11:00Z</td><td>WARN</td><td>api-gateway</td><td>Latency threshold exceeded</td></tr></tbody></table>
    <Button variant="outline">Export CSV</Button>
  </Card>;
}

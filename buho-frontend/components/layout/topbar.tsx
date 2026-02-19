'use client';

import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

export function Topbar() {
  return (
    <header className="glass flex items-center justify-between rounded-2xl px-4 py-3">
      <Input className="max-w-md" placeholder="Search telemetry..." />
      <div className="flex items-center gap-3">
        <Badge className="border-emerald-400/50 text-emerald-300">NOC MODE</Badge>
        <Button variant="outline" onClick={() => { localStorage.removeItem('buho_token'); document.cookie = 'buho_token=; Max-Age=0; path=/'; location.href='/auth/login'; }}>Logout</Button>
      </div>
    </header>
  );
}

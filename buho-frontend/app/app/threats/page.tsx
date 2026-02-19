'use client';

import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { endpoints } from '@/lib/api/endpoints';

export default function ThreatsPage() {
  return <Card className="space-y-4">
    <Button className="w-full text-base tracking-wide" onClick={() => endpoints.runThreatScan()}>ACCION NOCTURNA</Button>
    <table className="w-full text-sm"><thead><tr className="text-left text-slate-400"><th>file/path</th><th>hash</th><th>yara_match</th><th>vt_score</th><th>severity</th><th>agent</th></tr></thead>
      <tbody><tr className="border-t border-slate-800"><td>/tmp/suspicious.bin</td><td>4f2...</td><td>evil_loader</td><td>9/72</td><td>high</td><td>noc-eu-01</td></tr></tbody></table>
  </Card>;
}

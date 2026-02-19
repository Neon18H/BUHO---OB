'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Activity, AlertTriangle, AppWindow, LayoutDashboard, ScrollText, Server, Settings, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';

const items = [
  { href: '/app/overview', label: 'Overview', icon: LayoutDashboard },
  { href: '/app/agents', label: 'Agents', icon: Shield },
  { href: '/app/servers', label: 'Servers', icon: Server },
  { href: '/app/apps', label: 'Apps', icon: AppWindow },
  { href: '/app/logs', label: 'Logs', icon: ScrollText },
  { href: '/app/alerts', label: 'Alerts', icon: AlertTriangle },
  { href: '/app/threats', label: 'Threats', icon: Activity },
  { href: '/app/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="glass w-64 shrink-0 rounded-2xl p-3">
      <div className="mb-4 px-2 py-3 text-lg font-semibold text-accent">BUHO // NOC</div>
      <nav className="space-y-1">
        {items.map(({ href, label, icon: Icon }) => (
          <Link key={href} href={href} className={cn('flex items-center gap-2 rounded-xl px-3 py-2 text-sm hover:bg-slate-900', pathname === href && 'bg-slate-900 text-accent')}>
            <Icon size={16} /> {label}
          </Link>
        ))}
      </nav>
    </aside>
  );
}

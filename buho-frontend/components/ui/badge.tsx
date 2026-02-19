import { cn } from '@/lib/utils';

export function Badge({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn('rounded-full border border-slate-700 px-2 py-1 text-xs', className)}>{children}</span>;
}

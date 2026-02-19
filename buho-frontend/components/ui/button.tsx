import * as React from 'react';
import { cn } from '@/lib/utils';

type Props = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'outline' | 'ghost' | 'danger';
};

export function Button({ className, variant = 'default', ...props }: Props) {
  return (
    <button
      className={cn(
        'inline-flex h-10 items-center justify-center rounded-2xl px-4 text-sm font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50',
        variant === 'default' && 'bg-accent/20 text-accent hover:bg-accent/30',
        variant === 'outline' && 'border border-slate-700 bg-transparent hover:bg-slate-900',
        variant === 'ghost' && 'hover:bg-slate-900/80',
        variant === 'danger' && 'bg-danger/20 text-red-200 hover:bg-danger/30',
        className,
      )}
      {...props}
    />
  );
}

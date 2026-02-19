import * as React from 'react';
import { cn } from '@/lib/utils';

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('glass rounded-2xl p-5 shadow-2xl shadow-black/30', className)} {...props} />;
}

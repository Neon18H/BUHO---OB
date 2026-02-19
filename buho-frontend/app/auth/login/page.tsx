'use client';

import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { endpoints } from '@/lib/api/endpoints';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { ShieldCheck } from 'lucide-react';

const schema = z.object({ email: z.string().email(), password: z.string().min(6) });

type FormData = z.infer<typeof schema>;

export default function LoginPage() {
  const { register, handleSubmit, formState } = useForm<FormData>({ resolver: zodResolver(schema) });

  const onSubmit = async (data: FormData) => {
    const res = await endpoints.login(data);
    const token = res.data?.token || res.data?.access;
    if (token) localStorage.setItem('buho_token', token);
    document.cookie = `buho_token=${token}; path=/`;
    location.href = '/app/overview';
  };

  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden noc-grid p-6">
      <Card className="w-full max-w-md space-y-5">
        <div className="flex items-center gap-2 text-accent"><ShieldCheck size={18} /> Restricted Access</div>
        <h1 className="text-2xl font-semibold">BUHO Clearance Login</h1>
        <form className="space-y-4" onSubmit={handleSubmit(onSubmit)}>
          <Input placeholder="Email" {...register('email')} />
          <Input placeholder="Password" type="password" {...register('password')} />
          <Button className="w-full" disabled={formState.isSubmitting}>Authenticate</Button>
        </form>
      </Card>
    </main>
  );
}

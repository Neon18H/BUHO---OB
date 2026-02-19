'use client';

import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { endpoints } from '@/lib/api/endpoints';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

const schema = z.object({ org_name: z.string().min(2), email: z.string().email(), password: z.string().min(8) });
type FormData = z.infer<typeof schema>;

export default function RegisterPage() {
  const { register, handleSubmit, formState } = useForm<FormData>({ resolver: zodResolver(schema) });

  const onSubmit = async (data: FormData) => {
    await endpoints.register(data as Record<string, string>);
    location.href = '/auth/login';
  };

  return (
    <main className="grid min-h-screen place-items-center noc-grid p-6">
      <Card className="w-full max-w-md space-y-4">
        <h1 className="text-2xl font-semibold">Create Organization Command Center</h1>
        <form className="space-y-4" onSubmit={handleSubmit(onSubmit)}>
          <Input placeholder="Organization" {...register('org_name')} />
          <Input placeholder="Admin Email" {...register('email')} />
          <Input placeholder="Password" type="password" {...register('password')} />
          <Button className="w-full" disabled={formState.isSubmitting}>Create BUHO HQ</Button>
        </form>
      </Card>
    </main>
  );
}

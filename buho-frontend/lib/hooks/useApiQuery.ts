'use client';

import { useQuery } from '@tanstack/react-query';

export function useApiQuery<T>(key: string[], fn: () => Promise<{ data: T }>, fallback: T) {
  return useQuery({
    queryKey: key,
    queryFn: async () => {
      try {
        const { data } = await fn();
        return data;
      } catch {
        return fallback;
      }
    },
  });
}

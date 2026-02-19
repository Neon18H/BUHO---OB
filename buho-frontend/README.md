# buho-frontend

Frontend SOC "Acción Nocturna" para Buho, construido con Next.js App Router + TypeScript + Tailwind.

## Stack
- Next.js 14 + React 18 + TypeScript
- TailwindCSS
- shadcn/ui-style lightweight components
- lucide-react, recharts, react-hook-form + zod
- TanStack Query + Axios

## Instalación
```bash
cd buho-frontend
npm install
npm run dev
```

## Variables de entorno
Copiar `.env.example` a `.env.local`.

```env
NEXT_PUBLIC_BUHO_API_URL=https://<tu-django>.up.railway.app
NEXT_PUBLIC_APP_NAME=Buho
NEXT_PUBLIC_THEME=NOC
```

## Build y deploy
```bash
npm run build
npm run start
```

## Integración backend
El cliente API está en `lib/api/endpoints.ts` y consume endpoints Django esperados.
Si algún endpoint no existe, la UI usa fallback mock para no bloquear rendering.

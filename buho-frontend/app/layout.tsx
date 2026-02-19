import './globals.css';
import { Providers } from '@/lib/providers';

export const metadata = {
  title: process.env.NEXT_PUBLIC_APP_NAME || 'Buho',
  description: 'Buho SOC Frontend',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es" className="dark">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}

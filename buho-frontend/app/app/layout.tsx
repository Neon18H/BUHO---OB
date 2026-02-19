import { Sidebar } from '@/components/layout/sidebar';
import { Topbar } from '@/components/layout/topbar';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="noc-grid min-h-screen p-4">
      <div className="mx-auto flex max-w-[1600px] gap-4">
        <Sidebar />
        <main className="flex-1 space-y-4">
          <Topbar />
          {children}
        </main>
      </div>
    </div>
  );
}

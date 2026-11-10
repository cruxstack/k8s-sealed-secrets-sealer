import type { ReactNode } from "react";
import { Header } from "./Header";

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto scroll-smooth">
          <div className="mx-auto max-w-7xl p-4 md:p-8 xl:p-10">{children}</div>
        </main>
      </div>
    </div>
  );
}

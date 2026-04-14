import { ReactNode } from "react";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-[#050505]">
      <main className="p-0">{children}</main>
    </div>
  );
}

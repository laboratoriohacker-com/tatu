import type { ReactNode } from "react";

export function Panel({ children, className = "", onClick }: { children: ReactNode; className?: string; onClick?: () => void }) {
  return (
    <div className={`bg-tatu-surface border border-tatu-border rounded-lg p-5 ${className}`} onClick={onClick}>
      {children}
    </div>
  );
}

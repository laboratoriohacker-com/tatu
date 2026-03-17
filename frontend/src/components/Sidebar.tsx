import { NavLink } from "react-router-dom";
import { TatuLogo } from "./TatuLogo";

const NAV_ITEMS = [
  { to: "/", icon: "\u25C6", label: "Overview" },
  { to: "/alerts", icon: "\u26A1", label: "Live Alerts" },

  { to: "/rules", icon: "\u25B7", label: "Rules" },
  { to: "/compliance", icon: "\u25CE", label: "Compliance" },
  { to: "/developers", icon: "\u29EB", label: "Developers" },
  { to: "/audit", icon: "\u25A4", label: "Audit Log" },
  { to: "/settings", icon: "\u2699", label: "Settings" },
];

interface SidebarProps {
  onLogout?: () => void;
  userEmail?: string;
}

export function Sidebar({ onLogout, userEmail }: SidebarProps = {}) {
  return (
    <nav className="w-[220px] min-h-screen bg-tatu-surface border-r border-tatu-border p-5 flex flex-col gap-1 shrink-0 relative z-10">
      <div className="flex items-center gap-2.5 px-4 pb-5 border-b border-tatu-border mb-3">
        <TatuLogo size={32} />
        <div>
          <div className="text-base font-bold text-tatu-text tracking-widest">TATU</div>
          <div className="text-[8px] text-tatu-text-dim tracking-widest uppercase">AI-Assisted DevSecOps</div>
        </div>
      </div>
      {NAV_ITEMS.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.to === "/"}
          className={({ isActive }) =>
            `flex items-center gap-2.5 w-full px-4 py-2.5 rounded-md text-xs tracking-wide transition-colors ${
              isActive
                ? "bg-tatu-accent-glow text-tatu-accent font-semibold"
                : "text-tatu-text-dim hover:text-tatu-text-muted"
            }`
          }
        >
          <span className="text-base w-5 text-center">{item.icon}</span>
          {item.label}
        </NavLink>
      ))}
      <div className="flex-1" />
      <div className="px-4 pt-3 border-t border-tatu-border mt-2 space-y-3">
        {userEmail && (
          <div className="text-[10px] text-tatu-text-dim truncate">{userEmail}</div>
        )}
        {onLogout && (
          <button
            onClick={onLogout}
            className="flex items-center gap-2 w-full px-0 text-xs text-tatu-text-dim hover:text-tatu-critical transition-colors"
          >
            <span className="text-base w-5 text-center">&#x2192;</span>
            Logout
          </button>
        )}
        <div>
          <div className="text-[10px] text-tatu-text-dim tracking-widest">Powered by</div>
          <div className="text-xs text-tatu-text mt-1">Laborat&oacute;rio Hacker</div>
        </div>
      </div>
    </nav>
  );
}

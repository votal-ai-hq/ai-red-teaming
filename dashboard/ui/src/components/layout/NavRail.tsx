import { useLocation, useNavigate } from "react-router";
import { useUIStore } from "@/stores/uiStore";
import {
  LayoutDashboard,
  Play,
  PlusCircle,
  FileText,
  AlertTriangle,
  CheckSquare,
  Shield,
  Briefcase,
  Database,
  Gauge,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";

const MAIN_NAV = [
  { path: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { path: "/scans", label: "Scan Activity", icon: Play },
  { path: "/new-scan", label: "Launch Scan", icon: PlusCircle },
  { path: "/datasets", label: "Datasets", icon: Database },
  { path: "/evaluations", label: "Evaluations", icon: Gauge },
  { path: "/reports", label: "Reports", icon: FileText },
  { path: "/risk", label: "Risk", icon: AlertTriangle },
  { path: "/compliance", label: "Compliance", icon: CheckSquare },
  { path: "/activity-log", label: "Activity Log", icon: Shield },
  { path: "/policies", label: "Policies", icon: Briefcase },
] as const;

export function NavRail() {
  const location = useLocation();
  const navigate = useNavigate();
  const { navCollapsed, toggleNav } = useUIStore();

  const isActive = (path: string) => location.pathname.startsWith(path);

  return (
    <aside
      className={`flex flex-col shrink-0 border-r border-border bg-card transition-[width] duration-200 ${
        navCollapsed ? "w-16" : "w-[220px]"
      }`}
    >
      {/* Brand */}
      <div
        className="flex items-center gap-2.5 h-14 px-4 border-b border-border cursor-pointer shrink-0 overflow-hidden"
        onClick={() => navigate("/dashboard")}
      >
        <div className="w-8 h-8 shrink-0 rounded-lg bg-primary flex items-center justify-center">
          <Shield className="w-4 h-4 text-white" />
        </div>
        {!navCollapsed && (
          <div className="min-w-0">
            <span className="text-sm font-semibold text-foreground tracking-tight block leading-tight">
              Red Team
            </span>
            <span className="text-[10px] text-muted-foreground uppercase tracking-widest">
              AI Security
            </span>
          </div>
        )}
      </div>

      {/* Section label */}
      {!navCollapsed && (
        <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground/60 px-4 pt-5 pb-1.5">
          Menu
        </div>
      )}

      {/* Nav items */}
      <nav className={`flex-1 overflow-y-auto overflow-x-hidden flex flex-col gap-px ${navCollapsed ? "px-2 py-2" : "px-2.5 py-0.5"}`}>
        {MAIN_NAV.map(({ path, label, icon: Icon }) => {
          const active = isActive(path);
          return (
            <button
              key={path}
              onClick={() => {
                navigate(path);
                if (window.innerWidth < 1100) useUIStore.getState().setNavCollapsed(true);
              }}
              className={`flex items-center gap-2.5 w-full rounded-md transition-colors relative group
                ${navCollapsed ? "justify-center px-0 py-2.5" : "px-2.5 py-[7px]"}
                ${
                  active
                    ? "text-foreground bg-muted font-medium"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                }
              `}
            >
              <Icon className={`w-4 h-4 shrink-0 ${active ? "text-foreground" : ""}`} />
              {!navCollapsed && (
                <span className="text-[13px] flex-1 text-left truncate">{label}</span>
              )}
              {navCollapsed && (
                <div className="absolute left-[calc(100%+8px)] top-1/2 -translate-y-1/2 bg-foreground text-background text-[11px] font-medium px-2 py-1 rounded whitespace-nowrap opacity-0 pointer-events-none group-hover:opacity-100 z-50 shadow-lg">
                  {label}
                </div>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-border p-2.5">
        <button
          onClick={toggleNav}
          className="flex items-center gap-2.5 w-full px-2.5 py-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
        >
          {navCollapsed ? (
            <ChevronsRight className="w-4 h-4 mx-auto" />
          ) : (
            <>
              <ChevronsLeft className="w-4 h-4" />
              <span className="text-[12px]">Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
}

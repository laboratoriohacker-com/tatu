import { useEffect } from "react";
import { BrowserRouter, Routes, Route, Outlet } from "react-router-dom";
import { useAuth } from "./hooks/useAuth";
import { Sidebar } from "./components/Sidebar";
import { GridPattern } from "./components/GridPattern";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { LiveAlerts } from "./pages/LiveAlerts";

import { Compliance } from "./pages/Compliance";
import { Developers } from "./pages/Developers";
import { AuditLog } from "./pages/AuditLog";
import { Rules } from "./pages/Rules";
import { RuleEdit } from "./pages/RuleEdit";
import { Settings } from "./pages/Settings";
import { AcceptInvite } from "./pages/AcceptInvite";

function DashboardLayout({ onLogout, userEmail }: { onLogout: () => void; userEmail?: string }) {
  return (
    <div className="flex min-h-screen bg-tatu-bg relative">
      <GridPattern />
      <Sidebar onLogout={onLogout} userEmail={userEmail} />
      <main className="flex-1 p-7 overflow-y-auto relative z-[1]">
        <Outlet />
      </main>
    </div>
  );
}

export default function App() {
  const { user, isAuthenticated, error, otpSent, sendOtp, verifyOtp, checkAuth, logout } = useAuth();
  useEffect(() => { checkAuth(); }, [checkAuth]);

  if (isAuthenticated === null) {
    return <div className="min-h-screen bg-tatu-bg" />;
  }

  // Accept-invite is accessible without authentication
  if (window.location.pathname === "/accept-invite") {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="accept-invite" element={<AcceptInvite />} />
        </Routes>
      </BrowserRouter>
    );
  }

  if (!isAuthenticated) {
    return <Login onSendOtp={sendOtp} onVerifyOtp={verifyOtp} otpSent={otpSent} error={error} />;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<DashboardLayout onLogout={logout} userEmail={user?.email} />}>
          <Route index element={<Overview />} />
          <Route path="alerts" element={<LiveAlerts />} />

          <Route path="rules" element={<Rules />} />
          <Route path="rules/:ruleId" element={<RuleEdit />} />
          <Route path="compliance" element={<Compliance />} />
          <Route path="developers" element={<Developers />} />
          <Route path="audit" element={<AuditLog />} />
          <Route path="settings" element={<Settings userRole={user?.role} />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

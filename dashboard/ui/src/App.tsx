import { HashRouter, Routes, Route, Navigate } from "react-router";
import { AuthGate } from "@/components/auth/AuthGate";
import { AppShell } from "@/components/layout/AppShell";
import DashboardPage from "@/pages/DashboardPage";
import RunsPage from "@/pages/RunsPage";
import NewScanPage from "@/pages/NewScanPage";
import ReportsPage from "@/pages/ReportsPage";
import RiskPage from "@/pages/RiskPage";
import CompliancePage from "@/pages/CompliancePage";
import AuditPage from "@/pages/AuditPage";
import GuardrailsPage from "@/pages/GuardrailsPage";
import DatasetsPage from "@/pages/DatasetsPage";
import EvaluationsPage, { EvaluationRunPage } from "@/pages/EvaluationsPage";

export function App() {
  return (
    <HashRouter>
      <AuthGate>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/scans" element={<RunsPage />} />
            <Route path="/new-scan" element={<NewScanPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/reports/:filename" element={<ReportsPage />} />
            <Route path="/risk" element={<RiskPage />} />
            <Route path="/compliance" element={<CompliancePage />} />
            <Route path="/activity-log" element={<AuditPage />} />
            <Route path="/policies" element={<GuardrailsPage />} />
            <Route path="/datasets" element={<DatasetsPage />} />
            <Route path="/evaluations" element={<EvaluationsPage />} />
            <Route path="/evaluations/:filename" element={<EvaluationRunPage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
      </AuthGate>
    </HashRouter>
  );
}

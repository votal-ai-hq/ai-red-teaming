import { type ReactNode } from "react";
import { useAuthStore } from "@/stores/authStore";
import { useAuthInit } from "@/hooks/useAuth";
import { LoginForm } from "./LoginForm";

interface AuthGateProps {
  children: ReactNode;
}

export function AuthGate({ children }: AuthGateProps) {
  useAuthInit();

  const { initialized, authMode, user, token } = useAuthStore();

  if (!initialized) {
    return (
      <div className="fixed inset-0 bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <span className="text-sm text-muted-foreground">Loading...</span>
        </div>
      </div>
    );
  }

  // No auth needed
  if (authMode === "none" || authMode === "dev") {
    return <>{children}</>;
  }

  // Simple auth - show login if no session, or the set-password page from an
  // emailed sign-up / reset link (even when already signed in)
  if (
    authMode === "simple" &&
    ((!user && !token) || window.location.hash.startsWith("#/set-password"))
  ) {
    return <LoginForm />;
  }

  // OIDC - would need Clerk integration here
  if (authMode === "oidc" && !user && !token) {
    return <LoginForm />;
  }

  return <>{children}</>;
}

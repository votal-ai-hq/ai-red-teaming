import { create } from "zustand";
import type { AuthUser } from "@/api/types";

interface AuthState {
  token: string | null;
  authMode: "none" | "simple" | "dev" | "oidc";
  user: AuthUser | null;
  hcaptchaSiteKey: string | null;
  clerkPublishableKey: string | null;
  signupEnabled: boolean;
  initialized: boolean;

  setToken: (token: string | null) => void;
  setAuthMode: (mode: AuthState["authMode"]) => void;
  setUser: (user: AuthUser | null) => void;
  setHcaptchaSiteKey: (key: string | null) => void;
  setClerkPublishableKey: (key: string | null) => void;
  setSignupEnabled: (v: boolean) => void;
  setInitialized: (v: boolean) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  token: null,
  authMode: "none",
  user: null,
  hcaptchaSiteKey: null,
  clerkPublishableKey: null,
  signupEnabled: false,
  initialized: false,

  setToken: (token) => set({ token }),
  setAuthMode: (authMode) => set({ authMode }),
  setUser: (user) => set({ user }),
  setHcaptchaSiteKey: (hcaptchaSiteKey) => set({ hcaptchaSiteKey }),
  setClerkPublishableKey: (clerkPublishableKey) => set({ clerkPublishableKey }),
  setSignupEnabled: (signupEnabled) => set({ signupEnabled }),
  setInitialized: (initialized) => set({ initialized }),
  logout: () => set({ token: null, user: null }),
}));

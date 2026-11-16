import { useEffect } from "react";
import { useAuthStore } from "@/stores/authStore";
import * as authApi from "@/api/auth";

export function useAuthInit() {
  const {
    setAuthMode,
    setUser,
    setToken,
    setHcaptchaSiteKey,
    setClerkPublishableKey,
    setSignupEnabled,
    setInitialized,
  } = useAuthStore();

  useEffect(() => {
    let cancelled = false;

    async function init() {
      try {
        const config = await authApi.getAuthConfig();
        if (cancelled) return;

        setAuthMode(config.mode);
        if (config.hcaptchaSiteKey) setHcaptchaSiteKey(config.hcaptchaSiteKey);
        if (config.clerkPublishableKey) setClerkPublishableKey(config.clerkPublishableKey as string);
        setSignupEnabled(!!config.signupEnabled);

        if (config.mode === "none" || config.mode === "dev") {
          setInitialized(true);
          return;
        }

        if (config.mode === "simple") {
          // Try to restore session
          try {
            const { user } = await authApi.getMe();
            if (!cancelled) {
              setUser(user);
              setToken("session");
            }
          } catch {
            // No active session, will show login
          }
        }

        if (!cancelled) setInitialized(true);
      } catch {
        if (!cancelled) setInitialized(true);
      }
    }

    init();
    return () => { cancelled = true; };
  }, [
    setAuthMode,
    setUser,
    setToken,
    setHcaptchaSiteKey,
    setClerkPublishableKey,
    setSignupEnabled,
    setInitialized,
  ]);
}

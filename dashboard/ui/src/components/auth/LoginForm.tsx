import { useState, useRef, type FormEvent } from "react";
import { useAuthStore } from "@/stores/authStore";
import * as authApi from "@/api/auth";
import { Shield } from "lucide-react";
import HCaptcha from "@hcaptcha/react-hcaptcha";

export function LoginForm() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { setUser, setToken, hcaptchaSiteKey } = useAuthStore();
  const captchaRef = useRef<HCaptcha>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");

    if (hcaptchaSiteKey && !captchaToken) {
      setError("Please complete the CAPTCHA verification.");
      return;
    }

    setLoading(true);
    try {
      const { user } = await authApi.login(
        username,
        password,
        captchaToken || undefined,
      );
      setUser(user);
      setToken("session");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
      // Reset captcha on failure so user can retry
      captchaRef.current?.resetCaptcha();
      setCaptchaToken("");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-muted flex items-center justify-center z-[9999]">
      <div className="w-full max-w-[400px] mx-5 bg-white border border-border rounded-xl p-10 shadow-lg animate-in fade-in slide-in-from-bottom-2 duration-300">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-primary flex items-center justify-center shadow-sm">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-foreground tracking-tight">
              Red-Team AI
            </h1>
            <p className="text-sm text-muted-foreground">
              Sign in with your credentials
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-muted-foreground">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              className="w-full px-3.5 py-2.5 rounded-lg border border-input bg-white text-foreground text-[15px] outline-none focus:border-primary focus:ring-2 focus:ring-primary/10 transition-all"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-sm font-medium text-muted-foreground">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="w-full px-3.5 py-2.5 rounded-lg border border-input bg-white text-foreground text-[15px] outline-none focus:border-primary focus:ring-2 focus:ring-primary/10 transition-all"
            />
          </div>

          {hcaptchaSiteKey && (
            <div className="flex justify-center">
              <HCaptcha
                ref={captchaRef}
                sitekey={hcaptchaSiteKey}
                onVerify={(token) => setCaptchaToken(token)}
                onExpire={() => setCaptchaToken("")}
                onError={() => setCaptchaToken("")}
              />
            </div>
          )}

          {error && (
            <p className="text-sm text-red-600">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading || !username || !password || (!!hcaptchaSiteKey && !captchaToken)}
            className="w-full py-3 rounded-lg bg-foreground text-white text-sm font-semibold hover:bg-foreground/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors mt-2"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <p className="text-xs text-muted-foreground text-center mt-4">
          Session is shared across tabs with a secure cookie
        </p>
      </div>
    </div>
  );
}

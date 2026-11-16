import { useState, useRef, type FormEvent } from "react";
import { useAuthStore } from "@/stores/authStore";
import * as authApi from "@/api/auth";
import { Shield } from "lucide-react";
import HCaptcha from "@hcaptcha/react-hcaptcha";

type Mode = "login" | "signup" | "forgot" | "sent" | "set-password";

/** Token from an emailed link: #/set-password?token=... */
function linkToken(): string | null {
  const hash = window.location.hash;
  if (!hash.startsWith("#/set-password")) return null;
  return new URLSearchParams(hash.split("?")[1] ?? "").get("token");
}

function errorMessage(err: unknown, fallback: string): string {
  const message = err instanceof Error ? err.message : fallback;
  return message.replace(/^API error \d+: /, "");
}

const SUBTITLES: Record<Mode, string> = {
  login: "Sign in with your credentials",
  signup: "Create your account",
  forgot: "Reset your password",
  sent: "Check your email",
  "set-password": "Choose your password",
};

const inputClass =
  "w-full px-3.5 py-2.5 rounded-lg border border-input bg-white text-foreground text-[15px] outline-none focus:border-primary focus:ring-2 focus:ring-primary/10 transition-all";
const labelClass = "text-sm font-medium text-muted-foreground";
const linkClass = "text-primary hover:underline";

export function LoginForm() {
  const [token] = useState(linkToken);
  const [mode, setMode] = useState<Mode>(
    window.location.hash.startsWith("#/set-password") ? "set-password" : "login",
  );
  const [username, setUsername] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { setUser, setToken, hcaptchaSiteKey, signupEnabled } = useAuthStore();
  const captchaRef = useRef<HCaptcha>(null);

  const needsCaptcha = !!hcaptchaSiteKey && mode !== "set-password" && mode !== "sent";

  const switchMode = (next: Mode) => {
    if (mode === "set-password") window.location.hash = "#/dashboard";
    setMode(next);
    setError("");
    setPassword("");
    captchaRef.current?.resetCaptcha();
    setCaptchaToken("");
  };

  const signIn = (user: Awaited<ReturnType<typeof authApi.login>>["user"]) => {
    setUser(user);
    setToken("session");
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");

    if (needsCaptcha && !captchaToken) {
      setError("Please complete the CAPTCHA verification.");
      return;
    }

    setLoading(true);
    try {
      if (mode === "login") {
        const { user } = await authApi.login(username, password, captchaToken || undefined);
        signIn(user);
      } else if (mode === "signup") {
        await authApi.signup(username, name, captchaToken || undefined);
        setMode("sent");
      } else if (mode === "forgot") {
        await authApi.forgotPassword(username, captchaToken || undefined);
        setMode("sent");
      } else if (mode === "set-password" && token) {
        const { user } = await authApi.setPassword(token, password);
        window.location.hash = "#/dashboard";
        signIn(user);
      }
    } catch (err) {
      setError(errorMessage(err, "Something went wrong"));
      // Reset captcha on failure so user can retry
      captchaRef.current?.resetCaptcha();
      setCaptchaToken("");
    } finally {
      setLoading(false);
    }
  };

  const submitLabel: Record<Exclude<Mode, "sent">, string> = {
    login: loading ? "Signing in..." : "Sign In",
    signup: loading ? "Sending..." : "Create account",
    forgot: loading ? "Sending..." : "Email me a reset link",
    "set-password": loading ? "Saving..." : "Set password and sign in",
  };

  const filled =
    mode === "login" ? !!username && !!password : mode === "set-password" ? !!token && !!password : !!username;
  const canSubmit = !loading && filled && (!needsCaptcha || !!captchaToken);

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
            <p className="text-sm text-muted-foreground">{SUBTITLES[mode]}</p>
          </div>
        </div>

        {mode === "sent" ? (
          <div className="flex flex-col gap-4">
            <p className="text-sm text-foreground">
              We've emailed a link to <span className="font-medium">{username}</span> if it can
              be used here. Open it to choose your password. It expires in 24 hours.
            </p>
            <button type="button" onClick={() => switchMode("login")} className={`text-sm ${linkClass} self-start`}>
              Back to sign in
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            {mode === "set-password" && !token && (
              <p className="text-sm text-red-600">This link is incomplete. Request a new one.</p>
            )}

            {mode !== "set-password" && (
              <div className="flex flex-col gap-1.5">
                <label className={labelClass}>
                  {mode === "login" ? (signupEnabled ? "Email or username" : "Username") : "Email"}
                </label>
                <input
                  type={mode === "login" ? "text" : "email"}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete={mode === "login" ? "username" : "email"}
                  className={inputClass}
                />
              </div>
            )}

            {mode === "signup" && (
              <div className="flex flex-col gap-1.5">
                <label className={labelClass}>Name (optional)</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="name"
                  className={inputClass}
                />
              </div>
            )}

            {(mode === "login" || mode === "set-password") && (
              <div className="flex flex-col gap-1.5">
                <label className={labelClass}>
                  {mode === "set-password" ? "New password (8+ characters)" : "Password"}
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete={mode === "set-password" ? "new-password" : "current-password"}
                  className={inputClass}
                />
              </div>
            )}

            {needsCaptcha && (
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

            {error && <p className="text-sm text-red-600">{error}</p>}

            <button
              type="submit"
              disabled={!canSubmit}
              className="w-full py-3 rounded-lg bg-foreground text-white text-sm font-semibold hover:bg-foreground/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors mt-2"
            >
              {submitLabel[mode]}
            </button>

            {(signupEnabled || mode !== "login") && (
              <div className="flex justify-between text-sm">
                {mode === "login" ? (
                  <>
                    <button type="button" onClick={() => switchMode("signup")} className={linkClass}>
                      Create an account
                    </button>
                    <button type="button" onClick={() => switchMode("forgot")} className={linkClass}>
                      Forgot password?
                    </button>
                  </>
                ) : (
                  <button type="button" onClick={() => switchMode("login")} className={linkClass}>
                    Back to sign in
                  </button>
                )}
              </div>
            )}
          </form>
        )}

        {mode === "login" && (
          <p className="text-xs text-muted-foreground text-center mt-4">
            Session is shared across tabs with a secure cookie
          </p>
        )}
      </div>
    </div>
  );
}

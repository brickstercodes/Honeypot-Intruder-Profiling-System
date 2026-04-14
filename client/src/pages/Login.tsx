import { useState } from "react";
import { useLocation } from "wouter";

export default function Login() {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [, navigate] = useLocation();

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ password }),
      });
      if (!res.ok) { setError("Access denied — invalid credentials"); return; }
      window.location.href = "/admin";
    } catch {
      setError("Connection failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="console-shell flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm animate-in">
        {/* Logo mark */}
        <div className="mb-8 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-sky-500/10 ring-1 ring-sky-500/20">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="m9 12 2 2 4-4"/>
            </svg>
          </div>
          <div>
            <div className="eyebrow">HoneyIDS</div>
            <div className="text-xs text-slate-500 mt-0.5">Admin Console</div>
          </div>
        </div>

        <div className="panel">
          <h1 className="text-2xl font-semibold tracking-tight text-white mb-1">Sign in</h1>
          <p className="text-sm text-slate-400 mb-6">Enter your admin password to access the dashboard.</p>

          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-2 tracking-wide uppercase" style={{fontFamily:"var(--font-mono)",letterSpacing:"0.16em"}}>
                Password
              </label>
              <input
                type="password"
                className="field"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••••••"
                autoFocus
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-xl bg-red-500/10 border border-red-500/20 px-4 py-3 text-sm text-red-300">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                {error}
              </div>
            )}

            <button
              type="submit"
              className="btn btn-primary w-full"
              disabled={loading || !password}
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
                  Authenticating...
                </span>
              ) : "Enter console"}
            </button>
          </form>
        </div>

        <p className="mt-4 text-center text-xs text-slate-600">
          Password is set via <span style={{fontFamily:"var(--font-mono)"}}>ADMIN_PASSWORD</span> in <span style={{fontFamily:"var(--font-mono)"}}>/.env</span>
        </p>
      </div>
    </div>
  );
}

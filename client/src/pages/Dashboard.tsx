import { useState } from "react";
import { useLocation } from "wouter";
import {
  Area, AreaChart, Bar, BarChart, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import type { DashboardSnapshot, SeverityLevel, AttackSession } from "@shared/honeypot";
import WorldMap from "@/components/WorldMap";
import LiveFeed from "@/components/LiveFeed";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";

// ── Design tokens ──────────────────────────────────────────
const SEV_CLASS: Record<SeverityLevel, string> = {
  low:      "sev-badge low",
  medium:   "sev-badge medium",
  high:     "sev-badge high",
  critical: "sev-badge critical",
};

const SEV_DOT: Record<SeverityLevel, string> = {
  low: "sev-dot low", medium: "sev-dot medium",
  high: "sev-dot high", critical: "sev-dot critical",
};

const CHART_COLORS = ["#38bdf8","#f59e0b","#ef4444","#10b981","#a78bfa","#f97316"];

const SEV_PIE: Record<string, string> = {
  low: "#10b981", medium: "#f59e0b", high: "#f97316", critical: "#ef4444",
};

const KIND_COLOR: Record<string, string> = {
  session_started:  "#38bdf8",
  session_ended:    "#10b981",
  alert_fired:      "#ef4444",
  ip_blocked:       "#f97316",
  ip_unblocked:     "#a78bfa",
  command_captured: "#f59e0b",
};

function fmtTime(iso: string) { return iso.slice(11,16); }

// ── Sub-components ─────────────────────────────────────────
function SevBadge({ s }: { s: SeverityLevel }) {
  return (
    <span className={SEV_CLASS[s]}>
      <span className={SEV_DOT[s]} />
      {s}
    </span>
  );
}

function Metric({ label, value, sub, accent }: { label: string; value: string | number; sub: string; accent?: boolean }) {
  return (
    <div className={`panel metric-card min-h-[120px] justify-between ${accent ? "ring-1 ring-sky-500/20" : ""}`}>
      <span>{label}</span>
      <strong style={accent ? { color: "var(--accent)" } : {}}>{value}</strong>
      <small>{sub}</small>
    </div>
  );
}

function ChartShell({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="panel" style={{ height: 300 }}>
      <div className="eyebrow mb-4">{title}</div>
      <div style={{ height: 230 }}>{children}</div>
    </div>
  );
}

function ServiceCard({ svc }: { svc: DashboardSnapshot["services"][0] }) {
  return (
    <div className="flex items-center gap-3 rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-3">
      <div className={`status-dot ${svc.listening ? "live" : "down"}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-white uppercase tracking-wide">{svc.service}</span>
          <span className="text-xs text-slate-500" style={{ fontFamily: "var(--font-mono)" }}>:{svc.port}</span>
        </div>
        <div className="text-xs text-slate-500 mt-0.5">{svc.activeConnections} active · {svc.totalConnections} total</div>
      </div>
      <span className={`text-xs px-2 py-0.5 rounded-full ${svc.listening ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20" : "bg-slate-700/40 text-slate-500"}`}>
        {svc.listening ? "armed" : "down"}
      </span>
    </div>
  );
}

function SessionRow({ session, selected, onClick }: { session: AttackSession; selected: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-2xl border px-4 py-3 transition-all ${
        selected
          ? "border-sky-500/40 bg-sky-500/8"
          : "border-white/6 bg-white/[0.02] hover:border-white/12 hover:bg-white/[0.03]"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="ip-addr text-white text-sm">{session.attackerIp}</div>
          <div className="text-xs text-slate-400 mt-0.5 truncate">
            {session.service.toUpperCase()} · {session.geo.country} · {session.classification.replace(/_/g, " ")}
          </div>
        </div>
        <SevBadge s={session.severity} />
      </div>
      <div className="flex gap-3 mt-2 text-xs text-slate-500" style={{ fontFamily: "var(--font-mono)" }}>
        <span>{session.usernameAttempts.length} users</span>
        <span>{session.commands.length} cmds</span>
        <span>{session.payloads.length} payloads</span>
        <span>{session.failureCount} fails</span>
      </div>
    </button>
  );
}

function SessionPanel({ sessionId, onClose, onBlock, onTerminate }: {
  sessionId: string;
  onClose: () => void;
  onBlock: (ip: string) => void;
  onTerminate: (id: string) => void;
}) {
  const q = trpc.dashboard.session.useQuery({ sessionId }, { enabled: !!sessionId });
  const s = q.data;

  if (!s) return (
    <div className="panel flex items-center justify-center py-12 text-slate-500 text-sm">
      {q.isLoading ? "Loading session…" : "Session not found"}
    </div>
  );

  return (
    <div className="panel animate-in">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-5">
        <div>
          <div className="eyebrow mb-1">Session detail</div>
          <div className="ip-addr text-xl text-white">{s.attackerIp}</div>
          <div className="text-sm text-slate-400 mt-1">{s.geo.country} · {s.geo.city} · {s.geo.org}</div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <SevBadge s={s.severity} />
          <button onClick={onClose} className="btn btn-ghost btn-sm">✕</button>
        </div>
      </div>

      {/* Meta grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { k: "Service", v: s.service.toUpperCase() },
          { k: "Port", v: s.destinationPort },
          { k: "Score", v: s.severityScore },
          { k: "ASN", v: s.geo.asn },
          { k: "Classification", v: s.classification.replace(/_/g, " ") },
          { k: "Started", v: fmtTime(s.startedAt) },
          { k: "Usernames tried", v: s.usernameAttempts.length },
          { k: "Commands", v: s.commands.length },
        ].map(m => (
          <div key={m.k} className="rounded-xl border border-white/6 bg-white/[0.02] px-3 py-2">
            <div className="text-xs text-slate-500 mb-1" style={{ fontFamily: "var(--font-mono)", letterSpacing: "0.1em" }}>{m.k}</div>
            <div className="text-sm font-medium text-white">{m.v}</div>
          </div>
        ))}
      </div>

      {/* Signals */}
      {s.threatSignals.length > 0 && (
        <div className="mb-5">
          <div className="eyebrow mb-2">Threat signals</div>
          <div className="space-y-1.5">
            {s.threatSignals.map(sig => (
              <div key={sig.id} className="flex items-center gap-3 rounded-xl border border-white/6 bg-white/[0.02] px-3 py-2 text-sm">
                <span className={`text-xs px-2 py-0.5 rounded-full ${sig.kind === "signature" ? "bg-red-500/10 text-red-300" : sig.kind === "anomaly" ? "bg-amber-500/10 text-amber-300" : "bg-purple-500/10 text-purple-300"}`}>
                  {sig.kind}
                </span>
                <span className="text-slate-300 flex-1">{sig.label}</span>
                <span className="text-slate-500 text-xs" style={{ fontFamily: "var(--font-mono)" }}>w:{sig.weight}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Transcript */}
      {s.transcript.length > 0 && (
        <div className="mb-5">
          <div className="eyebrow mb-2">Session transcript</div>
          <div className="scroll-panel rounded-xl border border-white/6 bg-black/30 p-3">
            {s.transcript.map(f => (
              <div key={f.id} className={`transcript-line ${f.direction}`}>
                <span className="ts">{fmtTime(f.at)}</span>
                <span className="content break-all">{f.content}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Username attempts */}
      {s.usernameAttempts.length > 0 && (
        <div className="mb-5">
          <div className="eyebrow mb-2">Credential attempts</div>
          <div className="flex flex-wrap gap-2">
            {s.usernameAttempts.slice(0, 20).map((u, i) => (
              <span key={i} className="text-xs rounded-lg border border-white/8 bg-white/[0.03] px-2 py-1" style={{ fontFamily: "var(--font-mono)" }}>{u}</span>
            ))}
          </div>
        </div>
      )}

      {/* Response actions */}
      <div className="flex gap-3 pt-2 border-t border-white/6">
        <button className="btn btn-danger btn-sm" onClick={() => onBlock(s.attackerIp)}>
          Block IP
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => onTerminate(s.id)}>
          Terminate session
        </button>
      </div>
    </div>
  );
}

function AlertCard({ alert }: { alert: DashboardSnapshot["alerts"][0] }) {
  return (
    <div className={`rounded-2xl border px-4 py-3 ${
      alert.severity === "critical" ? "border-red-500/25 bg-red-500/8 alert-critical-pulse" :
      alert.severity === "high"     ? "border-orange-500/25 bg-orange-500/8" :
      alert.severity === "medium"   ? "border-amber-500/20 bg-amber-500/6" :
                                      "border-emerald-500/15 bg-emerald-500/5"
    }`}>
      <div className="flex items-center justify-between gap-2 mb-1">
        <SevBadge s={alert.severity} />
        <span className="text-xs text-slate-500" style={{ fontFamily: "var(--font-mono)" }}>{alert.service.toUpperCase()}</span>
      </div>
      <div className="text-sm font-medium text-white mt-1">{alert.title}</div>
      <div className="text-xs text-slate-400 mt-1 leading-5">{alert.message}</div>
      {alert.channels.length > 0 && (
        <div className="text-xs text-slate-600 mt-2">→ {alert.channels.join(", ")}</div>
      )}
    </div>
  );
}

// ── Forensic Chain Tab ──────────────────────────────────────
function ForensicsTab() {
  const chain = trpc.dashboard.forensicChain.useQuery(
    { limit: 60 },
    { refetchInterval: 10000 }
  );

  const data = chain.data;

  return (
    <div className="space-y-5 animate-in">
      {/* Explainer */}
      <div className="panel">
        <div className="eyebrow mb-3">What is the forensic chain?</div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[
            {
              title: "Tamper-evident log",
              icon: "🔗",
              desc: "Every security event (session, alert, block) is written as an encrypted entry. Each entry includes the SHA-256 hash of the previous entry, forming an immutable chain.",
            },
            {
              title: "AES-256-GCM encryption",
              icon: "🔐",
              desc: "Each log line is individually encrypted with AES-256-GCM using a key derived from your EVIDENCE_ENCRYPTION_KEY env variable. Data at rest is always ciphertext.",
            },
            {
              title: "Hash chain integrity",
              icon: "🧮",
              desc: "Changing or deleting any past entry breaks the chain — every subsequent hash becomes invalid. This makes retroactive tampering detectable.",
            },
            {
              title: "Forensic admissibility",
              icon: "⚖️",
              desc: "The chain provides a verifiable audit trail for incident response. Each entry has a timestamp, event kind, and cryptographic proof of ordering.",
            },
          ].map(c => (
            <div key={c.title} className="rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-4">
              <div className="text-2xl mb-2">{c.icon}</div>
              <div className="text-sm font-semibold text-white mb-1">{c.title}</div>
              <div className="text-xs text-slate-400 leading-5">{c.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Chain status */}
      <div className="panel">
        <div className="flex items-center justify-between mb-4">
          <div className="eyebrow">Chain integrity status</div>
          {data && (
            <span className={`flex items-center gap-1.5 text-xs px-3 py-1 rounded-full border ${
              data.chainValid
                ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/25"
                : "bg-red-500/10 text-red-300 border-red-500/25"
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${data.chainValid ? "bg-emerald-400" : "bg-red-400"}`} />
              {data.chainValid ? "Chain intact" : "Chain broken — tamper detected"}
            </span>
          )}
        </div>

        {chain.isLoading && (
          <div className="py-10 text-center text-slate-500 text-sm">Loading forensic chain…</div>
        )}

        {data && data.entries.length === 0 && (
          <div className="py-10 text-center text-slate-500 text-sm">
            No evidence entries yet. Events are written to the chain as attacks occur.
          </div>
        )}

        {data && data.entries.length > 0 && (
          <>
            <div className="text-xs text-slate-500 mb-4" style={{ fontFamily: "var(--font-mono)" }}>
              Showing {data.entries.length} of {data.totalCount} entries · most recent first
            </div>
            <div className="space-y-2">
              {data.entries.map((entry, i) => (
                <div
                  key={i}
                  className={`rounded-2xl border px-4 py-3 ${
                    !entry.chainOk
                      ? "border-red-500/30 bg-red-500/5"
                      : "border-white/6 bg-white/[0.02]"
                  }`}
                >
                  <div className="flex items-center gap-3 flex-wrap">
                    {/* Kind badge */}
                    <span
                      className="text-xs px-2 py-0.5 rounded-full border"
                      style={{
                        background: `${KIND_COLOR[entry.kind] || "#64748b"}18`,
                        color: KIND_COLOR[entry.kind] || "#94a3b8",
                        borderColor: `${KIND_COLOR[entry.kind] || "#64748b"}35`,
                      }}
                    >
                      {entry.kind.replace(/_/g, " ")}
                    </span>

                    {/* Timestamp */}
                    <span className="text-xs text-slate-400" style={{ fontFamily: "var(--font-mono)" }}>
                      {entry.timestamp.slice(0, 19).replace("T", " ")}
                    </span>

                    {/* Chain link indicator */}
                    {entry.chainOk ? (
                      <span className="text-xs text-emerald-500" style={{ fontFamily: "var(--font-mono)" }}>✓ linked</span>
                    ) : (
                      <span className="text-xs text-red-400" style={{ fontFamily: "var(--font-mono)" }}>✗ broken</span>
                    )}

                    {/* Hash preview */}
                    <span className="ml-auto text-xs text-slate-600" style={{ fontFamily: "var(--font-mono)" }}>
                      #{entry.hash.slice(0, 12)}…
                    </span>
                  </div>

                  {/* PrevHash link */}
                  <div className="mt-1.5 text-xs text-slate-600" style={{ fontFamily: "var(--font-mono)" }}>
                    ↑ prev: {entry.prevHash === "GENESIS" ? "GENESIS (chain origin)" : `#${entry.prevHash.slice(0, 12)}…`}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* How to use */}
      <div className="panel">
        <div className="eyebrow mb-3">How IP blocking works</div>
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            {
              step: "01",
              title: "Severity threshold",
              desc: "When a session's severity score reaches the AUTO_BLOCK_THRESHOLD (default 55), the IP is automatically added to the blocklist.",
            },
            {
              step: "02",
              title: "What gets blocked",
              desc: "Blocked IPs are rejected at all TCP decoy services (SSH:2222, FTP:2121, Telnet:2323, HTTP:8081, DB:33060) and at the /trap HTTP route. The admin console at :3000 is intentionally not behind the blocklist.",
            },
            {
              step: "03",
              title: "How to trigger",
              desc: "Visit the HTTP trap at :8081 or /trap and send probing requests. Each hit raises the severity score. At score ≥55 the IP is blocked. Use 'Simulate attacks' to see the effect instantly.",
            },
          ].map(c => (
            <div key={c.step} className="rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-4">
              <div className="text-xs text-sky-400 mb-2" style={{ fontFamily: "var(--font-mono)" }}>STEP {c.step}</div>
              <div className="text-sm font-semibold text-white mb-1">{c.title}</div>
              <div className="text-xs text-slate-400 leading-5">{c.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Main Dashboard ─────────────────────────────────────────
export default function Dashboard() {
  const { user, isAuthenticated, loading, logout } = useAuth();
  const [, navigate] = useLocation();
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [tab, setTab] = useState<"overview" | "attackers" | "sessions" | "alerts" | "forensics">("overview");
  const utils = trpc.useUtils();

  const snapshot = trpc.dashboard.snapshot.useQuery(undefined, {
    refetchInterval: 4000,
    refetchOnWindowFocus: true,
  });

  const simulate = trpc.dashboard.simulate.useMutation({
    onSuccess: () => utils.dashboard.snapshot.invalidate(),
  });

  const blockMutation = trpc.dashboard.blockIp.useMutation({
    onSuccess: () => utils.dashboard.snapshot.invalidate(),
  });

  const unblockMutation = trpc.dashboard.unblockIp.useMutation({
    onSuccess: () => utils.dashboard.snapshot.invalidate(),
  });

  const terminateMutation = trpc.dashboard.terminateSession.useMutation({
    onSuccess: () => utils.dashboard.snapshot.invalidate(),
  });

  if (loading) return <div className="min-h-screen" style={{ background: "var(--bg-0)" }} />;
  if (!isAuthenticated || user?.role !== "admin") {
    navigate("/login");
    return null;
  }

  const snap = snapshot.data;

  const downloadReport = () => {
    const a = document.createElement("a");
    a.href = "/api/forensic-report";
    a.download = `honeypot-report-${new Date().toISOString().slice(0,10)}.html`;
    a.click();
  };

  return (
    <div className="console-shell min-h-screen px-4 py-5 md:px-6 xl:px-8">
      <div className="mx-auto max-w-[1600px] space-y-5">

        {/* ── Top bar ── */}
        <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-sky-500/10 ring-1 ring-sky-500/20">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="m9 12 2 2 4-4"/>
              </svg>
            </div>
            <div>
              <div className="text-sm font-semibold text-white">HoneyIDS Console</div>
              <div className="text-xs text-slate-500">
                {snap ? `Last updated ${fmtTime(snap.capturedAt)}` : "Connecting…"}
              </div>
            </div>
            {snap && snap.metrics.activeSessions > 0 && (
              <span className="flex items-center gap-1.5 rounded-full bg-red-500/15 border border-red-500/25 px-3 py-1 text-xs text-red-300">
                <span className="sev-dot critical" />
                {snap.metrics.activeSessions} active
              </span>
            )}
          </div>

          <div className="flex flex-wrap gap-2">
            <button className="btn btn-primary btn-sm" onClick={() => simulate.mutate({ count: 16 })} disabled={simulate.isPending}>
              {simulate.isPending ? "Simulating…" : "Simulate attacks"}
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => window.open("/trap", "_blank")}>
              Preview trap
            </button>
            <button className="btn btn-ghost btn-sm" onClick={downloadReport}>
              Download report
            </button>
            <button className="btn btn-ghost btn-sm" onClick={logout}>
              Sign out
            </button>
          </div>
        </header>

        {!snap ? (
          <div className="panel py-20 text-center text-slate-500">Loading dashboard state…</div>
        ) : (
          <>
            {/* ── Metrics ── */}
            <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 xl:grid-cols-6">
              <Metric label="Sessions" value={snap.metrics.totalSessions} sub={`${snap.metrics.activeSessions} active`} />
              <Metric label="Alerts" value={snap.metrics.totalAlerts} sub="all channels" accent />
              <Metric label="Attackers" value={snap.metrics.uniqueAttackers} sub="unique IPs" />
              <Metric label="Events" value={snap.metrics.totalEvents} sub="forensic chain" />
              <Metric label="Blocked" value={snap.metrics.blockedIps} sub="IPs blacklisted" />
              <Metric label="Avg score" value={snap.metrics.averageSeverityScore} sub="severity 0–100" />
            </div>

            {/* ── Tab nav ── */}
            <div className="flex gap-1 rounded-2xl border border-white/6 bg-white/[0.02] p-1 w-fit flex-wrap">
              {(["overview","sessions","attackers","alerts","forensics"] as const).map(t => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`px-4 py-2 rounded-xl text-sm font-medium capitalize transition-all ${
                    tab === t
                      ? "bg-sky-500/15 text-sky-300 border border-sky-500/25"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {t}
                  {t === "alerts" && snap.metrics.totalAlerts > 0 && (
                    <span className="ml-2 text-xs bg-red-500/20 text-red-300 rounded-full px-1.5 py-0.5">{snap.metrics.totalAlerts}</span>
                  )}
                  {t === "forensics" && (
                    <span className="ml-2 text-xs bg-sky-500/15 text-sky-400 rounded-full px-1.5 py-0.5">chain</span>
                  )}
                </button>
              ))}
            </div>

            {/* ── Tab: Overview ── */}
            {tab === "overview" && (
              <div className="space-y-5 animate-in">
                {/* Charts row */}
                <div className="grid gap-5 xl:grid-cols-3">
                  <ChartShell title="Attack timeline">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={snap.analytics.timeline}>
                        <defs>
                          <linearGradient id="tl" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.5} />
                            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="bucket" tick={{ fill: "#475569", fontSize: 10 }} tickFormatter={fmtTime} />
                        <YAxis tick={{ fill: "#475569", fontSize: 10 }} />
                        <Tooltip contentStyle={{ background: "#091422", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 12, fontSize: 11 }} />
                        <Area type="monotone" dataKey="count" stroke="#38bdf8" strokeWidth={2} fill="url(#tl)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </ChartShell>

                  <ChartShell title="Failed logins by hour">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={snap.analytics.failedLoginsByHour}>
                        <XAxis dataKey="bucket" tick={{ fill: "#475569", fontSize: 10 }} tickFormatter={fmtTime} />
                        <YAxis tick={{ fill: "#475569", fontSize: 10 }} />
                        <Tooltip contentStyle={{ background: "#091422", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 12, fontSize: 11 }} />
                        <Bar dataKey="count" fill="#f97316" radius={[6, 6, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </ChartShell>

                  <ChartShell title="Severity distribution">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={snap.analytics.severityDistribution} dataKey="value" nameKey="label" innerRadius={50} outerRadius={80} paddingAngle={4}>
                          {snap.analytics.severityDistribution.map(e => (
                            <Cell key={e.label} fill={SEV_PIE[e.label] || "#475569"} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ background: "#091422", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 12, fontSize: 11 }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </ChartShell>
                </div>

                {/* Services + Map */}
                <div className="grid gap-5 xl:grid-cols-[320px_1fr]">
                  <div className="panel space-y-3">
                    <div className="eyebrow mb-2">Decoy services</div>
                    {snap.services.map(s => <ServiceCard key={s.service} svc={s} />)}
                  </div>
                  <div className="panel">
                    <WorldMap
                      markers={snap.attackers.map(a => ({
                        id: a.ip,
                        label: `${a.ip} · ${a.geo.country}`,
                        lat: a.geo.latitude,
                        lng: a.geo.longitude,
                        severity: snap.recentSessions.find(s => s.attackerIp === a.ip)?.severity || "low",
                      }))}
                    />
                  </div>
                </div>

                {/* Classification chart */}
                <ChartShell title="Attack classification breakdown">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={snap.analytics.classificationDistribution} layout="vertical">
                      <XAxis type="number" tick={{ fill: "#475569", fontSize: 10 }} />
                      <YAxis dataKey="label" type="category" tick={{ fill: "#94a3b8", fontSize: 10 }} width={160} tickFormatter={l => l.replace(/_/g, " ")} />
                      <Tooltip contentStyle={{ background: "#091422", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 12, fontSize: 11 }} />
                      <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                        {snap.analytics.classificationDistribution.map((_, i) => (
                          <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </ChartShell>
                <LiveFeed />
              </div>
            )}

            {/* ── Tab: Sessions ── */}
            {tab === "sessions" && (
              <div className="grid gap-5 xl:grid-cols-[380px_1fr] animate-in">
                <div className="panel space-y-2 scroll-panel">
                  <div className="eyebrow mb-3">Attack sessions ({snap.recentSessions.length})</div>
                  {snap.recentSessions.length === 0 ? (
                    <div className="py-10 text-center text-sm text-slate-500">No sessions yet — simulate or hit a decoy port</div>
                  ) : snap.recentSessions.map(s => (
                    <SessionRow
                      key={s.id}
                      session={s}
                      selected={selectedSession === s.id}
                      onClick={() => setSelectedSession(selectedSession === s.id ? null : s.id)}
                    />
                  ))}
                </div>

                <div>
                  {selectedSession ? (
                    <SessionPanel
                      sessionId={selectedSession}
                      onClose={() => setSelectedSession(null)}
                      onBlock={ip => blockMutation.mutate({ ip, reason: "Blocked from dashboard" })}
                      onTerminate={id => terminateMutation.mutate({ sessionId: id })}
                    />
                  ) : (
                    <div className="panel flex flex-col items-center justify-center py-20 text-center">
                      <div className="text-slate-600 text-4xl mb-3">←</div>
                      <div className="text-slate-400 text-sm">Select a session to inspect transcript, signals, and credentials</div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ── Tab: Attackers ── */}
            {tab === "attackers" && (
              <div className="space-y-5 animate-in">
                <div className="panel">
                  <div className="eyebrow mb-4">GeoIP attacker map</div>
                  <WorldMap
                    markers={snap.attackers.map(a => ({
                      id: a.ip,
                      label: `${a.ip} · ${a.geo.country}`,
                      lat: a.geo.latitude,
                      lng: a.geo.longitude,
                      severity: snap.recentSessions.find(s => s.attackerIp === a.ip)?.severity || "low",
                    }))}
                  />
                </div>

                <div className="panel overflow-x-auto">
                  <div className="eyebrow mb-4">Attacker profiles</div>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th>Country / ASN</th>
                        <th>Sessions</th>
                        <th>Alerts</th>
                        <th>Preferred</th>
                        <th>Score</th>
                        <th>Behavior</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {snap.attackers.map(a => (
                        <tr key={a.ip}>
                          <td><span className="ip-addr">{a.ip}</span></td>
                          <td>
                            <div className="text-sm text-white">{a.geo.country}</div>
                            <div className="text-xs text-slate-500">{a.geo.asn}</div>
                          </td>
                          <td className="mono text-center">{a.sessionCount}</td>
                          <td className="mono text-center">{a.alertCount}</td>
                          <td><span className="text-xs uppercase text-cyan-300">{a.preferredService}</span></td>
                          <td className="mono">{a.totalSeverityScore}</td>
                          <td className="text-xs text-slate-400 max-w-[200px] truncate">{a.behaviorPatterns.slice(0,2).join(" · ") || "—"}</td>
                          <td>
                            {!snap.blockedIps.includes(a.ip) ? (
                              <button
                                className="btn btn-danger btn-sm"
                                onClick={() => blockMutation.mutate({ ip: a.ip, reason: "Blocked from attacker table" })}
                                disabled={blockMutation.isPending}
                              >Block</button>
                            ) : (
                              <button
                                className="btn btn-ghost btn-sm text-xs"
                                onClick={() => unblockMutation.mutate({ ip: a.ip })}
                                disabled={unblockMutation.isPending}
                              >Unblock</button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {snap.attackers.length === 0 && (
                    <div className="py-10 text-center text-sm text-slate-500">No attacker profiles yet</div>
                  )}
                </div>

                {/* Blocked IPs */}
                {snap.blockedIps.length > 0 && (
                  <div className="panel">
                    <div className="eyebrow mb-3">Blocked IPs ({snap.blockedIps.length})</div>
                    <div className="flex flex-wrap gap-2">
                      {snap.blockedIps.map(ip => (
                        <span key={ip} className="flex items-center gap-2 rounded-xl border border-red-500/20 bg-red-500/8 px-3 py-1.5 text-sm text-red-300" style={{ fontFamily: "var(--font-mono)" }}>
                          {ip}
                          <button
                            className="text-red-400 hover:text-white transition-colors text-xs ml-1"
                            onClick={() => unblockMutation.mutate({ ip })}
                            disabled={unblockMutation.isPending}
                            title="Unblock this IP"
                          >✕</button>
                        </span>
                      ))}
                    </div>
                    <div className="mt-3 text-xs text-slate-600">
                      Click ✕ to unblock an IP. Blocked IPs are rejected at all decoy service ports.
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── Tab: Alerts ── */}
            {tab === "alerts" && (
              <div className="space-y-4 animate-in">
                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                  {snap.alerts.length === 0 ? (
                    <div className="panel col-span-3 py-16 text-center text-sm text-slate-500">No alerts yet</div>
                  ) : snap.alerts.map(a => <AlertCard key={a.id} alert={a} />)}
                </div>

                {/* Correlation chains */}
                {snap.correlation.length > 0 && (
                  <div className="panel">
                    <div className="eyebrow mb-3">SIEM correlation chains</div>
                    <div className="space-y-3">
                      {snap.correlation.map(c => (
                        <div key={c.id} className="rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-3">
                          <div className="flex items-center gap-3 mb-2">
                            <SevBadge s={c.severity} />
                            <span className="ip-addr text-sm text-white">{c.attackerIp}</span>
                            <span className="text-xs text-slate-500">{fmtTime(c.createdAt)}</span>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            {c.stages.map((stage, i) => (
                              <span key={i} className="flex items-center gap-1">
                                <span className="text-xs rounded-lg border border-white/8 bg-white/[0.03] px-2 py-1 text-slate-300">{stage}</span>
                                {i < c.stages.length - 1 && <span className="text-slate-600 text-xs">→</span>}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── Tab: Forensics ── */}
            {tab === "forensics" && <ForensicsTab />}
          </>
        )}
      </div>
    </div>
  );
}

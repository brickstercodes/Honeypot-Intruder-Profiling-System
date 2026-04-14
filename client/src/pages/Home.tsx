import { useLocation } from "wouter";

const FEATURES = [
  { icon: "🛡", label: "SSH / FTP / Telnet / HTTP / DB decoys" },
  { icon: "⚡", label: "Hybrid signature + anomaly detection" },
  { icon: "🗺", label: "GeoIP attacker map (OpenStreetMap)" },
  { icon: "📋", label: "Session capture & replay" },
  { icon: "🔗", label: "SIEM-style cross-service correlation" },
  { icon: "🚨", label: "Discord / Telegram / Email alerts" },
  { icon: "⚖", label: "Severity scoring & attack classification" },
  { icon: "🔒", label: "Tamper-evident forensic chain (SHA-256)" },
  { icon: "📄", label: "Auto-generated forensic report" },
];

export default function Home() {
  const [, navigate] = useLocation();
  return (
    <div className="console-shell min-h-screen px-4 py-10 md:py-16">
      <div className="mx-auto max-w-5xl space-y-10 animate-in">

        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-sky-500/10 ring-1 ring-sky-500/20">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div className="eyebrow">HoneyIDS — Honeypot Intrusion Detection System</div>
        </div>

        {/* Hero */}
        <div className="panel">
          <div className="grid gap-10 xl:grid-cols-[1.1fr_1fr]">
            <div className="space-y-5">
              <h1 className="text-4xl font-semibold tracking-tight text-white md:text-5xl leading-tight">
                Decoy services.<br/>
                <span style={{color:"var(--accent)"}}>Real-time detection.</span>
              </h1>
              <p className="text-base leading-7 text-slate-300 max-w-lg">
                A full honeypot IDS stack — fake login traps, multi-protocol decoy services, live attack correlation, GeoIP profiling, and forensic evidence chains. Built for cybersecurity labs.
              </p>
              <div className="flex flex-wrap gap-3 pt-2">
                <button className="btn btn-primary" onClick={() => navigate("/login")}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                  Open admin console
                </button>
                <button className="btn btn-ghost" onClick={() => window.open("/trap", "_blank")}>
                  Preview honey trap
                </button>
              </div>
            </div>

            {/* Live service indicators */}
            <div className="space-y-3">
              <div className="eyebrow mb-3">Decoy services</div>
              {[
                { name: "SSH", port: 2222, desc: "Fake OpenSSH — logs credentials & commands" },
                { name: "FTP", port: 2121, desc: "Fake vsftpd — captures file ops" },
                { name: "Telnet", port: 2323, desc: "Interactive shell emulation" },
                { name: "HTTP", port: 8081, desc: "Fake admin panel + bait files" },
                { name: "MySQL", port: 33060, desc: "Fake database — logs queries" },
              ].map(svc => (
                <div key={svc.name} className="flex items-center gap-4 rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-3">
                  <div className="status-dot live" />
                  <div className="flex-1 min-w-0">
                    <span className="text-sm font-medium text-white">{svc.name}</span>
                    <span className="ml-2 text-xs text-slate-500" style={{fontFamily:"var(--font-mono)"}}> :{svc.port}</span>
                    <div className="text-xs text-slate-500 truncate">{svc.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Feature grid */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(f => (
            <div key={f.label} className="flex items-center gap-3 rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-3">
              <span className="text-lg">{f.icon}</span>
              <span className="text-sm text-slate-300">{f.label}</span>
            </div>
          ))}
        </div>

        {/* Quick test */}
        <div className="panel">
          <div className="eyebrow mb-3">Quick test</div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { cmd: "telnet localhost 2323", label: "Telnet" },
              { cmd: "ftp localhost 2121", label: "FTP" },
              { cmd: "curl http://localhost:8081/wp-admin", label: "HTTP" },
              { cmd: "nc localhost 2222", label: "SSH raw" },
            ].map(t => (
              <div key={t.cmd} className="rounded-xl bg-black/30 border border-white/6 px-3 py-3">
                <div className="text-xs text-slate-500 mb-1">{t.label}</div>
                <code className="text-xs text-cyan-300" style={{fontFamily:"var(--font-mono)"}}>{t.cmd}</code>
              </div>
            ))}
          </div>
        </div>

        <p className="text-center text-xs text-slate-600">
          For isolated lab use only. Run inside Docker or a segmented VM.
        </p>
      </div>
    </div>
  );
}

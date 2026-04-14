import type { AttackSession } from "@shared/honeypot";

const chip = "rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-slate-300";

export default function SessionDetailPanel({
  session,
  onBlock,
  onTerminate,
}: {
  session: AttackSession | null | undefined;
  onBlock: (ip: string) => void;
  onTerminate: (sessionId: string) => void;
}) {
  if (!session) {
    return (
      <div className="panel flex h-full min-h-[360px] items-center justify-center text-sm text-slate-400">
        Pick a session to inspect transcript, indicators, and response actions.
      </div>
    );
  }

  return (
    <div className="panel flex h-full min-h-[360px] flex-col gap-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="eyebrow">Session</div>
          <h3 className="text-2xl font-semibold text-white">{session.attackerIp}</h3>
          <p className="mt-1 text-sm text-slate-400">
            {session.service.toUpperCase()} on port {session.destinationPort} · {session.classification.replaceAll("_", " ")}
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <button className="action-button" onClick={() => onBlock(session.attackerIp)}>
            Block IP
          </button>
          <button className="action-button muted" onClick={() => onTerminate(session.id)}>
            Terminate
          </button>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <div className="metric-card">
          <span>Severity</span>
          <strong>{session.severity.toUpperCase()}</strong>
          <small>score {session.severityScore}</small>
        </div>
        <div className="metric-card">
          <span>Geo / ASN</span>
          <strong>{session.geo.country}</strong>
          <small>{session.asnProfile}</small>
        </div>
        <div className="metric-card">
          <span>Duration</span>
          <strong>{Math.max(1, Math.round(session.durationMs / 1000))}s</strong>
          <small>{session.status}</small>
        </div>
        <div className="metric-card">
          <span>Credentials</span>
          <strong>{session.usernameAttempts.length}</strong>
          <small>{session.passwordAttempts.length} passwords seen</small>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {session.threatSignals.map((signal) => (
          <span key={signal.id} className={chip}>
            {signal.kind}: {signal.label}
          </span>
        ))}
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.2fr_.8fr]">
        <div className="rounded-[22px] border border-white/10 bg-slate-950/70 p-4">
          <div className="eyebrow">Transcript</div>
          <div className="mt-3 space-y-2 overflow-y-auto pr-1 text-sm text-slate-200 max-h-[280px]">
            {session.transcript.map((frame) => (
              <div key={frame.id} className="rounded-2xl border border-white/6 bg-white/[0.03] px-4 py-3">
                <div className="mb-1 flex items-center justify-between text-[11px] uppercase tracking-[0.18em] text-slate-500">
                  <span>{frame.direction}</span>
                  <span>{frame.kind}</span>
                </div>
                <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-[13px] leading-6 text-slate-200">
                  {frame.content}
                </pre>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-[22px] border border-white/10 bg-slate-950/70 p-4">
            <div className="eyebrow">Intel</div>
            <div className="mt-3 space-y-3 text-sm text-slate-300">
              <div>
                <div className="mb-1 text-slate-500">Usernames</div>
                <div>{session.indicators.usernames.join(", ") || "none"}</div>
              </div>
              <div>
                <div className="mb-1 text-slate-500">Commands</div>
                <div>{session.indicators.commands.join(" · ") || "none"}</div>
              </div>
              <div>
                <div className="mb-1 text-slate-500">Payload patterns</div>
                <div>{session.indicators.payloadPatterns.join(" · ") || "none"}</div>
              </div>
              <div>
                <div className="mb-1 text-slate-500">URLs</div>
                <div className="break-all">{session.indicators.urls.join(" · ") || "none"}</div>
              </div>
            </div>
          </div>

          <div className="rounded-[22px] border border-white/10 bg-slate-950/70 p-4">
            <div className="eyebrow">Response</div>
            <ul className="mt-3 space-y-2 text-sm text-slate-300">
              {session.responseActions.length > 0 ? (
                session.responseActions.map((action, index) => (
                  <li key={`${action}-${index}`} className="rounded-2xl border border-white/6 bg-white/[0.03] px-3 py-2">
                    {action}
                  </li>
                ))
              ) : (
                <li>No automated response yet.</li>
              )}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

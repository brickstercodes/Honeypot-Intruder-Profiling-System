import { useEffect, useRef, useState } from "react";

interface LiveEvent {
  type: string;
  ts: string;
  ip?: string;
  filename?: string;
  service?: string;
  severity?: string;
  message?: string;
}

const TYPE_STYLE: Record<string, string> = {
  connected:   "text-emerald-400",
  bait_file:   "text-amber-300",
  alert:       "text-red-300",
  session:     "text-sky-300",
  block:       "text-orange-300",
  default:     "text-slate-300",
};

const TYPE_LABEL: Record<string, string> = {
  connected:   "CONNECTED",
  bait_file:   "BAIT HIT",
  alert:       "ALERT",
  session:     "SESSION",
  block:       "BLOCKED",
};

export default function LiveFeed() {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const es = new EventSource("/api/live-events");

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    es.onmessage = (e) => {
      try {
        const ev: LiveEvent = JSON.parse(e.data);
        setEvents(prev => [...prev.slice(-199), ev]);
      } catch {}
    };

    return () => es.close();
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  const fmtTime = (iso: string) => {
    try { return new Date(iso).toLocaleTimeString(); } catch { return iso; }
  };

  return (
    <div className="panel flex flex-col" style={{ height: 340 }}>
      <div className="flex items-center justify-between mb-3">
        <div className="eyebrow">Live event feed</div>
        <div className="flex items-center gap-2">
          <div className={`status-dot ${connected ? "live" : "down"}`} />
          <span className="text-xs text-slate-500">{connected ? "streaming" : "reconnecting…"}</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto rounded-xl border border-white/6 bg-black/30 p-3 space-y-0.5">
        {events.length === 0 ? (
          <div className="flex items-center justify-center h-full text-sm text-slate-600">
            Waiting for events… trigger a decoy service or simulate
          </div>
        ) : events.map((ev, i) => (
          <div key={i} className="flex items-baseline gap-3 font-mono text-xs py-0.5 border-b border-white/[0.03] live-feed-row">
            <span className="text-slate-600 flex-shrink-0 tabular-nums">{fmtTime(ev.ts)}</span>
            <span className={`flex-shrink-0 w-20 ${TYPE_STYLE[ev.type] || TYPE_STYLE.default}`}>
              {TYPE_LABEL[ev.type] || ev.type.toUpperCase()}
            </span>
            <span className="text-slate-300 truncate">
              {ev.ip && <span className="text-white mr-2">{ev.ip}</span>}
              {ev.service && <span className="text-cyan-400 mr-2">{ev.service.toUpperCase()}</span>}
              {ev.filename && <span>→ {ev.filename}</span>}
              {ev.message && <span>{ev.message}</span>}
              {ev.severity && <span className={
                ev.severity === "critical" ? "text-red-400" :
                ev.severity === "high" ? "text-orange-400" :
                ev.severity === "medium" ? "text-amber-400" : "text-emerald-400"
              }> [{ev.severity}]</span>}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

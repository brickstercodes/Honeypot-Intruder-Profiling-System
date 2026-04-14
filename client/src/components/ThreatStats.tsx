import { trpc } from "@/lib/trpc";
import {
  BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, LineChart, Line, AreaChart, Area,
} from "recharts";
import { TrendingUp, Globe, Clock } from "lucide-react";

const THREAT_PALETTE = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#8b5cf6", "#10b981", "#06b6d4", "#ec4899"];

const Panel = ({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) => (
  <div className="bg-black/50 border border-red-950/40 rounded-lg">
    <div className="px-4 py-3 border-b border-red-950/40 flex items-center gap-2">
      <span className="text-red-400">{icon}</span>
      <h3 className="text-xs font-mono text-red-400 tracking-wider">{title}</h3>
    </div>
    <div className="p-4">{children}</div>
  </div>
);

export default function ThreatStats() {
  const { data: topIPs } = trpc.intrusions.topIPs.useQuery({ limit: 10 });
  const { data: topCountries } = trpc.intrusions.topCountries.useQuery({ limit: 8 });
  const { data: timeline7 } = trpc.intrusions.timeline.useQuery({ days: 7 });
  const { data: timeline30 } = trpc.intrusions.timeline.useQuery({ days: 30 });
  const { data: dist } = trpc.intrusions.threatDistribution.useQuery();
  const { data: count } = trpc.intrusions.count.useQuery();

  const ipData = topIPs?.map((i: any) => ({ name: i.ip, count: i.count })) || [];
  const countryData = topCountries?.map((c: any) => ({ name: c.country || "Unknown", value: c.count })) || [];
  const distData = dist ? [
    { name: "LOW", value: (dist as any).low ?? 0, fill: "#3b82f6" },
    { name: "MEDIUM", value: (dist as any).medium ?? 0, fill: "#eab308" },
    { name: "HIGH", value: (dist as any).high ?? 0, fill: "#f97316" },
    { name: "CRITICAL", value: (dist as any).critical ?? 0, fill: "#ef4444" },
  ] : [];

  const tooltipStyle = { backgroundColor: "#0a0a0a", border: "1px solid #450a0a", fontFamily: "monospace", fontSize: "11px" };

  return (
    <div className="space-y-4">
      {/* Threat Distribution */}
      <div className="grid grid-cols-4 gap-3">
        {distData.map((d) => (
          <div key={d.name} className="bg-black/50 border border-red-950/40 rounded-lg p-4 text-center">
            <p className="text-xs font-mono text-gray-600">{d.name}</p>
            <p className="text-3xl font-bold font-mono mt-1" style={{ color: d.fill }}>{d.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* 7-day timeline */}
        <Panel title="7-DAY INTRUSION TIMELINE" icon={<Clock className="w-3.5 h-3.5" />}>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timeline7 || []}>
              <defs>
                <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a0505" />
              <XAxis dataKey="date" tick={{ fill: "#4b5563", fontSize: 9, fontFamily: "monospace" }} />
              <YAxis tick={{ fill: "#4b5563", fontSize: 9, fontFamily: "monospace" }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="count" stroke="#ef4444" fill="url(#redGrad)" name="Intrusions" />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>

        {/* 30-day timeline */}
        <Panel title="30-DAY TREND" icon={<TrendingUp className="w-3.5 h-3.5" />}>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={timeline30 || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a0505" />
              <XAxis dataKey="date" tick={{ fill: "#4b5563", fontSize: 9, fontFamily: "monospace" }} />
              <YAxis tick={{ fill: "#4b5563", fontSize: 9, fontFamily: "monospace" }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Line type="monotone" dataKey="count" stroke="#f97316" dot={false} name="Intrusions" />
            </LineChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      {/* Top IPs */}
      <Panel title="TOP ATTACKING IPs" icon={<TrendingUp className="w-3.5 h-3.5" />}>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={ipData} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="#1a0505" horizontal={false} />
            <XAxis type="number" tick={{ fill: "#4b5563", fontSize: 9, fontFamily: "monospace" }} />
            <YAxis type="category" dataKey="name" tick={{ fill: "#9ca3af", fontSize: 10, fontFamily: "monospace" }} width={110} />
            <Tooltip contentStyle={tooltipStyle} />
            <Bar dataKey="count" fill="#ef4444" name="Hits" radius={[0, 3, 3, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Panel>

      {/* Top Countries */}
      <Panel title="ATTACK ORIGINS BY COUNTRY" icon={<Globe className="w-3.5 h-3.5" />}>
        <div className="flex items-center gap-8">
          <ResponsiveContainer width="50%" height={200}>
            <PieChart>
              <Pie data={countryData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={false}>
                {countryData.map((_, i) => (
                  <Cell key={i} fill={THREAT_PALETTE[i % THREAT_PALETTE.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex-1 space-y-2">
            {countryData.slice(0, 8).map((c, i) => (
              <div key={c.name} className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: THREAT_PALETTE[i % THREAT_PALETTE.length] }} />
                <span className="text-xs font-mono text-gray-400 flex-1 truncate">{c.name}</span>
                <span className="text-xs font-mono text-gray-500">{c.value}</span>
              </div>
            ))}
          </div>
        </div>
      </Panel>
    </div>
  );
}

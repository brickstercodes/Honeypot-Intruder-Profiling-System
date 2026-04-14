import { Eye, Bot, Wifi, Shield } from "lucide-react";

const THREAT_COLORS = {
  low: { text: "text-blue-400", bg: "bg-blue-950/40 border-blue-800/40" },
  medium: { text: "text-yellow-400", bg: "bg-yellow-950/30 border-yellow-800/40" },
  high: { text: "text-orange-400", bg: "bg-orange-950/40 border-orange-800/40" },
  critical: { text: "text-red-400", bg: "bg-red-950/50 border-red-700/50" },
};

export default function IntrusionTable({
  intrusions,
  isLoading,
  onSelectIntrusion,
}: {
  intrusions: any[];
  isLoading: boolean;
  onSelectIntrusion: (id: number) => void;
}) {
  if (isLoading) {
    return (
      <div className="animate-pulse space-y-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-12 bg-red-950/10 rounded" />
        ))}
      </div>
    );
  }

  if (intrusions.length === 0) {
    return (
      <div className="text-center py-12">
        <Shield className="w-10 h-10 text-gray-700 mx-auto mb-2" />
        <p className="font-mono text-xs text-gray-600">NO INTRUSIONS LOGGED</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b border-red-950/40 text-gray-600 text-left">
            <th className="py-2 pr-4">THREAT</th>
            <th className="py-2 pr-4">IP ADDRESS</th>
            <th className="py-2 pr-4">LOCATION</th>
            <th className="py-2 pr-4">ATTACK TYPE</th>
            <th className="py-2 pr-4">DEVICE</th>
            <th className="py-2 pr-4">FLAGS</th>
            <th className="py-2 pr-4">TIME</th>
            <th className="py-2">ACTIONS</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-red-950/20">
          {intrusions.map((entry: any) => {
            const level = (entry.threatLevel || "medium") as keyof typeof THREAT_COLORS;
            const c = THREAT_COLORS[level];
            return (
              <tr key={entry.id} className="hover:bg-white/5 transition-colors">
                <td className="py-2 pr-4">
                  <span className={`px-2 py-0.5 rounded text-xs border ${c.bg} ${c.text} uppercase tracking-wider`}>
                    {level}
                  </span>
                </td>
                <td className="py-2 pr-4 text-gray-200">{entry.ip}</td>
                <td className="py-2 pr-4 text-gray-400">
                  {entry.city ? `${entry.city}, ` : ""}{entry.country || "—"}
                </td>
                <td className="py-2 pr-4 text-gray-400 max-w-32 truncate">
                  {entry.attackType || "—"}
                </td>
                <td className="py-2 pr-4 text-gray-500">
                  {entry.deviceType || "—"} / {entry.osName || "—"}
                </td>
                <td className="py-2 pr-4">
                  <div className="flex gap-1">
                    {entry.isBot === 1 && <Bot className="w-3.5 h-3.5 text-purple-400" title="Bot" />}
                    {entry.isTor === 1 && <Wifi className="w-3.5 h-3.5 text-gray-400" title="Tor" />}
                    {entry.imageUrl && <Eye className="w-3.5 h-3.5 text-green-400" title="Camera captured" />}
                    {entry.blocked === 1 && <Shield className="w-3.5 h-3.5 text-red-400" title="Blocked" />}
                  </div>
                </td>
                <td className="py-2 pr-4 text-gray-600">
                  {entry.timestamp
                    ? new Date(entry.timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
                    : "—"}
                </td>
                <td className="py-2">
                  <button
                    onClick={() => onSelectIntrusion(entry.id)}
                    className="text-red-400 hover:text-red-300 border border-red-950 hover:border-red-800 px-2 py-0.5 rounded transition-colors"
                  >
                    VIEW
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

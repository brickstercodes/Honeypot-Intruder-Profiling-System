import { trpc } from "@/lib/trpc";
import { Shield, Globe, Monitor, Camera, Brain, Lock, Flag } from "lucide-react";

const THREAT_COLORS = {
  low: "text-blue-400 border-blue-800 bg-blue-950/30",
  medium: "text-yellow-400 border-yellow-800 bg-yellow-950/30",
  high: "text-orange-400 border-orange-800 bg-orange-950/30",
  critical: "text-red-400 border-red-700 bg-red-950/40",
};

export default function IntrusionDetail({ id }: { id: number }) {
  const { data: intrusion, isLoading } = trpc.intrusions.getById.useQuery({ id });
  const updateMutation = trpc.intrusions.update.useMutation();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-red-400 font-mono text-sm animate-pulse">LOADING INTEL...</div>
      </div>
    );
  }

  if (!intrusion) {
    return <div className="text-gray-600 font-mono text-sm p-4">RECORD NOT FOUND</div>;
  }

  const level = (intrusion.threatLevel || "medium") as keyof typeof THREAT_COLORS;
  const mitreTactics = intrusion.mitreTactics ? JSON.parse(intrusion.mitreTactics as string) : [];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className={`border rounded-lg p-4 ${THREAT_COLORS[level]}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6" />
            <div>
              <p className="font-mono font-bold text-lg">{intrusion.ip}</p>
              <p className="text-xs font-mono opacity-70">{intrusion.attackType || "Unknown Attack Type"}</p>
            </div>
          </div>
          <div className="text-right">
            <span className="text-xs font-mono uppercase tracking-widest px-3 py-1 rounded border opacity-80">
              {level} THREAT
            </span>
            {intrusion.confidenceScore && (
              <p className="text-xs font-mono mt-1 opacity-60">
                {Math.round(parseFloat(intrusion.confidenceScore as string) * 100)}% confidence
              </p>
            )}
          </div>
        </div>
        <p className="mt-3 text-sm font-mono opacity-80">{intrusion.threatSummary}</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Geo Intel */}
        <div className="bg-black/50 border border-red-950/40 rounded-lg p-4">
          <h3 className="text-xs font-mono text-red-400 tracking-wider mb-3 flex items-center gap-2">
            <Globe className="w-3.5 h-3.5" /> GEOGRAPHIC INTEL
          </h3>
          <div className="space-y-2">
            {[
              ["IP", intrusion.ip],
              ["Country", `${intrusion.countryCode ? `[${intrusion.countryCode}]` : ""} ${intrusion.country || "—"}`],
              ["Region", intrusion.region || "—"],
              ["City", intrusion.city || "—"],
              ["ISP", intrusion.isp || "—"],
              ["Organization", intrusion.org || "—"],
              ["ASN", intrusion.asn || "—"],
              ["Coordinates", intrusion.latitude && intrusion.longitude ? `${intrusion.latitude}, ${intrusion.longitude}` : "—"],
              ["Timezone", intrusion.timezone || "—"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between text-xs font-mono">
                <span className="text-gray-600">{k}</span>
                <span className="text-gray-300 max-w-48 text-right truncate">{v}</span>
              </div>
            ))}
          </div>
          {/* Network flags */}
          <div className="flex gap-2 mt-3 flex-wrap">
            {intrusion.isProxy === 1 && <span className="text-xs bg-yellow-950/60 text-yellow-400 px-2 py-0.5 rounded font-mono">PROXY</span>}
            {intrusion.isVpn === 1 && <span className="text-xs bg-blue-950/60 text-blue-400 px-2 py-0.5 rounded font-mono">VPN</span>}
            {intrusion.isTor === 1 && <span className="text-xs bg-gray-900 text-gray-400 px-2 py-0.5 rounded font-mono">TOR</span>}
            {intrusion.isBot === 1 && <span className="text-xs bg-purple-950/60 text-purple-400 px-2 py-0.5 rounded font-mono">BOT</span>}
            {intrusion.isDatacenter === 1 && <span className="text-xs bg-orange-950/60 text-orange-400 px-2 py-0.5 rounded font-mono">DATACENTER</span>}
          </div>
        </div>

        {/* Device Profile */}
        <div className="bg-black/50 border border-red-950/40 rounded-lg p-4">
          <h3 className="text-xs font-mono text-red-400 tracking-wider mb-3 flex items-center gap-2">
            <Monitor className="w-3.5 h-3.5" /> DEVICE PROFILE
          </h3>
          <div className="space-y-2">
            {[
              ["Device", intrusion.deviceType || "—"],
              ["OS", intrusion.osName || "—"],
              ["Browser", `${intrusion.browserName || "—"} ${intrusion.browserVersion || ""}`],
              ["Resolution", intrusion.screenResolution || "—"],
              ["Language", intrusion.language || "—"],
              ["Cookies", intrusion.cookiesEnabled === 1 ? "Enabled" : "Disabled"],
              ["Referrer", intrusion.referrer || "Direct"],
              ["Fingerprint", intrusion.browserFingerprint ? intrusion.browserFingerprint.slice(0, 12) + "..." : "—"],
              ["Timestamp", intrusion.timestamp ? new Date(intrusion.timestamp).toLocaleString() : "—"],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between text-xs font-mono">
                <span className="text-gray-600">{k}</span>
                <span className="text-gray-300 max-w-48 text-right truncate">{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Gemini AI Analysis */}
      <div className="bg-black/50 border border-purple-900/40 rounded-lg p-4">
        <h3 className="text-xs font-mono tracking-wider mb-3 flex items-center gap-2">
          <Brain className="w-3.5 h-3.5 text-purple-400" />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-400">GEMINI AI ANALYSIS</span>
        </h3>
        <div className="space-y-3">
          <div>
            <p className="text-xs font-mono text-gray-600 mb-1">THREAT SUMMARY</p>
            <p className="text-sm font-mono text-gray-300">{intrusion.threatSummary || "—"}</p>
          </div>
          <div>
            <p className="text-xs font-mono text-gray-600 mb-1">RECOMMENDED ACTIONS</p>
            <p className="text-sm font-mono text-gray-300">{intrusion.defensiveActions || "—"}</p>
          </div>
          {mitreTactics.length > 0 && (
            <div>
              <p className="text-xs font-mono text-gray-600 mb-2">MITRE ATT&CK TACTICS</p>
              <div className="flex flex-wrap gap-1.5">
                {mitreTactics.map((t: string) => (
                  <span key={t} className="text-xs bg-purple-950/60 text-purple-300 px-2 py-0.5 rounded font-mono border border-purple-900/40">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Webcam Image */}
      {intrusion.imageUrl && (
        <div className="bg-black/50 border border-green-900/40 rounded-lg p-4">
          <h3 className="text-xs font-mono text-green-400 tracking-wider mb-3 flex items-center gap-2">
            <Camera className="w-3.5 h-3.5" /> CAPTURED IMAGE
          </h3>
          <img
            src={intrusion.imageUrl}
            alt="Intruder capture"
            className="max-w-sm rounded border border-green-900/40"
          />
        </div>
      )}

      {/* User Agent Raw */}
      <div className="bg-black/50 border border-red-950/40 rounded-lg p-4">
        <h3 className="text-xs font-mono text-red-400 tracking-wider mb-2">RAW USER AGENT</h3>
        <p className="text-xs font-mono text-gray-500 break-all">{intrusion.userAgent || "—"}</p>
      </div>

      {/* Actions */}
      <div className="flex gap-2">
        <button
          onClick={() => updateMutation.mutate({ id, reviewed: 1 })}
          className="flex items-center gap-2 px-3 py-2 text-xs font-mono border border-green-900/60 text-green-400 rounded hover:bg-green-950/30 transition-colors"
        >
          ✓ MARK REVIEWED
        </button>
        <button
          onClick={() => updateMutation.mutate({ id, flagged: 1 })}
          className="flex items-center gap-2 px-3 py-2 text-xs font-mono border border-orange-900/60 text-orange-400 rounded hover:bg-orange-950/30 transition-colors"
        >
          <Flag className="w-3.5 h-3.5" /> FLAG
        </button>
      </div>
    </div>
  );
}

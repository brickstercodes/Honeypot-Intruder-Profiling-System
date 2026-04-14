import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Lock, Unlock, Plus, Trash2 } from "lucide-react";

export default function BlocklistPanel() {
  const [ipInput, setIpInput] = useState("");
  const [reasonInput, setReasonInput] = useState("");
  const { data: blocked, refetch } = trpc.blocklist.list.useQuery();
  const blockMutation = trpc.blocklist.block.useMutation({ onSuccess: () => refetch() });
  const unblockMutation = trpc.blocklist.unblock.useMutation({ onSuccess: () => refetch() });

  const handleBlock = async () => {
    if (!ipInput.trim()) return;
    await blockMutation.mutateAsync({ ip: ipInput.trim(), reason: reasonInput || undefined });
    setIpInput("");
    setReasonInput("");
  };

  return (
    <div className="space-y-4">
      {/* Add to blocklist */}
      <div className="bg-black/50 border border-red-950/40 rounded-lg p-4">
        <h2 className="text-sm font-mono text-red-400 tracking-wider mb-3 flex items-center gap-2">
          <Lock className="w-4 h-4" /> BLOCK IP ADDRESS
        </h2>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="192.168.1.1"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            className="flex-1 bg-black border border-red-950/60 rounded px-3 py-2 text-sm font-mono text-gray-300 placeholder-gray-700 focus:outline-none focus:border-red-700"
          />
          <input
            type="text"
            placeholder="Reason (optional)"
            value={reasonInput}
            onChange={(e) => setReasonInput(e.target.value)}
            className="flex-1 bg-black border border-red-950/60 rounded px-3 py-2 text-sm font-mono text-gray-300 placeholder-gray-700 focus:outline-none focus:border-red-700"
          />
          <button
            onClick={handleBlock}
            disabled={blockMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-red-900/60 border border-red-700/60 text-red-300 text-sm font-mono rounded hover:bg-red-900 transition-colors disabled:opacity-50"
          >
            <Plus className="w-4 h-4" /> BLOCK
          </button>
        </div>
      </div>

      {/* Blocked IPs list */}
      <div className="bg-black/50 border border-red-950/40 rounded-lg">
        <div className="px-4 py-3 border-b border-red-950/40">
          <h2 className="text-sm font-mono text-red-400 tracking-wider">
            BLOCKED IPs ({blocked?.length ?? 0})
          </h2>
        </div>
        <div className="divide-y divide-red-950/20">
          {!blocked || blocked.length === 0 ? (
            <div className="p-8 text-center">
              <Unlock className="w-8 h-8 text-gray-700 mx-auto mb-2" />
              <p className="text-xs font-mono text-gray-600">NO IPs BLOCKED</p>
            </div>
          ) : (
            blocked.map((entry: any) => (
              <div key={entry.id} className="flex items-center justify-between px-4 py-3 hover:bg-white/5">
                <div>
                  <p className="font-mono text-sm text-red-300">{entry.ip}</p>
                  {entry.reason && (
                    <p className="text-xs font-mono text-gray-600 mt-0.5">{entry.reason}</p>
                  )}
                  <p className="text-xs font-mono text-gray-700 mt-0.5">
                    {entry.blockedAt ? new Date(entry.blockedAt).toLocaleString() : ""}
                  </p>
                </div>
                <button
                  onClick={() => unblockMutation.mutate({ ip: entry.ip })}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono border border-gray-800 text-gray-500 rounded hover:border-gray-600 hover:text-gray-300 transition-colors"
                >
                  <Unlock className="w-3 h-3" /> UNBLOCK
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

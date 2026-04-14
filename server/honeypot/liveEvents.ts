/**
 * Live event broadcaster — patches honeypotEngine methods to emit SSE events.
 * Import this ONCE after engine is initialized (in index.ts boot).
 */

const clients = new Set<{ write: (d: string) => void; end: () => void }>();

export function addSseClient(res: { write: (d: string) => void; end: () => void }) {
  clients.add(res);
}

export function removeSseClient(res: { write: (d: string) => void; end: () => void }) {
  clients.delete(res);
}

export function broadcast(event: Record<string, unknown>) {
  const payload = `data: ${JSON.stringify({ ...event, ts: new Date().toISOString() })}\n\n`;
  for (const c of clients) {
    try { c.write(payload); } catch { clients.delete(c); }
  }
}
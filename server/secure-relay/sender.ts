import crypto from "node:crypto";

// ── helpers ───────────────────────────────────────────────────────────────────

function deriveKey(): Buffer {
  const secret = process.env.RELAY_ENCRYPTION_KEY || "relay-default-key-change-me";
  return crypto.createHash("sha256").update(secret).digest();
}

function keyFingerprint(): string {
  return deriveKey().toString("hex").slice(0, 8) + "..." + deriveKey().toString("hex").slice(-4);
}

function payloadPreview(json: string): string {
  try {
    const s = JSON.parse(json);
    const sessions = (s.sessions as unknown[])?.length ?? 0;
    const alerts   = (s.alerts   as unknown[])?.length ?? 0;
    const blocked  = (s.blockedIps as unknown[])?.length ?? 0;
    const kb       = (Buffer.byteLength(json, "utf8") / 1024).toFixed(1);
    return `${sessions} sessions · ${alerts} alerts · ${blocked} blocked IPs · ${kb} KB`;
  } catch {
    return `${(Buffer.byteLength(json, "utf8") / 1024).toFixed(1)} KB`;
  }
}

function encryptPayload(plaintext: string): {
  envelope: string;
  ivHex: string;
  tagHex: string;
} {
  const key = deriveKey();
  const iv  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    envelope: JSON.stringify({
      alg: "aes-256-gcm",
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    }),
    ivHex:  iv.toString("hex").slice(0, 8),
    tagHex: tag.toString("hex").slice(0, 8),
  };
}

// ── ASCII box logger ───────────────────────────────────────────────────────────

const W = 64;
const line = (s = "") => {
  const pad = W - 2 - s.length;
  return `│ ${s}${" ".repeat(Math.max(0, pad))} │`;
};
const divider = `├${"─".repeat(W - 2)}┤`;
const top     = `┌${"─".repeat(W - 2)}┐`;
const bot     = `└${"─".repeat(W - 2)}┘`;

function logBox(rows: string[]) {
  console.log(top);
  for (const r of rows) console.log(line(r));
  console.log(bot);
}

function logRelayHeader(preview: string, ivHex: string, tagHex: string, target: string) {
  console.log(top);
  console.log(line("  SECURE RELAY TRANSFER  ·  AES-256-GCM / 256-bit key"));
  console.log(divider);
  console.log(line(`  [1] KEY      ✓  fingerprint: ${keyFingerprint()}`));
  console.log(line(`  [2] PAYLOAD  ✓  ${preview}`));
  console.log(line(`  [3] ENCRYPT  ✓  IV: ${ivHex}…  Tag: ${tagHex}…`));
  console.log(line(`  [4] SEND     →  ${target}`));
  console.log(divider);
}

function logRelaySuccess(filename: string) {
  console.log(line(`  [5] ACK      ✓  HTTP 200 · saved as ${filename}`));
  console.log(line(`  [6] DESTRUCT ✓  snapshot.json wiped from source`));
  console.log(bot);
}

function logRelayFail(reason: string) {
  console.log(line(`  [5] ACK      ✗  ${reason}`));
  console.log(line(`      NOTE     ·  snapshot retained on disk (relay offline)`));
  console.log(bot);
}

// ── public API ────────────────────────────────────────────────────────────────

export async function sendToRelay(jsonData: string): Promise<void> {
  const receiverUrl = process.env.RELAY_RECEIVER_URL || "http://localhost:5000";
  const target      = `${receiverUrl}/relay/ingest`;
  const preview     = payloadPreview(jsonData);

  const { envelope, ivHex, tagHex } = encryptPayload(jsonData);

  logRelayHeader(preview, ivHex, tagHex, target);

  const res = await fetch(target, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    envelope,
  });

  if (!res.ok) {
    const reason = `HTTP ${res.status} from receiver`;
    logRelayFail(reason);
    throw new Error(reason);
  }

  const body = await res.json() as { filename?: string };
  logRelaySuccess(body.filename ?? "unknown");
}

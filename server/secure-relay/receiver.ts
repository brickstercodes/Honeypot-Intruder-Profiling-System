import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";

const RECEIVER_PORT = parseInt(process.env.RELAY_RECEIVER_PORT || "5000", 10);
const receivedDir = path.resolve(import.meta.dirname, "../../data/relay-received");

function deriveKey(): Buffer {
  const secret = process.env.RELAY_ENCRYPTION_KEY || "relay-default-key-change-me";
  return crypto.createHash("sha256").update(secret).digest();
}

function decryptPayload(envelope: {
  alg: string;
  iv: string;
  tag: string;
  ciphertext: string;
}): string {
  if (envelope.alg !== "aes-256-gcm") throw new Error("Unsupported cipher");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    deriveKey(),
    Buffer.from(envelope.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

const app = express();
app.use(express.json({ limit: "10mb" }));
app.disable("x-powered-by");

// Receive encrypted snapshot, decrypt, persist
app.post("/relay/ingest", (req, res) => {
  try {
    const decrypted = decryptPayload(req.body as { alg: string; iv: string; tag: string; ciphertext: string });
    const parsed = JSON.parse(decrypted);

    fs.mkdirSync(receivedDir, { recursive: true });
    const filename = `snapshot-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    fs.writeFileSync(path.join(receivedDir, filename), JSON.stringify(parsed, null, 2), "utf8");

    const kb = (Buffer.byteLength(JSON.stringify(parsed), "utf8") / 1024).toFixed(1);
    console.log(`[relay-receiver] ✓ decrypted · saved: ${filename} (${kb} KB)`);
    res.json({ ok: true, filename });
  } catch (err) {
    console.error("[relay-receiver] failed to decrypt/save", err);
    res.status(400).json({ ok: false, error: "Decryption failed" });
  }
});

// List all received snapshots
app.get("/relay/status", (_req, res) => {
  const files = fs.existsSync(receivedDir)
    ? fs.readdirSync(receivedDir).filter((f) => f.endsWith(".json"))
    : [];
  res.json({ ok: true, received: files.length, files });
});

// Serve a received snapshot by filename
app.get("/relay/data/:filename", (req, res) => {
  const safe = path.basename(req.params.filename);
  const filepath = path.join(receivedDir, safe);
  if (!fs.existsSync(filepath)) {
    res.status(404).json({ ok: false, error: "Not found" });
    return;
  }
  res.json(JSON.parse(fs.readFileSync(filepath, "utf8")));
});

export function startRelayReceiver() {
  app.listen(RECEIVER_PORT, () => {
    console.log(`  relay receiver →  http://localhost:${RECEIVER_PORT}  (AES-256-GCM secure channel)`);
  });
}

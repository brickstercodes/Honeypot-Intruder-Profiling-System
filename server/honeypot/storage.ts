import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type {
  AlertRecord,
  AttackSession,
  EvidenceEnvelope,
  HoneypotEvent,
  ServiceStatus,
} from "@shared/honeypot";
import { honeypotConfig } from "./config";
import { sendToRelay } from "../secure-relay/sender";

export interface PersistedState {
  sessions: AttackSession[];
  events: HoneypotEvent[];
  alerts: AlertRecord[];
  blockedIps: string[];
  services: ServiceStatus[];
  lastHash: string;
}

const dataRoot = path.resolve(import.meta.dirname, "../..", "data");
const evidenceDir = path.join(dataRoot, "evidence");
const snapshotPath = path.join(dataRoot, "snapshot.json");
const evidenceLogPath = path.join(evidenceDir, "forensic-chain.jsonl");

const ensureDirs = () => {
  fs.mkdirSync(evidenceDir, { recursive: true });
};

const defaultState = (): PersistedState => ({
  sessions: [],
  events: [],
  alerts: [],
  blockedIps: [],
  services: [],
  lastHash: "GENESIS",
});

const deriveEvidenceKey = () =>
  crypto.createHash("sha256").update(honeypotConfig.evidenceEncryptionKey).digest();

const encryptEvidenceLine = (plaintext: string) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveEvidenceKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    alg: "aes-256-gcm",
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
};

export function decryptEvidenceLine(encrypted: {
  alg: string;
  iv: string;
  tag: string;
  ciphertext: string;
}) {
  if (encrypted.alg !== "aes-256-gcm") {
    throw new Error("Unsupported evidence cipher");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    deriveEvidenceKey(),
    Buffer.from(encrypted.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(encrypted.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

export function loadState(): PersistedState {
  ensureDirs();

  if (!fs.existsSync(snapshotPath)) {
    return defaultState();
  }

  try {
    const raw = fs.readFileSync(snapshotPath, "utf8");
    const parsed = JSON.parse(raw) as PersistedState;
    return {
      ...defaultState(),
      ...parsed,
    };
  } catch (error) {
    console.warn("[Storage] Snapshot load failed, starting fresh", error);
    return defaultState();
  }
}

export function saveState(state: PersistedState) {
  ensureDirs();
  fs.writeFileSync(snapshotPath, JSON.stringify(state, null, 2), "utf8");

  if (honeypotConfig.relayEnabled) {
    const payload = JSON.stringify(state, null, 2);
    sendToRelay(payload)
      .then(() => {
        fs.rmSync(snapshotPath, { force: true });
        console.log("[relay] snapshot sent & self-destructed");
      })
      .catch((err) => {
        console.error("[relay] send failed — snapshot kept on disk:", err);
      });
  }
}

export function appendEvidence<T>(
  state: PersistedState,
  kind: EvidenceEnvelope<T>["kind"],
  payload: T
) {
  ensureDirs();
  const timestamp = new Date().toISOString();
  const prevHash = state.lastHash || "GENESIS";
  const base = JSON.stringify({ kind, timestamp, prevHash, payload });
  const hash = crypto.createHash("sha256").update(base).digest("hex");
  const envelope: EvidenceEnvelope<T> = {
    kind,
    timestamp,
    prevHash,
    hash,
    payload,
  };

  const encrypted = encryptEvidenceLine(JSON.stringify(envelope));
  fs.appendFileSync(
    evidenceLogPath,
    `${JSON.stringify({ version: 1, ...encrypted, hash })}\n`,
    "utf8"
  );
  state.lastHash = hash;
}

export function getForensicPaths() {
  return {
    dataRoot,
    evidenceLogPath,
    snapshotPath,
  };
}

import crypto from "node:crypto";
import type {
  AttackSession,
  ClassificationLabel,
  HoneypotService,
  SeverityLevel,
  ThreatIntel,
  ThreatSignal,
} from "@shared/honeypot";

export interface DetectionContext {
  recentSessionsFromIp: AttackSession[];
  uniqueServicesFromIp: HoneypotService[];
  recentConnectionBurst: number;
}

type SignatureRule = {
  id: string;
  label: string;
  regex: RegExp;
  weight: number;
  classification: ClassificationLabel;
  detail: string;
};

const signatureRules: SignatureRule[] = [
  {
    id: "sig-nmap",
    label: "Scanner tool detected",
    regex: /\b(nmap|masscan|zmap|nikto|gobuster|dirbuster)\b/i,
    weight: 24,
    classification: "reconnaissance",
    detail: "Classic recon tooling present in payload or user agent.",
  },
  {
    id: "sig-web-probe",
    label: "Web probe payload",
    regex: /(\.\.\/|\/etc\/passwd|wp-admin|phpmyadmin|\.env|select.+from|union.+select|or\s+1=1)/i,
    weight: 22,
    classification: "web_probe",
    detail: "Directory traversal, SQLi, or admin panel probing pattern seen.",
  },
  {
    id: "sig-malware-fetch",
    label: "Malware fetch pattern",
    regex: /\b(wget|curl|Invoke-WebRequest|bitsadmin|certutil)\b.+(http|https)/i,
    weight: 28,
    classification: "malware_drop_attempt",
    detail: "Downloader behavior indicates payload staging or malware fetch attempt.",
  },
  {
    id: "sig-shell-abuse",
    label: "Shell execution payload",
    regex: /(bash\s+-i|nc\s+-e|powershell|cmd\.exe|chmod\s+\+x|\/bin\/sh)/i,
    weight: 26,
    classification: "privilege_escalation_attempt",
    detail: "Command execution payload suggests post-compromise activity.",
  },
  {
    id: "sig-bot-agent",
    label: "Bot-like user agent",
    regex: /\b(bot|crawler|spider|python-requests|curl|go-http-client|libwww-perl)\b/i,
    weight: 16,
    classification: "bot_activity",
    detail: "User agent maps to automation or scripted client behavior.",
  },
  {
    id: "sig-admin-guess",
    label: "Common credential guessing",
    regex: /\b(root|admin|test|oracle|postgres|mysql|ubnt|support)\b/i,
    weight: 10,
    classification: "brute_force",
    detail: "High-risk username or credential stuffing keyword detected.",
  },
];

const severityFromScore = (score: number): SeverityLevel => {
  if (score >= 85) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
};

const unique = (items: string[]) => Array.from(new Set(items.filter(Boolean)));

const extractWithRegex = (input: string, regex: RegExp) => {
  const results = new Set<string>();
  const flags = regex.flags.includes("g") ? regex.flags : `${regex.flags}g`;
  const pattern = new RegExp(regex.source, flags);
  let match: RegExpExecArray | null = pattern.exec(input);

  while (match) {
    if (match[1]) results.add(match[1]);
    else if (match[0]) results.add(match[0]);
    match = pattern.exec(input);
  }
  return Array.from(results);
};

export const extractThreatIntel = (session: Pick<
  AttackSession,
  "attackerIp" | "commands" | "payloads" | "requestedPaths" | "usernameAttempts"
>): ThreatIntel => {
  const corpus = [
    session.attackerIp,
    ...session.commands,
    ...session.payloads,
    ...session.requestedPaths,
    ...session.usernameAttempts,
  ].join("\n");

  const ips = unique([
    session.attackerIp,
    ...extractWithRegex(corpus, /\b((?:\d{1,3}\.){3}\d{1,3})\b/g),
  ]);
  const usernames = unique([
    ...session.usernameAttempts,
    ...extractWithRegex(corpus, /\b(user|username|login|USER)\s*[:=]?\s*([a-z0-9._-]{2,32})/gi)
      .map((value) => value.split(/[:=\s]+/).pop() || value),
  ]);
  const urls = unique(
    extractWithRegex(corpus, /\b(https?:\/\/[^\s'"]+)/gi)
  );
  const commands = unique(
    extractWithRegex(
      corpus,
      /\b(?:wget|curl|chmod|bash|sh|python|powershell|nmap|masscan|nc|telnet|ftp)\b[^\n]*/gi
    )
  );
  const payloadPatterns = unique(
    extractWithRegex(
      corpus,
      /(\.\.\/|\/etc\/passwd|union\s+select|<script|cmd\.exe|powershell|bash\s+-i|wget\s+http[^\s]*)/gi
    )
  );

  const hashes = unique(
    commands
      .concat(payloadPatterns)
      .filter(Boolean)
      .map((value) => crypto.createHash("sha256").update(value).digest("hex"))
  );

  return { ips, usernames, urls, commands, payloadPatterns, hashes };
};

export interface DetectionOutcome {
  signals: ThreatSignal[];
  classification: ClassificationLabel;
  severityScore: number;
  severity: SeverityLevel;
  correlationNotes: string[];
}

export function evaluateSession(
  session: AttackSession,
  context: DetectionContext
): DetectionOutcome {
  const corpus = [
    ...session.usernameAttempts,
    ...session.passwordAttempts,
    ...session.commands,
    ...session.payloads,
    ...session.requestedPaths,
    ...session.transcript.map((frame) => frame.content),
  ].join("\n");

  const signals: ThreatSignal[] = [];
  const correlationNotes: string[] = [];
  const classWeights = new Map<ClassificationLabel, number>();

  for (const rule of signatureRules) {
    if (!rule.regex.test(corpus)) continue;
    signals.push({
      id: rule.id,
      kind: "signature",
      label: rule.label,
      detail: rule.detail,
      weight: rule.weight,
    });
    classWeights.set(
      rule.classification,
      (classWeights.get(rule.classification) || 0) + rule.weight
    );
  }

  if (session.failureCount >= 4) {
    signals.push({
      id: "anom-retries",
      kind: "anomaly",
      label: "Repeated authentication failures",
      detail: `${session.failureCount} failed logins seen in the same session.`,
      weight: 18,
    });
    classWeights.set(
      "brute_force",
      (classWeights.get("brute_force") || 0) + 18
    );
  }

  if (context.recentConnectionBurst >= 6) {
    signals.push({
      id: "anom-burst",
      kind: "anomaly",
      label: "Burst connection behavior",
      detail: `${context.recentConnectionBurst} connections from the same IP inside the short correlation window.`,
      weight: 16,
    });
    classWeights.set(
      "bot_activity",
      (classWeights.get("bot_activity") || 0) + 16
    );
  }

  if (context.uniqueServicesFromIp.length >= 3) {
    signals.push({
      id: "corr-multi-service",
      kind: "correlation",
      label: "Cross-service correlation",
      detail: `Same IP touched ${context.uniqueServicesFromIp.length} decoy services.`,
      weight: 20,
    });
    classWeights.set(
      "reconnaissance",
      (classWeights.get("reconnaissance") || 0) + 20
    );
    correlationNotes.push(
      `IP moved across ${context.uniqueServicesFromIp.join(", ")} within the active window.`
    );
  }

  if (session.commands.length >= 4) {
    signals.push({
      id: "anom-command-volume",
      kind: "anomaly",
      label: "Unexpected command volume",
      detail: `${session.commands.length} commands captured from one session.`,
      weight: 12,
    });
  }

  if (session.payloads.some((payload) => payload.length > 256)) {
    signals.push({
      id: "anom-large-payload",
      kind: "anomaly",
      label: "Large payload submission",
      detail: "Oversized request body or command payload indicates exploit staging.",
      weight: 14,
    });
  }

  const chosenClassification =
    Array.from(classWeights.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ||
    "unknown";

  let severityScore =
    signals.reduce((sum, signal) => sum + signal.weight, 8) +
    Math.min(session.commands.length * 3, 12) +
    Math.min(session.payloads.length * 4, 20);

  if (session.geo.source === "remote") severityScore += 4;
  if (session.status === "terminated") severityScore += 6;

  if (chosenClassification === "malware_drop_attempt") severityScore += 14;
  if (chosenClassification === "privilege_escalation_attempt") severityScore += 12;
  if (chosenClassification === "credential_stuffing") severityScore += 10;

  severityScore = Math.min(severityScore, 99);

  return {
    signals,
    classification: chosenClassification,
    severityScore,
    severity: severityFromScore(severityScore),
    correlationNotes,
  };
}

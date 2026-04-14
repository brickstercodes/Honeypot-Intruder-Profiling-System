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
    regex: /\b(nmap|masscan|zmap|nikto|gobuster|dirbuster|ffuf|wfuzz|feroxbuster|dirb)\b/i,
    weight: 24,
    classification: "reconnaissance",
    detail: "Classic recon tooling present in payload or user agent.",
  },
  {
    id: "sig-web-probe",
    label: "Web probe payload",
    regex: /(\.\.\/|\/etc\/passwd|wp-admin|phpmyadmin|\.env|select.+from|union.+select|or\s+1=1|<script|onerror=|javascript:void)/i,
    weight: 22,
    classification: "web_probe",
    detail: "Directory traversal, SQLi, XSS, or admin panel probing pattern seen.",
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
    regex: /(bash\s+-i|nc\s+-e|powershell|cmd\.exe|chmod\s+\+x|\/bin\/sh|\/bin\/bash|mkfifo|2>&1\s*\/dev\/null)/i,
    weight: 26,
    classification: "privilege_escalation_attempt",
    detail: "Command execution payload suggests post-compromise activity.",
  },
  {
    id: "sig-bot-framework",
    label: "Automated attack framework",
    // Specific known attack/scanning automation tools — not generic CLI tools
    regex: /\b(python-requests|go-http-client|libwww-perl|zgrab|nuclei|sqlmap|hydra|medusa|acunetix|wpscan|dirhunt|masscan|httpclient|okhttp|java\/|apache-httpclient)\b/i,
    weight: 20,
    classification: "bot_activity",
    detail: "Known attack automation framework or headless scanner identified in user agent.",
  },
  {
    id: "sig-headless-browser",
    label: "Headless browser fingerprint",
    regex: /\b(headlesschrome|phantomjs|puppeteer|playwright|selenium|webdriver|chrome-lighthouse)\b/i,
    weight: 18,
    classification: "bot_activity",
    detail: "Headless browser or WebDriver automation detected — likely scripted credential harvesting.",
  },
  {
    id: "sig-crawler-ua",
    label: "Generic crawler / bot agent",
    // Generic bot UAs — lower weight than framework-specific ones
    regex: /\b(bot|crawler|spider|scrapy|wget\/|curl\/\d)\b/i,
    weight: 12,
    classification: "bot_activity",
    detail: "Generic bot or crawler user agent without specific attack tool fingerprint.",
  },
  {
    id: "sig-path-enum",
    label: "Automated path enumeration",
    regex: /(\/api\/v\d|\/admin\/|\/\.git\/|\/\.svn\/|\/backup|\/config\.php|\/secret|\/\.env\b|\/passwd|\/shadow|\/etc\/|\/proc\/self)/i,
    weight: 14,
    classification: "web_probe",
    detail: "Sequential sensitive-path probing indicates automated directory or file enumeration.",
  },
  {
    id: "sig-admin-guess",
    label: "Common credential guessing",
    regex: /\b(root|admin|test|oracle|postgres|mysql|ubnt|support|administrator|backup|service|guest|operator)\b/i,
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

  // Anomaly: repeated auth failures
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
  } else if (session.failureCount >= 2) {
    // Moderate failure count — weaker brute-force signal
    signals.push({
      id: "anom-retries-soft",
      kind: "anomaly",
      label: "Multiple authentication failures",
      detail: `${session.failureCount} failed logins — possible credential probing.`,
      weight: 8,
    });
    classWeights.set(
      "brute_force",
      (classWeights.get("brute_force") || 0) + 8
    );
  }

  // Anomaly: connection burst (lowered threshold from 6 → 4 for sensitivity)
  if (context.recentConnectionBurst >= 6) {
    signals.push({
      id: "anom-burst",
      kind: "anomaly",
      label: "High-frequency connection burst",
      detail: `${context.recentConnectionBurst} connections from the same IP in the short correlation window — scanner or bot activity.`,
      weight: 18,
    });
    classWeights.set(
      "bot_activity",
      (classWeights.get("bot_activity") || 0) + 18
    );
  } else if (context.recentConnectionBurst >= 4) {
    signals.push({
      id: "anom-burst-soft",
      kind: "anomaly",
      label: "Elevated connection frequency",
      detail: `${context.recentConnectionBurst} connections from the same IP — possible automated probing.`,
      weight: 10,
    });
    classWeights.set(
      "bot_activity",
      (classWeights.get("bot_activity") || 0) + 10
    );
  }

  // Anomaly: multi-service correlation
  if (context.uniqueServicesFromIp.length >= 3) {
    signals.push({
      id: "corr-multi-service",
      kind: "correlation",
      label: "Cross-service scan correlation",
      detail: `Same IP touched ${context.uniqueServicesFromIp.length} decoy services — systematic network sweep.`,
      weight: 22,
    });
    classWeights.set(
      "reconnaissance",
      (classWeights.get("reconnaissance") || 0) + 22
    );
    correlationNotes.push(
      `IP swept across ${context.uniqueServicesFromIp.join(", ")} within the active window — consistent with automated port/service enumeration.`
    );
  } else if (context.uniqueServicesFromIp.length === 2) {
    signals.push({
      id: "corr-dual-service",
      kind: "correlation",
      label: "Dual-service probe",
      detail: `IP touched ${context.uniqueServicesFromIp.join(" and ")} — probing multiple attack surfaces.`,
      weight: 10,
    });
    classWeights.set(
      "reconnaissance",
      (classWeights.get("reconnaissance") || 0) + 10
    );
    correlationNotes.push(
      `IP accessed ${context.uniqueServicesFromIp.join(" and ")} — may indicate targeted lateral movement.`
    );
  }

  // Anomaly: high command volume
  if (session.commands.length >= 4) {
    signals.push({
      id: "anom-command-volume",
      kind: "anomaly",
      label: "Unexpected command volume",
      detail: `${session.commands.length} commands captured — active post-access exploration.`,
      weight: 12,
    });
  }

  // Anomaly: large payload (potential exploit staging)
  if (session.payloads.some((payload) => payload.length > 256)) {
    signals.push({
      id: "anom-large-payload",
      kind: "anomaly",
      label: "Oversized payload submission",
      detail: "Request body exceeds typical human input — likely automated exploit staging.",
      weight: 14,
    });
    classWeights.set(
      "malware_drop_attempt",
      (classWeights.get("malware_drop_attempt") || 0) + 8
    );
  }

  // Anomaly: many unique paths requested (path enumeration not caught by sig)
  if (session.requestedPaths.length >= 5) {
    const uniquePaths = new Set(session.requestedPaths).size;
    if (uniquePaths >= 5) {
      signals.push({
        id: "anom-path-sweep",
        kind: "anomaly",
        label: "Broad path sweep",
        detail: `${uniquePaths} distinct paths probed — systematic content discovery.`,
        weight: 12,
      });
      classWeights.set(
        "web_probe",
        (classWeights.get("web_probe") || 0) + 12
      );
    }
  }

  // ── Smart classification fallback ─────────────────────────────────────────
  // Instead of blindly returning "unknown", use context signals to make an
  // educated classification guess when no hard signatures fire.
  let chosenClassification: ClassificationLabel;

  if (classWeights.size > 0) {
    // We have weighted signals — pick the highest
    chosenClassification = Array.from(classWeights.entries())
      .sort((a, b) => b[1] - a[1])[0][0];
  } else if (context.uniqueServicesFromIp.length >= 2) {
    // Multi-service touch with no signatures → quiet reconnaissance sweep
    chosenClassification = "reconnaissance";
    correlationNotes.push(
      "No payload signatures matched but IP accessed multiple decoy services — passive or low-noise reconnaissance likely."
    );
  } else if (session.requestedPaths.length >= 3) {
    // Several paths requested with no signatures → silent path discovery
    chosenClassification = "web_probe";
  } else if (context.recentConnectionBurst >= 4) {
    // Burst connections but no other signals → automated probing with no payload
    chosenClassification = "bot_activity";
  } else if (session.failureCount >= 2) {
    // Some auth failures but below anomaly threshold → low-grade credential probing
    chosenClassification = "brute_force";
  } else {
    // Truly no observable signals — session connected but did nothing notable
    chosenClassification = "unknown";
  }

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

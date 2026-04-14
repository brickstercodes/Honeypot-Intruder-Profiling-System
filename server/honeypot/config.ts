import type { HoneypotService, IsolationProfile } from "@shared/honeypot";

export interface ServiceDefinition {
  service: HoneypotService;
  port: number;
  enabled: boolean;
  banner: string;
}

export interface HoneypotConfig {
  appPort: number;
  adminPassword: string;
  sessionCookieName: string;
  sessionCookieSecret: string;
  evidenceEncryptionKey: string;
  trapPreviewPath: string;
  autoBlockThreshold: number;
  terminateHighRisk: boolean;
  snapshotLimit: number;
  publicBaseUrl: string;
  geoIpEnabled: boolean;
  relayEnabled: boolean;
  relayReceiverUrl: string;
  alerting: {
    dashboard: boolean;
    discordWebhookUrl?: string;
    telegramBotToken?: string;
    telegramChatId?: string;
    resendApiKey?: string;
    alertEmailTo?: string;
    alertEmailFrom?: string;
  };
  isolation: IsolationProfile;
  services: ServiceDefinition[];
}

const parseNumber = (value: string | undefined, fallback: number) => {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const parseBoolean = (value: string | undefined, fallback: boolean) => {
  if (value === undefined) return fallback;
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
};

const serviceDefaults: Record<HoneypotService, { port: number; banner: string }> = {
  ssh: { port: 2222, banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" },
  ftp: { port: 2121, banner: "220 ProFTPD 1.3.7a Server ready." },
  telnet: { port: 2323, banner: "Ubuntu 22.04 LTS" },
  http: { port: 8081, banner: "nginx/1.22.1" },
  database: { port: 33060, banner: "5.7.43-log MySQL Community Server" },
};

const makeService = (service: HoneypotService): ServiceDefinition => ({
  service,
  port: parseNumber(
    process.env[`DECOY_${service.toUpperCase()}_PORT`],
    serviceDefaults[service].port
  ),
  enabled: parseBoolean(
    process.env[`DECOY_${service.toUpperCase()}_ENABLED`],
    true
  ),
  banner: process.env[`DECOY_${service.toUpperCase()}_BANNER`] || serviceDefaults[service].banner,
});

export const honeypotConfig: HoneypotConfig = {
  appPort: parseNumber(process.env.PORT, 3000),
  adminPassword: process.env.ADMIN_PASSWORD || "change-me-now",
  sessionCookieName: process.env.ADMIN_COOKIE_NAME || "hp_admin_session",
  sessionCookieSecret: process.env.ADMIN_COOKIE_SECRET || "honeypot-local-secret",
  evidenceEncryptionKey:
    process.env.EVIDENCE_ENCRYPTION_KEY || process.env.ADMIN_COOKIE_SECRET || "honeypot-local-secret",
  trapPreviewPath: process.env.TRAP_PREVIEW_PATH || "/trap",
  autoBlockThreshold: parseNumber(process.env.AUTO_BLOCK_THRESHOLD, 55),
  terminateHighRisk: parseBoolean(process.env.TERMINATE_HIGH_RISK, true),
  snapshotLimit: parseNumber(process.env.SNAPSHOT_LIMIT, 120),
  publicBaseUrl: process.env.PUBLIC_BASE_URL || "http://localhost:3000",
  geoIpEnabled: parseBoolean(process.env.GEOIP_ENABLED, true),
  relayEnabled: parseBoolean(process.env.RELAY_ENABLED, false),
  relayReceiverUrl: process.env.RELAY_RECEIVER_URL || "http://localhost:5000",
  alerting: {
    dashboard: true,
    discordWebhookUrl: process.env.DISCORD_WEBHOOK_URL,
    telegramBotToken: process.env.TELEGRAM_BOT_TOKEN,
    telegramChatId: process.env.TELEGRAM_CHAT_ID,
    resendApiKey: process.env.RESEND_API_KEY,
    alertEmailTo: process.env.ALERT_EMAIL_TO,
    alertEmailFrom: process.env.ALERT_EMAIL_FROM,
  },
  isolation: {
    mode:
      (process.env.ISOLATION_MODE as IsolationProfile["mode"] | undefined) ||
      "container",
    notes: [
      process.env.ISOLATION_NOTE_1 ||
        "Run in Docker, VM, or a segmented lab VLAN. Do not expose decoy ports from a production workstation.",
      process.env.ISOLATION_NOTE_2 ||
        "Only forward decoy ports you want to study. Keep the admin console private to localhost or VPN.",
      process.env.ISOLATION_NOTE_3 ||
        "Use NAT or an internal lab network so captured attackers cannot pivot through the host.",
    ],
  },
  services: (["ssh", "ftp", "telnet", "http", "database"] as HoneypotService[]).map(
    makeService
  ),
};

export const getServiceDefinition = (service: HoneypotService) =>
  honeypotConfig.services.find((entry) => entry.service === service);

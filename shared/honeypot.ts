export type HoneypotService =
  | "ssh"
  | "ftp"
  | "telnet"
  | "http"
  | "database";

export type SeverityLevel = "low" | "medium" | "high" | "critical";

export type ClassificationLabel =
  | "reconnaissance"
  | "brute_force"
  | "web_probe"
  | "malware_drop_attempt"
  | "bot_activity"
  | "privilege_escalation_attempt"
  | "credential_stuffing"
  | "lateral_movement"
  | "unknown";

export type SignalKind = "signature" | "anomaly" | "correlation";

export type EventCategory =
  | "connection_opened"
  | "connection_closed"
  | "login_attempt"
  | "command"
  | "payload"
  | "scan"
  | "alert"
  | "response_action"
  | "web_request"
  | "correlation";

export interface GeoProfile {
  country: string;
  countryCode: string;
  city: string;
  region: string;
  asn: string;
  org: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  source: "local" | "remote" | "offline";
}

export interface ThreatSignal {
  id: string;
  kind: SignalKind;
  label: string;
  detail: string;
  weight: number;
}

export interface ThreatIntel {
  ips: string[];
  usernames: string[];
  urls: string[];
  commands: string[];
  payloadPatterns: string[];
  hashes: string[];
}

export interface SessionFrame {
  id: string;
  at: string;
  direction: "in" | "out" | "meta";
  kind: "banner" | "auth" | "command" | "payload" | "http" | "system";
  content: string;
}

export interface HoneypotEvent {
  id: string;
  sessionId: string;
  timestamp: string;
  attackerIp: string;
  service: HoneypotService;
  destinationPort: number;
  category: EventCategory;
  summary: string;
  severity: SeverityLevel;
  details?: string;
  signalIds: string[];
}

export interface AttackSession {
  id: string;
  attackerIp: string;
  sourcePort: number;
  service: HoneypotService;
  destinationPort: number;
  protocol: "tcp" | "http";
  startedAt: string;
  endedAt?: string;
  lastActivityAt: string;
  durationMs: number;
  status: "active" | "closed" | "terminated";
  classification: ClassificationLabel;
  severity: SeverityLevel;
  severityScore: number;
  usernameAttempts: string[];
  passwordAttempts: string[];
  commands: string[];
  payloads: string[];
  requestedPaths: string[];
  responseActions: string[];
  transcript: SessionFrame[];
  threatSignals: ThreatSignal[];
  indicators: ThreatIntel;
  geo: GeoProfile;
  asnProfile: string;
  alertIds: string[];
  correlationNotes: string[];
  failureCount: number;
}

export interface AlertRecord {
  id: string;
  createdAt: string;
  sessionId: string;
  attackerIp: string;
  service: HoneypotService;
  severity: SeverityLevel;
  title: string;
  message: string;
  classification: ClassificationLabel;
  channels: string[];
  delivered: string[];
}

export interface AttackerProfile {
  ip: string;
  geo: GeoProfile;
  firstSeen: string;
  lastSeen: string;
  sessionCount: number;
  eventCount: number;
  alertCount: number;
  totalSeverityScore: number;
  preferredService: HoneypotService;
  services: Record<HoneypotService, number>;
  classifications: Record<ClassificationLabel, number>;
  topUsernames: string[];
  behaviorPatterns: string[];
}

export interface ServiceStatus {
  service: HoneypotService;
  port: number;
  enabled: boolean;
  listening: boolean;
  activeConnections: number;
  totalConnections: number;
  banner: string;
}

export interface IsolationProfile {
  mode: "container" | "vm" | "segmented-lab" | "process";
  notes: string[];
}

export interface TimelinePoint {
  bucket: string;
  count: number;
}

export interface DistributionPoint {
  label: string;
  value: number;
}

export interface CorrelationRecord {
  id: string;
  attackerIp: string;
  createdAt: string;
  stages: string[];
  severity: SeverityLevel;
}

export interface DashboardMetrics {
  totalSessions: number;
  activeSessions: number;
  totalEvents: number;
  totalAlerts: number;
  blockedIps: number;
  uniqueAttackers: number;
  averageSeverityScore: number;
}

export interface DashboardSnapshot {
  capturedAt: string;
  metrics: DashboardMetrics;
  services: ServiceStatus[];
  recentSessions: AttackSession[];
  alerts: AlertRecord[];
  attackers: AttackerProfile[];
  events: HoneypotEvent[];
  correlation: CorrelationRecord[];
  blockedIps: string[];
  analytics: {
    timeline: TimelinePoint[];
    topPorts: DistributionPoint[];
    serviceDistribution: DistributionPoint[];
    failedLoginsByHour: TimelinePoint[];
    severityDistribution: DistributionPoint[];
    classificationDistribution: DistributionPoint[];
  };
  isolation: IsolationProfile;
}

export interface EvidenceEnvelope<T> {
  kind: "event" | "session" | "alert";
  timestamp: string;
  prevHash: string;
  hash: string;
  payload: T;
}

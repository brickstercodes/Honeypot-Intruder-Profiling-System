import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { appRouter } from "../routers";
import { honeypotConfig } from "../honeypot/config";
import { honeypotEngine } from "../honeypot/engine";
import { addSseClient, removeSseClient, broadcast } from "../honeypot/liveEvents";
import { createContext, signAdminToken } from "./context";
import { serveStatic, setupVite } from "./vite";
import { startRelayReceiver } from "../secure-relay/receiver";

// ── Inline forensic report ─────────────────────────────────────────────────
function generateForensicReport(): string {
  const snap = honeypotEngine.getSnapshot();
  const now = new Date().toLocaleString();
  const C: Record<string,string> = { critical:"#ef4444", high:"#f97316", medium:"#f59e0b", low:"#10b981" };
  const badge = (s: string) =>
    `<span style="display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:600;text-transform:uppercase;background:${C[s]||"#64748b"}22;color:${C[s]||"#64748b"};border:1px solid ${C[s]||"#64748b"}44">${s}</span>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<title>HoneyIDS Report — ${now}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI",system-ui,sans-serif;background:#f8fafc;color:#1e293b;padding:40px 24px}
h1{font-size:24px;font-weight:700;margin-bottom:4px}
.sub{font-size:12px;color:#64748b;margin-bottom:28px}
.sec{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:20px;margin-bottom:16px}
.sec h2{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:#64748b;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #f1f5f9}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px}
.box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px}
.box .k{font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.1em;margin-bottom:3px}
.box .v{font-size:26px;font-weight:700;line-height:1}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:7px 10px;background:#f8fafc;color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.08em;border-bottom:2px solid #e2e8f0}
td{padding:8px 10px;border-bottom:1px solid #f1f5f9;vertical-align:middle}
.mono{font-family:monospace;font-size:11px}
.foot{text-align:center;font-size:11px;color:#94a3b8;margin-top:24px}
@media print{button{display:none}}
</style></head><body>
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
  <h1>🛡 HoneyIDS Forensic Report</h1>
  <button onclick="window.print()" style="padding:7px 14px;border-radius:8px;border:1px solid #e2e8f0;background:#fff;cursor:pointer;font-size:12px">Print / PDF</button>
</div>
<div class="sub">Generated: ${now} · Isolation: ${snap.isolation.mode} · SHA-256 evidence chain</div>

<div class="sec"><h2>Summary</h2><div class="grid">
  ${[["Sessions",snap.metrics.totalSessions],["Active",snap.metrics.activeSessions],["Alerts",snap.metrics.totalAlerts],["Unique IPs",snap.metrics.uniqueAttackers],["Blocked",snap.metrics.blockedIps],["Events",snap.metrics.totalEvents],["Avg Score",snap.metrics.averageSeverityScore]]
    .map(([k,v])=>`<div class="box"><div class="k">${k}</div><div class="v">${v}</div></div>`).join("")}
</div></div>

<div class="sec"><h2>Sessions (last 50)</h2>
${snap.recentSessions.length===0?'<p style="color:#94a3b8;font-size:13px">None yet.</p>':`
<table><thead><tr><th>IP</th><th>Service</th><th>Severity</th><th>Location</th><th>Classification</th><th>Usernames</th><th>Started</th></tr></thead><tbody>
${snap.recentSessions.slice(0,50).map(s=>`<tr>
  <td class="mono">${s.attackerIp}</td><td>${s.service.toUpperCase()}</td><td>${badge(s.severity)}</td>
  <td>${s.geo.city}, ${s.geo.country}</td><td>${s.classification.replace(/_/g," ")}</td>
  <td class="mono">${s.usernameAttempts.slice(0,3).join(", ")||"—"}</td>
  <td>${new Date(s.startedAt).toLocaleString()}</td>
</tr>`).join("")}
</tbody></table>`}</div>

<div class="sec"><h2>Alerts (last 30)</h2>
${snap.alerts.length===0?'<p style="color:#94a3b8;font-size:13px">None yet.</p>':`
<table><thead><tr><th>Severity</th><th>Service</th><th>IP</th><th>Title</th><th>Channels</th><th>Time</th></tr></thead><tbody>
${snap.alerts.slice(0,30).map(a=>`<tr>
  <td>${badge(a.severity)}</td><td>${a.service.toUpperCase()}</td><td class="mono">${a.attackerIp}</td>
  <td>${a.title}</td><td>${a.channels.join(", ")}</td><td>${new Date(a.createdAt).toLocaleString()}</td>
</tr>`).join("")}
</tbody></table>`}</div>

<div class="sec"><h2>Attacker Profiles</h2>
${snap.attackers.length===0?'<p style="color:#94a3b8;font-size:13px">None yet.</p>':`
<table><thead><tr><th>IP</th><th>Country</th><th>ASN</th><th>Sessions</th><th>Alerts</th><th>Preferred</th><th>Top Usernames</th></tr></thead><tbody>
${snap.attackers.map(a=>`<tr>
  <td class="mono">${a.ip}</td><td>${a.geo.country}</td><td>${a.geo.asn}</td>
  <td>${a.sessionCount}</td><td>${a.alertCount}</td><td>${a.preferredService}</td>
  <td class="mono">${a.topUsernames.slice(0,3).join(", ")||"—"}</td>
</tr>`).join("")}
</tbody></table>`}</div>

<div class="sec"><h2>Decoy Services</h2>
<table><thead><tr><th>Service</th><th>Port</th><th>Status</th><th>Active</th><th>Total</th></tr></thead><tbody>
${snap.services.map(s=>`<tr>
  <td>${s.service.toUpperCase()}</td><td class="mono">${s.port}</td>
  <td style="color:${s.listening?"#10b981":"#ef4444"}">${s.listening?"Armed":"Down"}</td>
  <td>${s.activeConnections}</td><td>${s.totalConnections}</td>
</tr>`).join("")}
</tbody></table></div>

<div class="sec"><h2>Blocked IPs</h2>
${snap.blockedIps.length===0?'<p style="color:#94a3b8;font-size:13px">None.</p>':
  snap.blockedIps.map(ip=>`<span class="mono" style="display:inline-block;margin:3px;padding:2px 10px;background:#fee2e2;color:#dc2626;border:1px solid #fca5a5;border-radius:999px">${ip}</span>`).join("")}
</div>

<div class="foot">HoneyIDS · Tamper-evident SHA-256 forensic chain active</div>
</body></html>`;
}

// ── Cookie parser ──────────────────────────────────────────────────────────
const parseCookies = (req: express.Request, _res: express.Response, next: express.NextFunction) => {
  const c: Record<string,string> = {};
  for (const p of (req.headers.cookie||"").split(";")) {
    const [k,...v] = p.trim().split("=");
    if (k) c[k] = decodeURIComponent(v.join("=").trim());
  }
  (req as express.Request & { cookies: Record<string,string> }).cookies = c;
  next();
};

const isPortFree = (p: number) => new Promise<boolean>(r => {
  const s = net.createServer();
  s.listen(p, () => s.close(() => r(true)));
  s.on("error", () => r(false));
});

const findPort = async (start = 3000) => {
  for (let p = start; p < start+20; p++) if (await isPortFree(p)) return p;
  throw new Error("No free port");
};

// ── Monkey-patch engine to emit live SSE events ────────────────────────────
function patchEngine() {
  const eng = honeypotEngine as unknown as Record<string, unknown>;

  // Patch: finalizeSession → broadcast session_closed
  const origFinalize = (eng["finalizeSession"] as Function).bind(honeypotEngine);
  eng["finalizeSession"] = function(sessionId: string) {
    origFinalize(sessionId);
    const snap = honeypotEngine.getSnapshot();
    const sess = snap.recentSessions.find(s => s.id === sessionId);
    if (sess) {
      broadcast({
        type: "session",
        ip: sess.attackerIp,
        service: sess.service,
        severity: sess.severity,
        message: `${sess.classification.replace(/_/g," ")} · score ${sess.severityScore}`,
      });
    }
  };

  // Patch: blockIp → broadcast block event
  const origBlock = (eng["blockIp"] as Function).bind(honeypotEngine);
  eng["blockIp"] = function(ip: string, reason?: string) {
    origBlock(ip, reason);
    broadcast({ type: "block", ip, message: reason || "blocked" });
  };
}

// ── Boot ───────────────────────────────────────────────────────────────────
async function startServer() {
  const app = express();
  const server = createServer(app);

  app.disable("x-powered-by");
  app.set("trust proxy", true);
  // Suppress stale Manus analytics requests (leftover in cached dist)
  app.use((req, res, next) => {
    if (req.url && req.url.includes('VITE_ANALYTICS')) {
      res.status(204).end();
      return;
    }
    next();
  });


  app.use(express.json({ limit: "2mb" }));
  app.use(express.urlencoded({ extended: true, limit: "2mb" }));
  app.use(parseCookies);

  // Auth
  app.post(["/api/auth/login","/api/local-login"], (req, res) => {
    if (String(req.body?.password||"") !== honeypotConfig.adminPassword) {
      res.status(401).json({ success:false, error:"Invalid password" });
      return;
    }
    res.cookie(honeypotConfig.sessionCookieName, signAdminToken(honeypotConfig.adminPassword), {
      httpOnly:true, sameSite:"lax", secure:false, path:"/", maxAge:604800000,
    });
    res.json({ success:true });
  });

  app.post(["/api/auth/logout","/api/local-logout"], (_req, res) => {
    res.clearCookie(honeypotConfig.sessionCookieName, { httpOnly:true, sameSite:"lax", path:"/" });
    res.json({ success:true });
  });

  // OSM tile proxy
  app.get("/api/osm-tile/:z/:x/:y.png", async (req, res) => {
    const { z, x, y } = req.params;
    try {
      const up = await fetch(`https://tile.openstreetmap.org/${z}/${x}/${y}.png`,
        { headers: { "User-Agent":"HoneypotIDS/1.0 (educational)" } });
      if (!up.ok) { res.status(up.status).end(); return; }
      res.set("Content-Type","image/png").set("Cache-Control","public, max-age=86400");
      res.send(Buffer.from(await up.arrayBuffer()));
    } catch { res.status(502).end(); }
  });

  // Forensic report
  app.get("/api/forensic-report", (_req, res) => {
    try {
      res.set("Content-Type","text/html");
      res.set("Content-Disposition",`attachment; filename="honeypot-report-${new Date().toISOString().slice(0,10)}.html"`);
      res.send(generateForensicReport());
    } catch { res.status(500).send("Report generation failed"); }
  });

  // SSE live feed
  app.get("/api/live-events", (req, res) => {
    res.set({ "Content-Type":"text/event-stream", "Cache-Control":"no-cache", "Connection":"keep-alive" });
    res.flushHeaders();
    res.write(`data: ${JSON.stringify({ type:"connected", ts:new Date().toISOString() })}\n\n`);
    addSseClient(res);
    req.on("close", () => removeSseClient(res));
  });

  // Bait files — log access + broadcast live
  app.get("/files/:filename", (req, res) => {
    const { filename } = req.params;
    const ip = (req.ip||"").replace(/^::ffff:/,"");
    console.log(`[bait] ${ip} → ${filename}`);
    broadcast({ type:"bait_file", ip, filename });
    if (filename.endsWith(".pdf")) {
      res.type("application/pdf").send(Buffer.from("%PDF-1.4 bait"));
    } else if (filename.endsWith(".txt")) {
      res.type("text/plain").send("admin:Password123!\nroot:toor\nbackup:backup2024\nguest:guest123");
    } else {
      res.type("application/octet-stream").send("BAIT_FILE");
    }
  });

  // Trap preview & HTTP decoy
  app.use(honeypotConfig.trapPreviewPath, honeypotEngine.createTrapRouter());

  // tRPC
  app.use("/api/trpc", createExpressMiddleware({ router: appRouter, createContext }));

  // Start decoy services then patch engine for live events
  await honeypotEngine.start();
  patchEngine();

  if (honeypotConfig.relayEnabled) {
    startRelayReceiver();
  }

  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  const port = await findPort(honeypotConfig.appPort);
  server.listen(port, () => {
    const httpPort = honeypotConfig.services.find(s => s.service==="http")?.port || 8081;
    console.log(`\n  admin console  →  http://localhost:${port}`);
    console.log(`  honey trap     →  http://localhost:${httpPort}  ← visit this / share for live hits`);
    console.log(`  trap preview   →  http://localhost:${port}${honeypotConfig.trapPreviewPath}`);
    console.log(`  forensic rpt   →  http://localhost:${port}/api/forensic-report`);
    console.log(`  live feed SSE  →  http://localhost:${port}/api/live-events`);
    console.log(`  tcp decoys     →  ${honeypotConfig.services.filter(s=>s.service!=="http").map(s=>`${s.service}:${s.port}`).join(", ")}\n`);
  });
}

startServer().catch(e => { console.error("[boot] failed", e); process.exitCode = 1; });
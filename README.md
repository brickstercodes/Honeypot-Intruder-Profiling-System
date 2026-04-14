# HoneyIDS — Honeypot Intrusion Detection & Prevention System

A full-stack honeypot IDS built for network security education and demonstration. Deploys decoy services, captures attacker behaviour in real time, and securely relays forensic data to a remote device using AES-256-GCM encryption with automatic source self-destruction.

---

## Features

- **Decoy services** — SSH, FTP, Telnet, HTTP, Database (TCP + HTTP listeners)
- **Real-time detection** — signature rules + anomaly scoring + SIEM-style cross-service correlation
- **Session capture** — credentials, commands, payloads, HTTP requests, browser fingerprints
- **GeoIP profiling** — country, city, ASN, org per attacker IP
- **Severity scoring** — 0–100 numeric scale → low / medium / high / critical
- **Attack classification** — 9 categories (brute force, recon, web probe, malware drop, bot, etc.)
- **Alerting** — dashboard, Discord webhook, Telegram bot, email (Resend)
- **Forensic storage** — tamper-evident SHA-256 hash chain, AES-256-GCM encrypted at rest
- **Secure relay** — snapshot encrypted with AES-256-GCM and sent to a 3rd device; source self-destructs on success
- **Response actions** — block IP, terminate session, auto-block at configurable severity threshold
- **Admin dashboard** — charts, world map, live SSE feed, attacker profiles, forensic report export
- **GitHub-clone decoy trap** — realistic fake login page for HTTP honeypot

---

## Quick Start

```bash
cp .env.example .env
# Set ADMIN_PASSWORD in .env
npm install
npm run dev
```

| Endpoint | URL |
|---|---|
| Admin console | `http://localhost:3000` |
| Trap preview | `http://localhost:3000/trap` |
| HTTP decoy | `http://localhost:8081` |
| TCP decoys | `2222` (SSH) · `2121` (FTP) · `2323` (Telnet) · `33060` (DB) |

---

## Secure Relay (3-Device Setup)

Enable encrypted transfer of forensic snapshots to a separate receiver device.

**Device 1 — Honeypot server** (`.env`):
```
RELAY_ENABLED=true
RELAY_RECEIVER_URL=http://<device3-ip>:5000
RELAY_ENCRYPTION_KEY=your-256-bit-secret
```

**Device 3 — Receiver** (`.env`):
```
RELAY_ENCRYPTION_KEY=your-256-bit-secret
RELAY_RECEIVER_PORT=5000
```
Run receiver: `npx tsx server/secure-relay/receiver.ts`

**Flow:** attacker hits trap → engine logs session → `saveState` encrypts snapshot (AES-256-GCM) → POSTs to receiver → on HTTP 200, `snapshot.json` is deleted from source.

Receiver endpoints:
- `GET /relay/status` — list received snapshots
- `GET /relay/data/:filename` — read a snapshot

---

## Simulate Attacks

```bash
npm run simulate
# or from the dashboard → "Simulate attacks"
```

Manual:
```bash
telnet localhost 2323
ftp localhost 2121
curl http://localhost:8081/wp-admin
nc localhost 33060
```

---

## Docker

```bash
docker compose up --build
```

Data persists in `./data/`. The `data/` directory is git-ignored — only generated at runtime.

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `ADMIN_PASSWORD` | Admin console password | `change-me-now` |
| `ADMIN_COOKIE_SECRET` | Session signing secret | — |
| `PORT` | Admin UI port | `3000` |
| `AUTO_BLOCK_THRESHOLD` | Severity score to auto-block | `82` |
| `EVIDENCE_ENCRYPTION_KEY` | AES key for forensic chain | falls back to cookie secret |
| `RELAY_ENABLED` | Enable secure relay | `false` |
| `RELAY_RECEIVER_URL` | Receiver device URL | `http://localhost:5000` |
| `RELAY_ENCRYPTION_KEY` | Shared AES key for relay | — |
| `RELAY_RECEIVER_PORT` | Port for receiver server | `5000` |
| `DISCORD_WEBHOOK_URL` | Discord alerts | — |
| `TELEGRAM_BOT_TOKEN` | Telegram alerts | — |
| `TELEGRAM_CHAT_ID` | Telegram chat ID | — |
| `RESEND_API_KEY` | Email alerts via Resend | — |

See `.env.example` for full list.

---

## Project Structure

```
server/
  honeypot/        # Core engine, detection, alerts, storage, config
  secure-relay/    # AES-256-GCM relay sender + receiver
  _core/           # Express server, auth, tRPC context
  routers.ts       # tRPC API endpoints
  db.ts            # Drizzle ORM + MySQL
client/src/
  pages/           # Dashboard, Login, Trap (decoy preview)
  components/      # Charts, world map, live feed, UI primitives
shared/            # Shared TypeScript types
drizzle/           # DB schema + migrations
data/              # Runtime only (git-ignored): snapshots, evidence, relay
```

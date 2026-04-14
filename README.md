# HoneyIDS

> Honeypot-based Intrusion Detection & Prevention System with AES-256-GCM encrypted secure relay

A full-stack network honeypot built for cybersecurity education and demonstration. It deploys realistic decoy services, captures attacker behaviour in real time, classifies threats automatically, and ships forensic evidence to a separate device over an encrypted channel — destroying the source copy once delivery is confirmed.

---

## How It Works

```
  Attacker (Device 2)
       │
       │  TCP / HTTP
       ▼
  Decoy Services ──► Detection Engine ──► Severity Score
  SSH  · FTP                               │
  Telnet · HTTP                            ▼
  Database                          score ≥ 55 → auto-block IP
       │                                   │
       ▼                                   ▼
  Session Capture                   Forensic Chain (JSONL)
  credentials · commands            AES-256-GCM encrypted
  payloads · fingerprints           SHA-256 hash-linked
       │
       ▼ (RELAY_ENABLED=true)
  AES-256-GCM encrypt snapshot
       │
       ▼  HTTP POST  (up to 2 retries)
  Relay Receiver (Device 3) ──► save snapshot ──► ACK
       │
       ▼
  snapshot.json self-destructs on source
```

---

## Features

| Category | Details |
|---|---|
| **Decoy services** | SSH `:2222`, FTP `:2121`, Telnet `:2323`, HTTP `:8081`, Database `:33060` |
| **HTTP trap** | GitHub-clone login page — captures credentials, browser fingerprint, public IP |
| **Detection** | 9 signature rules + 6 anomaly checks + SIEM-style cross-service correlation |
| **Classification** | 9 attack categories with smart context-aware fallback (no blind "unknown") |
| **Bot detection** | Separates attack frameworks (nuclei, hydra, sqlmap) from headless browsers from generic crawlers |
| **Severity scoring** | 0–100 numeric scale → `low` / `medium` / `high` / `critical` |
| **GeoIP profiling** | Country, city, ASN, org per attacker IP |
| **Auto-blocking** | IP auto-blocked at severity ≥ 55; manual block/unblock from dashboard |
| **Forensic chain** | Tamper-evident SHA-256 hash chain, each entry AES-256-GCM encrypted at rest |
| **Forensic viewer** | Dashboard tab that decrypts and displays live chain entries with integrity check |
| **Secure relay** | AES-256-GCM encrypted snapshot transfer to 3rd device; auto-retry (×2); self-destructs on ACK |
| **Alerting** | Dashboard live feed, Discord webhook, Telegram bot, email (Resend) |
| **Admin dashboard** | Charts, world map, session inspector, attacker profiles, exportable HTML report |

---

## Quick Start

**Prerequisites:** Node.js 20+, pnpm

```bash
# 1. Clone and install
git clone <repo-url>
cd honeypot-project
pnpm install

# 2. Configure
cp .env.example .env
# Edit .env — at minimum set ADMIN_PASSWORD

# 3. Run
pnpm dev
```

| URL | Purpose |
|---|---|
| `http://localhost:3000` | Admin console (login required) |
| `http://localhost:3000/trap` | HTTP decoy preview |
| `http://localhost:8081` | Live HTTP honeypot — share this URL |
| `localhost:2222` | SSH decoy |
| `localhost:2121` | FTP decoy |
| `localhost:2323` | Telnet decoy |
| `localhost:33060` | Database decoy |

---

## Simulate Attacks

Instantly generate synthetic attack sessions without any external tools:

```bash
# From the terminal
pnpm simulate

# Or click "Simulate attacks" in the admin dashboard
```

Manual probing (to demo blocking behaviour):

```bash
telnet localhost 2323
ftp localhost 2121
curl http://localhost:8081/wp-admin
curl http://localhost:8081/.env
nc localhost 33060
```

Each connection raises the session severity score. At score ≥ 55 the IP is automatically blocked from all decoy ports.

---

## Secure Relay — 3-Device Setup

Transfer encrypted forensic snapshots to a physically separate receiver device.

**Device 1 — Honeypot** (`.env`):
```env
RELAY_ENABLED=true
RELAY_RECEIVER_URL=http://<device3-ip>:5000
RELAY_ENCRYPTION_KEY=your-shared-secret
```

**Device 3 — Receiver** (`.env`):
```env
RELAY_ENCRYPTION_KEY=your-shared-secret   # must match Device 1
RELAY_RECEIVER_PORT=5000
```

Start the receiver on Device 3:
```bash
npx tsx server/secure-relay/receiver.ts
```

**What happens on each `saveState()` call:**

```
[1] KEY      256-bit AES key derived via SHA-256(RELAY_ENCRYPTION_KEY)
[2] PAYLOAD  snapshot serialised to JSON
[3] ENCRYPT  AES-256-GCM  ·  random 12-byte IV  ·  16-byte auth tag
[4] SEND     POST /relay/ingest  (retry ×2 on failure, delays 1s / 2s)
[5] ACK      HTTP 200 from receiver — snapshot saved remotely
[6] DESTRUCT snapshot.json deleted from source
```

If all retries fail, `snapshot.json` is kept on disk until the relay comes back online — no data loss.

**Receiver API:**

| Method | Path | Description |
|---|---|---|
| `GET` | `/relay/status` | List all received snapshot files |
| `GET` | `/relay/data/:filename` | Read a specific snapshot |

---

## Forensic Chain

Every security event (session start/end, alert fired, IP blocked) is written as an encrypted entry to `data/evidence/forensic-chain.jsonl`.

Each entry contains:
- `kind` — event type
- `timestamp` — ISO 8601
- `prevHash` — SHA-256 of the previous entry
- `hash` — SHA-256 of this entry's content including `prevHash`
- `payload` — AES-256-GCM encrypted event data

Modifying or deleting any past entry breaks all subsequent hash links, making tampering detectable. The **Forensics tab** in the admin dashboard decrypts and displays the live chain with per-entry integrity verification.

---

## Environment Variables

### Core

| Variable | Description | Default |
|---|---|---|
| `ADMIN_PASSWORD` | Admin console password | `change-me-now` |
| `ADMIN_COOKIE_SECRET` | Session cookie signing key | `honeypot-local-secret` |
| `PORT` | Admin UI port | `3000` |
| `AUTO_BLOCK_THRESHOLD` | Severity score that triggers auto-block | `55` |
| `EVIDENCE_ENCRYPTION_KEY` | AES-256 key for forensic chain | falls back to cookie secret |
| `PUBLIC_BASE_URL` | Canonical URL of the honeypot | `http://localhost:3000` |
| `GEOIP_ENABLED` | Enable IP geolocation lookups | `true` |

### Relay

| Variable | Description | Default |
|---|---|---|
| `RELAY_ENABLED` | Enable encrypted relay to Device 3 | `false` |
| `RELAY_RECEIVER_URL` | Full URL of the receiver server | `http://localhost:5000` |
| `RELAY_ENCRYPTION_KEY` | Shared AES key (must match on both devices) | — |
| `RELAY_RECEIVER_PORT` | Port the receiver listens on | `5000` |

### Decoy Ports (optional overrides)

| Variable | Default |
|---|---|
| `DECOY_SSH_PORT` | `2222` |
| `DECOY_FTP_PORT` | `2121` |
| `DECOY_TELNET_PORT` | `2323` |
| `DECOY_HTTP_PORT` | `8081` |
| `DECOY_DATABASE_PORT` | `33060` |

### Alerting (all optional)

| Variable | Description |
|---|---|
| `DISCORD_WEBHOOK_URL` | Post alerts to a Discord channel |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token |
| `TELEGRAM_CHAT_ID` | Telegram chat/group ID |
| `RESEND_API_KEY` | Email alerts via Resend |
| `ALERT_EMAIL_TO` | Recipient email address |
| `ALERT_EMAIL_FROM` | Sender email address |

---

## Docker

```bash
docker compose up --build
```

Runtime data (`data/`) is mounted as a volume and git-ignored — snapshots, evidence, and relay files persist across restarts but are never committed.

---

## Project Structure

```
honeypot-project/
├── server/
│   ├── honeypot/          # Engine, detection, alerts, storage, config
│   ├── secure-relay/      # AES-256-GCM relay sender & receiver
│   ├── _core/             # Express boot, auth, tRPC context
│   └── routers.ts         # tRPC API routes
├── client/src/
│   ├── pages/             # Dashboard, Login, Home
│   └── components/        # Charts, world map, live feed, UI
├── shared/                # Shared TypeScript types (honeypot.ts)
├── data/                  # Runtime only — git-ignored
│   ├── snapshot.json      # Current in-memory state (self-destructs on relay)
│   ├── evidence/          # forensic-chain.jsonl (encrypted)
│   └── relay-received/    # Snapshots received by Device 3
├── .env.example
├── docker-compose.yml
└── IMPLEMENTATION.md      # Academic implementation report
```

---

## Security Notes

- Run inside Docker, a VM, or a segmented lab VLAN — never expose decoy ports from a production machine
- Set strong, unique values for `ADMIN_PASSWORD`, `ADMIN_COOKIE_SECRET`, `EVIDENCE_ENCRYPTION_KEY`, and `RELAY_ENCRYPTION_KEY` before deployment
- The admin console (`:3000`) should stay behind a firewall or VPN; only the decoy ports should be internet-facing
- `RELAY_ENCRYPTION_KEY` must be identical on Device 1 and Device 3 — treat it like a pre-shared key

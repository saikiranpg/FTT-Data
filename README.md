# FTT Data

**End-to-end encrypted file & text transfer between devices.** No accounts, nothing to install.

Paste text or pick a file (up to 500 MB) on one device. Then scan the QR code or type a short code
like `K7QM3F-9XTR-2PWD` on the other device. Encryption happens in the browser with AES-256-GCM, so
the server only stores ciphertext. It never sees a key, a code, a filename or any plaintext, and each
drop is deleted when its timer (3 min to 1 h) runs out, or right after it's read once if you choose
burn-after-reading.

- [Quick start (your computer)](#quick-start-your-computer)
- [Deployment](#deployment): server setup, HTTPS options, verification, operations, troubleshooting
- [How it works](#how-it-works) · [Security model](#security-model) · [Content safety](#content-safety)
- [Configuration](#configuration) · [API](#api) · [Development & tests](#development--tests)

---

## Quick start (your computer)

Requires [Docker Desktop](https://docs.docker.com/get-docker/) (or Docker Engine with Compose v2).

```bash
git clone https://github.com/SaikiranNalla/FTT-File-Text-Transfer.git
```

```bash
cd FTT-File-Text-Transfer && docker compose up -d --build
```

Open <http://localhost:8000>. To try it from your phone, give it a temporary HTTPS address with a
[Cloudflare quick tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/).
This requires `cloudflared` installed on your computer:

```bash
cloudflared tunnel --url http://localhost:8000
```

> **Why HTTPS matters:** browsers only provide the Web Crypto API on HTTPS pages (and on
> `localhost`). Opened as `http://192.168.x.x:8000` from a phone, the app shows a red
> "Encryption isn't available" banner and refuses to send or receive.

---

## Deployment

FTT Data runs as two containers: the app and Redis. Docker Compose behaves the same on any Linux
server, so the deployment is the same everywhere. The only part that varies is **how HTTPS reaches
the app**, which step 3 covers.

```
Browser ──HTTPS──▶ HTTPS front end ──HTTP──▶ app :8000 ──▶ Redis (metadata + TTL, memory only)
                   Caddy / Cloudflare Tunnel /       └──▶ /tmp/drops volume (encrypted chunks)
                   Tailscale / your own proxy
```

### Requirements

| | Minimum |
|---|---|
| Server | Any 64-bit Linux host (x86-64 or ARM64): a VPS (DigitalOcean, Hetzner, AWS EC2/Lightsail, GCP, Azure…), a home server, a NAS or a Raspberry Pi 4/5 |
| CPU / RAM | 1 vCPU, 1 GB RAM (the app and Redis use about 150 MB at idle) |
| Disk | `DISK_CAP_BYTES` (5 GB by default) plus about 2 GB for images |
| Software | Docker Engine 24+ with the Compose v2 plugin, and git |
| HTTPS | One of: a domain name, a Cloudflare account, or Tailscale (see step 3) |

### Step 1: Prepare the server

Install Docker Engine and the Compose plugin by following
[Docker's guide for your distribution](https://docs.docker.com/engine/install/). On a fresh
Ubuntu or Debian test box, Docker's convenience script is the quickest way:

```bash
curl -fsSL https://get.docker.com | sudo sh
```

```bash
sudo systemctl enable --now docker && sudo usermod -aG docker "$USER"
```

Log out and back in so the group change applies, then confirm `docker compose version` prints
v2.x. Docker restarts the containers after a reboot, because they use `restart: unless-stopped`.

**Firewall:** allow only SSH, plus 80/443 if you use option A. The app's own port is bound to
`127.0.0.1`, so it is never exposed directly. Note that Docker-published ports bypass `ufw` rules.

```bash
sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443 && sudo ufw enable
```

### Step 2: Get the code and create `.env`

```bash
git clone https://github.com/SaikiranNalla/FTT-File-Text-Transfer.git
```

```bash
cd FTT-File-Text-Transfer && cp .env.example .env
```

Every setting in `.env` is optional and documented inline. Never commit `.env`, because it may hold
a tunnel token; it is already in `.gitignore`.

### Step 3: Choose how HTTPS reaches the app

| Your situation | Use | Open ports | You need |
|---|---|---|---|
| Server with a public IP | **A. Caddy** (auto Let's Encrypt) | 80, 443 | A domain whose DNS you control |
| Behind NAT / no public IP (home server, Pi, NAS) | **B. Cloudflare Tunnel** | none | A domain on Cloudflare (free plan is fine) |
| Only your own devices | **C. Tailscale** | none | Tailscale on the server and your devices |
| You already run nginx / Traefik / a load balancer | **D. Your proxy** | yours | Its TLS config |
| A platform that runs one Dockerfile (Render, Railway, Fly.io…) | **E. PaaS** | n/a | Managed Redis and a volume |

#### A. Caddy: a server with a public IP and a domain

1. Create a DNS `A` record (and an `AAAA` record for IPv6) for your hostname, e.g.
   `ftt.example.com`, pointing to the server's public IP.
2. Add these lines to `.env`:
   ```dotenv
   COMPOSE_FILE=docker-compose.yml:deploy/compose.caddy.yml
   FTT_DOMAIN=ftt.example.com
   ```
3. Start it. Caddy obtains and renews the certificate automatically.
   ```bash
   docker compose up -d --build
   ```

The overlay ([`deploy/compose.caddy.yml`](deploy/compose.caddy.yml)) adds a Caddy container on
ports 80/443 and sets the app's `TRUSTED_PROXIES` to Caddy's fixed address, `172.30.0.10`.

#### B. Cloudflare Tunnel: no public IP, no open ports

1. In the Cloudflare dashboard, go to **Zero Trust → Networks → Tunnels → Create a tunnel**, choose
   **Cloudflared**, and name it. Copy the token from the install command it shows (the long
   `eyJ…` string after `--token`).
2. In the tunnel's **Public Hostname** tab, add a hostname (e.g. `ftt.example.com`) with service
   type **HTTP** and URL **`app:8000`**.
3. Add these lines to `.env`, then start the stack:
   ```dotenv
   COMPOSE_FILE=docker-compose.yml:deploy/compose.cloudflared.yml
   CLOUDFLARE_TUNNEL_TOKEN=eyJ...
   ```
   ```bash
   docker compose up -d --build
   ```

The overlay ([`deploy/compose.cloudflared.yml`](deploy/compose.cloudflared.yml)) runs
`cloudflared` next to the app and trusts its fixed address, `172.30.0.11`. Cloudflare limits a
request to 100 MB on the free plan. FTT Data uploads in 5 MB chunks, so 500 MB files still work.

#### C. Tailscale: private, across your own devices

1. [Install Tailscale](https://tailscale.com/download) on the server and on every device that will
   use FTT Data, signed in to the same tailnet. In the admin console, under **DNS**, enable MagicDNS
   and **HTTPS Certificates**.
2. Start the stack and publish it to your tailnet over HTTPS:
   ```bash
   docker compose up -d --build
   ```
   ```bash
   sudo tailscale serve --bg 8000
   ```
3. Open `https://<server-name>.<tailnet>.ts.net` from any of your devices.

`tailscale serve` runs on the host and reaches the app through the Docker gateway `172.30.0.1`,
which is the default `TRUSTED_PROXIES`, so no further configuration is needed.

#### D. Your existing reverse proxy

Point the proxy at `http://127.0.0.1:8000` (or `FTT_PORT`). It must:

- **allow request bodies of at least 6 MB**: each upload is one 5 MB chunk plus 28 bytes of overhead;
- **send `X-Forwarded-For`**;
- **match `TRUSTED_PROXIES`**: a proxy on the same host connects from `172.30.0.1` (the default). A
  proxy container on the compose network needs its own IP set in `.env`.

An nginx example (TLS lines omitted; use certbot or your own certificates):

```nginx
server {
    listen 443 ssl;
    server_name ftt.example.com;
    client_max_body_size 6m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_request_buffering off;
    }
}
```

#### E. Platforms that run a single Dockerfile (no Compose)

Render, Railway, Fly.io, Koyeb, Azure Container Apps and similar platforms can run the
[`Dockerfile`](Dockerfile) directly:

1. Deploy the Dockerfile as a web service on **port 8000**. The platform provides HTTPS.
2. Add a Redis instance (a managed add-on or a private service) and set `REDIS_URL`. FTT Data
   keeps only short-lived metadata there, so persistence can be off.
3. Mount a persistent volume at **`/tmp/drops`**. Without one, a redeploy loses in-flight drops.
4. Run **exactly one instance**. Chunks live on that instance's disk.
5. Set `TRUSTED_PROXIES` to the platform's internal proxy range. To find it, open the site once
   and read the app logs: the address in `INFO: 10.x.x.x:port - "GET / …"` is the proxy. Common
   ranges are `10.0.0.0/8`, `172.16.0.0/12` and `100.64.0.0/10`.

### Step 4: Verify the deployment

Replace `ftt.example.com` with your own HTTPS address.

```bash
docker compose ps
```

```bash
curl -fsS https://ftt.example.com/api/health
```

```bash
curl -s -D - -o /dev/null https://ftt.example.com/ | grep -iE "content-security-policy|strict-transport"
```

1. `docker compose ps` shows every service `Up`, and the app and Redis as `(healthy)`.
2. The health check returns `{"ok":true}`, and the page is served with a Content-Security-Policy
   header.
3. Send some text from your laptop and scan the QR code with your phone. Then send a file and open it
   with the typed code.
4. Check that rate limits see real client IPs. In `docker compose logs app`, request lines start
   with your proxy's address (e.g. `172.30.0.10`). That address must be covered by
   `TRUSTED_PROXIES`. If not, every user shares the proxy's rate-limit budget.

### Operating it

| Task | Command / note |
|---|---|
| Follow logs | `docker compose logs -f app` |
| Update to the latest code | `git pull && docker compose up -d --build` |
| Update base images (monthly) | `docker compose build --pull && docker compose pull && docker compose up -d` |
| Change a setting | Edit `.env`, then `docker compose up -d` |
| Restart the app | `docker compose restart app`. Live drops survive (files on the volume, metadata in Redis). |
| Restart Redis / reboot | **All live drops end.** This is by design: metadata is memory-only. Leftover files are deleted at startup. |
| Stop | `docker compose down`. Avoid `down -v` with option A: it deletes Caddy's certificates too. |
| Backups | Nothing to back up except `.env`. Drops are meant to disappear. |

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Red "Encryption isn't available" banner | Page opened over `http://` from another device | Use the HTTPS address |
| Everyone gets "Too many requests" | `TRUSTED_PROXIES` doesn't match the proxy, so all users share one IP | Find the proxy IP in `docker compose logs app`, set it in `.env`, then `docker compose up -d` |
| Uploads fail at the first chunk with an HTML 413 page | The proxy's body-size limit is under 6 MB | Raise it (`client_max_body_size 6m` in nginx) |
| "Server storage is full" (HTTP 507) | `DISK_CAP_BYTES` reached, or the disk itself is full | Wait for drops to expire, raise the cap, or free disk space |
| Caddy has no certificate | DNS doesn't point at the server yet, or ports 80/443 are blocked | `docker compose logs caddy`; check DNS and the firewall |
| Cloudflare shows error 502 or 1033 | Wrong token, or the public hostname's service isn't `http://app:8000` | `docker compose logs cloudflared`; fix the hostname in the dashboard |
| `port is already allocated` on start | Something else uses port 8000 | Set `FTT_PORT=8080` (or similar) in `.env` |
| "The sender is still uploading" never clears | The upload was interrupted | Send again. Unfinished uploads are discarded after 30 minutes. |

### Security checklist

- [ ] HTTPS is the only way in. Port 8000 stays bound to `127.0.0.1` (the default).
- [ ] The only open ports are SSH, plus 80/443 for option A (none for options B and C).
- [ ] `TRUSTED_PROXIES` lists exactly your proxy's address, nothing broader.
- [ ] `.env` is not committed and is readable only by you (`chmod 600 .env`).
- [ ] Base images are rebuilt regularly (see *Operating it*).

---

## How it works

| Step | What happens |
|---|---|
| Code | The browser generates `K7QM3F-9XTR-2PWD`: a 6-character **lookup ID** that is sent to the server, plus an 8-character **secret** (40 bits) that is never sent. Both use Crockford base32. |
| Key | `M = PBKDF2-SHA256(secret, "ftt/v2/salt/<id>", 600 000)`. In *QR code / link only* mode, `M` is 32 random bytes and no code is shown. |
| Subkeys | `encKey = HKDF(M, "ftt/v2/enc/<id>")` (AES-256-GCM, non-extractable); `authToken = HKDF(M, "ftt/v2/auth/<id>")`. |
| QR / link | `/r/<id>#<base64url(M)>`. URL fragments are never sent to servers, and the page removes the key from the address bar and history as soon as it loads. |
| Manifest | `{kind, name, mime, size, chunks}` is encrypted too, so the server can't tell text from files or see filenames. |
| Chunks | `File.slice()` into 5 MB pieces. Each piece is `iv(12) ‖ AES-GCM(ciphertext ‖ tag)` with a fresh random IV and the AAD `ftt/v2\|<id>\|chunk\|<index>\|<total>`, so swapped, reordered or truncated chunks fail to decrypt. Upload and download progress are shown live. |
| Upload | `POST /api/drops` sends the ID, TTL, burn flag, `SHA-256(authToken)`, chunk count, total size and the encrypted manifest. Chunks then go up in order with `PUT`, and `complete` starts the TTL. |
| Download | The receiver proves it has the key by sending `authToken`, which the server checks against the stored hash. Only then are the manifest and chunks released. Five wrong attempts destroy the drop. |
| Storage | Redis holds metadata only, and its TTL *is* the drop's lifetime; persistence is off. Chunks live in `/tmp/drops/<id>/`. A sweeper deletes a drop's files within about a second of its key disappearing, and burn-after-reading deletes everything as soon as the last chunk has been sent. |

## Security model

- **The server cannot:** read content, filenames or types; decrypt drops from a Redis dump or the
  disk; give ciphertext to someone who only guessed an ID; let a link-preview bot burn a drop (bots
  never see the fragment).
- **The server can still:**
  - see the IDs, ciphertext sizes (which reveal approximate plaintext size), TTLs and client IPs;
  - brute-force a **typed code** offline. 40 bits at 600k PBKDF2 iterations is roughly 2 GPU-years.
    Use *QR code / link only* for a full 256-bit key.
- **Whoever serves the page** (the server, or whatever terminates TLS: Cloudflare, your proxy)
  could ship modified JavaScript. Every web-based E2EE app shares this weakness. All scripts are
  self-hosted and the Content Security Policy forbids inline and third-party code, which narrows
  the risk but cannot remove it.

## Content safety

| Check | Where | Bypassable? |
|---|---|---|
| Text ≤ 5 MB, file ≤ 500 MB, blocked extensions / MIME types / executable signatures, keyword & regex rules ([`safety_rules.json`](safety_rules.json)) | Sender's browser, before encryption | Yes: a modified client skips it, which is inherent to E2EE |
| The same rules on decrypted content. Text that matches is hidden behind a warning with **Show anyway**. Flagged files get an extra warning above the standard safety reminder. | Receiver's browser | No |
| Text rendered only via `textContent`. Files offered as an `application/octet-stream` Blob through `<a download>`. Filenames stripped of paths, control and bidi characters. | Receiver's browser | No |
| Streamed body-size caps, TTL bounds, ID format, per-IP rate limits, 5-try lockout, 5 GB disk cap → **507**, `attachment` + `nosniff` + `no-store` on ciphertext | Server | No |

Server-side malware scanning or keyword moderation is impossible without giving up end-to-end
encryption.

## Configuration

**Compose level** (`.env` only):

| Variable | Default | |
|---|---|---|
| `COMPOSE_FILE` | `docker-compose.yml` | Add an overlay from `deploy/` (step 3) |
| `FTT_PORT` | `8000` | Host port, bound to `127.0.0.1` |
| `FTT_DOMAIN` | — | Option A: the hostname Caddy serves |
| `CLOUDFLARE_TUNNEL_TOKEN` | — | Option B: the tunnel token |

**App settings** (`.env` with Compose, or plain environment variables):

| Variable | Default | |
|---|---|---|
| `TRUSTED_PROXIES` | none (`172.30.0.1` under Compose) | IPs/CIDRs whose `X-Forwarded-For` is believed |
| `DISK_CAP_BYTES` | `5368709120` (5 GiB) | Encrypted bytes on disk at once; beyond this, `507` |
| `MAX_TEXT_BYTES` / `MAX_FILE_BYTES` | 5 MiB / 500 MiB | Text must fit in one chunk |
| `CHUNK_SIZE_BYTES` | 5 MiB | |
| `TTL_PRESETS_SECONDS` | `180,300,600,3600` | 3 min, 5 min, 10 min, 1 h |
| `TTL_DEFAULT_SECONDS` | `300` | |
| `TTL_MIN_SECONDS` / `TTL_MAX_SECONDS` | `60` / `3600` | Bounds for the custom 1–60 min option |
| `UPLOAD_WINDOW_SECONDS` | `1800` | Unfinished uploads are discarded after this |
| `MAX_FAILED_ATTEMPTS` | `5` | Wrong codes before a drop is destroyed |
| `RATE_WINDOW_SECONDS`, `RATE_CREATE`, `RATE_OPEN`, `RATE_CHUNK` | `60`, `10`, `30`, `600` | Requests per IP per window |
| `REDIS_URL` | `redis://localhost:6379/0` | Set by Compose |
| `DATA_DIR` | `/tmp/drops` | Set by Compose |
| `SWEEP_INTERVAL_SECONDS` | `1` | |
| `SAFETY_RULES_PATH` | `safety_rules.json` | |

## API

| Method & path | Purpose |
|---|---|
| `GET /api/config` | Limits, TTL presets and safety rules |
| `GET /api/health` | Liveness check |
| `POST /api/drops` | Create (JSON). Returns `upload_token`. Errors: `409` ID taken · `413` too large · `422` invalid · `429` · `507` storage full |
| `PUT /api/drops/{id}/chunks/{i}` | Upload chunk `i` (raw bytes, header `X-Upload-Token`, in order) |
| `POST /api/drops/{id}/complete` | Finish the upload. The TTL starts now. Returns `expires_in_ms` |
| `POST /api/drops/{id}/open` | Header `X-Auth-Token`. Burn drops first answer `claim_required`; then `X-Claim: 1` returns a `claim_token` |
| `GET /api/drops/{id}/chunks/{i}` | Encrypted chunk. Header `X-Auth-Token` (+ `X-Claim-Token` for burn drops) |

## Development & tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

```bash
npm install --ignore-scripts && npm run build:css
```

```bash
docker run -d --rm -p 127.0.0.1:6379:6379 redis:7.4-alpine
```

```bash
.venv/bin/uvicorn main:app --reload --no-proxy-headers
```

Run the tests: 79 in pytest (on fakeredis, no services needed) and 33 in Node's built-in runner.

```bash
.venv/bin/python -m pytest
```

```bash
npm test
```

To run pytest against a real Redis, set `TEST_REDIS_URL`. That database is **flushed** before
every test, so point it at a scratch DB:

```bash
TEST_REDIS_URL=redis://127.0.0.1:6379/15 .venv/bin/python -m pytest
```

| Requirement | Proven by |
|---|---|
| Encryption round trips (text, multi-chunk files, empty files) | `tests/js/crypto.test.mjs`, `tests/test_flow.py` |
| Python and JS implementations agree byte-for-byte | `tests/vectors/ftt_v2.json`, checked by both suites |
| Wrong or malformed codes rejected; 5 tries, then destroyed | `crypto.test.mjs`, `test_flow.py` |
| Tampered, reordered, truncated or cross-drop chunks rejected | `crypto.test.mjs`, `test_flow.py` |
| Exact TTL (3/5/10/60 min and custom), unreadable at expiry, files deleted | `tests/test_ttl.py` |
| Burn after reading: one reader, then deleted; 20 concurrent claims → 1 winner | `tests/test_burn.py` |
| Oversized payloads refused (with or without `Content-Length`); disk cap → `507` | `tests/test_limits.py` |
| Per-IP rate limits; `X-Forwarded-For` honoured only from trusted proxies | `tests/test_ratelimit.py` |
| Cipher opacity: no plaintext, filename, MIME type or key anywhere in Redis or on disk | `tests/test_opacity.py` |
| Safety rules (limits, extensions, MIME types, signatures, keywords/regex, filenames) | `tests/js/safety.test.mjs` |

### Known limits

- The receiving browser assembles a downloaded file in memory. Desktop browsers handle 500 MB, but
  mobile Safari may not. Streaming to disk would need the File System Access API or a Service
  Worker.
- The app runs as one async worker. Disk-quota accounting is atomic in Redis, so adding workers is
  safe, but each worker would run its own sweeper.
- [`static/vendor/qrcode.js`](static/vendor/qrcode.js) is `qrcode-generator@2.0.4` (MIT), vendored
  from `dist/qrcode.mjs` after checking the tarball against npm's `sha512-mZSiP6RnbHl4…` integrity
  hash.

### Layout

```
main.py              routes, streamed body limits, security headers
storage.py           Redis metadata + TTL, chunk files, burn, lockout, sweeper (atomic Lua scripts)
ratelimit.py         fixed-window per-IP limits, trusted-proxy IP resolution
config.py            settings from environment variables
safety_rules.json    content rules shared with the browser via /api/config
static/crypto.js     codes, PBKDF2/HKDF, chunked AES-GCM (no DOM, tested under Node)
static/safety.js     content rules (no DOM, tested under Node)
static/app.js        UI wiring only
templates/index.html + tailwind/input.css → static/tailwind.css
deploy/              optional HTTPS front ends: Caddy, Cloudflare Tunnel
tests/               pytest suite, tests/js Node suite, shared test vector
```

## License

[MIT](LICENSE)

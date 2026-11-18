# syntax=docker/dockerfile:1

# ---- Stage 1: compile Tailwind CSS. Node exists only at build time. ----
FROM node:22-alpine AS css
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tailwind/ tailwind/
COPY templates/ templates/
COPY static/app.js static/app.js
RUN npm run build:css

# ---- Stage 2: runtime ----
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/tmp/drops
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --system --uid 10001 --no-create-home app \
 && mkdir -p /tmp/drops && chown app:app /tmp/drops

COPY config.py main.py ratelimit.py storage.py safety_rules.json ./
COPY templates/ templates/
COPY static/ static/
COPY --from=css /build/static/tailwind.css static/tailwind.css

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"

# --no-proxy-headers: ratelimit.py resolves client IPs itself and only believes
# X-Forwarded-For from TRUSTED_PROXIES. One worker: the sweeper and all I/O are async.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--no-server-header"]

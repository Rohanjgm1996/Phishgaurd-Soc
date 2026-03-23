# ─────────────────────────────────────────────────────────────────────────────
# PhishGuard SOC — Dockerfile
# Multi-stage: Node.js frontend build → Python 3.12 backend
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build React frontend ─────────────────────────────────────────────
FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --silent

COPY frontend/ ./
RUN npm run build


# ── Stage 2: Python backend ────────────────────────────────────────────────────
FROM python:3.12-slim AS backend

# System deps: libmagic (python-magic), libclamav-dev if ClamAV enabled,
# YARA shared library, oletools deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
        libyara-dev \
        file \
        unrar-free \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Backend source
COPY backend/ ./

# Frontend build artifacts → serve as static files from backend
COPY --from=frontend-build /app/frontend/dist ./static

# YARA rules
COPY rules/ ./rules/

# Samples (benign demo data only)
COPY samples/ ./samples/

# Non-root user for security
RUN useradd -m -u 1001 phishguard && \
    mkdir -p ./uploads ./reports && \
    chown -R phishguard:phishguard .

USER phishguard

EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

# ── Stage 1: build the React/Vite admin SPA ─────────────────────────────────
FROM node:20-slim AS spa-builder

WORKDIR /spa
COPY spa/package*.json ./
RUN npm ci --prefer-offline

COPY spa/ ./
RUN npm run build
# Outputs to /spa-dist


# ── Stage 2: Python / FastAPI service ────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Service source
COPY auth.py config.py crl.py db.py main.py ./

# pki/pki.py — PKI library imported at runtime via sys.path.insert (see main.py).
COPY pki/pki.py ./pki/pki.py

# Built SPA
COPY --from=spa-builder /spa-dist/ /app/spa-dist/

ARG BUILD_COMMIT=dev
ARG BUILD_TIME=unknown
ENV BUILD_COMMIT=${BUILD_COMMIT}
ENV BUILD_TIME=${BUILD_TIME}

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

# --- Stage 1: build the React dashboard -------------------------------------
FROM node:20-slim AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build            # outputs /frontend/dist

# --- Stage 2: python runtime ------------------------------------------------
FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY dns_engine/ ./dns_engine/
COPY privacy/ ./privacy/
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY run.py config.yaml ./

# Serve the built dashboard from FastAPI at /
COPY --from=frontend /frontend/dist ./frontend/dist

# DNS (UDP) and the HTTP API/dashboard
EXPOSE 53/udp
EXPOSE 8000

# Runs the DNS resolver and API together (shared state). See run.py.
CMD ["python", "run.py"]

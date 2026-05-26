# ── Stage 1: builder ──────────────────────────────────────────────────────────
# Install deps in a separate layer so they're cached between rebuilds.
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Create data dir (event store lives here — mount a volume in production)
RUN mkdir -p /app/data /app/config

# Non-root user — security best practice
RUN useradd -m appuser && chown -R appuser /app
USER appuser

# Expose API port
EXPOSE 8000

# Heartbeat — Docker restarts the container if this fails 3× in a row
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Start the API
CMD ["uvicorn", "security_core.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

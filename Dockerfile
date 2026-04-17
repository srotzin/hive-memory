# ─────────────────────────────────────────────
# HiveMind — Sovereign Agent Memory Service
# ─────────────────────────────────────────────
FROM python:3.12-slim

# Non-root user for security
RUN addgroup --system hive && adduser --system --ingroup hive hiveuser

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY auth.py models.py store.py main.py ./

# Switch to non-root
USER hiveuser

EXPOSE 8000

# Render sets PORT env var; fall back to 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]

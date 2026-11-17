# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Labels & Metadata
LABEL maintainer="NO ENTRY Cyber Platform <dev@noentry.internal>"
LABEL description="NO ENTRY - Production Cybersecurity Training Platform & Simulation Range"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    PORT=8000 \
    HOST=0.0.0.0

# Install base system packages & network diagnostics
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    ca-certificates \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create application operator user
RUN if ! getent group operator >/dev/null; then groupadd --system operator; fi && \
    if ! id -u operator >/dev/null 2>&1; then \
      useradd --create-home --system --gid operator --shell /bin/bash operator; \
    fi && \
    mkdir -p /app /app/data /app/reports && \
    chown -R operator:operator /app

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy platform source tree
COPY --chown=operator:operator . .

# Switch to non-root operator user
USER operator

# Expose web application port
EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/health || exit 1

# Launch ASGI application
CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]


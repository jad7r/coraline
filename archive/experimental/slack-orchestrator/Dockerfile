# ===================================================================
# Coreline Slack Orchestrator - Production Dockerfile
# ===================================================================
# Multi-stage build for minimal attack surface and compliance
# Compliance: FedRAMP IR-4, ISO 27001 A.12.6.2 (non-root execution)
# ===================================================================

# ===================================================================
# Stage 1: Builder - Dependency Isolation
# ===================================================================
FROM python:3.11-slim AS builder

LABEL stage=builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install to user site-packages
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ===================================================================
# Stage 2: Runner - Hardened Runtime Environment
# ===================================================================
FROM python:3.11-slim AS runner

LABEL maintainer="Coreline Security Operations <security@example.com>"
LABEL org.opencontainers.image.title="Coreline Slack Orchestrator"
LABEL org.opencontainers.image.description="Creates Slack incident response channels from Jira webhook notifications"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="Coreline"

WORKDIR /app

# Install minimal runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for FedRAMP compliance
# UID/GID 10001 (non-standard to avoid conflicts)
RUN groupadd -g 10001 coreline && \
    useradd -u 10001 -g coreline -s /sbin/nologin -c "Coreline Service User" coreline

# Copy dependencies from builder stage
COPY --from=builder /root/.local /home/coreline/.local

# Copy application code
COPY --chown=coreline:coreline . .

# Set PATH to include user site-packages
ENV PATH=/home/coreline/.local/bin:$PATH

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER coreline

# Expose service port
EXPOSE 8081

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Run application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8081", "--workers", "1"]

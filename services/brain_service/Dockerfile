# ==========================================
# Coreline-Brain Service - Production Dockerfile
# Multi-stage build for minimal attack surface
# Compliant with FedRAMP & ISO 27001 container hardening
# ==========================================

# ==========================================
# Stage 1: Build & Dependency Isolation
# ==========================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies (removed after this stage)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install to user site-packages
COPY services/brain_service/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ==========================================
# Stage 2: Hardened Runtime Environment
# ==========================================
FROM python:3.11-slim AS runner

# Metadata labels for compliance tracking
LABEL maintainer="Coreline Security Operations <security@example.com>"
LABEL org.opencontainers.image.title="Coreline-Brain Service"
LABEL org.opencontainers.image.description="Automated Post-Incident Review generation using Claude AI"
LABEL org.opencontainers.image.version="1.0.0"
LABEL security.compliance="ISO27001,FedRAMP"

WORKDIR /app

# Install runtime dependencies (curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-privileged user for FedRAMP compliance
# GID/UID 10001 ensures no conflicts with host systems
RUN groupadd -g 10001 coreline && \
    useradd -u 10001 -g coreline -s /sbin/nologin -c "Coreline Service User" coreline

# Copy installed Python dependencies from builder stage
COPY --from=builder /root/.local /home/coreline/.local

# Copy application code as an importable package (services.brain_service.*).
# The brain/collectors/services.shared modules the archived build referenced do
# not yet exist in the active tree; _lib_shim.py vendors offline stand-ins until
# they land (see ADR-0003). Copy the whole services/ package so imports resolve
# from the repo root.
COPY --chown=coreline:coreline services/ /app/services/

# Create PIR output directory with correct permissions
RUN mkdir -p /output/pirs && chown -R coreline:coreline /output

# Update PATH for user-installed packages
ENV PATH=/home/coreline/.local/bin:$PATH

# Security hardening environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Switch to non-root user (ISO 27001 A.12.6.2 requirement)
USER coreline

# Expose application port
EXPOSE 8082

# Health check for container orchestration (Cloud Run, K8s)
# ISO 27001 A.12.1.3: Capacity Management
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8082/health || exit 1

# Production startup command
CMD ["uvicorn", "services.brain_service.main:app", "--host", "0.0.0.0", "--port", "8082", "--workers", "1"]

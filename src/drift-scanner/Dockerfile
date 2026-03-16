# ==========================
# Drift Scanner — Dockerfile
# ==========================

# Multi-stage build for sandboxed Terraform execution.
#
# Stage 1 (builder): Downloads and verifies Terraform binary
# Stage 2 (runtime): Minimal Python image with scanner code
#
# Usage:
#   docker build -t drift-scanner .
#   docker run -e AWS_REGION=us-east-1 \
#              -e TF_STATE_BUCKET=my-state-bucket \
#              -v ~/.aws:/root/.aws:ro \
#              drift-scanner

# -------------------------------------
# Stage 1: Builder — download Terraform
# -------------------------------------
FROM python:3.12-slim AS builder

ARG TERRAFORM_VERSION=1.9.8

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    unzip \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Download and verify Terraform
RUN curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
    -o /tmp/terraform.zip && \
    curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS" \
    -o /tmp/terraform_sha256sums && \
    cd /tmp && grep "linux_amd64.zip" terraform_sha256sums | sha256sum -c - && \
    unzip /tmp/terraform.zip -d /usr/local/bin/ && \
    rm /tmp/terraform.zip /tmp/terraform_sha256sums && \
    terraform --version

# ---------------------------------------------
# Stage 2: Runtime — minimal image with scanner
# ---------------------------------------------
FROM python:3.12-slim AS runtime

LABEL maintainer="DevOps Team"
LABEL description="Infrastructure Drift Detection Scanner"
LABEL version="1.0.0"

# Install minimal runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash scanner

# Copy Terraform binary from builder
COPY --from=builder /usr/local/bin/terraform /usr/local/bin/terraform

# Verify Terraform installation
RUN terraform --version

# Set up working directory
WORKDIR /opt/scanner

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner source code
COPY scanner.py .
COPY classifier.py .
COPY reporter.py .

# Copy Terraform configs (sample-infra) for local scanning
# In production, this is pulled from S3/Git at runtime
COPY --chown=scanner:scanner . /opt/scanner/

# Create directories for reports and Terraform workspace
RUN mkdir -p /opt/scanner/reports /opt/terraform && \
    chown -R scanner:scanner /opt/scanner /opt/terraform

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=dev \
    AWS_REGION=us-east-1 \
    TF_WORKING_DIR=/opt/terraform/sample-infra \
    TF_IN_AUTOMATION=true \
    TF_INPUT=0

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import scanner; print('OK')" || exit 1

# Run as non-root user
USER scanner

# Default: run the scanner CLI
ENTRYPOINT ["python", "scanner.py"]
CMD ["--local-only", "--output-dir", "/opt/scanner/reports"]

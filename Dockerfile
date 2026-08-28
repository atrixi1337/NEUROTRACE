# =============================================================================
# NEUROTRACE — multi-stage production Dockerfile
# =============================================================================
# Stage 1: build deps + install the package
# Stage 2: slim runtime with baked-in Volatility3 ISF symbols
# =============================================================================

# ---- Stage 1: builder -------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System build deps for capstone, pefile, cryptography wheels.
# We only need these during build; the runtime stage drops them.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
        libssl-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt ./
RUN pip install --prefix=/install -r requirements.txt

COPY . .
RUN pip install --prefix=/install --no-deps .


# ---- Stage 2: runtime -------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="NEUROTRACE" \
      org.opencontainers.image.description="AI volatile memory forensics engine. Volatility3 + Velociraptor + multi-provider LLM analyst." \
      org.opencontainers.image.source="https://github.com/atrixi1337/NEUROTRACE" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="2.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NEUROTRACE_HOME=/opt/neurotrace \
    NEUROTRACE_SYMBOL_DIR=/opt/neurotrace/symbols \
    VOLATILITY_SYMBOL_DIR=/opt/neurotrace/symbols

# Runtime-only system deps. capstone & pefile ship as Python wheels, no
# native libraries are required at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        unzip \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash --uid 1000 neurotrace

# Copy the installed Python environment from the builder.
COPY --from=builder /install /usr/local

# Strip bytecode caches, .dist-info, and pip's wheel cache to shrink
# the runtime layer. These are reproducible from the .py files at
# first import, so dropping them costs nothing.
RUN find /usr/local/lib/python3.11 -type d -name '__pycache__' -prune -exec rm -rf {} + \
    && find /usr/local/lib/python3.11 -name '*.pyc' -delete \
    && find /usr/local/lib/python3.11 -name '*.pyo' -delete

# Copy the application code into /opt/neurotrace and own it as the
# non-root user.
WORKDIR /opt/neurotrace
COPY --chown=neurotrace:neurotrace . /opt/neurotrace

# Strip bytecode again for the app code itself.
RUN find /opt/neurotrace -type d -name '__pycache__' -prune -exec rm -rf {} + \
    && find /opt/neurotrace -name '*.pyc' -delete

# Reinstall the package in editable-less mode (already done by builder,
# but keep this idempotent in case someone builds with --target runtime).
RUN pip install --no-deps . 2>/dev/null || true

# ---- Volatility3 ISF symbols -----------------------------------------------
# The Windows ISF pack is ~100 MB. We download it at build time so the
# container is self-contained — drop a dump in and Vol3 can parse it.
# Set NEUROTRACE_SKIP_SYMBOLS=1 to skip this (e.g. for CI on small runners).
ARG SYMBOLS_URL=https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
RUN mkdir -p /opt/neurotrace/symbols && \
    if [ "${NEUROTRACE_SKIP_SYMBOLS:-0}" != "1" ]; then \
        echo "[+] Downloading Volatility3 ISF symbols from $SYMBOLS_URL ..."; \
        curl -fsSL -o /tmp/windows.zip "$SYMBOLS_URL" \
            && cd /opt/neurotrace/symbols \
            && unzip -q /tmp/windows.zip \
            && rm /tmp/windows.zip \
            && echo "[+] Symbols installed: $(ls /opt/neurotrace/symbols/ | wc -l) files"; \
    else \
        echo "[+] NEUROTRACE_SKIP_SYMBOLS=1 — symbols not installed"; \
    fi

# ---- Persistent storage -----------------------------------------------------
RUN mkdir -p /opt/neurotrace/uploads \
             /opt/neurotrace/reports \
             /opt/neurotrace/workspace \
    && chown -R neurotrace:neurotrace /opt/neurotrace

USER neurotrace

EXPOSE 8010

# Healthcheck: hit /api/health and grep for "operational".
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8010/api/health | grep -q '"status":"operational"' \
        || exit 1

# tini reaps zombies and forwards signals — important for clean shutdown.
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command: launch the FastAPI server.
CMD ["python", "app.py"]

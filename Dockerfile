# AndroSleuth - Docker Image
# Advanced Android APK Forensic Analysis Tool

FROM python:3.11-slim-bullseye

LABEL maintainer="NatsuGwada <natsu@github.com>"
LABEL description="AndroSleuth - Advanced Android APK Forensic Analysis Tool"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=1.7.1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    ANDROSLEUTH_HOME="/opt/androsleuth"

# Add Poetry to PATH
ENV PATH="$POETRY_HOME/bin:$ANDROSLEUTH_HOME/.venv/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    # Git for cloning repositories
    git \
    # SSL/TLS support
    ca-certificates \
    libssl-dev \
    # XML/HTML parsing
    libxml2-dev \
    libxslt1-dev \
    # Image processing
    libjpeg-dev \
    zlib1g-dev \
    # Required for some Python packages
    libffi-dev \
    # For ADB (Android Debug Bridge) - optional for Frida
    adb \
    # Utilities
    curl \
    wget \
    unzip \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - \
    && chmod +x $POETRY_HOME/bin/poetry

# Create working directory
WORKDIR $ANDROSLEUTH_HOME

# Copy project files
COPY pyproject.toml poetry.lock ./
COPY README.md LICENSE ./
COPY config/ ./config/
COPY src/ ./src/
COPY yara_rules/ ./yara_rules/
COPY frida_scripts/ ./frida_scripts/
COPY tests/ ./tests/

# Create directories
RUN mkdir -p reports samples logs

# Install Python dependencies with Poetry
# Install full profile with all features
RUN poetry install --no-dev -E full

# Create a non-root user for security
RUN useradd -m -u 1000 -s /bin/bash androsleuth \
    && chown -R androsleuth:androsleuth $ANDROSLEUTH_HOME \
    && chmod -R 755 $ANDROSLEUTH_HOME/reports $ANDROSLEUTH_HOME/logs $ANDROSLEUTH_HOME/samples

# Switch to non-root user
USER androsleuth

# Set working directory for samples
WORKDIR $ANDROSLEUTH_HOME

# Expose port for potential web interface (future)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD poetry run python -c "import sys; from src.utils.logger import setup_logger; sys.exit(0)"

# Default command - show help
CMD ["poetry", "run", "androsleuth", "--help"]

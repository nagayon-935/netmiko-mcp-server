# --- Build Stage ---
FROM python:3.11-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache

# --- Final Stage ---
FROM python:3.11-slim

WORKDIR /app

# Copy the virtualenv from the build stage
COPY --from=builder /app/.venv /app/.venv

# Copy runtime modules (import_inventory.py / inventory_builder.py are
# interactive CLIs and intentionally excluded)
COPY main.py inventory.py server.py security.py audit.py http_auth.py output_store.py credential_crypto.py tool_results.py diagnostics.py .

# Paths and environment
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Entrypoint: always read the inventory mounted at /app/config.toml
ENTRYPOINT ["python", "main.py", "/app/config.toml"]

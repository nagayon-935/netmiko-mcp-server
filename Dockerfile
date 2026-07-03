# --- Build Stage ---
FROM python:3.11-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# 依存関係のインストール
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache

# --- Final Stage ---
FROM python:3.11-slim

WORKDIR /app

# ビルドステージから仮想環境をコピー
COPY --from=builder /app/.venv /app/.venv

# ソースコードをコピー
COPY main.py inventory.py server.py security.py audit.py http_auth.py .

# パスと環境変数の設定
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# 実行コマンド
# コンテナ内の /app/config.toml を読み込むように固定
ENTRYPOINT ["python", "main.py", "/app/config.toml"]

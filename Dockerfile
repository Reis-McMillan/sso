FROM python:3.14-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 libpq-dev gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH"

ARG ENV=prod

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini README.md LICENSE ./
RUN cp src/verys/config/config.${ENV}.py src/verys/config/config.py
RUN uv sync --frozen

EXPOSE 8080

CMD [".venv/bin/uvicorn", "verys.app:app", "--host", "0.0.0.0", "--port", "8080"]

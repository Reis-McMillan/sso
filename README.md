# Verys

An OAuth2 / OpenID Connect identity provider built with FastAPI, SQLModel, and PostgreSQL.

Verys provides passwordless email-code authentication, OIDC discovery, JWKS, authorization code + refresh token flows with PKCE, consent management, federated login from external providers, and email verification.

## Requirements

- Python 3.14 (managed via [`uv`](https://docs.astral.sh/uv/))
- PostgreSQL 17 (locally via Docker, or your own instance)
- An SMTP relay for verification emails (in dev: any service of your choosing)

## Quickstart with Docker

```bash
docker compose up
```

This starts both PostgreSQL and the Verys backend (on port `8080`). The container builds with the `dev` config by default; override with `--build-arg ENV=prod` if needed.

OIDC discovery is then available at:

```
http://localhost:8080/.well-known/openid-configuration
```

## Local development

```bash
uv sync --extra dev   # installs runtime + test deps; creates .venv
uv run uvicorn verys.app:app --reload --port 8080
```

Migrations:

```bash
uv run alembic upgrade head
```

Tests:

```bash
uv run pytest tests/unit          # fast, no external deps
uv run pytest tests/functional    # requires JWT_PRIVATE_KEY set in config.test.py
```

## Configuration

Environment-specific config lives in [src/verys/config/](src/verys/config/). At build time, the appropriate file is copied to `config.py`:

```
src/verys/config/
├── config.dev.py     # local development defaults
├── config.prod.py    # reads from environment variables
├── config.test.py    # used by the test suite
└── config.py         # selected at build/deploy time (gitignored)
```

Key environment variables expected in production:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_PRIVATE_KEY` | PEM-encoded Ed25519 signing key for OIDC tokens |
| `USERNAME_SMTP` / `PASSWORD_SMTP` | SMTP relay credentials for verification emails |
| `VERYS_CLIENT_ID` | OAuth2 client ID seeded at startup |
| `VERYS_CLIENT_REDIRECT_URI` | Where the Verys public client redirects after auth |
| `VERYS_CLIENT_REGISTRATION_URI` | External registration page URL (optional) |
| `OPENOBSERVE_ENDPOINT` / `OPENOBSERVE_USER` / `OPENOBSERVE_TOKEN` | Log shipping (optional) |

## Project layout

```
verys/
├── pyproject.toml          # project metadata + deps
├── uv.lock                 # resolved dependency graph
├── Dockerfile              # uv-based, src-layout aware
├── docker-compose.yml      # postgres + verys services
├── alembic.ini
├── alembic/                # database migrations
├── tests/
│   ├── unit/
│   ├── functional/
│   └── integration/
└── src/
    └── verys/
        ├── app.py          # FastAPI app + lifespan
        ├── database.py     # SQLModel engine + session factory
        ├── config/
        ├── middleware/     # request logging, JWT auth
        ├── models/         # SQLModel ORM models
        ├── modules/        # JWT, cookies, PKCE, encryption, etc.
        ├── routes/         # FastAPI routers
        └── templates/      # Jinja2 templates for login / consent / register
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[BSD 3-Clause](LICENSE).

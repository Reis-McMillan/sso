from sqlmodel import create_engine, Session, SQLModel
from verys.config import config

import verys.models  # noqa: F401

engine = create_engine(config.DATABASE_URL, pool_pre_ping=True)


def initialize_db():
    """Initialize database schema. Uses create_all for simplicity;
    run `alembic upgrade head` separately for production migrations."""
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


if __name__ == '__main__':
    initialize_db()
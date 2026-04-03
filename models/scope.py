from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel, Session, select


class Scope(SQLModel, table=True):
    __tablename__ = "scope"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str = Field()
    provider_id: Optional[str] = Field(default=None, index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )

    @classmethod
    def get_by_name(cls, session: Session, name: str):
        statement = select(cls).where(cls.name == name)
        return session.exec(statement).first()

    @classmethod
    def get_by_provider(cls, session: Session, provider_id: str) -> list["Scope"]:
        statement = select(cls).where(cls.provider_id == provider_id)
        return list(session.exec(statement).all())

    @classmethod
    def all(cls, session: Session) -> list["Scope"]:
        statement = select(cls)
        return list(session.exec(statement).all())

    @classmethod
    def get_names(cls, session: Session) -> list[str]:
        """Return all scope names (for discovery endpoint)."""
        statement = select(cls.name)
        return list(session.exec(statement).all())

    @classmethod
    def seed_oidc_scopes(cls, session: Session):
        """Ensure standard OIDC scopes exist in the database."""
        defaults = [
            ("openid", "Verify your identity"),
            ("profile", "View your profile information"),
            ("email", "View your email address"),
        ]
        for name, description in defaults:
            existing = cls.get_by_name(session, name)
            if not existing:
                session.add(cls(name=name, description=description))
        session.commit()

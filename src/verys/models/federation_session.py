import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import Column, ARRAY, String, DateTime
from sqlmodel import Field, SQLModel, Session, select

FEDERATION_SESSION_TTL = 10 * 60  # 10 minutes


class FederationSession(SQLModel, table=True):
    __tablename__ = "federation_session"

    id: int | None = Field(default=None, primary_key=True)
    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        unique=True,
        index=True,
    )
    identity_id: int = Field()
    provider_id: str = Field()
    oauth2_session_id: Optional[str] = Field(default=None)
    redirect_uri: Optional[str] = Field(default=None)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.created_at + timedelta(
            seconds=FEDERATION_SESSION_TTL
        )

    @classmethod
    def get_by_session_id(cls, session: Session, session_id: str) -> Optional["FederationSession"]:
        statement = select(cls).where(cls.session_id == session_id)
        return session.exec(statement).first()

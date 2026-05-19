import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel, Session, select

OAUTH2_SESSION_TTL = 10 * 60  # 10 minutes


class OAuth2Session(SQLModel, table=True):
    __tablename__ = "oauth2_session"

    id: int | None = Field(default=None, primary_key=True)
    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        unique=True,
        index=True,
    )
    client_id: str = Field()
    redirect_uri: str = Field()
    response_type: str = Field()
    scope: str = Field()
    state: Optional[str] = Field(default=None)
    nonce: Optional[str] = Field(default=None)
    code_challenge: Optional[str] = Field(default=None)
    code_challenge_method: Optional[str] = Field(default=None)
    csrf_token: Optional[str] = Field(default=None)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.created_at + timedelta(
            seconds=OAUTH2_SESSION_TTL
        )

    @classmethod
    def get_by_session_id(cls, session: Session, session_id: str):
        statement = select(cls).where(cls.session_id == session_id)
        return session.exec(statement).first()

    @classmethod
    def cleanup_expired(cls, session: Session):
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=OAUTH2_SESSION_TTL)
        statement = select(cls).where(cls.created_at < cutoff)
        expired = session.exec(statement).all()
        for s in expired:
            session.delete(s)
        session.commit()

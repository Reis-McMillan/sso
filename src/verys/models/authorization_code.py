import secrets
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, ARRAY, String, DateTime
from sqlmodel import Field, SQLModel, Session, select

from verys.config import config


class AuthorizationCode(SQLModel, table=True):
    __tablename__ = "authorization_code"

    id: int | None = Field(default=None, primary_key=True)
    code: str = Field(
        default_factory=lambda: secrets.token_hex(32),
        unique=True,
        index=True,
    )
    client_id: str = Field()
    identity_email: str = Field()
    redirect_uri: str = Field()
    scopes: List[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String)),
    )
    nonce: Optional[str] = Field(default=None)
    code_challenge: Optional[str] = Field(default=None)
    code_challenge_method: Optional[str] = Field(default=None)
    auth_time: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    used: bool = Field(default=False)

    @classmethod
    def get_by_code(cls, session: Session, code: str):
        statement = select(cls).where(cls.code == code)
        return session.exec(statement).first()

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def mark_used(self, session: Session):
        self.used = True
        session.add(self)
        session.commit()

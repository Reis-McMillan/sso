import secrets
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, ARRAY, String, DateTime
from sqlmodel import Field, SQLModel, Session, select


class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_token"

    id: int | None = Field(default=None, primary_key=True)
    token: str = Field(
        default_factory=lambda: secrets.token_hex(48),
        unique=True,
        index=True,
    )
    client_id: str = Field()
    identity_id: int = Field()
    scopes: List[str] = Field(
        default_factory=list,
        sa_column=Column(ARRAY(String)),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    revoked: bool = Field(default=False)
    replaced_by: Optional[str] = Field(default=None)

    @classmethod
    def get_by_token(cls, session: Session, token: str):
        statement = select(cls).where(cls.token == token)
        return session.exec(statement).first()

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def revoke(self, session: Session, replaced_by: str | None = None):
        self.revoked = True
        if replaced_by:
            self.replaced_by = replaced_by
        session.add(self)
        session.commit()

    @classmethod
    def revoke_all_for_user_client(
        cls, session: Session, identity_id: int, client_id: str
    ):
        statement = select(cls).where(
            cls.identity_id == identity_id,
            cls.client_id == client_id,
            cls.revoked == False,
        )
        tokens = session.exec(statement).all()
        for t in tokens:
            t.revoked = True
            session.add(t)
        session.commit()
